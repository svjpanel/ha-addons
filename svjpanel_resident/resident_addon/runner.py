from __future__ import annotations

import json
import logging
import random
import re
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from . import keystore
from .client import MAX_POLL_S, MIN_POLL_S, Conflict, GatewayClient, Killed, PairRejected, Revoked, TransientError
from .ha_api import HAApi
from .policy import Dedupe, Rejected, build_call, parse_actions, ttl_of
from .state import Reporter, allowlist_entries, parse_reads, state_body

log = logging.getLogger("resident_addon")
CMD_ID_RE = re.compile(r"[A-Za-z0-9_-]{8,64}")
ROTATE_BEFORE = timedelta(days=14)
SAVE_ATTEMPTS = 3
SAVE_RETRY_S = 1.0
_pending_save: list[tuple[str, str | None, str]] = []
ROTATE_MIN_GAP_S = 3600.0
_last_rotate = [-ROTATE_MIN_GAP_S]
HEARTBEAT_S = 300
STATE_TICK_S = 5
IDLE_POLL_S = 60
IDLE_JITTER_S = 10
FAST_WAIT_S = 25
FAST_MIN_INTERVAL_S = 1.0
CONFIRM_CODE_RE = re.compile(r"^\d{4}$")


def idle_delay(next_poll_s: float | None, rnd=random.random) -> float:
    base = next_poll_s if next_poll_s is not None else IDLE_POLL_S
    return min(max(base, MIN_POLL_S), MAX_POLL_S) + rnd() * IDLE_JITTER_S


def fast_poll_pause(elapsed: float) -> float:
    """A fast-mode poll that returned empty sooner than this must not be re-issued at once (wait ignored by a proxy)."""
    return max(0.0, FAST_MIN_INTERVAL_S - elapsed)


def load_options(path: str = "/data/options.json") -> dict[str, Any]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def execute_command(cmd: dict[str, Any], grants, ha: HAApi, dedupe: Dedupe, received_at: float,
                    clock=time.monotonic, persist=None) -> tuple[bool, str | None]:
    """Returns (ok, error). Never raises on bad input; duplicates return (True, 'duplicate')."""
    cmd_id = cmd.get("cmd_id")
    if not isinstance(cmd_id, str) or not CMD_ID_RE.fullmatch(cmd_id):
        return False, "bad cmd_id"
    if dedupe.seen(cmd_id):
        return True, "duplicate"
    try:
        ttl = ttl_of(cmd)
        domain, service, payload = build_call(cmd, grants)
    except Rejected as exc:
        dedupe.add(cmd_id)
        return False, f"rejected: {exc}"
    except Exception:  # noqa: BLE001
        dedupe.add(cmd_id)
        return False, "rejected: internal"
    dedupe.add(cmd_id)
    if persist:
        try:
            persist()
        except OSError:
            log.warning("could not persist dedupe state")
    if clock() - received_at > ttl:
        return False, "expired"
    try:
        ha.call_service(domain, service, payload)
    except Exception as exc:  # noqa: BLE001
        return False, f"ha error: {type(exc).__name__}"
    return True, None


def _parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def maybe_rotate(client: GatewayClient, record: dict[str, Any], now: datetime | None = None) -> None:
    if _pending_save and _try_save(*_pending_save[0]):
        _pending_save.clear()
    exp = _parse_ts(record.get("expires_at"))
    now = now or datetime.now(timezone.utc)
    if exp is None or exp - now > ROTATE_BEFORE:
        return
    if time.monotonic() - _last_rotate[0] < ROTATE_MIN_GAP_S:
        return
    _last_rotate[0] = time.monotonic()
    res = client.rotate()
    client.set_key(res["key"])
    args = (res["key"], res.get("expires_at"), record["install_id"])
    if not _try_save(*args):
        _pending_save[:] = [args]


def _try_save(key: str, expires_at: str | None, install_id: str) -> bool:
    for attempt in range(SAVE_ATTEMPTS):
        try:
            keystore.save_key(key, expires_at, install_id)
            return True
        except OSError as e:
            log.error("save_key failed after rotate (attempt %d/%d): %s", attempt + 1, SAVE_ATTEMPTS, e)
            if attempt + 1 < SAVE_ATTEMPTS:
                time.sleep(SAVE_RETRY_S)
    return False


def run(options: dict[str, Any] | None = None, ha: HAApi | None = None) -> int:
    opts = options if options is not None else load_options()
    ha = ha or HAApi()
    install_id = keystore.load_install_id()
    record = keystore.load_key()
    client = GatewayClient(install_id, record["key"] if record else None)
    try:
        if record is None:
            code = str(opts.get("pairing_code", "")).strip()
            if not code or opts.get("t3_declaration") is not True:
                log.warning("not paired: set pairing_code and confirm the T3 declaration in the add-on options")
                return 2
            res = client.pair(code, ha.ha_version())
            keystore.save_key(res["key"], res.get("expires_at"), install_id)
            client.set_key(res["key"])
            record = keystore.load_key()
            code_out = res.get("check_code")
            if isinstance(code_out, str) and CONFIRM_CODE_RE.match(code_out):
                log.info("paired: enter confirmation code %s in the portal to finish pairing", code_out)
            else:
                log.warning("paired, but the gateway sent no valid confirmation code; re-pair from the portal")
        reads = parse_reads(opts.get("read_entities", []))
        grants = parse_actions(opts.get("actions", []))
        try:
            initial = ha.states()
        except Exception:  # noqa: BLE001
            initial = []
        client.push_allowlist(allowlist_entries(reads, grants, initial))
        reporter = Reporter(reads)
        dedupe = Dedupe(seed=keystore.load_dedupe())
        last_beat = last_tick = 0.0
        fast = False
        delay = 0.0
        while True:
            now = time.monotonic()
            if now - last_tick >= STATE_TICK_S:
                last_tick = now
                try:
                    batch = reporter.collect(ha.states())
                except Exception:  # noqa: BLE001
                    batch = []
                if batch:
                    client.push_state(state_body(batch))
                    last_beat = now
                elif now - last_beat >= HEARTBEAT_S:
                    client.push_state({})
                    last_beat = now
                if record:
                    maybe_rotate(client, record)
                    record = keystore.load_key() or record
            if not fast and delay > 0:
                time.sleep(min(delay, STATE_TICK_S))
                delay -= STATE_TICK_S
                continue
            poll_started = time.monotonic()
            try:
                polled = client.poll(FAST_WAIT_S if fast else 0)
            except Conflict:
                time.sleep(30)
                continue
            cmds = polled.commands
            if fast and not cmds:
                time.sleep(fast_poll_pause(time.monotonic() - poll_started))
            fast = polled.fast
            delay = 0.0 if fast else idle_delay(polled.next_poll_s)
            received = time.monotonic()
            for cmd in cmds:
                ok, err = execute_command(cmd, grants, ha, dedupe, received,
                                          persist=lambda: keystore.save_dedupe(dedupe.snapshot()))
                if err == "duplicate":
                    continue
                cid = cmd.get("cmd_id")
                if isinstance(cid, str) and CMD_ID_RE.fullmatch(cid):
                    client.post_result(cid, ok, err)
    except Revoked:
        keystore.delete_key()
        log.error("disconnected: key revoked; re-pair from the portal")
        return 3
    except PairRejected:
        log.error("pairing code rejected (unknown, used, expired or locked); create a new code in the portal")
        return 2
    except Killed:
        log.error("disabled by gateway kill switch or version below minimum")
        return 4
    except TransientError:
        log.warning("gateway unreachable")
        return 1
