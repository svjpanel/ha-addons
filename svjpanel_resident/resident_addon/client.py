"""Gateway client: outbound HTTPS only, fixed URL, no redirects, TLS verified."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any, NamedTuple

from . import PROTOCOL, VERSION

GATEWAY_URL = "https://ha-gateway.svjpanel.cz"
MAX_BODY = 1_000_000
TOKEN_MARGIN_S = 120
DEFAULT_TOKEN_TTL_S = 600


class Poll(NamedTuple):
    commands: list[dict[str, Any]]
    fast: bool
    next_poll_s: float | None


class Revoked(Exception):
    """Key revoked or unknown (401 key/token, 403 revoked): drop key, show disconnected, do not retry."""


class PairRejected(Exception):
    """Pairing code unknown, used, expired or locked (401 pair_invalid / 429 pair_locked)."""


class Killed(Exception):
    """Gateway kill switch: add-on disabled or below min_version."""


class Conflict(Exception):
    """Another poll is active for this key (409)."""


class TransientError(Exception):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


REVOKE_CODES = frozenset({"key", "token"})


def _error_code(exc: urllib.error.HTTPError) -> str | None:
    """Gateway error body {"error": code}; proxy/IAM/cap 401/403 pages carry none, so they never revoke the key."""
    try:
        body = json.loads(exc.read(4096))
    except (ValueError, OSError, AttributeError):
        return None
    code = body.get("error") if isinstance(body, dict) else None
    return code if isinstance(code, str) else None


def _version_tuple(v: str) -> tuple[int, ...]:
    try:
        return tuple(int(p) for p in v.split("."))
    except ValueError:
        return (0,)


class GatewayClient:
    def __init__(self, install_id: str, key: str | None = None, base_url: str = GATEWAY_URL, opener=None,
                 clock=time.monotonic):
        self._install_id = install_id
        self._key = key
        self._base = base_url.rstrip("/")
        self._opener = opener or urllib.request.build_opener(_NoRedirect)
        self._token: str | None = None
        self._token_exp = 0.0
        self._clock = clock

    def set_key(self, key: str | None) -> None:
        self._key = key
        self._token = None

    def _fresh_token(self) -> str:
        if self._token is None or self._clock() >= self._token_exp:
            res = self._request("POST", "/v1/token", {}, auth="key")
            if not isinstance(res, dict) or not isinstance(res.get("token"), str) or not res["token"]:
                raise TransientError("bad token response")
            ttl = res.get("expires_in")
            ttl = ttl if isinstance(ttl, (int, float)) and ttl > 0 else DEFAULT_TOKEN_TTL_S
            self._token = res["token"]
            self._token_exp = self._clock() + max(ttl - TOKEN_MARGIN_S, 0)
        return self._token

    def _call(self, method: str, path: str, body: dict[str, Any] | None = None, timeout: float = 15) -> Any:
        """Token-authenticated call; one fresh token after a 401 (expiry), then Revoked propagates."""
        try:
            return self._request(method, path, body, timeout, auth="token")
        except Revoked:
            if self._token is None:
                raise
        self._token = None
        return self._request(method, path, body, timeout, auth="token")

    def _request(self, method: str, path: str, body: dict[str, Any] | None = None, timeout: float = 15,
                 auth: str | None = None) -> Any:
        headers = {"Content-Type": "application/json", "X-Install-Id": self._install_id,
                   "X-Addon-Version": VERSION, "X-Protocol": PROTOCOL}
        if auth == "key" and self._key:
            headers["Authorization"] = f"Bearer {self._key}"
        elif auth == "token":
            headers["Authorization"] = f"Bearer {self._fresh_token()}"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self._base + path, data=data, method=method, headers=headers)
        try:
            with self._opener.open(req, timeout=timeout) as resp:
                raw = resp.read(MAX_BODY + 1)
                min_version = resp.headers.get("X-Min-Version")
                status = resp.status
        except urllib.error.HTTPError as exc:
            code = _error_code(exc)
            if exc.code == 401 and code in REVOKE_CODES:
                raise Revoked() from None
            if exc.code == 403 and code == "revoked":
                raise Revoked() from None
            if path == "/v1/pair" and (exc.code == 401 or (exc.code == 429 and code == "pair_locked")):
                raise PairRejected() from None
            if exc.code in (410, 426):
                raise Killed() from None
            if exc.code == 409:
                raise Conflict() from None
            raise TransientError(f"http {exc.code}") from None
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise TransientError(type(exc).__name__) from None
        if len(raw) > MAX_BODY or status >= 300:
            raise TransientError("bad response")
        if min_version and _version_tuple(VERSION) < _version_tuple(min_version):
            raise Killed()
        if not raw:
            return None
        try:
            payload = json.loads(raw)
        except ValueError:
            raise TransientError("bad json") from None
        if isinstance(payload, dict) and payload.get("disabled") is True:
            raise Killed()
        return payload

    def pair(self, code: str, ha_version: str) -> dict[str, Any]:
        res = self._request("POST", "/v1/pair", {"code": code, "addon_version": VERSION,
                                                 "ha_version": ha_version, "install_id": self._install_id})
        if not isinstance(res, dict) or not isinstance(res.get("key"), str):
            raise TransientError("bad pair response")
        return res

    def rotate(self) -> dict[str, Any]:
        res = self._request("POST", "/v1/rotate", {}, auth="key")
        if not isinstance(res, dict) or not isinstance(res.get("key"), str):
            raise TransientError("bad rotate response")
        return res

    def push_allowlist(self, entities: list[dict[str, Any]]) -> None:
        self._call("POST", "/v1/allowlist", {"entities": entities})

    def push_state(self, states: dict[str, Any]) -> None:
        self._call("POST", "/v1/state", {"states": states})

    def poll(self, wait: int = 0) -> Poll:
        res = self._call("GET", f"/v1/commands?wait={wait}", timeout=wait + 10)
        if isinstance(res, list):
            cmds, mode, nxt = res, "idle", None
        elif isinstance(res, dict):
            cmds, mode, nxt = res.get("commands", []), res.get("mode"), res.get("next_poll_s")
        else:
            cmds, mode, nxt = [], "idle", None
        if not isinstance(cmds, list):
            cmds = []
        nxt = float(nxt) if isinstance(nxt, (int, float)) and not isinstance(nxt, bool) and nxt > 0 else None
        return Poll([c for c in cmds if isinstance(c, dict)], mode == "fast", nxt)

    def poll_commands(self, wait: int = 25) -> list[dict[str, Any]]:
        return self.poll(wait).commands

    def post_result(self, cmd_id: str, ok: bool, error: str | None = None) -> None:
        body: dict[str, Any] = {"ok": ok}
        if error:
            body["error"] = error
        self._call("POST", f"/v1/commands/{cmd_id}/result", body)
