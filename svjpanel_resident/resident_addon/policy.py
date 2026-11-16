"""Command policy: the add-on builds every HA call itself."""
from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

DENY_DOMAINS = frozenset({
    "lock", "cover", "alarm_control_panel", "camera", "media_player", "person",
    "device_tracker", "notify", "shell_command", "homeassistant", "hassio",
    "rest_command", "zone", "geo_location",
})
READ_DOMAINS = frozenset({"sensor", "binary_sensor", "climate", "weather"})
TRIGGERS_OTHERS = frozenset({"script", "scene", "switch", "input_boolean"})

ENTITY_RE = re.compile(r"^[a-z_]+\.[a-z0-9_]{1,100}$")
FORBIDDEN_KEYS = frozenset({"entity_id", "device_id", "area_id", "label_id", "floor_id", "target"})
TEMPLATE_MARKERS = ("{{", "{%", "{#")
MAX_TTL_S = 60
CLIMATE_MIN_C = 5.0
CLIMATE_MAX_C = 30.0


class Rejected(Exception):
    pass


def _int_range(lo: int, hi: int) -> Callable[[Any], int]:
    def check(v: Any) -> int:
        if isinstance(v, bool) or not isinstance(v, int | float) or v != int(v):
            raise Rejected("expected integer")
        return max(lo, min(hi, int(v)))
    return check


def _clamped_float(lo: float, hi: float) -> Callable[[Any], float]:
    def check(v: Any) -> float:
        if isinstance(v, bool) or not isinstance(v, int | float) or v != v:
            raise Rejected("expected number")
        return max(lo, min(hi, float(v)))
    return check


# (domain, service) -> {data key: validator}. Single place to extend only after a deliberate decision and a security review.
SERVICE_SPECS: dict[tuple[str, str], dict[str, Callable[[Any], Any]]] = {
    ("light", "turn_on"): {
        "brightness_pct": _int_range(0, 100),
        "color_temp_kelvin": _int_range(1000, 10000),
    },
    ("light", "turn_off"): {},
    ("switch", "turn_on"): {},
    ("switch", "turn_off"): {},
    ("input_boolean", "turn_on"): {},
    ("input_boolean", "turn_off"): {},
    ("scene", "turn_on"): {},
    ("script", "turn_on"): {},
    ("button", "press"): {},
    ("climate", "set_temperature"): {"temperature": _clamped_float(CLIMATE_MIN_C, CLIMATE_MAX_C)},
}


@dataclass(frozen=True)
class ActionGrant:
    entity_id: str
    service: str
    confirmed_triggers_others: bool = False


def parse_actions(raw: list[dict[str, Any]]) -> dict[tuple[str, str], ActionGrant]:
    grants: dict[tuple[str, str], ActionGrant] = {}
    for item in raw or []:
        entity_id = str(item.get("entity_id", ""))
        service = str(item.get("service", ""))
        if not ENTITY_RE.fullmatch(entity_id) or service.count(".") != 1:
            continue
        domain = entity_id.split(".", 1)[0]
        svc_domain, svc = service.split(".", 1)
        if domain in DENY_DOMAINS or svc_domain != domain or (domain, svc) not in SERVICE_SPECS:
            continue
        grant = ActionGrant(entity_id, service, bool(item.get("confirm_triggers_others", False)))
        if domain in TRIGGERS_OTHERS and not grant.confirmed_triggers_others:
            continue
        grants[(entity_id, service)] = grant
    return grants


def _scan_strings(value: Any) -> None:
    if isinstance(value, str):
        if any(m in value for m in TEMPLATE_MARKERS):
            raise Rejected("template")
    elif isinstance(value, dict):
        for k, v in value.items():
            _scan_strings(k)
            _scan_strings(v)
    elif isinstance(value, list | tuple):
        for v in value:
            _scan_strings(v)


def build_call(cmd: dict[str, Any], grants: dict[tuple[str, str], ActionGrant]) -> tuple[str, str, dict[str, Any]]:
    """Return (domain, service, payload) built from an allowlisted entity + service, or raise Rejected."""
    entity_id = cmd.get("entity_id")
    service = cmd.get("service")
    if not all(isinstance(x, str) for x in (entity_id, service)):
        raise Rejected("malformed")
    if not ENTITY_RE.fullmatch(entity_id):
        raise Rejected("bad entity_id")
    domain = entity_id.split(".", 1)[0]
    if domain in DENY_DOMAINS:
        raise Rejected("denied domain")
    spec = SERVICE_SPECS.get((domain, service))
    if spec is None:
        raise Rejected("service not supported")
    if (entity_id, f"{domain}.{service}") not in grants:
        raise Rejected("not in allowlist")
    data = cmd.get("params")
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise Rejected("params must be an object")
    _scan_strings(data)
    clean: dict[str, Any] = {}
    for key, value in data.items():
        if key in FORBIDDEN_KEYS:
            raise Rejected("forbidden data key")
        validator = spec.get(key)
        if validator is None:
            raise Rejected("data key not allowed")
        clean[key] = validator(value)
    if (domain, service) == ("climate", "set_temperature") and "temperature" not in clean:
        raise Rejected("temperature required")
    return domain, service, {"entity_id": entity_id, **clean}


def ttl_of(cmd: dict[str, Any]) -> float:
    ttl = cmd.get("ttl_s")
    if isinstance(ttl, bool) or not isinstance(ttl, int | float) or ttl <= 0:
        raise Rejected("bad ttl_s")
    return min(float(ttl), MAX_TTL_S)


class Dedupe:
    def __init__(self, size: int = 200, seed: list[str] | None = None):
        self._size = size
        self._ids: list[str] = list(seed or [])[-size:]

    def seen(self, cmd_id: str) -> bool:
        return cmd_id in self._ids

    def add(self, cmd_id: str) -> None:
        self._ids.append(cmd_id)
        del self._ids[:-self._size]

    def snapshot(self) -> list[str]:
        return list(self._ids)
