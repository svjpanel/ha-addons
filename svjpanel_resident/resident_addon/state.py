"""Outbound state filter: opt-in per entity, numbers/enums by default."""
from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass
from typing import Any

from .policy import DENY_DOMAINS, ENTITY_RE, READ_DOMAINS

MAX_ENTITIES = 200
MAX_TEXT = 64
MAX_NAME = 64
MIN_INTERVAL_S = 5.0
SENSITIVE_MIN_INTERVAL_S = 60.0
KEEP_ATTRS = ("unit_of_measurement", "device_class", "friendly_name")
SAFE_CLASSES = frozenset({
    "temperature", "battery", "pressure", "atmospheric_pressure", "voltage", "signal_strength",
    "timestamp", "date", "duration", "aqi", "pm1", "pm10", "pm25", "precipitation",
    "precipitation_intensity", "wind_speed", "irradiance", "uv_index", "enum", "connectivity",
    "problem", "battery_charging", "plug", "running", "update", "heat", "cold", "light",
})
AUDIO_CLASSES = frozenset({"sound", "sound_pressure"})
LOCATION_ATTRS = frozenset({"latitude", "longitude", "gps_accuracy"})
MEDIA_ATTRS = frozenset({"media_title", "media_artist", "media_content_id", "microphone"})
WEATHER_STATES = frozenset({
    "clear-night", "cloudy", "exceptional", "fog", "hail", "lightning", "lightning-rainy",
    "partlycloudy", "pouring", "rainy", "snowy", "snowy-rainy", "sunny", "windy", "windy-variant",
})
HVAC_MODES = frozenset({"off", "heat", "cool", "auto", "heat_cool", "dry", "fan_only"})
ENUM_STATES = frozenset({"on", "off", "unavailable", "unknown"}) | HVAC_MODES | WEATHER_STATES
NUMBER_RE = re.compile(r"-?\d{1,15}(\.\d{1,12})?")
NAME_OK = re.compile(r"[\w .,()\-/+°%]{1,64}")
DC_OK = re.compile(r"[a-z_]{1,40}")
NAME_BAD = re.compile(r"[<>\x00-\x1f\x7f]")


def is_sensitive_class(device_class: Any) -> bool:
    return isinstance(device_class, str) and device_class not in SAFE_CLASSES


@dataclass(frozen=True)
class ReadGrant:
    entity_id: str
    text_ack: bool = False
    sensitive_ack: bool = False


def parse_reads(raw: list[dict[str, Any]]) -> dict[str, ReadGrant]:
    out: dict[str, ReadGrant] = {}
    for item in (raw or [])[:MAX_ENTITIES]:
        eid = str(item.get("entity_id", ""))
        if not ENTITY_RE.fullmatch(eid):
            continue
        domain = eid.split(".", 1)[0]
        if domain in DENY_DOMAINS or domain not in READ_DOMAINS:
            continue
        out[eid] = ReadGrant(eid, bool(item.get("text", False)), bool(item.get("sensitive_ack", False)))
    return out


def _is_number(s: str) -> bool:
    return len(s) <= 32 and NUMBER_RE.fullmatch(s) is not None


def wire_value(value: str) -> int | float | str:
    """Numeric states go out as JSON numbers (gateway StateIn.states values), everything else as the short string."""
    if _is_number(value):
        return float(value) if "." in value else int(value)
    return value


def state_body(batch: list[dict[str, Any]]) -> dict[str, int | float | str]:
    return {rec["entity_id"]: wire_value(rec["state"]) for rec in batch}


def allowlist_entries(reads: dict[str, ReadGrant], grants: dict, states: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Gateway AllowlistIn.entities: one dict per entity, read and action grants merged, bare service names."""
    by_id = {st.get("entity_id"): st for st in states if isinstance(st, dict)}
    order = list(reads) + [eid for eid, _ in grants if eid not in reads]
    entries: dict[str, dict[str, Any]] = {}
    for eid in order:
        if eid in entries:
            continue
        attrs = (by_id.get(eid) or {}).get("attributes") or {}
        dc, unit = attrs.get("device_class"), attrs.get("unit_of_measurement")
        read = reads.get(eid)
        if dc in AUDIO_CLASSES or (is_sensitive_class(dc) and not (read and read.sensitive_ack)):
            continue
        services = sorted(g.service.split(".", 1)[1] for (e, _), g in grants.items() if e == eid)
        name = _clean_name(attrs.get("friendly_name"))
        entry: dict[str, Any] = {"entity_id": eid, "name": name if name and NAME_OK.fullmatch(name) else eid,
                                 "services": services}
        if isinstance(dc, str) and DC_OK.fullmatch(dc):
            entry["device_class"] = dc
        if isinstance(unit, str) and len(unit) <= 16 and unit.isprintable():
            entry["unit"] = unit
        if read:
            entry["text_confirmed"] = read.text_ack
            entry["privacy_confirmed"] = read.sensitive_ack
        if any(g.confirmed_triggers_others for (e, _), g in grants.items() if e == eid):
            entry["risky_confirmed"] = True
        entries[eid] = entry
    return list(entries.values())[:MAX_ENTITIES]


def _clean_name(name: Any) -> str | None:
    if not isinstance(name, str) or not name or len(name) > MAX_NAME or NAME_BAD.search(name):
        return None
    return name


def project(state: dict[str, Any], grant: ReadGrant | None) -> dict[str, Any] | None:
    """Return the sanitised record to transmit, or None if the entity must not leave the flat."""
    if grant is None:
        return None
    attrs = state.get("attributes") or {}
    if LOCATION_ATTRS & attrs.keys() or attrs.get("source_type") == "gps":
        return None
    if MEDIA_ATTRS & attrs.keys():
        return None
    device_class = attrs.get("device_class")
    if device_class in AUDIO_CLASSES:
        return None
    if is_sensitive_class(device_class) and not grant.sensitive_ack:
        return None
    value = state.get("state")
    if not isinstance(value, str):
        return None
    if not (_is_number(value) or value in ENUM_STATES):
        if not grant.text_ack or len(value) > MAX_TEXT or NAME_BAD.search(value):
            return None
    out: dict[str, Any] = {"entity_id": grant.entity_id, "state": value}
    unit = attrs.get("unit_of_measurement")
    if isinstance(unit, str) and len(unit) <= 16 and not NAME_BAD.search(unit):
        out["unit_of_measurement"] = unit
    if isinstance(device_class, str) and len(device_class) <= 32 and not NAME_BAD.search(device_class):
        out["device_class"] = device_class
        if is_sensitive_class(device_class):
            out["privacy_sensitive"] = True
    name = _clean_name(attrs.get("friendly_name"))
    if name:
        out["friendly_name"] = name
    return out


class Reporter:
    """Change detection + per-entity rate limit; heartbeat is a separate empty push."""

    def __init__(self, reads: dict[str, ReadGrant], clock=time.monotonic):
        self._reads = reads
        self._clock = clock
        self._last: dict[str, tuple[str, float]] = {}

    def collect(self, states: list[dict[str, Any]]) -> list[dict[str, Any]]:
        now = self._clock()
        batch: list[dict[str, Any]] = []
        for st in states:
            rec = project(st, self._reads.get(st.get("entity_id", "")))
            if rec is None:
                continue
            digest = hashlib.sha256(json.dumps(rec, sort_keys=True).encode()).hexdigest()
            prev = self._last.get(rec["entity_id"])
            if prev and prev[0] == digest:
                continue
            interval = SENSITIVE_MIN_INTERVAL_S if rec.get("privacy_sensitive") else MIN_INTERVAL_S
            if prev and now - prev[1] < interval:
                continue
            self._last[rec["entity_id"]] = (digest, now)
            batch.append(rec)
            if len(batch) >= MAX_ENTITIES:
                break
        return batch
