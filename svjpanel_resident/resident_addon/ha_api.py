from __future__ import annotations

import json
import os
import urllib.request
from typing import Any

BASE = "http://supervisor/core/api"


class HAApi:
    def __init__(self, token: str | None = None, base: str = BASE):
        self._token = token or os.environ.get("SUPERVISOR_TOKEN", "")
        self._base = base

    def _req(self, method: str, path: str, body: dict[str, Any] | None = None) -> Any:
        req = urllib.request.Request(
            self._base + path, method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={"Authorization": f"Bearer {self._token}", "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read()
        return json.loads(raw) if raw else None

    def states(self) -> list[dict[str, Any]]:
        res = self._req("GET", "/states")
        return res if isinstance(res, list) else []

    def ha_version(self) -> str:
        res = self._req("GET", "/config")
        return str(res.get("version", "")) if isinstance(res, dict) else ""

    def call_service(self, domain: str, service: str, payload: dict[str, Any]) -> None:
        self._req("POST", f"/services/{domain}/{service}", payload)
