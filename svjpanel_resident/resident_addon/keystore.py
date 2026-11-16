"""Flat key and dedupe state in the add-on's private /data (never in Options, never logged)."""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

SHORT_ID_LEN = 6
DATA_DIR = Path(os.environ.get("ADDON_DATA_DIR", "/data"))


def _path(name: str) -> Path:
    return DATA_DIR / name


def _write_atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=path.name, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def _read(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def load_key() -> dict[str, Any] | None:
    data = _read(_path("flat_key.json"))
    if data and isinstance(data.get("key"), str) and "." in data["key"]:
        return data
    return None


def save_key(key: str, expires_at: str | None, install_id: str) -> None:
    _write_atomic(_path("flat_key.json"), {"key": key, "expires_at": expires_at, "install_id": install_id})


def delete_key() -> None:
    _path("flat_key.json").unlink(missing_ok=True)


def load_install_id() -> str:
    data = _read(_path("install.json"))
    if data and isinstance(data.get("install_id"), str):
        return data["install_id"]
    install_id = os.urandom(12).hex()
    _write_atomic(_path("install.json"), {"install_id": install_id})
    return install_id


def short_install_id(install_id: str) -> str:
    """Label the portal confirm dialog shows (first 6 chars); the resident types it there."""
    return install_id[:SHORT_ID_LEN]


def load_dedupe() -> list[str]:
    data = _read(_path("dedupe.json"))
    ids = data.get("ids") if data else None
    return [i for i in ids if isinstance(i, str)] if isinstance(ids, list) else []


def save_dedupe(ids: list[str]) -> None:
    _write_atomic(_path("dedupe.json"), {"ids": ids})
