"""Record per-arch image digests of a release into release-digests.json (RELEASE.md step 1).

Usage: python record_digest.py release-digests.json <version> aarch64=sha256:<hex> amd64=sha256:<hex>
A version is never re-recorded with different digests (tag is never reused).
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ARCHES = ("aarch64", "amd64")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_VERSION = re.compile(r"^\d+\.\d+\.\d+$")


def add_release(path: Path, version: str, digests: dict[str, str]) -> bool:
    if not _VERSION.match(version):
        raise ValueError(f"invalid version {version!r}")
    if set(digests) != set(ARCHES):
        raise ValueError(f"digests required for exactly {ARCHES}")
    for arch, d in digests.items():
        if not _DIGEST.match(d):
            raise ValueError(f"invalid digest for {arch}")
    data = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    if version in data:
        if data[version] == digests:
            return False
        raise ValueError(f"version {version} already recorded with different digests (re-tag)")
    data[version] = digests
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return True


def main(argv: list[str]) -> int:
    if len(argv) != 5:
        print(__doc__)
        return 2
    digests = dict(a.split("=", 1) for a in argv[3:])
    changed = add_release(Path(argv[1]), argv[2], digests)
    print("recorded" if changed else "unchanged")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
