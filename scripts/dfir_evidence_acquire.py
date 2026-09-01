#!/usr/bin/env python3
"""SHA-verified acquisition of the Phase 3D-C real DFIR evidence artifact.

Downloads the corpus described in ``evaluation/dfir_evidence_manifest.json``
into ``.runtime/eval-artifacts/dfir/`` (never committed), verifies size and
SHA-256, and aborts on any mismatch. Writes a small acquisition audit record.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "evaluation" / "dfir_evidence_manifest.json"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def acquire(*, force: bool = False) -> dict:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    corpus = manifest["corpus"]
    target = ROOT / corpus["target_relative"]
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.is_file() and not force:
        data = target.read_bytes()
        actual = _sha256(data)
        if actual == corpus["sha256"]:
            return {
                "ok": True,
                "cached": True,
                "path": str(target),
                "size": len(data),
                "sha256": actual,
            }
        raise SystemExit(
            f"cached {target} SHA mismatch: expected {corpus['sha256']} got {actual}"
        )
    print(f"downloading {corpus['source_url']}", file=sys.stderr)
    with urllib.request.urlopen(corpus["source_url"], timeout=60) as response:
        data = response.read()
    size = len(data)
    if size != int(corpus["expected_size"]):
        raise SystemExit(
            f"size mismatch: expected {corpus['expected_size']} got {size}"
        )
    actual = _sha256(data)
    if actual != corpus["sha256"]:
        raise SystemExit(
            f"SHA mismatch: expected {corpus['sha256']} got {actual}; refusing to use"
        )
    target.write_bytes(data)
    return {
        "ok": True,
        "cached": False,
        "path": str(target),
        "size": size,
        "sha256": actual,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Acquire the DFIR evidence artifact")
    parser.add_argument("--force", action="store_true", help="re-download even if cached")
    args = parser.parse_args()
    result = acquire(force=args.force)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
