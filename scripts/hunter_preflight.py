#!/usr/bin/env python3
"""hunter preflight - non-live four-domain environment summary.

Runs each real adapter's healthcheck only. No analysis, no model call, no
Docker container, and no MCP session is started.

Usage:
    pentestgpt-core/pentestgpt_agent/.venv/bin/python scripts/hunter_preflight.py
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for entry in (str(ROOT), str(ROOT / "pentestgpt-core/pentestgpt_agent/src")):
    if entry not in sys.path:
        sys.path.insert(0, entry)

from integrations.preflight import DOMAIN_ORDER, run_preflight  # noqa: E402


async def main() -> int:
    results = await run_preflight(repo_root=ROOT)
    print(f"{'domain':<24}{'status':<9}detail")
    print("-" * 72)
    for domain in DOMAIN_ORDER:
        item = results[domain]
        reason = item.error_code or item.message or "ready"
        print(f"{domain:<24}{item.status.value:<9}{reason}")
        for key, value in sorted(item.details.items()):
            text = str(value)
            print(f"    {key}: {text[:120]}")
    ready = all(item.status.value == "READY" for item in results.values())
    return 0 if ready else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
