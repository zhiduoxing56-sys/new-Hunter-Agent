#!/usr/bin/env python3
"""Idempotent TRUDI Full runtime bootstrap + healthcheck.

Recovers the pinned Node.js + Claude Code runtime under ``.runtime/`` so a fresh
checkout can reach a TRUDI Full healthcheck-ready state once a valid DeepSeek
API key is available (process environment or the existing Kong ``config.db``
secret store). It never writes secrets to disk and never prints a secret value.

Pinned versions are derived from the verified installs in this repository
(not invented):

- Node.js    22.23.2   (``.runtime/node-runtime/node_modules/node/package.json``)
- Claude Code 2.1.251  (``.runtime/claude-code/node_modules/@anthropic-ai/claude-code/package.json``)

``--ensure`` installs only when the installed versions do not match the pins
(idempotent: a second run is a no-op). ``--check`` (default) only verifies.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]

NODE_VERSION = "22.23.2"
CLAUDE_VERSION = "2.1.251"
CONFIG_DB = ROOT / ".runtime" / "kong" / "config" / "config.db"
NODE_PREFIX = ROOT / ".runtime" / "node-runtime"
CLAUDE_PREFIX = ROOT / ".runtime" / "claude-code"
NODE_BIN = NODE_PREFIX / "node_modules" / ".bin" / "node"
CLAUDE_BIN = CLAUDE_PREFIX / "node_modules" / ".bin" / "claude"


def _run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, capture_output=True, text=True)


def _installed_node_version() -> str | None:
    pkg = NODE_PREFIX / "node_modules" / "node" / "package.json"
    if not pkg.is_file():
        return None
    try:
        return str(json.loads(pkg.read_text(encoding="utf-8")).get("version", ""))
    except (OSError, json.JSONDecodeError):
        return None


def _installed_claude_version() -> str | None:
    pkg = CLAUDE_PREFIX / "node_modules" / "@anthropic-ai" / "claude-code" / "package.json"
    if not pkg.is_file():
        return None
    try:
        return str(json.loads(pkg.read_text(encoding="utf-8")).get("version", ""))
    except (OSError, json.JSONDecodeError):
        return None


def ensure_runtime(*, quiet: bool = False) -> dict[str, Any]:
    """Idempotently restore the pinned Node.js + Claude Code runtime."""
    steps: list[str] = []
    node_version = _installed_node_version()
    claude_version = _installed_claude_version()
    node_ok = node_version == NODE_VERSION
    claude_ok = claude_version == CLAUDE_VERSION
    for prefix, pinned, installed, ok, package in (
        (NODE_PREFIX, NODE_VERSION, node_version, node_ok, f"node@{NODE_VERSION}"),
        (CLAUDE_PREFIX, CLAUDE_VERSION, claude_version, claude_ok, f"@anthropic-ai/claude-code@{CLAUDE_VERSION}"),
    ):
        if ok:
            continue
        prefix.mkdir(parents=True, exist_ok=True)
        result = _run(["npm", "install", "--prefix", str(prefix), "--no-audit", "--no-fund", package])
        if result.returncode != 0:
            return {
                "ok": False,
                "error": f"npm install failed for {package}: {result.stderr[-500:]}",
                "steps": steps + [f"install:{package}"],
                "node": _installed_node_version(),
                "claude": _installed_claude_version(),
            }
        steps.append(f"install:{package}")
    return {
        "ok": True,
        "steps": steps,
        "node": _installed_node_version(),
        "claude": _installed_claude_version(),
    }


def resolve_key() -> str | None:
    for name in ("HUNTER_TRUDI_DEEPSEEK_API_KEY", "DEEPSEEK_API_KEY"):
        value = os.environ.get(name)
        if value and value.strip():
            return value.strip()
    if CONFIG_DB.is_file():
        try:
            with sqlite3.connect(f"file:{CONFIG_DB}?mode=ro", uri=True) as con:
                row = con.execute("SELECT value FROM config WHERE key='custom_api_key'").fetchone()
            if row and isinstance(row[0], str) and row[0].strip():
                return row[0].strip()
        except sqlite3.Error:
            return None
    return None


def deepseek_reachable(key: str | None) -> bool:
    if not key:
        return False
    try:
        import httpx

        response = httpx.post(
            "https://api.deepseek.com/chat/completions",
            headers={"Authorization": f"Bearer {key}"},
            json={
                "model": "deepseek-v4-flash",
                "messages": [{"role": "user", "content": "ping"}],
                "max_tokens": 1,
            },
            timeout=15,
        )
        return response.status_code == 200
    except Exception:
        return False


def full_healthcheck(evidence: Path | None) -> dict[str, Any] | None:
    """Run the real TrudiAdapter full healthcheck against an evidence file."""
    if evidence is None:
        return None
    for entry in (str(ROOT), str(ROOT / "pentestgpt-core/pentestgpt_agent/src")):
        if entry not in sys.path:
            sys.path.insert(0, entry)
    import hashlib

    from pentestgpt_agent.protocol import (
        AuthorizationScope,
        InputObject,
        TargetObject,
        TaskSpec,
    )

    key = resolve_key()
    if key is not None and not os.environ.get("HUNTER_TRUDI_DEEPSEEK_API_KEY"):
        # In-process injection only: the adapter reads the key from the
        # environment. The value is never printed or written to disk.
        os.environ["HUNTER_TRUDI_DEEPSEEK_API_KEY"] = key

    data = evidence.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    task = TaskSpec(
        task_id="trudi-full-bootstrap-hc",
        domain="dfir",
        target=str(evidence.resolve()),
        goal="Investigate the supplied evidence.",
        metadata={
            "file_type": {"normalized_type": "evidence_file", "sha256": digest},
            "trudi_mode": "full",
        },
        input_object=InputObject(
            "input", "file", str(evidence.resolve()), path=str(evidence.resolve()),
            source_name=evidence.name, sha256=digest, size_bytes=len(data),
        ),
        target_object=TargetObject("target", "evidence_file", str(evidence.resolve())),
        authorization=AuthorizationScope((str(evidence.resolve()),)),
    )
    from integrations.trudi.adapter import TrudiAdapter

    adapter = TrudiAdapter(repo_root=ROOT, mode="full")
    health = asyncio.run(adapter.healthcheck(task))
    result = {
        "available": health.available,
        "details": health.details,
    }
    if health.error is not None:
        result["error_code"] = health.error.code
        result["error_message"] = health.error.message
    return result


def report(evidence: Path | None = None) -> dict[str, Any]:
    key = resolve_key()
    node_version = _installed_node_version()
    claude_version = _installed_claude_version()
    node_path = str(NODE_BIN.resolve()) if NODE_BIN.is_file() else None
    claude_path = str(CLAUDE_BIN.resolve()) if CLAUDE_BIN.is_file() else None
    return {
        "runtime": {
            "node_pinned": NODE_VERSION,
            "claude_pinned": CLAUDE_VERSION,
            "node_installed": node_version,
            "claude_installed": claude_version,
            "node_path": node_path,
            "claude_path": claude_path,
            "node_ready": node_version == NODE_VERSION and node_path is not None,
            "claude_ready": claude_version == CLAUDE_VERSION and claude_path is not None,
        },
        "secret": {
            "key_available": key is not None,
            "deepseek_reachable": deepseek_reachable(key),
        },
        "full_healthcheck": full_healthcheck(evidence),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="TRUDI Full runtime bootstrap + healthcheck")
    parser.add_argument("--ensure", action="store_true", help="idempotently install pinned runtime")
    parser.add_argument("--evidence", type=Path, help="run the real full healthcheck on this file")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args()

    if args.ensure:
        result = ensure_runtime()
        if not result["ok"]:
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 1

    result = report(evidence=args.evidence)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    runtime = result["runtime"]
    print(f"node:    {runtime['node_installed']} (pinned {runtime['node_pinned']}) ready={runtime['node_ready']}")
    print(f"claude:  {runtime['claude_installed']} (pinned {runtime['claude_pinned']}) ready={runtime['claude_ready']}")
    print(f"key:     available={result['secret']['key_available']} deepseek_reachable={result['secret']['deepseek_reachable']}")
    health = result["full_healthcheck"]
    if health is not None:
        print(f"full healthcheck: available={health['available']} error_code={health.get('error_code')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
