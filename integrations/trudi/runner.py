"""Small stdio-MCP client for TRUDI's official server."""

from __future__ import annotations

import argparse
import asyncio
import json
import runpy
import shutil
from pathlib import Path
from typing import Any

from fastmcp import Client


def _structured(result: Any) -> dict[str, Any]:
    value = result.structured_content
    if not isinstance(value, dict):
        raise RuntimeError("TRUDI tool returned no structured content")
    return value


async def triage(
    server: Path, evidence: Path, case_dir: Path, *, export_evidence: bool = False
) -> dict[str, Any]:
    analysis = case_dir / "analysis"
    exports = case_dir / "exports"
    reports = case_dir / "reports"
    for directory in (analysis, exports, reports):
        directory.mkdir(parents=True, exist_ok=True)
    trace_path = analysis / "trace.json"
    strings_path = exports / "strings.txt"

    async def execute(call_tool: Any) -> tuple[dict[str, Any], ...]:
        started = _structured(await call_tool("misc_start_execution_log", {
            "case_id": case_dir.name,
            "output_path": str(trace_path),
            "launch_dashboard": False,
            "case_dir": str(case_dir),
        }))
        hashed = _structured(await call_tool("hash_hash_file", {
            "file_path": str(evidence),
        }))
        stat = _structured(await call_tool("strings_stat_file", {
            "file_path": str(evidence),
        }))
        strings = _structured(await call_tool("strings_strings_extract", {
            "file_path": str(evidence),
            "min_length": 8,
            "unicode": True,
            "output_path": str(strings_path),
        }))
        return started, hashed, stat, strings

    try:
        async with Client(str(server), init_timeout=15, timeout=30) as client:
            started, hashed, stat, strings = await execute(client.call_tool)
        transport = "stdio"
    except RuntimeError as exc:
        if "Failed to initialize server session" not in str(exc):
            raise
        runpy.run_path(str(server))
        from tools.hashing import hash_file
        from tools.misc import start_execution_log
        from tools.strings_tools import stat_file, strings_extract

        async def call_official_tool(name: str, arguments: dict[str, Any]) -> Any:
            implementations = {
                "hash_hash_file": hash_file,
                "misc_start_execution_log": start_execution_log,
                "strings_stat_file": stat_file,
                "strings_strings_extract": strings_extract,
            }
            implementation = implementations[name]
            value = implementation(**arguments)

            class DirectResult:
                structured_content = value

            return DirectResult()

        started, hashed, stat, strings = await execute(call_official_tool)
        transport = "official_tool_fallback"
    exported_evidence_path: str | None = None
    if export_evidence:
        exported = exports / evidence.name
        shutil.copy2(evidence, exported)
        exported_evidence_path = str(exported)
    return {
        "success": all(item.get("success") is not False for item in (started, hashed, stat, strings)),
        "evidence_path": str(evidence),
        "trace_path": str(trace_path),
        "strings_path": str(strings_path) if strings_path.is_file() else None,
        "exported_evidence_path": exported_evidence_path,
        "transport": transport,
        "tools": {
            "start_execution_log": started,
            "hash_file": hashed,
            "stat_file": stat,
            "strings_extract": strings,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--case-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--export-evidence", action="store_true")
    args = parser.parse_args()
    output: dict[str, Any]
    returncode = 0
    try:
        evidence = args.evidence.resolve(strict=True)
        if not evidence.is_file():
            raise ValueError("TRUDI lightweight triage currently requires a file evidence target")
        output = asyncio.run(triage(
            args.server.resolve(strict=True),
            evidence,
            args.case_dir.resolve(),
            export_evidence=args.export_evidence,
        ))
        if not output["success"]:
            returncode = 1
    except Exception as exc:
        output = {"success": False, "error": f"{type(exc).__name__}: {exc}"}
        returncode = 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2, sort_keys=True), encoding="utf-8")
    return returncode


if __name__ == "__main__":
    raise SystemExit(main())
