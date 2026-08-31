"""Run FuzzingBrain with its local environment and optional runtime patch."""

from __future__ import annotations

import os
import runpy
import sqlite3
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FB_DIR = ROOT / "third_party" / "fuzzingbrain"
EXPECTED_PYTHON = FB_DIR / ".venv" / "bin" / "python"
KONG_CONFIG_DB = ROOT / ".runtime" / "kong" / "config" / "config.db"


def _inject_unified_deepseek_key() -> None:
    """Load the existing Kong credential into this child process only."""
    if os.environ.get("DEEPSEEK_API_KEY"):
        return
    if not KONG_CONFIG_DB.is_file():
        return
    with sqlite3.connect(f"file:{KONG_CONFIG_DB}?mode=ro", uri=True) as database:
        row = database.execute(
            "SELECT value FROM config WHERE key = ?", ("custom_api_key",)
        ).fetchone()
    if row and isinstance(row[0], str) and row[0].strip():
        os.environ["DEEPSEEK_API_KEY"] = row[0].strip()


def main() -> int:
    if Path(sys.executable).resolve() != EXPECTED_PYTHON.resolve():
        print(f"error: use {EXPECTED_PYTHON} {Path(__file__).resolve()} ...", file=sys.stderr)
        return 2

    os.chdir(FB_DIR)
    sys.path.insert(0, str(FB_DIR))
    venv_bin = str(FB_DIR / ".venv" / "bin")
    if venv_bin not in os.environ.get("PATH", "").split(os.pathsep):
        os.environ["PATH"] = venv_bin + os.pathsep + os.environ.get("PATH", "")
    os.environ.setdefault("MONGODB_URL", "mongodb://127.0.0.1:27018")
    os.environ.setdefault("MONGODB_DB", "fuzzingbrain")
    os.environ.setdefault("REDIS_URL", "redis://127.0.0.1:6380/0")
    os.environ.setdefault("LLM_DEFAULT_MODEL", "deepseek-v4-flash")
    _inject_unified_deepseek_key()

    patch_module = os.environ.get("FUZZINGBRAIN_PATCH_MODULE")
    if patch_module:
        __import__(patch_module)

    runpy.run_module("fuzzingbrain.main", run_name="__main__", alter_sys=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
