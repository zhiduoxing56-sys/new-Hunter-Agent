"""Small task-facing view of TRUDI's official MCP server for file triage."""

from __future__ import annotations

import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
TRUDI_ROOT = PROJECT_ROOT / "third_party" / "trudi"
if str(TRUDI_ROOT) not in sys.path:
    sys.path.insert(0, str(TRUDI_ROOT))

from server import mcp  # noqa: E402


LITE_TOOLS = {
    "hash_hash_file",
    "misc_start_execution_log",
    "strings_stat_file",
    "strings_strings_extract",
}
mcp.enable(names=LITE_TOOLS, components={"tool"}, only=True)


if __name__ == "__main__":
    mcp.run(transport="stdio")
