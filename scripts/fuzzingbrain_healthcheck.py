"""Non-secret health check for the isolated FuzzingBrain runtime."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FB_DIR = ROOT / "third_party" / "fuzzingbrain"


def tcp_check(host: str, port: int) -> tuple[bool, str]:
    try:
        with socket.create_connection((host, port), timeout=2):
            return True, "reachable"
    except OSError as exc:
        return False, str(exc)


def command_check(command: list[str]) -> tuple[bool, str]:
    result = subprocess.run(command, capture_output=True, text=True, timeout=15)
    message = (result.stdout or result.stderr).strip()
    return result.returncode == 0, message


def main() -> int:
    checks: dict[str, dict[str, object]] = {}
    expected_python = FB_DIR / ".venv" / "bin" / "python"
    checks["python"] = {
        "ok": Path(sys.executable).resolve() == expected_python.resolve(),
        "detail": sys.executable,
    }
    service_ports = (
        ("mongodb", int(os.environ.get("FUZZINGBRAIN_MONGO_PORT", "27018"))),
        ("redis", int(os.environ.get("FUZZINGBRAIN_REDIS_PORT", "6380"))),
    )
    for name, port in service_ports:
        ok, detail = tcp_check("127.0.0.1", port)
        checks[name] = {"ok": ok, "detail": detail}
    ok, detail = command_check(["docker", "info", "--format", "{{.ServerVersion}}"])
    checks["docker"] = {"ok": ok, "detail": detail}
    ok, detail = command_check([
        "docker", "image", "inspect", "--format", "{{.Id}}",
        "gcr.io/oss-fuzz/base-builder",
    ])
    checks["oss_fuzz_base_builder"] = {"ok": ok, "detail": detail or "not present"}
    print(json.dumps(checks, ensure_ascii=False, indent=2))
    return 0 if all(bool(item["ok"]) for item in checks.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
