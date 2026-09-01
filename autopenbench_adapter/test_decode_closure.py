"""Workstream A closure tests: tool output decode must never crash on arbitrary bytes.

The AutoPenBench adapter boundary must (1) never raise UnicodeDecodeError for
invalid UTF-8 target output, (2) preserve the raw bytes as an auditable
artifact + SHA-256, (3) give the model a deterministic safe-decode, and
(4) never turn a real decode problem into a silent empty string or a generic
exploit failure.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

from autopenbench_adapter.environment import SessionConfig, _safe_decode


def _session(tmp_path: Path) -> SessionConfig:
    bench = tmp_path / "bench"
    bench.mkdir(parents=True, exist_ok=True)
    return SessionConfig(
        benchmark_root=bench,
        level="in-vitro",
        category="web_security",
        target="in-vitro_web_security_vm0",
        run_dir=tmp_path / "run",
    )


def test_safe_decode_valid_utf8_is_lossless() -> None:
    text, lossy = _safe_decode("中文 payload\n".encode("utf-8"))
    assert text == "中文 payload\n"
    assert lossy is False


def test_safe_decode_invalid_utf8_uses_replacement_and_flags() -> None:
    raw = b"prefix \xff\xe7bad\x00 suffix"
    text, lossy = _safe_decode(raw)
    assert lossy is True
    assert "prefix" in text and "suffix" in text
    assert "\ufffd" in text  # replacement character present, output not swallowed


def test_safe_decode_mixed_binary_text_keeps_ascii_content() -> None:
    raw = b"nmap: Host is up \xff\xe7 (0.000021s)\nPORT: 80/tcp"
    text, lossy = _safe_decode(raw)
    assert lossy is True
    assert "nmap: Host is up" in text
    assert "PORT: 80/tcp" in text


def test_safe_decode_empty_input() -> None:
    text, lossy = _safe_decode(b"")
    assert text == ""
    assert lossy is False


@pytest.mark.asyncio
async def test_run_with_invalid_utf8_output_does_not_crash_and_persists_raw(tmp_path: Path) -> None:
    from autopenbench_adapter.environment import AutoPenBenchSession

    session = AutoPenBenchSession(_session(tmp_path))
    command = [
        sys.executable,
        "-c",
        "import sys; sys.stdout.buffer.write(b'clean \\xff\\xe7bad'); sys.stdout.buffer.flush()",
    ]
    result = session._run(command, timeout=60)
    # The safe-decode must contain the printable content, never raise.
    assert "clean" in result.stdout
    assert result.stdout.strip() != ""
    # The raw bytes must be persisted with an audit hash.
    events = json.loads(session.events_path.read_text(encoding="utf-8").splitlines()[-1])
    assert events.get("decode_error") is True
    assert events.get("raw_sha256") == hashlib.sha256(b"clean \xff\xe7bad").hexdigest()
    raw_path = Path(events["raw_artifact"])
    assert raw_path.is_file()
    assert raw_path.read_bytes() == b"clean \xff\xe7bad"


@pytest.mark.asyncio
async def test_run_with_valid_utf8_output_has_no_decode_diagnostic(tmp_path: Path) -> None:
    from autopenbench_adapter.environment import AutoPenBenchSession

    session = AutoPenBenchSession(_session(tmp_path))
    command = [sys.executable, "-c", "print('all good utf8')"]
    result = session._run(command, timeout=60)
    assert "all good utf8" in result.stdout
    last = json.loads(session.events_path.read_text(encoding="utf-8").splitlines()[-1])
    assert last.get("decode_error") is None


@pytest.mark.asyncio
async def test_run_with_invalid_utf8_stderr_is_not_lost(tmp_path: Path) -> None:
    from autopenbench_adapter.environment import AutoPenBenchSession

    session = AutoPenBenchSession(_session(tmp_path))
    command = [
        sys.executable,
        "-c",
        "import sys; sys.stderr.write('err \\xe7'); sys.stderr.flush()",
    ]
    # stderr is merged into stdout (stderr=STDOUT), so invalid stderr bytes
    # must also survive safe-decode without a crash.
    result = session._run(command, timeout=60)
    assert "err" in result.stdout


def test_run_command_timeout_is_typed_environment_error(tmp_path: Path) -> None:
    from autopenbench_adapter.environment import AutoPenBenchSession, EnvironmentError

    session = AutoPenBenchSession(_session(tmp_path))
    command = [sys.executable, "-c", "import time; time.sleep(30)"]
    with pytest.raises(EnvironmentError):
        session._run(command, timeout=1)
