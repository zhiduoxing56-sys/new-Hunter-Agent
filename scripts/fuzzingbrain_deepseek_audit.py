"""Run a redacted DeepSeek qualification through FuzzingBrain's LLM client."""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import types
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
FB_DIR = ROOT / "third_party" / "fuzzingbrain"
CONFIG_DB = ROOT / ".runtime" / "kong" / "config" / "config.db"
AUDIT_FILE = ROOT / "artifacts" / "fuzzingbrain" / "deepseek-smoke.json"


def _read_key() -> str:
    with sqlite3.connect(f"file:{CONFIG_DB}?mode=ro", uri=True) as database:
        row = database.execute(
            "SELECT value FROM config WHERE key = ?", ("custom_api_key",)
        ).fetchone()
    if not row or not isinstance(row[0], str) or not row[0].strip():
        raise RuntimeError("unified Kong DeepSeek credential is missing")
    return row[0].strip()


def _public_error(error: Exception) -> dict[str, str]:
    return {"type": type(error).__name__, "category": error.__class__.__name__}


def _call(client: Any, model: str) -> dict[str, Any]:
    from fuzzingbrain.llms.client import _calculate_cost

    response = client.call(
        [{"role": "user", "content": "Reply with exactly: OK"}],
        model=model,
        temperature=0.0,
        max_tokens=16,
    )
    _, _, cost = _calculate_cost(
        response.model, response.input_tokens, response.output_tokens
    )
    return {
        "ok": True,
        "provider": response.provider,
        "model": response.model,
        "content_exact_ok": response.content.strip() == "OK",
        "usage": response.usage,
        "estimated_cost_usd": round(cost, 10),
        "latency_ms": round(response.latency_ms, 2),
        "fallback_used": response.fallback_used,
    }


def main() -> int:
    os.chdir(FB_DIR)
    sys.path.insert(0, str(FB_DIR))
    os.environ["DEEPSEEK_API_KEY"] = _read_key()
    os.environ["LLM_DEFAULT_MODEL"] = "deepseek-v4-flash"

    from fuzzingbrain.llms.client import LLMClient
    from fuzzingbrain.llms.config import LLMConfig

    config = LLMConfig.from_env()
    config.fallback_enabled = False
    config.max_retries = 0
    config.timeout = 30.0

    audit: dict[str, Any] = {
        "timestamp": datetime.now(UTC).isoformat(),
        "credential_source": "kong_sqlite_child_process",
        "credential_persisted": False,
        "flash": {},
        "timeout_probe": {},
        "flash_only_probe": {},
        "error_mapping": {},
    }
    client = LLMClient(config=config)
    audit["flash"] = _call(client, "deepseek-v4-flash")

    # Strict flash-only: a rate limit must NOT escalate to deepseek-v4-pro.
    flash_only_config = LLMConfig.from_env()
    flash_only_config.fallback_enabled = True
    flash_only_config.max_retries = 0
    flash_only_config.timeout = 30.0
    flash_only_client = LLMClient(config=flash_only_config)
    original_call = flash_only_client._call_deepseek

    def force_primary_rate_limit(self, messages, model_id, *args, **kwargs):
        if model_id == "deepseek-v4-flash":
            raise RuntimeError("HTTP 429 forced audit rate limit")
        return original_call(messages, model_id, *args, **kwargs)

    flash_only_client._call_deepseek = types.MethodType(
        force_primary_rate_limit, flash_only_client
    )
    try:
        _call(flash_only_client, "deepseek-v4-flash")
        audit["flash_only_probe"] = {"ok": False, "unexpected_success": True}
    except Exception as error:
        audit["flash_only_probe"] = {
            "ok": "deepseek-v4-pro" not in flash_only_client._tried_models,
            "error": _public_error(error),
        }

    timeout_config = LLMConfig.from_env()
    timeout_config.fallback_enabled = False
    timeout_config.max_retries = 0
    timeout_config.timeout = 0.001
    try:
        LLMClient(config=timeout_config).call(
            [{"role": "user", "content": "OK"}],
            model="deepseek-v4-flash",
            max_tokens=1,
        )
        audit["timeout_probe"] = {"ok": False, "unexpected_success": True}
    except Exception as error:
        audit["timeout_probe"] = {
            "ok": error.__class__.__name__ == "LLMTimeoutError",
            "error": _public_error(error),
            "timeout_seconds": timeout_config.timeout,
        }

    invalid = LLMConfig.from_env()
    invalid.api_keys = {"deepseek": "invalid-audit-credential"}
    invalid.fallback_enabled = False
    invalid.max_retries = 0
    invalid.timeout = 10.0
    try:
        LLMClient(config=invalid).call(
            [{"role": "user", "content": "OK"}],
            model="deepseek-v4-flash",
            max_tokens=1,
        )
    except Exception as error:
        audit["error_mapping"]["authentication"] = _public_error(error)

    mapper = LLMClient(config=config)
    for name, message in (
        ("rate_limit", "HTTP 429 rate limit exceeded"),
        ("timeout", "request timed out"),
    ):
        mapped = mapper._handle_error(RuntimeError(message), "deepseek-v4-flash")
        audit["error_mapping"][name] = _public_error(mapped)

    serialized = json.dumps(audit, ensure_ascii=False, indent=2)
    if os.environ["DEEPSEEK_API_KEY"] in serialized:
        raise RuntimeError("credential leaked into audit payload")
    AUDIT_FILE.parent.mkdir(parents=True, exist_ok=True)
    AUDIT_FILE.write_text(serialized + "\n", encoding="utf-8")
    os.chmod(AUDIT_FILE, 0o600)
    print(serialized)
    return 0 if audit["flash"].get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
