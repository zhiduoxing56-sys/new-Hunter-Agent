"""Workstream D: auditable pentest failure taxonomy.

Maps the recorded specialist failure kinds / error strings to the Phase 3F-B
auditable categories. Reuses the existing pentestgpt-core failure_kind names
where possible (max_turns, search_budget_policy, provider) and only adds the
categories the phase requires on top of them. No enum in pentestgpt-core is
redefined here.
"""

from __future__ import annotations

from typing import Any

# Phase 3F-B auditable categories (Workstream D).
TOOL_TRANSPORT_ERROR = "tool_transport_error"
TOOL_DECODE_ERROR = "tool_decode_error"
COMMAND_TIMEOUT = "command_timeout"
TARGET_CONNECTION_ERROR = "target_connection_error"
COMMAND_EXECUTION_ERROR = "command_execution_error"
TOOL_TURN_EXHAUSTED = "tool_turn_exhausted"
SEARCH_BUDGET_EXHAUSTED = "search_budget_exhausted"
EXPLOIT_SELECTION_FAILURE = "exploit_selection_failure"
EXPLOIT_EXECUTION_FAILURE = "exploit_execution_failure"
VERIFICATION_FAILURE = "verification_failure"
PROVIDER_MODEL_ERROR = "provider/model_error"


def classify_error_kind(error_kind: str | None, error_text: str, *, target_phase: str | None = None) -> str:
    """Map the raw specialist error kind + text to one auditable category."""
    text = f"{error_kind} {error_text}".lower()
    if "utf-8" in text or "codec" in text or "decode" in text:
        return TOOL_DECODE_ERROR
    if "maximum tool turns" in text or "max_tool_turns" in text or error_kind == "provider_max_tool_turns":
        return TOOL_TURN_EXHAUSTED
    if "search budget" in text or "hypothesis deferred" in text or error_kind == "search_budget_policy":
        return SEARCH_BUDGET_EXHAUSTED
    if "connection" in text or "connection failed" in text or "dns" in text or "network" in text:
        # target/tool transport vs provider model transport are both transport;
        # the phase splits them, so prefer the specific signal when present.
        if "api" in text or "deepseek" in text or "provider" in text or "openai" in text:
            return PROVIDER_MODEL_ERROR
        return TARGET_CONNECTION_ERROR
    if "timed out" in text or "timeout" in text:
        return COMMAND_TIMEOUT
    if "execute_bash" in text or "executed" in text or "command" in text:
        return COMMAND_EXECUTION_ERROR
    if target_phase == "exploit_execution":
        return EXPLOIT_EXECUTION_FAILURE
    if target_phase == "exploit_selection":
        return EXPLOIT_SELECTION_FAILURE
    if target_phase in {"service_identification", "discovery"}:
        return TARGET_CONNECTION_ERROR
    return PROVIDER_MODEL_ERROR


def classify_primary(rec: dict[str, Any]) -> str:
    """Primary classification for a specialist-only control run record."""
    if rec.get("verified_success"):
        return "VERIFIED_SUCCESS"
    if rec.get("timed_out"):
        return COMMAND_TIMEOUT
    specialist = rec.get("specialist") or {}
    error_kind = specialist.get("error_kind") or rec.get("error_kind")
    error_text = str(specialist.get("backend_error") or rec.get("run_error") or "")
    stage = rec.get("last_successful_stage")
    if error_kind == "provider_max_tool_turns":
        return TOOL_TURN_EXHAUSTED
    if error_kind == "search_budget_policy":
        return SEARCH_BUDGET_EXHAUSTED
    if error_kind == "provider_tool_decode_error":
        return TOOL_DECODE_ERROR
    if error_kind == "provider_connection_error":
        return PROVIDER_MODEL_ERROR
    return classify_error_kind(error_kind, error_text, target_phase=stage)


def classify_hunter_primary(phase3e_attribution: str) -> str:
    """Map a Phase 3E/3F-A attribution class to the Workstream D taxonomy."""
    mapping = {
        "SPECIALIST_TIMEOUT_OR_BUDGET": TOOL_TURN_EXHAUSTED,
        "SPECIALIST_EXPLOIT_EXECUTION_FAILURE": EXPLOIT_EXECUTION_FAILURE,
        "SPECIALIST_EXPLOIT_SELECTION_FAILURE": EXPLOIT_SELECTION_FAILURE,
        "SPECIALIST_DISCOVERY_FAILURE": TARGET_CONNECTION_ERROR,
        "SPECIALIST_ENUMERATION_FAILURE": TARGET_CONNECTION_ERROR,
        "VERIFIED_SUCCESS": "VERIFIED_SUCCESS",
        "ORCHESTRATION_INVALID_DECISION_EXHAUSTION": "orchestration_invalid_decision_exhaustion",
        "ORCHESTRATION_PRE_DISPATCH_FAILURE": "orchestration_pre_dispatch_failure",
        "ORCHESTRATION_POST_BACKEND_RECOVERY_FAILURE": "orchestration_post_backend_recovery_failure",
    }
    return mapping.get(phase3e_attribution, PROVIDER_MODEL_ERROR)
