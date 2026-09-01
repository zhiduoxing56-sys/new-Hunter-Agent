#!/usr/bin/env python3
"""Compute the Phase 3C summary with explicit denominators and run participation.

Reads every evaluation/phase3c_results/*.jsonl record and classifies it into one
truth category. ``UNAVAILABLE`` runs (DFIR benchmark missing) are excluded from
verified-success/failure denominators, exactly as the Phase 3C gate requires.
"""

from __future__ import annotations

import json
import statistics
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "phase3c_results"


def _load() -> list[dict]:
    records: list[dict] = []
    for path in sorted(RESULTS.glob("*.jsonl")):
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                records.append(json.loads(line))
    return records


def _first_invoke(rec: dict) -> str | None:
    for decision in rec.get("supervisor_decisions") or []:
        if decision.get("action") == "invoke_capability":
            return decision.get("capability_id")
    return None


def _backend_success_counts(records: list[dict]) -> tuple[int, int]:
    successes = 0
    total = 0
    for rec in records:
        for child in rec.get("children") or []:
            total += 1
            if child.get("status") == "success":
                successes += 1
    return successes, total


def main() -> None:
    records = _load()
    eligible = [r for r in records if (r.get("classification") or {}).get("category") != "UNAVAILABLE"]
    categories = {
        name: [r for r in eligible if (r.get("classification") or {}).get("category") == name]
        for name in (
            "VERIFIED_SUCCESS",
            "VERIFIED_BUT_NOT_COMPLETE",
            "NOT_VERIFIED",
            "INCONCLUSIVE",
            "FALSE_SUCCESS",
            "TIMEOUT",
            "HONEST_INCOMPLETE",
        )
    }
    unavailable = [r for r in records if (r.get("classification") or {}).get("category") == "UNAVAILABLE"]
    routing_correct = sum(
        1
        for r in eligible
        if _first_invoke(r) == r.get("ground_truth_domain") and _first_invoke(r) is not None
    )
    backend_successes, backend_total = _backend_success_counts(records)
    latencies = [r.get("elapsed_seconds", 0.0) for r in eligible]
    verifier_rejections = [
        r
        for r in eligible
        if (r.get("classification") or {}).get("verdict")
        in {"not_verified", "inconclusive", "unavailable"}
    ]
    rejection_reasons: dict[str, list[str]] = {}
    for rec in verifier_rejections:
        reason = (rec.get("classification") or {}).get("reason") or "completion_verifier_rejected"
        rejection_reasons.setdefault(reason, []).append(rec["run_id"])

    raw_calls = sum((r.get("decision_ingress") or {}).get("raw_model_calls", 0) for r in eligible)
    raw_invalid = sum((r.get("decision_ingress") or {}).get("rejected_attempts", 0) for r in eligible)
    accepted = sum((r.get("decision_ingress") or {}).get("accepted_decisions", 0) for r in eligible)
    decisions_with_rejection = sum((r.get("decision_ingress") or {}).get("decisions_with_rejection", 0) for r in eligible)
    retries_recovered = sum((r.get("decision_ingress") or {}).get("retries_recovered", 0) for r in eligible)
    run_level_invalid_termination = [
        r for r in eligible if r.get("orchestration_status") == "invalid_decisions"
    ]

    def rate(count: int, total: int) -> float:
        return round(100.0 * count / total, 1) if total else 0.0

    per_domain: dict[str, dict[str, Any]] = {}
    for domain in sorted({r.get("ground_truth_domain") for r in records}):
        domain_records = [r for r in records if r.get("ground_truth_domain") == domain]
        domain_eligible = [r for r in domain_records if r not in unavailable]
        per_domain[domain] = {
            "runs": len(domain_records),
            "eligible": len(domain_eligible),
            "verified_success": len([r for r in domain_eligible if (r.get("classification") or {}).get("category") == "VERIFIED_SUCCESS"]),
            "false_success": len([r for r in domain_eligible if (r.get("classification") or {}).get("category") == "FALSE_SUCCESS"]),
            "not_verified": len([r for r in domain_eligible if (r.get("classification") or {}).get("category") == "NOT_VERIFIED"]),
            "inconclusive": len([r for r in domain_eligible if (r.get("classification") or {}).get("category") == "INCONCLUSIVE"]),
            "unavailable": len([r for r in domain_records if r.get("ground_truth_domain") == domain and r in unavailable]),
            "run_ids": [r["run_id"] for r in domain_records],
        }

    summary = {
        "evaluation_id": "phase3c_2026-08-31",
        "total_runs": len(records),
        "eligible_denominator": len(eligible),
        "excluded_unavailable": len(unavailable),
        "metrics": {
            "routing_accuracy": {
                "correct": routing_correct,
                "total": len(eligible),
                "rate": rate(routing_correct, len(eligible)),
                "run_ids": [r["run_id"] for r in eligible],
            },
            "backend_execution_success_rate": {
                "successful_child_backends": backend_successes,
                "total_child_backends": backend_total,
                "rate": rate(backend_successes, backend_total),
                "note": "backend process completed with ExecutionStatus.SUCCESS; never task-goal verified",
            },
            "verified_task_success_rate": {
                "count": len(categories["VERIFIED_SUCCESS"]),
                "total": len(eligible),
                "rate": rate(len(categories["VERIFIED_SUCCESS"]), len(eligible)),
                "run_ids": [r["run_id"] for r in categories["VERIFIED_SUCCESS"]],
            },
            "false_success_rate": {
                "count": len(categories["FALSE_SUCCESS"]),
                "total": len(eligible),
                "rate": rate(len(categories["FALSE_SUCCESS"]), len(eligible)),
                "run_ids": [r["run_id"] for r in categories["FALSE_SUCCESS"]],
            },
            "false_failure_rate": {
                "count": len(categories["VERIFIED_BUT_NOT_COMPLETE"]),
                "total": len(eligible),
                "rate": rate(len(categories["VERIFIED_BUT_NOT_COMPLETE"]), len(eligible)),
                "note": "a VERIFIED goal that did not reach COMPLETE would be a false failure",
                "run_ids": [r["run_id"] for r in categories["VERIFIED_BUT_NOT_COMPLETE"]],
            },
            "inconclusive_rate": {
                "count": len(categories["INCONCLUSIVE"]),
                "total": len(eligible),
                "rate": rate(len(categories["INCONCLUSIVE"]), len(eligible)),
                "run_ids": [r["run_id"] for r in categories["INCONCLUSIVE"]],
            },
            "not_verified_rejected": {
                "count": len(categories["NOT_VERIFIED"]),
                "total": len(eligible),
                "rate": rate(len(categories["NOT_VERIFIED"]), len(eligible)),
                "run_ids": [r["run_id"] for r in categories["NOT_VERIFIED"]],
            },
            "timeout_honest": {
                "count": len(categories["TIMEOUT"]),
                "run_ids": [r["run_id"] for r in categories["TIMEOUT"]],
            },
            "completion_latency_seconds": {
                "mean": round(statistics.mean(latencies), 1) if latencies else None,
                "p50": round(statistics.median(latencies), 1) if latencies else None,
                "p95": (
                    round(sorted(latencies)[max(int(len(latencies) * 0.95) - 1, 0)], 1)
                    if len(latencies) >= 1
                    else None
                ),
                "run_ids": [r["run_id"] for r in eligible],
            },
            "verifier_rejection_count": {
                "count": len(verifier_rejections),
                "eligible_total": len(eligible),
                "reasons": {reason: {"count": len(ids), "run_ids": ids} for reason, ids in sorted(rejection_reasons.items())},
            },
            "decision_ingress_reliability": {
                "raw_model_calls": raw_calls,
                "raw_invalid_attempts": raw_invalid,
                "accepted_decisions": accepted,
                "raw_invalid_rate": rate(raw_invalid, raw_calls) if raw_calls else 0.0,
                "decisions_with_rejection": decisions_with_rejection,
                "retries_recovered": retries_recovered,
                "retry_recovery_rate": rate(retries_recovered, decisions_with_rejection) if decisions_with_rejection else None,
                "run_level_invalid_decisions_termination_rate": {
                    "count": len(run_level_invalid_termination),
                    "total": len(eligible),
                    "rate": rate(len(run_level_invalid_termination), len(eligible)),
                    "run_ids": [r["run_id"] for r in run_level_invalid_termination],
                },
            },
        },
        "per_domain": per_domain,
        "unavailable_runs": [{"run_id": r["run_id"], "case_id": r["case_id"], "reason": (r.get("classification") or {}).get("reason")} for r in unavailable],
    }
    out = ROOT / "phase3c_summary.json"
    out.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
