#!/usr/bin/env python3
"""Phase 3E summary + failure matrix generator.

Reads evaluation/phase3e_results/*.jsonl and writes:
  evaluation/phase3e_summary.json
  evaluation/phase3e_failure_matrix.json

Separates availability from capability, computes per-case/per-domain verified
success, robustness (outcome sequences, variance), and efficiency. It never
modifies run records.
"""

from __future__ import annotations

import json
import statistics
from pathlib import Path

EVAL_ROOT = Path(__file__).resolve().parent
CASES = json.loads((EVAL_ROOT / "phase3e_cases.json").read_text(encoding="utf-8"))["cases"]
RESULTS = EVAL_ROOT / "phase3e_results"

ELIGIBLE_CLASSES = {
    "VERIFIED_SUCCESS",
    "FALSE_SUCCESS",
    "ORACLE_NOT_SATISFIED",
    "SEARCH_FAILURE",
    "TIMEOUT",
    "BUDGET_EXHAUSTED",
    "BACKEND_PROCESS_FAILURE",
    "BACKEND_SEMANTIC_FAILURE",
    "PARSER_INGRESS_FAILURE",
    "TOOL_FAILURE",
    "VERIFICATION_FAILURE",
    "INCONCLUSIVE_NEGATIVE",
    "SUPERVISOR_CONTRACT_FAILURE",
    "INVALID_DECISION_EXHAUSTION",
    "NO_PROGRESS",
    "ROUTING_ERROR",
    "INVOCATION_CONTRACT_ERROR",
}

AVAILABILITY_CLASSES = {"RUNTIME_UNAVAILABLE", "BENCHMARK_MISSING", "UNSUPPORTED_EVIDENCE"}


def load_runs() -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for path in sorted(RESULTS.glob("*.jsonl")):
        case_id = path.stem
        runs = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            runs.append(json.loads(line))
        out[case_id] = runs
    return out


def _wilson(positive: int, total: int) -> dict[str, float] | None:
    if total == 0:
        return None
    z = 1.959963984540054  # 95%
    phat = positive / total
    denom = 1 + z * z / total
    centre = (phat + z * z / (2 * total)) / denom
    half = z * (phat * (1 - phat) / total + z * z / (4 * total * total)) ** 0.5 / denom
    return {
        "point": round(phat, 4),
        "ci_low": round(max(centre - half, 0.0), 4),
        "ci_high": round(min(centre + half, 1.0), 4),
    }


def summarize() -> tuple[dict, dict]:
    runs = load_runs()
    per_case: dict[str, dict] = {}
    per_domain: dict[str, dict] = {}
    all_eligible: list[str] = []
    all_verified: list[str] = []
    all_false_success: list[str] = []
    avail_runs: list[dict] = []

    for case in CASES:
        case_id = case["case_id"]
        records = runs.get(case_id, [])
        valid = [r for r in records if not r.get("INVALID_EVALUATION_RUN")]
        entry = {
            "case_id": case_id,
            "domain": case["domain"],
            "tier": case.get("tier"),
            "ground_truth_domain": case["ground_truth_domain"],
            "repetitions_total": len(valid),
            "success_count": 0,
            "false_success_count": 0,
            "outcome_sequence": [],
            "classification_distribution": {},
            "duration": [],
            "tool_calls": [],
        }
        for rec in valid:
            category = rec.get("classification", {}).get("category")
            if category == "VERIFIED_SUCCESS":
                entry["success_count"] += 1
                all_verified.append(rec["run_id"])
            if category == "FALSE_SUCCESS":
                entry["false_success_count"] += 1
                all_false_success.append(rec["run_id"])
            if category in ELIGIBLE_CLASSES or category in AVAILABILITY_CLASSES:
                all_eligible.append(rec["run_id"])
            entry["outcome_sequence"].append(category)
            entry["classification_distribution"][category] = entry["classification_distribution"].get(category, 0) + 1
            if rec.get("elapsed_seconds") is not None:
                entry["duration"].append(rec["elapsed_seconds"])
            if rec.get("agent_result", {}).get("metrics", {}).get("tool_calls_used") is not None:
                entry["tool_calls"].append(rec["agent_result"]["metrics"]["tool_calls_used"])
            if category in AVAILABILITY_CLASSES:
                avail_runs.append(rec)

        entry["success_rate"] = round(entry["success_count"] / len(valid) * 100, 1) if valid else None
        entry["duration_median"] = round(statistics.median(entry["duration"]), 1) if entry["duration"] else None
        entry["duration_min"] = round(min(entry["duration"]), 1) if entry["duration"] else None
        entry["duration_max"] = round(max(entry["duration"]), 1) if entry["duration"] else None
        entry["tool_calls_median"] = round(statistics.median(entry["tool_calls"]), 1) if entry["tool_calls"] else None
        entry["wilson_95"] = _wilson(entry["success_count"], len(valid))
        if entry["success_count"] == len(valid) and len(valid) == 3:
            entry["stability"] = "3/3 stable under this frozen case/profile"
        elif entry["success_count"] == 0:
            entry["stability"] = "0/3 no success observed"
        elif entry["success_count"] == 1:
            entry["stability"] = "1/3 occasional success, poor repeatability"
        elif entry["success_count"] == 2:
            entry["stability"] = "2/3 real capability but insufficient repeatability"
        else:
            entry["stability"] = "mixed outcome"
        if len(valid) >= 3 and len(set(entry["outcome_sequence"])) > 1:
            entry["high_variance"] = True
        per_case[case_id] = entry

        domain = case["domain"]
        dom = per_domain.setdefault(domain, {
            "domain": domain, "cases": [], "runs": 0, "eligible": 0,
            "verified_success": 0, "false_success": 0,
            "availability_failures": 0, "eligible_cases": [],
        })
        dom["cases"].append(case_id)
        dom["runs"] += len(valid)
        for rec in valid:
            category = rec.get("classification", {}).get("category")
            if category in AVAILABILITY_CLASSES:
                dom["availability_failures"] += 1
            elif category in ELIGIBLE_CLASSES:
                dom["eligible"] += 1
                dom["eligible_cases"].append(case_id)
            if category == "VERIFIED_SUCCESS":
                dom["verified_success"] += 1
            if category == "FALSE_SUCCESS":
                dom["false_success"] += 1
        dom["verified_success_rate"] = round(dom["verified_success"] / dom["eligible"] * 100, 1) if dom["eligible"] else None

    eligible_total = len(all_eligible)
    verified_total = len(all_verified)
    domain_macro = (
        round(statistics.mean([d["verified_success_rate"] for d in per_domain.values() if d["verified_success_rate"] is not None]), 1)
        if any(d["verified_success_rate"] is not None for d in per_domain.values())
        else None
    )

    # failure matrix
    failure_matrix: dict[str, dict] = {}
    for case_id, entry in per_case.items():
        for category, count in entry["classification_distribution"].items():
            row = failure_matrix.setdefault(category, {"count": 0, "cases": {}, "run_ids": []})
            row["count"] += count
            row["cases"][case_id] = row["cases"].get(case_id, 0) + count
    for case_id, records in runs.items():
        for rec in records:
            if rec.get("INVALID_EVALUATION_RUN"):
                continue
            category = rec.get("classification", {}).get("category")
            if category in failure_matrix:
                failure_matrix[category]["run_ids"].append(rec["run_id"])

    # routing / ingress / availability aggregation
    routing_correct = 0
    routing_total = 0
    raw_invalid_attempts = 0
    accepted_decisions = 0
    runtime_available_total = 0
    benchmark_available_total = 0
    for records in runs.values():
        for rec in records:
            if rec.get("INVALID_EVALUATION_RUN"):
                continue
            if rec.get("routing_correct") is not None:
                routing_total += 1
                routing_correct += 1 if rec["routing_correct"] else 0
            ingress = rec.get("decision_ingress") or {}
            raw_invalid_attempts += ingress.get("rejected_attempts") or 0
            accepted_decisions += ingress.get("accepted_decisions") or 0
            if rec.get("runtime_available"):
                runtime_available_total += 1
            if rec.get("benchmark_available"):
                benchmark_available_total += 1

    valid_total = sum(1 for rs in runs.values() for r in rs if not r.get("INVALID_EVALUATION_RUN"))
    summary = {
        "evaluation_id": "phase3e_2026-09-01",
        "snapshot_sha": "aa7dc1d",
        "total_runs": valid_total,
        "invalid_evaluation_runs": sum(1 for rs in runs.values() for r in rs if r.get("INVALID_EVALUATION_RUN")),
        "per_case": per_case,
        "per_domain": per_domain,
        "system_reliability": {
            "routing_accuracy": {"correct": routing_correct, "total": routing_total, "rate": round(routing_correct / routing_total * 100, 1) if routing_total else None},
            "runtime_available_rate": round(runtime_available_total / valid_total * 100, 1) if valid_total else None,
            "benchmark_available_rate": round(benchmark_available_total / valid_total * 100, 1) if valid_total else None,
            "raw_invalid_decision_attempts": raw_invalid_attempts,
            "accepted_decisions": accepted_decisions,
        },
        "capability": {
            "eligible_denominator": eligible_total,
            "verified_task_success": verified_total,
            "verified_task_success_rate": round(verified_total / eligible_total * 100, 1) if eligible_total else None,
            "domain_macro_verified_success_rate": domain_macro,
            "case_weighted_overall_success": {
                "numerator": verified_total,
                "denominator": eligible_total,
                "case_composition": [c["case_id"] for c in CASES],
            },
            "false_success": len(all_false_success),
            "false_success_rate": round(len(all_false_success) / eligible_total * 100, 1) if eligible_total else 0.0,
            "availability_runs": len(avail_runs),
            "note": "RUNTIME_UNAVAILABLE/UNSUPPORTED_EVIDENCE/BENCHMARK_MISSING excluded from the capability denominator.",
        },
        "robustness": {cid: {
            "success_count": e["success_count"],
            "repetitions": e["repetitions_total"],
            "outcome_sequence": e["outcome_sequence"],
            "dominant_failure_class": (max(e["classification_distribution"], key=e["classification_distribution"].get) if e["classification_distribution"] else None),
            "duration_median": e["duration_median"],
            "duration_min": e["duration_min"],
            "duration_max": e["duration_max"],
            "tool_calls_median": e["tool_calls_median"],
            "wilson_95": e["wilson_95"],
            "high_variance": e.get("high_variance", False),
        } for cid, e in per_case.items()},
        "efficiency": {
            "cost_not_observed": True,
            "note": "no real API billing observed; token usage recorded per run when the provider exposed it; no price*quantity fabricated as real cost.",
        },
    }

    failure = {
        "evaluation_id": "phase3e_2026-09-01",
        "snapshot_sha": "aa7dc1d",
        "note": "every non-verified run has exactly one primary failure class; availability classes are reported separately",
        "matrix": failure_matrix,
    }
    return summary, failure


def main() -> int:
    summary, failure = summarize()
    (EVAL_ROOT / "phase3e_summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False, default=str) + "\n", encoding="utf-8"
    )
    (EVAL_ROOT / "phase3e_failure_matrix.json").write_text(
        json.dumps(failure, indent=2, ensure_ascii=False, default=str) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary["capability"], indent=2, ensure_ascii=False))
    print(json.dumps(summary["system_reliability"], indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
