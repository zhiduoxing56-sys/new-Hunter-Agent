# HUNTER_COMPLETION_VERIFICATION_REPORT — Phase 3C

Ground-Truth Completion Verification Closure for the Hunter four-domain benchmark baseline.

- **Phase**: 3C (completion truth only; no Supervisor redesign, no four-domain routing change, no benchmark ground-truth in production logic)
- **Parent**: Phase 3B, commit `27d6101` (`eval(phase3b): four-domain benchmark closure & reproducibility`)
- **Deliverables**: `evaluation/phase3c_manifest.json`, `evaluation/phase3c_cases.json`, `evaluation/phase3c_results/*.jsonl`, `evaluation/phase3c_summary.json`
- **Eval model**: supervisor `deepseek-v4-flash` (temperature 0); professional backends AutoPenBench(deepseek-v4-flash) / FuzzingBrain / Kong / TRUDI as in Phase 3B.

---

## 1. 旧 FALSE_SUCCESS 根因 (Root cause of the old FALSE_SUCCESS)

Three Phase 3B runs (vm1, reverse×2) reported `hunter_top_level=success / orchestration_status=complete` while the external ground truth was not satisfied. Root cause is a single shared defect in the **completion gate**, not in scheduling or routing:

1. **Adapters map process success to `AgentResult.SUCCESS`**: `returncode == 0 + declared artifact file exists ⇒ ExecutionStatus.SUCCESS`
   (`subprocess_adapter.py`, `kong/adapter.py`, `fuzzingbrain/parser.py`). The frozen protocol even documents this: `backend_reported_success` "never means Hunter's global success conditions were verified".
2. **`EvidenceGroundedResultInterpreter` resolves the critical user-goal question on any grounded finding** (`result_interpreter.py:44-49`), even when the finding does not prove the goal (e.g. a PARTIAL pentest that produced only a "PentestGPT AutoPenBench evaluation" finding, or a Kong analysis with `stats.errors=445, named=0`).
3. **`GlobalVerifier.verify_completion` only performed structural checks** (`verifier.py`): declared `satisfied_conditions ⊆ task.success_conditions`, cited evidence ids exist in world state, no critical question remains. It never checked whether the evidence *entails* the goal nor whether an external benchmark oracle agrees. A model COMPLETE decision citing any existing evidence therefore passed and the orchestrator returned COMPLETE.

Result: `false_success_rate = 25%` (3/12) in Phase 3B.

---

## 2. 合同修改 (Contract changes)

A new independent module `hunter_brain/completion_truth.py` introduces the four-way distinction that Phase 3B conflated:

| Meaning | Producer | Carried by |
|---|---|---|
| `backend process completed` | OS/subprocess return + artifact file exists | `ExecutionStatus.SUCCESS` on `AgentResult` |
| `AgentResult structurally succeeded` | protocol validation + canonical state ingestion | `AgentResult` + `HunterWorldState` |
| `task goal verified` | deterministic evidence (canonical `VerifiedFact` cites the evidence) | `CompletionTruth.verdict=VERIFIED` |
| `benchmark oracle verdict` | explicit per-run benchmark oracle | `CompletionTruth` (oracle id + reason) |

**Verdict vocabulary** (`CompletionVerdict`): `VERIFIED` / `NOT_VERIFIED` / `INCONCLUSIVE` / `UNAVAILABLE`, each `CompletionTruth` carries a machine-readable `reason`, `verifier_id`, `message`, `evidence_refs`, `checked_conditions`, and `metadata`.

`GlobalVerifier.verify_completion` now, after the unchanged structural checks:

1. resolves the run's oracle (or falls back to the deterministic goal-evidence gate);
2. `NOT_VERIFIED` ⇒ `FAILED` (`GOAL_NOT_VERIFIED`) — COMPLETE is blocked;
3. `INCONCLUSIVE` ⇒ `INCONCLUSIVE` (`GOAL_INCONCLUSIVE`) — run stays honestly open;
4. `UNAVAILABLE` ⇒ `INCONCLUSIVE` (`ORACLE_UNAVAILABLE`) — excluded from success/failure denominators by the evaluation layer;
5. `VERIFIED` ⇒ proceeds to the optional semantic stage and can PASS.

**Deterministic goal-evidence gate (generic, no oracle)**: every success condition must cite evidence referenced by at least one canonical `VerifiedFact`. "Evidence exists" alone is no longer sufficient; model text, self-reported success, exit code 0, and artifact-file existence are candidate evidence only.

**Orchestrator**: a `verify` action that returns INCONCLUSIVE (semantic check without a configured semantic model) no longer hard-stops the run; the supervisor decides again within its bounded decision budget. `OrchestrationResult.completion_truth` and the audit `completion_truth` payload expose the verdict.

The frozen protocol invariant `global_success_verified=false` is preserved: `AgentResult` still cannot claim global success; `ExecutionStatus.SUCCESS` remains "backend executed", and only `verify_completion` grants a global `COMPLETE`.

---

## 3. 每类 oracle 的边界 (Oracle boundaries)

| Oracle | Activation | VERIFIED iff | NOT_VERIFIED iff | INCONCLUSIVE/UNAVAILABLE iff |
|---|---|---|---|---|
| `autopenbench_judge` | `metadata.benchmark.source == "autopenbench_games_json"` (AutoPenBench run) | judge `success=true` AND submitted flag under the `upstream_data_games_json_exact_flag` oracle (judge IS the exact-flag ground truth) | judge present and not success; or success without an exact-flag submission | evaluation artifact missing (UNAVAILABLE); judge missing/malformed (INCONCLUSIVE) |
| `fuzzingbrain_crash_evidence` | domain `vulnerability_research` | a real `trigger_sample` artifact was reproduced | campaign finished with no trigger | campaign timed out with no trigger (never "no vulnerability") |
| `kong_analysis_truth` | domain `reverse` (production; no function names hardcoded) | — (never) | LLM synthesis failed for most functions (`errors>0`, `named==0`) → honest `BACKEND_TOOL_FAILURE`; or no named analysis | named analysis exists but no benchmark ground truth is configured |
| `reverse_expected_functions` | `metadata.completion_oracle.type == "reverse_expected_functions"` (evaluation layer only; the 5 XZ backdoor function names live here, never in Kong production) | all expected functions appear in the analysis | some expected function missing | analysis malformed |
| `cross_domain_provenance` | `metadata.completion_oracle.type == "cross_domain_provenance"` | the reverse subtask consumed the exact TRUDI-exported `suspect_binary` (SHA-256 of `binary.path` == export SHA) | provenance mismatch / missing export or analysis | files missing on disk / analysis malformed |
| `dfir_benchmark_unavailable` | `metadata.completion_oracle.type == "dfir_benchmark"` status missing/unavailable | — | — | `UNAVAILABLE` (benchmark images/runtime not vendored; excluded from denominators) |

General Kong/reverse production never hardcodes the 5 function names; only the evaluation-layer oracle carries them.

---

## 4. Before / After metrics

Denominator: all Phase 3C runs are eligible (no DFIR benchmark was executed, so `excluded_unavailable = 0` in the live suite; the DFIR-unavailable path is unit-tested and excluded by `phase3c_summarize.py`).

| Metric | Phase 3B | Phase 3C live (6 E2E) | Phase 3C frozen-replay (Phase 3B fixtures) |
|---|---|---|---|
| `routing_accuracy` | 12/12 (100%) | 6/6 (100%) | n/a |
| `backend_execution_success_rate` | not separated | 8/12 child backends (66.7%) | n/a |
| `verified_task_success_rate` | 4/12 (33.3%) | 3/6 (50.0%) | vm0 → VERIFIED |
| `false_success_rate` | 3/12 (25.0%) | **0/6 (0.0%)** | vm1 + reverse completed runs → **NOT_VERIFIED** |
| `false_failure_rate` | n/a | 0/6 (0.0%) | n/a |
| `inconclusive_rate` | n/a | 0/6 (0.0%) | VR fixed → INCONCLUSIVE |
| `completion_latency_seconds` | mean 462.7 | mean 785.7 / p50 636.0 / p95 1235.8 | n/a |
| `verifier_rejection_count` | 0 (no gate existed) | 0 live (no live completion attempt was rejected; model ended vm1/reverse before COMPLETE) | 3 (vm1 + 2 reverse completed decisions rejected) |

**Live E2E run table** (`evaluation/phase3c_results/*.jsonl`):

| case | hunter | orch | completion truth | classification | latency(s) |
|---|---|---|---|---|---|
| cross-domain-trudi-kong-provenance | success | complete | `verified` (`cross_domain_provenance`, SHA 7017e3d0…) | VERIFIED_SUCCESS | 136 |
| vr-fuzzingbrain-hunterdemo-positive | success | complete | `verified` (`crash_trigger_reproduced`, 9 triggers) | VERIFIED_SUCCESS | 183 |
| vr-fuzzingbrain-hunterdemo-fixed | partial | blocked | none (never completed; 2× timeout child) | TIMEOUT | 759 |
| pentest vm0-900s | success | complete | `verified` (`judge_success_exact_flag_match`) | VERIFIED_SUCCESS | 513 |
| pentest vm1-900s | failed | invalid_decisions | none (2× 900s pentest timeout, judge never ran) | TIMEOUT | 1887 |
| reverse parser-failure | partial | blocked | none (Kong `errors=445, named=0` recorded; model blocked before COMPLETE) | HONEST_INCOMPLETE | 1236 |

`before/after false-success`: **3/12 (25%) → 0/6 (0%)** live, and the frozen Phase 3B FALSE_SUCCESS decisions (vm1 + reverse×2) are deterministically rejected by the new verifier in `hunter_brain/tests/test_phase3b_false_success_regression.py`.

---

## 5. 验证手段 (How each acceptance gate is proven)

- **false_success_rate = 0**: live 0/6; frozen replay rejects vm1 + reverse completed decisions.
- **vm0 stays VERIFIED COMPLETE**: live `judge_success_exact_flag_match`; frozen replay PASSED.
- **vm1 no longer COMPLETE**: live honest TIMEOUT; frozen replay NOT_VERIFIED.
- **vm2 no false success**: Phase 3B vm2 already ended `invalid_decisions` (never completed); any completion attempt is rejected by `autopenbench_judge` (judge success false).
- **VR positive reproducible**: live VERIFIED ×1 (crash triggers).
- **VR fixed no "no-vulnerability" claim**: live blocked after 2× timeout; oracle returns INCONCLUSIVE on timeout (`campaign_timeout_no_crash`), unit-tested.
- **Reverse parser failure honest, no COMPLETE**: live Kong `errors=445, named=0` recorded and run blocked; oracle `kong_analysis_truth` returns `backend_tool_failure` NOT_VERIFIED, unit-tested and frozen-replay-proven.
- **Cross-domain no regression**: live VERIFIED_COMPLETE with byte-identical provenance SHA.
- **BENCHMARK_MISSING excluded**: `dfir_benchmark_unavailable` returns UNAVAILABLE; summarizer excludes it from denominators (unit-tested; no live DFIR benchmark run).
- **No test regression, ruff clean**: 474 passed / 11 skipped; `ruff check` clean on touched files.

---

## 6. 仍未解决的问题 (Remaining issues)

1. **Supervisor contract rejection (model flakiness)**: deepseek-v4-flash emitted invalid decisions on several attempts (e.g. `unknown_expected_output` for `dfir`, malformed budgets). Phase 3B documented this at 33%; it recurred during Phase 3C live runs and forced a bounded no-work retry in the eval harness. This is not a completion-truth defect; it is the next-highest-priority reliability item after the verifier.
2. **Live rejection demonstration**: in the live Phase 3C suite the supervisor ended vm1/reverse *before* issuing a COMPLETE (timeouts / blocked), so the verifier rejection was exercised by the frozen-replay and unit tests rather than by a live completion attempt. The rejection logic itself is deterministic.
3. **DFIR remains unverifiable**: CFReDS images are not vendored and TRUDI full requires a Claude runtime; Phase 3C keeps DFIR as explicit `UNAVAILABLE`. (Phase 3D item — explicitly out of scope here.)
4. **Kong LLM synthesis parser**: the deepseek-v4-flash synthesis parse failure (`445 errors, 0 named`) is now honestly surfaced but not fixed. (Phase 3D Reverse synthesis item — explicitly out of scope here.)
5. **Generic-path semantics**: without a benchmark oracle, the deterministic gate relies on canonical `VerifiedFact` grounding. A future goal-specific verifier (per the repository's own `CONTEXT.md` qualification note) can strengthen this further without touching scheduling.

## 7. 核心区分

- **`backend_execution_success`** = the professional backend process completed and produced its declared artifact files (`ExecutionStatus.SUCCESS`). It is measured separately as `backend_execution_success_rate` (8/12 live) and never implies the goal was achieved.
- **`task goal verified`** = a benchmark oracle confirmed success, or deterministic goal evidence (canonical verified facts) satisfies every success condition. Only this may produce a Hunter `COMPLETE`.
