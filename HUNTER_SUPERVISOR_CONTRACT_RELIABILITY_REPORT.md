# HUNTER_SUPERVISOR_CONTRACT_RELIABILITY_REPORT — Phase 3D-A

Supervisor Decision Contract Ingress: bounded, auditable retry for the global
supervisor model output before anything reaches Hunter canonical state.

- **Phase**: 3D-A (supervisor decision contract reliability; no completion-truth weakening)
- **Parent**: Phase 3C, commits `1c32588` + `b52ddd9`
- **Scope guard**: Kong synthesis parser (3D-B) and DFIR environment (3D-C) are **not** touched here.
- **Deliverables**: `evaluation/phase3c_results/*.jsonl` (re-run), `evaluation/phase3c_summary.json`,
  `hunter_brain/contract_ingress.py`, `hunter_brain/tests/test_contract_ingress.py`,
  `hunter_brain/tests/fixtures/phase3b_invalid_decisions.json`.

---

## A. 原始 Supervisor contract failure 的真实根因

Phase 3B/3C observed ~33% run-level supervisor contract failure
(`model_error` + `invalid_decisions`), e.g. vm1 ending after three identical
`unknown_expected_output` rejects. The full chain today was:

```
orchestrator.run loop -> HunterSupervisor.decide
  -> DeepSeekDecisionModel.decide (HTTP)
  -> json.loads (strict)
  -> decision_from_dict (schema, strict _exact_keys)
  -> DeterministicDecisionValidator.validate (semantic)
  -> orchestrator rejection handling
```

Six defects:
1. **RC1 无语法归一化** — markdown fences / leading prose made `json.loads` fail →
   immediate `SupervisorOutputError` → terminal `MODEL_ERROR`, no recovery.
2. **RC2 retry 无错误反馈** — a semantic rejection re-prompted the model with the
   *same* context; the model never saw what was invalid, so it repeated
   invalid proposals until the opaque 3-strike `rejected_decisions` counter →
   `INVALID_DECISIONS`.
3. **RC3 无重复 fingerprint** — three identical invalid outputs each counted once;
   no "equivalent decision repeated ⇒ stop retrying".
4. **RC4 无 per-decision attempt budget** — retries were indistinguishable from run
   progress in the ledger; raw-invalid and post-retry-accepted rates could not be
   measured separately.
5. **RC5 无 backend-failure 感知** — after a backend timeout/failure the model could
   reschedule the identical action with no new evidence; only a weak
   duplicate-without-progress check existed, with no consecutive-timeout threshold
   and no "new basis or BLOCK" requirement.
6. **RC6 trace 缺口** — raw outputs, normalization, per-attempt errors, retry indices
   were never written to the audit log; terminal failure was opaque.

---

## B. 修改的文件与设计

New module `hunter_brain/contract_ingress.py` — pure, side-effect-free ingress:

- `normalize_decision_json`: fixes only deterministic wrapping (markdown fence,
  surrounding prose, trailing text). It never guesses fields, never chooses a task
  for the model, never generates a completion basis, never changes semantics.
- `decision_fingerprint`: stable canonical SHA-256 of the effective decision
  (field-order invariant); for unparseable output fingerprints the raw text.
- `DecisionIngressPolicy`: `max_attempts=3`, `max_repeated_invalid=2`.

`hunter_brain/supervisor.py`:
- `DeepSeekDecisionModel.decide` now returns the raw text (`raw_content`) and
  `value=None` on non-JSON instead of raising; transport/auth errors still raise
  `SupervisorModelError`.
- `HunterSupervisor.decide` runs the **ingress retry loop**:
  `raw -> normalize -> decision_from_dict (schema) -> validator (semantic) -> accepted`.
  On rejection it records a `DecisionAttemptTrace` and re-prompts with a retry
  context carrying: exact machine-readable `previous_decision_errors`, the current
  `state_revision` (stable across attempts — retries never mutate canonical state),
  `retry_index`, and the allowed decision schema/vocabulary (already in the base context).
- Repeated identical invalid/no-progress proposals (same fingerprint)
  terminate retry early (`repeated_invalid_decision` / `repeated_no_progress_decision`).
  Exhaustion of `max_attempts` raises `SupervisorDecisionRejected`
  (`invalid_decision_exhausted`) with the full trace.
- `ModelDecisionResult` gains `raw_content`; `SupervisionOutcome` gains
  `traces`; model usage is aggregated across attempts so retries are not budget-free.

`hunter_brain/validator.py`:
- New `BACKEND_REPEATED_FAILURE` gate: if the same equivalent backend action
  (`capability_id` + `input_refs` + question) already failed/timed out
  `max_repeated_backend_failure` (default 2) consecutive times with no new
  canonical evidence, the invocation is rejected. The model must supply a new
  basis, a legal alternative, or an honest BLOCKED decision — the code never
  invents an attack/analysis path.

`hunter_brain/orchestrator.py`:
- Writes one `decision_attempt` audit event per ingress attempt (raw output,
  normalized dict, parse error, validation issues, fingerprint, retry index,
  decision index) and a `supervisor_decision_rejected` event on exhaustion.
- Catches `SupervisorDecisionRejected` → terminal `INVALID_DECISIONS` with the
  exact diagnostics (never COMPLETE).

`evaluation/phase3c_eval.py` / `phase3c_summarize.py`:
- Record accepted decisions from the audit (`decision` events) — rejected
  ingress attempts are never treated as decisions.
- New reliability metrics: `raw_model_calls`, `raw_invalid_attempts`,
  `raw_invalid_rate`, `decisions_with_rejection`, `retries_recovered`,
  `retry_recovery_rate`, `run_level_invalid_decisions_termination_rate`.

Model remains a **proposal source only**: canonical state mutation stays behind
`WorldStateUpdater` for accepted capability results; a rejected decision never
partially writes state (asserted by tests).

## C. 为什么不会削弱 Phase 3C completion truth

- `CompletionVerifier` / oracles / `CompletionVerdict` are untouched. The
  `verify_completion` gate, `completion_truth.py`, and the 15 completion-truth
  unit tests + 5 Phase 3B frozen replays are byte-identical.
- `AgentResult.SUCCESS` still never equals global COMPLETE; only
  `verify_completion` grants COMPLETE.
- The ingress only affects *how the supervisor proposes* a decision; the *truth* of
  a completion is still decided by deterministic evidence / benchmark oracles.
- Live evidence: vm0 this re-run proposed a COMPLETE the judge did not support →
  oracle returned `NOT_VERIFIED` and the run ended `verification_failed`
  (no false success). Reverse proposed a COMPLETE the eval oracle did not support
  (backdoor functions not found) → `NOT_VERIFIED`.

## D. retry / no-progress 状态机

```
for attempt in 0..max_attempts-1:
    context = base_context (+ decision_retry{retry_index, state_revision, previous_decision_errors})
    raw = model.decide(context)
    normalized = raw value if dict else normalize_decision_json(raw)
    fingerprint = decision_fingerprint(normalized | raw)
    if fingerprint == last: repeats += 1 else repeats = 1
    trace.record(attempt, raw, normalized, parse_error, validation_issues, fingerprint, accepted)
    if normalized is None:                      # unparseable
        if repeats >= max_repeated_invalid: raise repeated_invalid_decision
        continue
    try decision = decision_from_dict(normalized)
    except ValueError:                          # schema invalid
        if repeats >= max_repeated_invalid: raise repeated_invalid_decision
        continue
    validation = validator.validate(decision)   # semantic
    if validation.accepted: return SupervisionOutcome(traces)
    if repeats >= max_repeated_invalid: raise repeated_no_progress_decision
    continue
raise invalid_decision_exhausted(traces)
```

- Bounded: ≤ `max_attempts` model calls per decision; `max_attempts * max_decisions`
  bounds total model calls, so retry cannot consume the whole run budget.
- Canonical state is read-only during ingress (`state_revision` constant).
- Final failure is honest `INVALID_DECISIONS` with exact per-attempt trace; never COMPLETE.

## E. 测试结果

| Suite | Result |
|---|---|
| Full regression (`hunter_brain/tests`, `integrations/tests`, `tests`, `pentestgpt-core/tests`) | **497 passed / 11 skipped** (Phase 3C baseline 474/11 + 23 new ingress tests) |
| Completion-truth contract (`test_completion_truth.py`) | 15 passed |
| Phase 3B false-success frozen replay (`test_phase3b_false_success_regression.py`) | 5 passed |
| Contract ingress (`test_contract_ingress.py`) | 23 passed |
| ruff | clean on all touched files (pre-existing `integrations/fuzzingbrain/adapter.py` findings unchanged) |

Ingress tests cover: invalid JSON, fenced JSON, leading/trailing text, non-object,
missing required field, unknown field/enum/type, stable state revision across
retries, illegal COMPLETE with missing completion basis, repeated identical invalid
early-stop, semantically-equivalent no-progress early-stop, retry-then-accept,
retry exhaustion, repeated backend timeout without new evidence blocked, single
timeout not yet blocked, rejected attempts never mutate canonical state, and
orchestrator `decision_attempt` trace completeness. The frozen Phase 3B
invalid-decision corpus (vendored `phase3b_invalid_decisions.json`, 3 representative
decisions of the 23 rejected Phase 3B decisions) replays to
recover-or-terminate-honestly with no canonical mutation.

## F. Live E2E (Phase 3C 6-case default Hunter re-run)

`evaluation/phase3c_results/*.jsonl`

| case | orch | completion truth | class | ingress calls / rejected / recovered |
|---|---|---|---|---|
| cross-domain-trudi-kong-provenance | complete | `verified` (provenance SHA) | VERIFIED_SUCCESS | 3 / 0 / 0 |
| vr-fuzzingbrain-hunterdemo-positive | complete | `verified` (crash trigger) | VERIFIED_SUCCESS | 2 / 0 / 0 |
| vr-fuzzingbrain-hunterdemo-fixed | blocked (timeout child) | none | TIMEOUT | 4 / 0 / 0 |
| pentest vm0-900s | verification_failed | `not_verified` (judge not success — gate blocked a false COMPLETE) | NOT_VERIFIED | 5 / 2 / 2 |
| pentest vm1-900s | invalid_decisions | none | HONEST_INCOMPLETE | 6 / 4 / 1 |
| reverse parser-failure | verification_failed | `not_verified` (backdoor fns not found — eval oracle rejected COMPLETE) | NOT_VERIFIED | 7 / 1 / 1 |

**Before / After**

| Metric | Before (Phase 3C) | After (Phase 3D-A re-run) |
|---|---|---|
| raw invalid decision rate | not measured (no per-call trace) | 7/27 model calls = **25.9%** |
| retry recovery rate | 0 (no retry-with-feedback) | 4/5 decisions-with-rejection = **80.0%** |
| run-level invalid_decisions termination | 1/6 (vm1, opaque 3-strike) | 1/6 (vm1, bounded ingress + exact trace) |
| false-success rate | 0/6 | **0/6** |
| verified_task_success_rate | 3/6 (50%) | 2/6 (33.3%) — cross-domain + VR positive |
| routing accuracy | 6/6 | 6/6 |

Notes:
- vm0's re-run: the pentest backend did not capture the flag this time; the model
  proposed COMPLETE and the `autopenbench_judge` oracle returned `NOT_VERIFIED` —
  the Phase 3C gate converted a would-be FALSE_SUCCESS into an honest rejection
  (Phase 3C's vm0 VERIFIED_COMPLETE remains in the committed Phase 3C results).
- vm1: the ingress recovered decision 1 (`unknown_expected_output` → corrected);
  a later decision produced three *different* invalid outputs
  (`unknown_question`+`unknown_evidence`, empty-`blocking_question_ids`, `unknown_question`)
  and exhausted the bounded 3-attempt budget. The run terminated honestly with the
  exact per-attempt trace in the audit; no state pollution, no COMPLETE.

## G. 剩余 blocker 与下一阶段

1. **Supervisor model still flails when a question is genuinely exhausted**
   (vm1 final decision): deepseek-v4-flash produced three different invalid
   outputs in a row and consumed the bounded retry budget. The ingress made this
   honest and traceable but could not force recovery. A model-side follow-up
   (e.g. stronger "prefer BLOCKED over inventing references" prompting, or a
   domain-agnostic recovery hint) is the next reliability lever; the current
   `max_attempts=3` could be config-tuned per deployment without changing truth.
2. **Kong synthesis parser** (`errors=445, named=0`) is honestly surfaced and
   still unfixed → **should enter Phase 3D-B** as planned.
3. **DFIR environment** (CFReDS images, TRUDI full Claude runtime) is unavailable;
   Phase 3C keeps it `UNAVAILABLE`/excluded → **should enter Phase 3D-C** as planned.

These two are deliberately left for Phase 3D-B / 3D-C; they were not touched here.
