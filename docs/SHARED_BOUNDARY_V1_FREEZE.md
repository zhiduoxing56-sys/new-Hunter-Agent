# Hunter shared boundary freeze — protocol 1.0

Status: **FROZEN**  
Effective date: 2026-08-29  
Compatibility test: `tests/test_shared_boundary_v1_freeze.py`

This document freezes the shared boundary between the Hunter global brain and
professional backends. It freezes public wire contracts and lifecycle entry
points, not private implementations.

## Frozen contracts

### `TaskSpec`

The protocol version remains `1.0`. The serialized keys and their existing
meaning are frozen:

```text
schema_version, task_id, created_at, goal, domain, domain_scores,
input_object, target_object, target, authorization, timeout,
tool_call_budget, model_budget, resource_limits, workspace,
success_conditions, metadata, scope, budget
```

New global-brain context must first use the existing extension locations:
`metadata`, `scope`, `success_conditions`, and `resource_limits`. Existing key
meaning, validation, or requiredness must not be changed for brain convenience.

### `AgentResult`

The serialized keys and their existing meaning are frozen:

```text
schema_version, task_id, agent_id, domain, status, started_at, finished_at,
summary, findings, evidence, artifacts, metrics, error, raw_output,
global_success_verified
```

`global_success_verified` must remain `false`: backend success is local to the
subtask. New backend-specific result data must first use `metrics` or
`raw_output`. Findings must continue to reference real evidence, and evidence
must continue to reference real artifacts.

### Adapter lifecycle

The only global-brain execution boundary is the public `AgentAdapter` lifecycle:

```text
healthcheck(TaskSpec) -> HealthcheckResult
prepare(TaskSpec, RunLayout) -> PreparedTask
run(PreparedTask) -> ExecutionHandle
collect(PreparedTask, ExecutionHandle) -> AgentResult
stop(PreparedTask | None, reason=...) -> None
```

The global brain must invoke this lifecycle through `AdapterRunner.execute`.
It must not import or invoke private professional-backend functions.

### Run layout

Every task remains isolated below `runs/<task_id>/` with these shared paths:

```text
task.json
events.jsonl
result.json
world_state.json
artifacts/
evidence/
logs/
```

Brain-owned state may be added inside the same task directory under new,
brain-specific names. Existing backend paths and meanings must not change.

### Event envelope

The event envelope remains:

```text
schema_version, event_id, task_id, timestamp, event_type, source, status, payload
```

The frozen protocol event types are:

```text
task_created, task_prepared, adapter_started, tool_called, tool_result,
artifact_created, evidence_created, adapter_finished, verification_result,
strategy_switched, task_finished, error
```

Additional global-brain event names may be emitted because `event_type` is an
open string. Their data belongs in `payload`; existing event names and meanings
must not be repurposed.

## Change control

A change is non-breaking only when all existing protocol 1.0 consumers still
round-trip and behave identically. Prefer the extension locations above.

A change to a frozen field, its meaning, lifecycle signature, path meaning, or
existing event meaning requires all of the following:

1. explicit agreement by owners of the global brain and affected adapters;
2. a new protocol version and migration notes;
3. compatibility tests for old and new versions;
4. coordinated adapter rollout before the new version becomes the default.

The executable freeze test is intentionally independent of implementation
hashes. Refactoring private code remains allowed when this public behavior stays
unchanged.
