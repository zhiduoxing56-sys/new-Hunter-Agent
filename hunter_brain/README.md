# Hunter brain ownership boundary

`hunter_brain` is the independent upper-layer package for Hunter's global
decision loop. Its owner may implement:

- capability cataloguing;
- global world state and state updates;
- structured decisions and deterministic decision validation;
- supervision and global verification;
- serial orchestration and brain-specific audit state;
- tests for those components.

It may depend on the frozen public API exposed by
`pentestgpt_agent.protocol`. It must execute a professional capability through
`AdapterRunner` and an `AgentAdapter` implementation supplied from outside this
package.

It must not:

- import `integrations`, `third_party`, or a professional project;
- import private protocol implementation modules;
- call backend-private functions;
- modify or own professional adapters or parsers;
- redefine `TaskSpec`, `AgentResult`, adapter lifecycle, event envelope, or run
  layout;
- write into backend-owned artifact, evidence, or log paths except through the
  frozen protocol lifecycle.

Brain-owned files may be added beneath an existing `runs/<task_id>/` directory
using clearly brain-specific names. Shared boundary changes follow
[`docs/SHARED_BOUNDARY_V1_FREEZE.md`](../docs/SHARED_BOUNDARY_V1_FREEZE.md).

The module files are intentionally skeletal at this stage. Later implementation
phases fill them without moving global-brain logic into backend integrations.
