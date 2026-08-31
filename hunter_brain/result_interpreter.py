"""Deterministic translation of a grounded professional AgentResult into
canonical question resolutions.

A professional AgentResult that passes the adapter contract contributes
artifacts, evidence and findings to world state via the WorldStateUpdater.
This interpreter decides which pending question the decision actually answered,
using only grounded facts (findings backed by evidence that entered canonical
state). It never declares global success: ``AgentResult.status == success`` is
NOT ``Hunter global success``. Completion stays behind the deterministic
decision validator and the global verifier.
"""

from __future__ import annotations

from pentestgpt_agent.protocol import AgentResult, ExecutionStatus

from .decisions import InvokeCapabilityDecision
from .orchestrator import ResultInterpreter
from .state_updater import QuestionResolution, SemanticStateProposal, StateUpdate


class EvidenceGroundedResultInterpreter(ResultInterpreter):
    """Resolve the targeted question only when the result added grounded facts.

    ``WorldStateUpdater`` only promotes a finding to a ``VerifiedFact`` when the
    finding cites evidence, so ``preview.delta.added_fact_ids`` is the
    deterministic "grounded, contract-validated result" signal. Without new
    grounded facts the question stays unresolved, which prevents the supervisor
    from completing an evidence-empty SUCCESS.
    """

    def interpret(
        self,
        *,
        preview: StateUpdate,
        decision: InvokeCapabilityDecision,
        result: AgentResult,
    ) -> SemanticStateProposal:
        if result.status not in {
            ExecutionStatus.SUCCESS,
            ExecutionStatus.PARTIAL,
        }:
            return SemanticStateProposal()
        added = preview.delta.added_fact_ids
        if not added:
            return SemanticStateProposal()
        return SemanticStateProposal(
            resolutions=(
                QuestionResolution(decision.question_id, tuple(added)),
            )
        )
