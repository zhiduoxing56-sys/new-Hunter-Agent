"""Catalog-driven cross-domain question generation."""

from __future__ import annotations

import hashlib

from pentestgpt_agent.protocol import AgentResult

from .capabilities import CapabilityCatalog, default_catalog
from .decisions import InvokeCapabilityDecision
from .state import UnresolvedQuestion
from .state_updater import SemanticStateProposal, StateUpdate


class CrossDomainQuestionGenerator:
    """Turn newly produced compatible artifacts into unresolved questions.

    No source-to-destination route table exists here. Candidate domains are
    derived solely from the artifact type and the current capability catalog.
    """

    def __init__(self, catalog: CapabilityCatalog | None = None) -> None:
        self.catalog = catalog or default_catalog()

    def interpret(
        self,
        *,
        preview: StateUpdate,
        decision: InvokeCapabilityDecision,
        result: AgentResult,
    ) -> SemanticStateProposal:
        questions: list[UnresolvedQuestion] = []
        existing_sources = {
            item.source for item in preview.state.unresolved_questions.values()
        }
        for artifact_id in preview.delta.added_artifact_ids:
            artifact = preview.state.artifacts[artifact_id]
            candidates = tuple(
                capability
                for capability in self.catalog.candidates_for_input(
                    artifact.artifact_type
                )
                if capability.capability_id != decision.capability_id
            )
            if not candidates or artifact_id in existing_sources:
                continue
            digest = hashlib.sha256(artifact_id.encode()).hexdigest()[:16]
            questions.append(
                UnresolvedQuestion(
                    question_id=f"cross-domain-{digest}",
                    question=(
                        "What security-relevant conclusions should be derived from "
                        f"artifact {artifact_id} of type {artifact.artifact_type}?"
                    ),
                    priority=80,
                    source=artifact_id,
                )
            )
        return SemanticStateProposal(new_questions=tuple(questions))
