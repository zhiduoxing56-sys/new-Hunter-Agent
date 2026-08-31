from __future__ import annotations

from pathlib import Path

from autopenbench_adapter.protocol import AutoPenBenchProtocolAdapter
from hunter_brain.orchestrator import CapabilityAdapterRegistry
from integrations.hunter_brain import (
    AnalysisBrainAdapters,
    HunterBrainAdapters,
    build_hunter_brain_adapters,
)
from pentestgpt_agent.protocol.mock_adapter import MockAdapter


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _adapter(agent_id: str) -> MockAdapter:
    adapter = MockAdapter()
    adapter.agent_id = agent_id
    return adapter


def test_four_domains_are_added_only_by_composition() -> None:
    pentest = _adapter("pentest-professional")
    vulnerability = _adapter("vulnerability-professional")

    adapters = build_hunter_brain_adapters(
        repo_root=PROJECT_ROOT,
        pentest_adapter=pentest,
        vulnerability_research_adapter=vulnerability,
    )
    registry = adapters.registry()

    assert isinstance(adapters, HunterBrainAdapters)
    assert isinstance(registry, CapabilityAdapterRegistry)
    assert registry.get("dfir") is adapters.trudi
    assert registry.get("reverse") is adapters.kong
    assert registry.get("pentest") is pentest
    assert registry.get("vulnerability_research") is vulnerability


def test_phase_nine_two_domain_composition_remains_compatible() -> None:
    kong = _adapter("reverse-professional")
    trudi = _adapter("dfir-professional")
    adapters = AnalysisBrainAdapters(kong=kong, trudi=trudi)
    registry = adapters.registry()

    assert registry.get("dfir") is trudi
    assert registry.get("reverse") is kong
    assert registry.get("pentest") is None
    assert registry.get("vulnerability_research") is None


def test_existing_autopenbench_adapter_is_the_default_third_domain() -> None:
    adapters = build_hunter_brain_adapters(
        repo_root=PROJECT_ROOT,
        vulnerability_research_adapter=_adapter("vulnerability-professional"),
    )

    assert isinstance(adapters.pentest, AutoPenBenchProtocolAdapter)
    assert adapters.registry().get("pentest") is adapters.pentest
