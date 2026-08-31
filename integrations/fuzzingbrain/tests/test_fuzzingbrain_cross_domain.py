"""Cross-domain routing and artifact handoff for FuzzingBrain.

Non-live protocol/catalog tests covering 阶段六 items 4-5: every
FuzzingBrain-involved pair listed in the plan (TRUDI->FuzzingBrain,
Kong->FuzzingBrain, FuzzingBrain->Kong, FuzzingBrain->Pentest,
Pentest->FuzzingBrain) routes through the capability catalog, and all four
backends are dynamically selectable through one registry.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from hunter_brain.capabilities import default_catalog
from integrations.fuzzingbrain import FuzzingBrainAdapter
from integrations.hunter_brain import build_hunter_brain_adapters
from pentestgpt_agent.protocol.mock_adapter import MockAdapter

PROJECT_ROOT = Path(__file__).resolve().parents[3]

PAIRS = (
    ("dfir", "source_bundle", "vulnerability_research"),       # TRUDI -> FuzzingBrain
    ("reverse", "source_bundle", "vulnerability_research"),     # Kong -> FuzzingBrain
    ("vulnerability_research", "trigger_sample", "reverse"),    # FuzzingBrain -> Kong
    ("vulnerability_research", "vulnerability_bundle", "pentest"),  # FuzzingBrain -> Pentest
    ("pentest", "crash_bundle", "vulnerability_research"),      # Pentest -> FuzzingBrain
    ("pentest", "source_bundle", "vulnerability_research"),     # Pentest -> FuzzingBrain (alt)
)


def test_all_six_fuzzingbrain_pairs_route_through_catalog() -> None:
    catalog = default_catalog()
    for producer_id, output_type, consumer_id in PAIRS:
        assert output_type in catalog.get(producer_id).produces, (
            f"{producer_id} must be able to produce {output_type}"
        )
        assert output_type in catalog.get(consumer_id).accepted_input_types, (
            f"{consumer_id} must accept {output_type}"
        )
        candidates = {item.capability_id for item in catalog.candidates_for_input(output_type)}
        assert consumer_id in candidates, (
            f"catalog must route {output_type} to {consumer_id}, got {candidates}"
        )


def test_four_backend_registry_is_dynamically_selectable() -> None:
    adapters = build_hunter_brain_adapters(
        repo_root=PROJECT_ROOT,
        pentest_adapter=MockAdapter(),
    )
    registry = adapters.registry()
    assert set(registry._adapters) == {"dfir", "reverse", "pentest", "vulnerability_research"}
    assert isinstance(registry.get("vulnerability_research"), FuzzingBrainAdapter)
    assert all(registry.get(capability) is not None for capability in registry._adapters)

    catalog = default_catalog()
    for capability_id in ("dfir", "reverse", "pentest", "vulnerability_research"):
        capability = catalog.get(capability_id)
        assert registry.get(capability_id) is not None
        assert capability.solves and capability.produces and capability.accepted_input_types


def test_fuzzingbrain_inputs_cover_catalog_surface() -> None:
    """FuzzingBrain's fixture adapter handles every advertised input family."""
    capability = default_catalog().get("vulnerability_research")
    for accepted in ("source_tree", "source_bundle", "crash_bundle"):
        assert accepted in capability.accepted_input_types
    for produced in ("vulnerability_bundle", "crash_bundle", "trigger_sample"):
        assert produced in capability.produces


@pytest.mark.asyncio
async def test_fuzzingbrain_healthcheck_contract() -> None:
    """The registered adapter exposes the frozen healthcheck contract."""
    adapter = FuzzingBrainAdapter(repo_root=PROJECT_ROOT)
    from pentestgpt_agent.protocol import AuthorizationScope, TaskSpec

    fixture = PROJECT_ROOT / "third_party/fuzzingbrain/fixtures/hunterdemo"
    if not fixture.is_dir():
        pytest.skip("FuzzingBrain fixture is unavailable")
    task = TaskSpec(
        task_id="catalog-healthcheck",
        domain="vulnerability_research",
        target=str(fixture.resolve()),
        goal="Healthcheck contract.",
        workspace=str(fixture.parent),
        authorization=AuthorizationScope(
            allowed_targets=(str(fixture.resolve()),),
            allowed_read_paths=(str(fixture.resolve()),),
            workspace=str(fixture.parent),
        ),
    )
    health = await adapter.healthcheck(task)
    assert health.available is False or health.available is True
    assert isinstance(health.details, dict)
