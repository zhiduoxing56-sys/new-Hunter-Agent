from __future__ import annotations

import pytest

from hunter_brain.capabilities import (
    DEFAULT_CAPABILITIES,
    Capability,
    CapabilityCatalog,
    CapabilityCost,
    default_catalog,
)


def test_default_catalog_contains_only_four_professional_capabilities() -> None:
    catalog = default_catalog()

    assert catalog.capability_ids == (
        "dfir",
        "reverse",
        "pentest",
        "vulnerability_research",
    )
    assert len(catalog) == 4


@pytest.mark.parametrize(
    ("input_type", "expected"),
    [
        ("evtx", ("dfir",)),
        ("pcap", ("dfir",)),
        ("pe", ("reverse",)),
        ("elf", ("reverse",)),
        ("suspect_binary", ("reverse",)),
        ("network_target", ("pentest",)),
        ("source_code", ("vulnerability_research",)),
        ("decompiled_source", ("vulnerability_research",)),
        ("unknown", ()),
    ],
)
def test_input_compatibility_uses_layer_one_type_names(
    input_type: str, expected: tuple[str, ...]
) -> None:
    candidates = default_catalog().candidates_for_input(input_type)

    assert tuple(item.capability_id for item in candidates) == expected


def test_problem_matching_is_coarse_grained() -> None:
    catalog = default_catalog()

    assert tuple(
        item.capability_id for item in catalog.candidates_for_problem("persistence")
    ) == ("dfir",)
    assert tuple(
        item.capability_id
        for item in catalog.candidates_for_problem("vulnerability_validation")
    ) == ("pentest",)
    assert catalog.candidates_for_problem("port_scanner") == ()
    assert catalog.candidates_for_problem("disassembler") == ()


def test_catalog_serialization_is_deterministic_and_json_shaped() -> None:
    value = default_catalog().to_dict()

    assert tuple(value) == (
        "dfir",
        "reverse",
        "pentest",
        "vulnerability_research",
    )
    assert value["reverse"]["cost"] == "high"
    assert value["reverse"]["accepted_input_types"] == [
        "elf",
        "file_artifact",
        "firmware",
        "mach_o",
        "pe",
        "suspect_binary",
        "suspicious_binary",
        "trigger_sample",
    ]


def test_every_capability_pair_has_a_declared_semantic_handoff() -> None:
    """Pair coverage emerges from types, never from a source/destination route table."""
    catalog = default_catalog()

    for source in catalog:
        for destination in catalog:
            if source.capability_id == destination.capability_id:
                continue
            assert source.produces & destination.accepted_input_types, (
                source.capability_id,
                destination.capability_id,
            )


def test_duplicate_capability_registration_is_rejected() -> None:
    with pytest.raises(ValueError, match="duplicate capability_id"):
        CapabilityCatalog((DEFAULT_CAPABILITIES[0], DEFAULT_CAPABILITIES[0]))


def test_empty_catalog_and_invalid_capability_are_rejected() -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        CapabilityCatalog(())
    with pytest.raises(ValueError, match="accepted_input_types"):
        Capability(
            capability_id="invalid",
            display_name="Invalid",
            accepted_input_types=frozenset(),
            solves=frozenset({"problem"}),
            produces=frozenset({"output"}),
            cost=CapabilityCost.MEDIUM,
            description="Invalid test capability.",
        )


def test_unknown_capability_has_a_clear_error() -> None:
    with pytest.raises(KeyError, match="unknown capability"):
        default_catalog().get("missing")
