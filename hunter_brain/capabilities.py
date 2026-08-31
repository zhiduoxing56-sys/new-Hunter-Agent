"""Coarse-grained professional capability catalogue.

The catalogue describes professional agents, never the tools they use. Keeping
this module protocol-neutral also lets the global brain inspect capabilities
without importing a backend implementation.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Any


class CapabilityCost(StrEnum):
    """Deliberately coarse expected execution cost."""

    MEDIUM = "medium"
    MEDIUM_TO_HIGH = "medium_to_high"
    HIGH = "high"


@dataclass(frozen=True)
class Capability:
    """One high-level professional capability visible to the supervisor."""

    capability_id: str
    display_name: str
    accepted_input_types: frozenset[str]
    solves: frozenset[str]
    produces: frozenset[str]
    cost: CapabilityCost
    description: str

    def __post_init__(self) -> None:
        for label, value in (
            ("capability_id", self.capability_id),
            ("display_name", self.display_name),
            ("description", self.description),
        ):
            if not value.strip():
                raise ValueError(f"{label} must be nonempty")
        for label, values in (
            ("accepted_input_types", self.accepted_input_types),
            ("solves", self.solves),
            ("produces", self.produces),
        ):
            if not values or any(not value.strip() for value in values):
                raise ValueError(f"{label} must contain nonempty values")

    def accepts(self, input_type: str) -> bool:
        return input_type in self.accepted_input_types

    def can_solve(self, problem_type: str) -> bool:
        return problem_type in self.solves

    def to_dict(self) -> dict[str, Any]:
        return {
            "capability_id": self.capability_id,
            "display_name": self.display_name,
            "accepted_input_types": sorted(self.accepted_input_types),
            "solves": sorted(self.solves),
            "produces": sorted(self.produces),
            "cost": self.cost.value,
            "description": self.description,
        }


class CapabilityCatalog:
    """Immutable registry used as the supervisor's complete capability view."""

    def __init__(self, capabilities: Iterable[Capability]) -> None:
        indexed: dict[str, Capability] = {}
        for capability in capabilities:
            if capability.capability_id in indexed:
                raise ValueError(f"duplicate capability_id: {capability.capability_id!r}")
            indexed[capability.capability_id] = capability
        if not indexed:
            raise ValueError("capability catalogue must not be empty")
        self._capabilities = MappingProxyType(indexed)

    def __len__(self) -> int:
        return len(self._capabilities)

    def __iter__(self) -> Iterator[Capability]:
        return iter(self._capabilities.values())

    @property
    def capability_ids(self) -> tuple[str, ...]:
        return tuple(self._capabilities)

    def get(self, capability_id: str) -> Capability:
        try:
            return self._capabilities[capability_id]
        except KeyError as exc:
            raise KeyError(f"unknown capability: {capability_id!r}") from exc

    def candidates_for_input(self, input_type: str) -> tuple[Capability, ...]:
        return tuple(item for item in self if item.accepts(input_type))

    def candidates_for_problem(self, problem_type: str) -> tuple[Capability, ...]:
        return tuple(item for item in self if item.can_solve(problem_type))

    def to_dict(self) -> dict[str, dict[str, Any]]:
        return {item.capability_id: item.to_dict() for item in self}


DEFAULT_CAPABILITIES = (
    Capability(
        capability_id="dfir",
        display_name="Digital forensics and incident response",
        accepted_input_types=frozenset(
            {
                "evtx",
                "pcap",
                "memory_image",
                "disk_image",
                "log",
                "indicator",
                "indicator_bundle",
                "evidence_bundle",
                "evidence_file",
                "evidence_directory",
            }
        ),
        solves=frozenset(
            {
                "attack_timeline",
                "initial_access",
                "persistence",
                "indicator_search",
                "host_activity",
                "suspicious_file_discovery",
            }
        ),
        produces=frozenset(
            {
                "indicator",
                "indicator_bundle",
                "suspicious_binary",
                "timeline",
                "finding",
                "exported_evidence",
                "evidence_bundle",
                "network_target",
                "source_bundle",
            }
        ),
        cost=CapabilityCost.MEDIUM_TO_HIGH,
        description="Investigate host and network evidence and build evidence-grounded timelines.",
    ),
    Capability(
        capability_id="reverse",
        display_name="Reverse engineering",
        accepted_input_types=frozenset(
            {
                "pe",
                "elf",
                "mach_o",
                "firmware",
                "suspect_binary",
                "suspicious_binary",
                "file_artifact",
                "trigger_sample",
            }
        ),
        solves=frozenset(
            {
                "program_behavior",
                "key_functions",
                "network_communication",
                "command_and_control",
                "cryptographic_logic",
                "persistence_logic",
                "unpacking",
            }
        ),
        produces=frozenset(
            {
                "domain_name",
                "network_address",
                "registry_path",
                "mutex",
                "service_name",
                "key_function",
                "unpacked_binary",
                "program_behavior",
                "binary_metadata",
                "indicator_bundle",
                "evidence_bundle",
                "network_target",
                "source_bundle",
            }
        ),
        cost=CapabilityCost.HIGH,
        description="Explain executable and firmware behavior and extract actionable indicators.",
    ),
    Capability(
        capability_id="pentest",
        display_name="Authorized penetration testing",
        accepted_input_types=frozenset(
            {
                "network_target",
                "url",
                "service_target",
                "vulnerability",
                "vulnerability_bundle",
            }
        ),
        solves=frozenset(
            {
                "attack_surface",
                "service_identification",
                "vulnerability_validation",
                "exploitation",
                "access_acquisition",
                "target_proof",
            }
        ),
        produces=frozenset(
            {
                "service_information",
                "vulnerability_evidence",
                "exploit_result",
                "access_proof",
                "target_flag",
                "file_artifact",
                "evidence_bundle",
                "source_bundle",
                "crash_bundle",
                "trigger_sample",
            }
        ),
        cost=CapabilityCost.MEDIUM_TO_HIGH,
        description="Assess explicitly authorized network and service targets.",
    ),
    Capability(
        capability_id="vulnerability_research",
        display_name="Vulnerability research",
        accepted_input_types=frozenset(
            {
                "source_code",
                "script",
                "source_tree",
                "code_directory",
                "build_target",
                "decompiled_source",
                "source_bundle",
                "crash_bundle",
            }
        ),
        solves=frozenset(
            {
                "vulnerability_discovery",
                "suspicious_code_validation",
                "crash_validation",
                "vulnerability_trigger",
                "reproduction_proof",
            }
        ),
        produces=frozenset(
            {
                "vulnerability",
                "vulnerability_bundle",
                "crash",
                "crash_bundle",
                "trigger_sample",
                "code_location",
                "patch_guidance",
                "patch",
                "indicator_bundle",
                "evidence_bundle",
                "source_bundle",
            }
        ),
        cost=CapabilityCost.HIGH,
        description="Find and reproduce vulnerabilities in source and build targets.",
    ),
)


def default_catalog() -> CapabilityCatalog:
    """Return the four coarse capabilities defined by the phase-one design."""

    return CapabilityCatalog(DEFAULT_CAPABILITIES)
