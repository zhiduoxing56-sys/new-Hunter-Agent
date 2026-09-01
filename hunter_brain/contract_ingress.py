"""Deterministic decision ingress: raw model output -> canonical decision dict.

The model is only a proposal source; deterministic code owns canonical state.
This module owns the pure, side-effect-free part of the contract ingress:

- ``normalize_decision_json`` fixes only deterministic wrapping/serialization
  (markdown code fences, surrounding prose, trailing text). It never guesses
  missing fields, never chooses a task for the model, never generates a
  completion basis, and never changes decision semantics.
- ``decision_fingerprint`` produces a stable canonical fingerprint of an
  effective (normalized/parsed) decision for duplicate and no-progress
  detection. For unparseable output it fingerprints the raw text.
- ``DecisionIngressPolicy`` bounds per-decision model attempts and the number
  of consecutive identical invalid outputs that terminate retry early.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any


class DecisionNormalizationError(ValueError):
    """Raised when model output contains no recoverable JSON decision object."""


@dataclass(frozen=True)
class DecisionIngressPolicy:
    max_attempts: int = 3
    max_repeated_invalid: int = 2

    def __post_init__(self) -> None:
        if self.max_attempts < 1 or self.max_repeated_invalid < 1:
            raise ValueError("ingress policy values must be positive")
        if self.max_repeated_invalid > self.max_attempts:
            raise ValueError("max_repeated_invalid must not exceed max_attempts")


def normalize_decision_json(raw: str) -> dict[str, Any]:
    """Deterministically extract one JSON decision object from model output.

    Accepts the whole output as JSON, a markdown-fenced JSON block, or the
    first JSON object embedded in surrounding prose. Everything else is a
    ``DecisionNormalizationError``; nothing is repaired.
    """
    text = raw.strip()
    if not text:
        raise DecisionNormalizationError("model output is empty")
    candidates: list[str] = []
    fenced = _extract_fenced(text)
    if fenced is not None:
        candidates.append(fenced)
    candidates.append(text)
    last_error: Exception | None = None
    for candidate in candidates:
        value, error = _first_json_object(candidate)
        if value is not None:
            return value
        last_error = error
    raise DecisionNormalizationError(f"no JSON decision object found ({last_error})")


def decision_fingerprint(value: dict[str, Any] | None, *, raw: str | None = None) -> str:
    """Stable canonical fingerprint for duplicate / no-progress detection."""
    if value is not None:
        canonical = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        return f"sha256:{digest}"
    digest = hashlib.sha256((raw or "").strip().encode("utf-8")).hexdigest()
    return f"raw:{digest}"


def _extract_fenced(text: str) -> str | None:
    lines = text.splitlines()
    if not lines or not lines[0].strip().startswith("```"):
        return None
    body: list[str] = []
    for line in lines[1:]:
        stripped = line.strip()
        if stripped.startswith("```"):
            return "\n".join(body)
        body.append(line)
    return None


def _first_json_object(text: str) -> tuple[dict[str, Any] | None, Exception | None]:
    decoder = json.JSONDecoder()
    try:
        value, _end = decoder.raw_decode(text)
        if isinstance(value, dict):
            return value, None
    except json.JSONDecodeError as exc:
        last_error: Exception | None = exc
    else:
        last_error = None
    index = text.find("{")
    while index != -1:
        try:
            value, _end = decoder.raw_decode(text[index:])
            if isinstance(value, dict):
                return value, None
        except json.JSONDecodeError as exc:
            last_error = exc
        index = text.find("{", index + 1)
    return None, last_error
