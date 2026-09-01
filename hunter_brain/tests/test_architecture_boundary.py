"""Prevent the independent global brain from coupling to backend internals."""

from __future__ import annotations

import ast
from pathlib import Path


BRAIN_ROOT = Path(__file__).resolve().parents[1]
EXPECTED_MODULES = {
    "capabilities.py",
    "completion_truth.py",
    "contract_ingress.py",
    "decisions.py",
    "handoffs.py",
    "invocation_bridge.py",
    "orchestrator.py",
    "question_generator.py",
    "result_interpreter.py",
    "state.py",
    "state_updater.py",
    "supervisor.py",
    "validator.py",
    "verifier.py",
}
FORBIDDEN_PREFIXES = (
    "autopenbench_adapter",
    "integrations",
    "pentestgpt_legacy",
    "third_party",
)


def _production_modules() -> tuple[Path, ...]:
    return tuple(
        path
        for path in sorted(BRAIN_ROOT.glob("*.py"))
        if path.name != "__init__.py"
    )


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            imported.add(node.module)
    return imported


def test_global_brain_has_an_independent_complete_module_skeleton() -> None:
    assert {path.name for path in _production_modules()} == EXPECTED_MODULES


def test_global_brain_does_not_import_professional_implementations() -> None:
    violations: dict[str, list[str]] = {}
    for path in _production_modules():
        forbidden = sorted(
            name
            for name in _imports(path)
            if name.startswith(FORBIDDEN_PREFIXES)
        )
        if forbidden:
            violations[path.name] = forbidden

    assert violations == {}


def test_global_brain_uses_only_the_public_protocol_import_surface() -> None:
    private_protocol_imports: dict[str, list[str]] = {}
    for path in _production_modules():
        private = sorted(
            name
            for name in _imports(path)
            if name.startswith("pentestgpt_agent.protocol.")
        )
        if private:
            private_protocol_imports[path.name] = private

    assert private_protocol_imports == {}
