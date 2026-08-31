#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FB_DIR="$ROOT_DIR/third_party/fuzzingbrain"
VENV_DIR="$FB_DIR/.venv"

python3 -m venv "$VENV_DIR"
"$VENV_DIR/bin/python" -m pip install -r "$FB_DIR/requirements-test.txt"

git -C "$FB_DIR" submodule sync -- Z-VulnSentinel
git -C "$FB_DIR" submodule update --init --recursive -- Z-VulnSentinel

echo "FuzzingBrain Python: $VENV_DIR/bin/python"
echo "Start services: $ROOT_DIR/scripts/fuzzingbrain_services.sh up"
echo "Run tests: cd $FB_DIR && .venv/bin/python -m pytest -q tests"
