#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$ROOT_DIR/ops/fuzzingbrain/compose.yaml"
ACTION="${1:-up}"

case "$ACTION" in
  up)
    exec docker compose -f "$COMPOSE_FILE" up -d --wait mongo redis
    ;;
  down)
    exec docker compose -f "$COMPOSE_FILE" down
    ;;
  status)
    exec docker compose -f "$COMPOSE_FILE" ps
    ;;
  *)
    echo "usage: $0 {up|down|status}" >&2
    exit 2
    ;;
esac
