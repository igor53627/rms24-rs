#!/usr/bin/env bash
set -euo pipefail

DATA_ROOT=${DATA_ROOT:-/data/rms24}
RUN_ID=${RUN_ID:-"$(date +%Y%m%d_%H%M%S)_$(git rev-parse --short HEAD)"}
RUN_DIR="$DATA_ROOT/runs/$RUN_ID"

mkdir -p "$RUN_DIR"

echo "run_id=$RUN_ID" | tee "$RUN_DIR/env.txt"
# TODO: add env capture, dataset download, server/client runs
