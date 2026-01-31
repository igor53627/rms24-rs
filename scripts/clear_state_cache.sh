#!/usr/bin/env bash
set -euo pipefail

DATA_ROOT=${DATA_ROOT:-/data/rms24}
DATASET=${DATASET:-full}
ENTRY_SIZE=${ENTRY_SIZE:-40}
LAMBDA=${LAMBDA:-80}
SEED=${SEED:-42}
CACHE_DIR=${CACHE_DIR:-"$DATA_ROOT/cache"}
RMS24_STATE_PATH=${RMS24_STATE_PATH:-"$CACHE_DIR/hints_${DATASET}_entry${ENTRY_SIZE}_lambda${LAMBDA}_seed${SEED}.bin"}

if [[ -f "$RMS24_STATE_PATH" ]]; then
  rm -f "$RMS24_STATE_PATH"
  echo "removed: $RMS24_STATE_PATH"
else
  echo "missing: $RMS24_STATE_PATH"
fi
