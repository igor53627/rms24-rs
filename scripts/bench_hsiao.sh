#!/usr/bin/env bash
set -euo pipefail

DATA_ROOT=${DATA_ROOT:-/data/rms24}
DATASET=${DATASET:-slice}
RUN_ID=${RUN_ID:-"$(date +%Y%m%d_%H%M%S)_$(git rev-parse --short HEAD)"}
RUN_DIR="$DATA_ROOT/runs/$RUN_ID"

SERVER_ADDR=${SERVER_ADDR:-"127.0.0.1:4000"}
ENTRY_SIZE=${ENTRY_SIZE:-40}
LAMBDA=${LAMBDA:-80}
SEED=${SEED:-42}
RMS24_COVERAGE_INDEX=${RMS24_COVERAGE_INDEX:-}
CACHE_DIR=${CACHE_DIR:-"$DATA_ROOT/cache"}
RMS24_STATE_PATH=${RMS24_STATE_PATH:-}

MODES_DEFAULT=("rms24")
THREADS_DEFAULT=(1 4)
QUERIES_DEFAULT=(1000 10000)

mkdir -p "$RUN_DIR"

ENV_FILE="$RUN_DIR/env.txt"
LOG_SERVER="$RUN_DIR/server.jsonl"
LOG_CLIENT="$RUN_DIR/client.jsonl"
SUMMARY="$RUN_DIR/summary.csv"
REPORT="$RUN_DIR/report.md"

now_ms() {
  date +%s%3N
}

log_json() {
  local file="$1"
  local phase="$2"
  local start_ms="$3"
  local end_ms="$4"
  local extra="$5"
  local elapsed=$((end_ms - start_ms))
  printf '{"run_id":"%s","phase":"%s","t_start":%s,"t_end":%s,"elapsed_ms":%s%s}\n' \
    "$RUN_ID" "$phase" "$start_ms" "$end_ms" "$elapsed" "$extra" >> "$file"
}

write_env() {
  {
    echo "run_id=$RUN_ID"
    echo "dataset=$DATASET"
    echo "git_rev=$(git rev-parse HEAD)"
    echo "server_addr=$SERVER_ADDR"
    echo "entry_size=$ENTRY_SIZE"
    echo "lambda=$LAMBDA"
    echo "seed=$SEED"
    echo "data_root=$DATA_ROOT"
    echo "coverage_index=$RMS24_COVERAGE_INDEX"
    echo "state_path=$STATE_PATH"
    echo "timestamp_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  } | tee "$ENV_FILE"
}

download_dataset() {
  local base_url="$1"
  local data_dir="$2"
  shift 2
  local files=("$@")

  mkdir -p "$data_dir"
  for f in "${files[@]}"; do
    local dest="$data_dir/$f"
    if [[ -f "$dest" ]]; then
      continue
    fi
    echo "downloading $f..."
    curl -L --fail --retry 3 --retry-delay 2 -o "$dest" "$base_url/$f"
  done
}

case "$DATASET" in
  slice)
    DATA_BASE_URL="https://pir.53627.org/mainnet-v3-slice-1m-mixed"
    DATA_DIR="$DATA_ROOT/slice-1m"
    DATA_FILES=("database.bin" "account-mapping.bin" "storage-mapping.bin" "metadata.json")
    if [[ -z "$RMS24_COVERAGE_INDEX" ]]; then
      RMS24_COVERAGE_INDEX=1
    fi
    ;;
  full)
    DATA_BASE_URL="https://pir.53627.org/mainnet-pir-data-v3"
    DATA_DIR="$DATA_ROOT/full"
    DATA_FILES=("database.bin" "account-mapping.bin" "storage-mapping.bin" "code_store.bin" "manifest.json" "metadata.json")
    if [[ -z "$RMS24_COVERAGE_INDEX" ]]; then
      RMS24_COVERAGE_INDEX=0
    fi
    ;;
  *)
    echo "unknown DATASET=$DATASET (expected slice or full)" >&2
    exit 1
    ;;
esac

mkdir -p "$CACHE_DIR"
STATE_PATH=${RMS24_STATE_PATH:-"$CACHE_DIR/hints_${DATASET}_entry${ENTRY_SIZE}_lambda${LAMBDA}_seed${SEED}.bin"}
STATE_STATUS="unknown"
if [[ -f "$STATE_PATH" ]]; then
  STATE_STATUS="hit"
else
  STATE_STATUS="miss"
fi

write_env

start_download=$(now_ms)
download_dataset "$DATA_BASE_URL" "$DATA_DIR" "${DATA_FILES[@]}"
end_download=$(now_ms)
log_json "$LOG_SERVER" "download" "$start_download" "$end_download" ",\"dataset\":\"$DATASET\""

start_sha=$(now_ms)
sha256sum "${DATA_FILES[@]/#/$DATA_DIR/}" > "$RUN_DIR/sha256.txt"
end_sha=$(now_ms)
log_json "$LOG_SERVER" "checksum" "$start_sha" "$end_sha" ""

start_build=$(now_ms)
cargo build --release
end_build=$(now_ms)
log_json "$LOG_SERVER" "build" "$start_build" "$end_build" ""

echo "run_id,dataset,mode,threads,query_count,elapsed_ms" > "$SUMMARY"

SERVER_LOG_RAW="$RUN_DIR/server.log"

start_server=$(now_ms)
target/release/rms24_server \
  --db "$DATA_DIR/database.bin" \
  --entry-size "$ENTRY_SIZE" \
  --lambda "$LAMBDA" \
  --listen "$SERVER_ADDR" \
  > "$SERVER_LOG_RAW" 2>&1 &
SERVER_PID=$!
sleep 1
end_server=$(now_ms)
log_json "$LOG_SERVER" "server_start" "$start_server" "$end_server" ""

cleanup() {
  if kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" || true
  fi
}
trap cleanup EXIT

MODES=("${MODES[@]:-${MODES_DEFAULT[@]}}")
THREADS=("${THREADS[@]:-${THREADS_DEFAULT[@]}}")
QUERIES=("${QUERIES[@]:-${QUERIES_DEFAULT[@]}}")

for mode in "${MODES[@]}"; do
  for threads in "${THREADS[@]}"; do
    for qc in "${QUERIES[@]}"; do
      run_log="$RUN_DIR/client_${mode}_${threads}_${qc}.log"
      start_run=$(now_ms)
      COVERAGE_FLAG=()
      if [[ "$RMS24_COVERAGE_INDEX" == "1" ]]; then
        COVERAGE_FLAG=("--coverage-index")
      fi
      target/release/rms24_client \
        --db "$DATA_DIR/database.bin" \
        --entry-size "$ENTRY_SIZE" \
        --lambda "$LAMBDA" \
        --server "$SERVER_ADDR" \
        --query-count "$qc" \
        --threads "$threads" \
        --seed "$SEED" \
        --mode "$mode" \
        --state "$STATE_PATH" \
        "${COVERAGE_FLAG[@]}" \
        > "$run_log" 2>&1
      end_run=$(now_ms)
      elapsed_ms=$(rg -o "elapsed_ms=\d+" -m 1 "$run_log" | cut -d= -f2 || echo "0")
      log_json "$LOG_CLIENT" "client_run" "$start_run" "$end_run" ",\"dataset\":\"$DATASET\",\"mode\":\"$mode\",\"threads\":$threads,\"query_count\":$qc,\"elapsed_ms_client\":$elapsed_ms"
      echo "$RUN_ID,$DATASET,$mode,$threads,$qc,$elapsed_ms" >> "$SUMMARY"
    done
  done
done

cat <<REPORT > "$REPORT"
# RMS24 Benchmark Report

run_id: $RUN_ID

dataset: $DATASET
server: $SERVER_ADDR
entry_size: $ENTRY_SIZE
lambda: $LAMBDA

state_cache_path: $STATE_PATH
state_cache_status: $STATE_STATUS

Artifacts:
- $SUMMARY
- $LOG_SERVER
- $LOG_CLIENT
- $RUN_DIR/sha256.txt
REPORT

echo "done: $RUN_DIR"
