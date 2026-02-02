# RMS24 + KeywordPIR Full-Scale Benchmark Design (hsiao)

**Goal:** Produce a full performance report for RMS24 and KeywordPIR on a Linux host (hsiao), with component-level tracing and reproducible runs.

**Topology (first pass):** Single host, separate client/server processes on localhost (raw TCP).

**Datasets:**
- 1M slice (regression baseline)
- Full snapshot from the links in `plinko-rs/docs/data_format.md`

**Headline metrics:**
- End-to-end query latency (p50/p95/p99)
- Throughput (QPS)
- Hint generation time
- Peak RAM usage

**Component tracing:**
Each phase emits JSONL with `run_id`, `phase`, `t_start`, `t_end`, `elapsed_ms`, `bytes_in/out`, `rss_mb`, `cpu_pct`.
Phases: dataset download → checksum → preprocessing → hint generation → server load → query batch → verify.

**Protocol:** Raw TCP, length-prefixed `bincode` frames using `serde`.

**Modes:**
- `rms24` (baseline)
- `keywordpir` (keyword lookup + RMS24 queries; trace lookup time separately)

**Client/Server binaries:**
- `rms24-server`: loads DB, serves parity replies
- `rms24-client`: generates hints, sends queries, verifies replies

**Query sizes:** 1k and 10k per dataset.

**Concurrency:** Run both single-threaded (latency) and multi-threaded (throughput) clients.

**Run order:**
1) Slice + RMS24
2) Slice + KeywordPIR
3) Full + RMS24
4) Full + KeywordPIR

**Repeats:** 3 runs each; report median + variance.

**Artifacts:**
- `/data/rms24/runs/<run_id>/env.txt`
- `/data/rms24/runs/<run_id>/server.jsonl`
- `/data/rms24/runs/<run_id>/client.jsonl`
- `/data/rms24/runs/<run_id>/summary.csv`
- `/data/rms24/runs/<run_id>/report.md`

**Orchestration:** `scripts/bench_hsiao.sh` downloads data, builds, runs server/client, collects logs, and emits report.
