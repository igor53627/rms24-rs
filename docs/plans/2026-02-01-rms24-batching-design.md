# RMS24/KeywordPIR Online Batching Design (2026-02-01)

## Goal

Reduce per-query framing overhead in the online protocol by batching queries, while keeping correctness, ordering, and compatibility with existing single-query paths.

## Scope

- Online protocol framing and core API changes only.
- RMS24/KeywordPIR query logic is unchanged.
- Raw-TCP framed transport remains the reference implementation.
- Batching is opt-in; default behavior remains one query per frame.

## Design Overview

- Add batched request/response frames:
  - `BatchRequest { queries: Vec<Query> }`
  - `BatchReply { replies: Vec<Reply> }`
- Use a **count-based cap** for v1 (`max_batch_queries`) to keep tests deterministic and memory bounded.
- Preserve request/response symmetry: one batch in, one batch out.
- Replies are returned in the same order as the input queries.

## Protocol & Data Flow

1) Client connects and sends `RunConfig` (mode + params + batching configuration).
2) Server initializes per-connection state.
3) Client sends either:
   - `Query` frames (non-batched), or
   - `BatchRequest` frames with up to `max_batch_queries` items.
4) Server replies with:
   - `Reply` for single queries, or
   - `BatchReply` with the same number of replies in order.
5) EOF ends the session.

### Client Flow (batched)

- Accumulate up to `batch_size` queries in a buffer.
- Send one `BatchRequest`.
- Receive one `BatchReply` and map replies by index.
- A batch size of 1 is semantically identical to the existing path.

### Server Flow (batched)

- Validate `queries.len() <= max_batch_queries`.
- Process each query sequentially, collecting replies.
- Send a single `BatchReply`.

## API & Config Changes

### Core Types

- Extend framed message enums:
  - `ClientFrame::Query(Query)`
  - `ClientFrame::BatchRequest(BatchRequest)`
  - `ServerFrame::Reply(Reply)`
  - `ServerFrame::BatchReply(BatchReply)`

### RunConfig

- Add batching fields:
  - `batch_size: u32`
  - `max_batch_queries: u32`

### CLI

- `rms24_client`: add `--batch-size N` (default `1`).
- `rms24_server`: add `--max-batch-queries N` (default `1`).

## Error Handling & Compatibility

- Batching is opt-in; single-query path remains default and unchanged.
- If server receives a `BatchRequest` when batching is disabled, return a protocol error and close.
- If `queries.len() > max_batch_queries`, return a protocol error and close.
- If an individual query fails in a batch, return `Reply::Error` for that entry and continue.
- Serialization failures are treated as frame-level errors and terminate the connection.

## Instrumentation

When timing flags are enabled, log per-batch size and elapsed time (client and server) to align with existing timing output.

## Testing Plan

1) **Serialization round-trip** for `BatchRequest` and `BatchReply`.
2) **Order preservation**: replies correspond to queries by index.
3) **Error isolation**: failing query yields `Reply::Error` while others succeed.
4) **Max-batch enforcement**: oversized batch yields protocol error.
5) **Compat path**: existing single-query tests pass unchanged.
6) **Integration (gated)**: with `RMS24_DATA_DIR`, compare batch vs single-query outputs on the slice.

## Benchmarks

- Compare `N` single queries vs `N` batched queries.
- Report throughput and per-query latency for batch sizes: 1, 4, 8, 16.
- Run both RMS24 and KeywordPIR modes on the same dataset.

## Follow-ups

- Byte-size cap for batches.
- Windowed pipeline (multiple in-flight batches) if latency becomes a bottleneck.
- Optional per-query IDs for advanced routing or out-of-order replies.
