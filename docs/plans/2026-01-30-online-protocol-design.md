# RMS24 + KeywordPIR Online Protocol Design

**Goal:** Provide a production online protocol path for both RMS24 and KeywordPIR with a shared transport and a sync core API, while keeping benchmarking and future async support straightforward.

**Scope:** Library-level online API (client/server core), a transport trait, and a default raw-TCP framing implementation. Binaries can be thin wrappers. No HTTP/QUIC in this phase.

## Architecture

- **Core API:** `online` module with `RunConfig`, `Query`, `Reply`, and `OnlineError`.
- **Modes:** Unified `Mode` enum (RMS24 | KeywordPIR) to route inside the core.
- **Transport:** A small trait for framed send/recv; default TCP transport uses length-prefixed `bincode` frames.
- **Server Core:** `ServerCore` owns per-connection state derived from `RunConfig` and dispatches to protocol handlers.
- **Client Core:** `ClientCore` builds queries and parses replies; no I/O.

## Protocol & Data Flow

1) Client connects, sends a `RunConfig` frame (mode + params).
2) Server initializes per-connection state.
3) Client sends multiple `Query` frames; server returns a `Reply` frame per query.
4) EOF ends the session; one-query sessions are a trivial subset.

`Query` includes a `subset` field (for RMS24) plus a mode-specific payload. RMS24 queries map to `messages::Query` and call `Server::answer`. KeywordPIR queries route to its handler.

## Error Handling

Define `OnlineError` (decode/encode, protocol mismatch, unsupported mode, server failure). Prefer sending `Reply::Error { code, message }` and then closing the connection. Keep messages short and stable; detailed logs only in server logs or debug mode.

## Testing Strategy

- Serialization roundtrip tests for `RunConfig`, `Query`, `Reply`.
- Transport loopback test for framed send/recv.
- Server routing test: RMS24 query -> `messages::Query` with subset.
- Integration tests gated by `RMS24_DATA_DIR` (uses the real slice).

## Open Questions / Follow-ups

- Whether to add async wrappers or a tokio transport in a later phase.
- Whether to expose metrics in replies or keep them in side-channel logs.
