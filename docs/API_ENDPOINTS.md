# API Endpoints

This project does not expose HTTP API endpoints. It is a Rust library with CLI utilities under `src/bin`.

## Online protocol (raw TCP)

The online protocol uses a single raw TCP connection with length-prefixed `bincode` frames. The first frame is a `RunConfig`, followed by one or more `Query` frames, each producing a `Reply`.
