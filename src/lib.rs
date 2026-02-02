//! RMS24 single-server PIR implementation.
//!
//! Based on "Simple and Practical Amortized Sublinear Private Information
//! Retrieval" (https://eprint.iacr.org/2024/1362).

pub mod params;
pub mod prf;
pub mod hints;
pub mod client;
pub mod schema40;
pub mod messages;
pub mod server;
pub mod updates;
pub mod online;
pub mod online_framing;
pub mod online_transport;
pub mod online_server;
pub mod online_client;
pub mod bench_proto;
pub mod bench_framing;
pub mod bench_timing;
pub mod bench_handler;

#[cfg(feature = "cuda")]
pub mod gpu;

pub use params::Params;
pub use prf::Prf;
pub use client::OnlineClient;
