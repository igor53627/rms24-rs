//! RMS24 single-server PIR implementation.
//!
//! Based on "Simple and Practical Amortized Sublinear Private Information
//! Retrieval" (https://eprint.iacr.org/2024/1362).

pub mod bench_framing;
pub mod bench_handler;
pub mod bench_proto;
pub mod bench_timing;
pub mod client;
pub mod hints;
pub mod keyword_pir;
pub mod messages;
pub mod online;
pub mod online_client;
pub mod online_framing;
pub mod online_server;
pub mod online_transport;
pub mod params;
pub mod prf;
pub mod schema40;
pub mod server;
pub mod updates;

#[cfg(feature = "cuda")]
pub mod gpu;

pub use client::OnlineClient;
pub use params::Params;
pub use prf::Prf;
