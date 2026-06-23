//! Transport layer: TCP listener helpers, target resolution, optional
//! UDP-broadcast discovery + pairing codes.
//!
//! The wire-format framing for control messages lives in
//! `lanx_core::transfer` — `lanx-net` does not redefine it.

pub mod discovery;
pub mod interfaces;
pub mod tcp;
pub mod pairing;

pub use pairing::{resolve_target, Target};
pub use tcp::{GracefulListener, listen, pick_port};
pub use discovery::{generate_code, code_to_hash, DiscoveryHandle};
