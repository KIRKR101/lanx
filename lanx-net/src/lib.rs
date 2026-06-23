//! Transport layer: TCP listener helpers, target resolution, optional
//! UDP-broadcast discovery + pairing codes.
//!
//! The wire-format framing for control messages lives in
//! `lanx_core::transfer` — `lanx-net` does not redefine it.

pub mod discovery;
pub mod interfaces;
pub mod pairing;
pub mod tcp;

pub use discovery::{code_to_hash, generate_code, DiscoveryHandle};
pub use pairing::{resolve_target, Target};
pub use tcp::{listen, pick_port, GracefulListener};
