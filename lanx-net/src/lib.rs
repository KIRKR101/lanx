//! Transport layer: TCP listener helpers, target resolution, optional
//! UDP-broadcast discovery + pairing codes.
//!
//! The wire-format framing for control messages lives in
//! `lanx_core::transfer`; `lanx-net` does not redefine it.

pub mod discovery;
pub mod interfaces;
pub mod pairing;
pub mod relay;
pub mod tcp;

pub use discovery::{
    classify_relay_target, code_entropy_bits, code_to_hash, code_to_pairing_id, code_to_psk,
    code_word_count, entropy_bits_for_words, generate_code, generate_code_with_words,
    relay_target_is_public, DiscoveryHandle, RelayVisibility, DEFAULT_CODE_WORDS, MAX_CODE_WORDS,
    MIN_CODE_WORDS,
};
pub use pairing::{resolve_target, Target};
pub use tcp::{listen_default, listen_preferred, pick_port, GracefulListener, DEFAULT_SEND_PORT};
