//! Protocol-agnostic core: manifest construction, hashing, resume planning,
//! and the control-message enum shared with the transport layer.

pub mod crypto;
pub mod destinations;
pub mod hashing;
pub mod manifest;
pub mod progress;
pub mod resume;
pub mod sidecar;
pub mod transfer;

pub use destinations::{
    destination_paths, existing_conflicts, next_available_path, preview_conflicts,
    resolve_destinations, resolve_destinations_with_policy, ConflictPreview, Destinations,
    OverwritePolicy,
};
pub use hashing::{chunk_hashes, IncrementalHasher};
pub use manifest::{build, FileEntry, FileId, Manifest};
pub use progress::{NoopProgress, Progress};
pub use resume::ResumePlan;
pub use transfer::{
    receiver::{Approval, AutoAccept, ManifestApprover},
    supports_protocol_version, ControlMsg, HelloInfo, ProtocolError, PROTOCOL_VERSION,
    SUPPORTED_PROTOCOL_VERSIONS,
};
