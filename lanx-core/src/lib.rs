//! Protocol-agnostic core: manifest construction, hashing, resume planning,
//! and the control-message enum shared with the transport layer.

pub mod destinations;
pub mod hashing;
pub mod manifest;
pub mod progress;
pub mod resume;
pub mod transfer;

pub use destinations::{resolve_destinations, Destinations};
pub use hashing::{chunk_hashes, IncrementalHasher};
pub use manifest::{build, FileEntry, FileId, Manifest};
pub use progress::{NoopProgress, Progress};
pub use resume::ResumePlan;
pub use transfer::{ControlMsg, HelloInfo, ProtocolError, PROTOCOL_VERSION};
