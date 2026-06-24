//! Sidecar `.lanx-partial.json` for resume caching.
//!
//! The sidecar stores how many chunks of a partial file are already known
//! to be good. On the next resume we can skip the per-chunk hash checks
//! for that prefix and rebuild the incremental hasher in a single read
//! pass instead of reading chunk-by-chunk.
//!
//! The sidecar is only a hint: if it is stale or the file on disk has
//! changed, the final whole-file hash check will detect the mismatch and
//! the bad chunks will be re-fetched.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const SIDECAR_VERSION: u32 = 1;

/// A resume cache entry for a single file. Records how many chunks have
/// been verified so the next resume can skip the per-chunk re-hash.
///
/// The sidecar is only a hint: if it is stale or the file on disk has
/// changed, the final whole-file hash check will detect the mismatch.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Sidecar {
    /// Sidecar format version. Must match [`SIDECAR_VERSION`].
    pub version: u32,
    /// Relative path of the file (forward-slash form, matching the manifest).
    pub rel_path: String,
    /// Total file size in bytes as recorded in the manifest.
    pub size: u64,
    /// Chunk size used for this file (must match the manifest).
    pub chunk_size: u32,
    /// Number of chunks from the start of the file that have been verified
    /// to match their expected BLAKE3 hash. Chunks beyond this offset
    /// must be re-verified on resume.
    pub verified_chunks: u32,
}

impl Sidecar {
    /// Validate that the sidecar matches the manifest entry and the
    /// on-disk file well enough to be trusted.
    pub fn is_valid_for(&self, rel_path: &str, size: u64, chunk_size: u32, file_len: u64) -> bool {
        if self.version != SIDECAR_VERSION {
            return false;
        }
        if self.rel_path != rel_path || self.size != size || self.chunk_size != chunk_size {
            return false;
        }
        let verified_bytes = u64::from(self.verified_chunks) * u64::from(chunk_size);
        // The file must be at least as long as the sidecar claims.
        file_len >= verified_bytes.min(size)
    }
}

/// Sidecar path for a destination file.
#[must_use]
pub fn sidecar_path(dest: &Path) -> PathBuf {
    let mut p = dest.as_os_str().to_os_string();
    p.push(".lanx-partial.json");
    PathBuf::from(p)
}

/// Read a sidecar if it exists and is valid JSON. Returns `None` if the
/// file is missing, not valid JSON, or has a version mismatch.
pub fn read(dest: &Path) -> Option<Sidecar> {
    let path = sidecar_path(dest);
    let bytes = std::fs::read(&path).ok()?;
    let sidecar: Sidecar = serde_json::from_slice(&bytes).ok()?;
    // Reject sidecars with a version we don't understand.
    if sidecar.version != SIDECAR_VERSION {
        return None;
    }
    Some(sidecar)
}

/// Write a sidecar next to the destination file.
pub fn write(dest: &Path, sidecar: &Sidecar) -> std::io::Result<()> {
    let path = sidecar_path(dest);
    let json = serde_json::to_vec_pretty(sidecar)?;
    std::fs::write(path, json)
}

/// Remove the sidecar for a destination file.
pub fn remove(dest: &Path) -> std::io::Result<()> {
    let path = sidecar_path(dest);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("file.bin");
        std::fs::write(&dest, b"partial data").unwrap();

        let s = Sidecar {
            version: SIDECAR_VERSION,
            rel_path: "file.bin".to_string(),
            size: 100,
            chunk_size: 1024,
            verified_chunks: 0,
        };
        write(&dest, &s).unwrap();
        let read_back = read(&dest).unwrap();
        assert_eq!(s, read_back);

        remove(&dest).unwrap();
        assert!(read(&dest).is_none());
    }

    #[test]
    fn validation_checks_size_and_path() {
        let s = Sidecar {
            version: SIDECAR_VERSION,
            rel_path: "a.bin".to_string(),
            size: 100,
            chunk_size: 10,
            verified_chunks: 5,
        };
        assert!(s.is_valid_for("a.bin", 100, 10, 50));
        assert!(!s.is_valid_for("b.bin", 100, 10, 50));
        assert!(!s.is_valid_for("a.bin", 99, 10, 50));
        assert!(!s.is_valid_for("a.bin", 100, 11, 50));
        assert!(!s.is_valid_for("a.bin", 100, 10, 49));
    }
}
