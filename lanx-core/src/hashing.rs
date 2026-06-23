//! BLAKE3 hashing utilities.
//!
//! Sender side: compute per-chunk hashes for the manifest (parallel via rayon's
//! `update_rayon`), and an incremental whole-file hash while streaming.
//! Receiver side: incremental whole-file hash while writing, so the final
//! `FileEnd` hash check is a comparison of in-memory hasher state — no
//! extra read pass.

use blake3::Hasher;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use thiserror::Error;

pub const HASH_LEN: usize = 32;

/// Streaming whole-file hasher.
#[derive(Debug, Clone)]
pub struct IncrementalHasher {
    inner: Hasher,
    bytes: u64,
}

impl IncrementalHasher {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Hasher::new(),
            bytes: 0,
        }
    }

    pub fn update(&mut self, chunk: &[u8]) {
        self.inner.update(chunk);
        self.bytes = self.bytes.saturating_add(chunk.len() as u64);
    }

    #[must_use]
    pub fn finalize(self) -> ([u8; HASH_LEN], u64) {
        let hash = self.inner.finalize();
        let mut out = [0u8; HASH_LEN];
        out.copy_from_slice(hash.as_bytes());
        (out, self.bytes)
    }

    #[must_use]
    pub const fn bytes_seen(&self) -> u64 {
        self.bytes
    }
}

impl Default for IncrementalHasher {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Error)]
pub enum HashError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("file size overflow")]
    SizeOverflow,
}

/// Read a file in `chunk_size` pieces and return one BLAKE3 hash per chunk.
/// Empty files return an empty vec.
///
/// # Errors
///
/// Returns `HashError::Io` if the file cannot be opened or read, or if
/// `chunk_size` is zero.
pub fn chunk_hashes(path: &Path, chunk_size: u32) -> Result<Vec<[u8; HASH_LEN]>, HashError> {
    if chunk_size == 0 {
        return Err(HashError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "chunk_size must be > 0",
        )));
    }
    let file = File::open(path)?;
    let mut reader = BufReader::with_capacity(chunk_size as usize, file);
    let mut buf = vec![0u8; chunk_size as usize];
    let mut out = Vec::new();
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        let mut hasher = Hasher::new();
        hasher.update_rayon(&buf[..n]);
        let finalized = hasher.finalize();
        let mut h = [0u8; HASH_LEN];
        h.copy_from_slice(finalized.as_bytes());
        out.push(h);
        if n < buf.len() {
            break;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn empty_file_yields_no_chunks() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("empty.bin");
        File::create(&p).unwrap();
        assert!(chunk_hashes(&p, 1024).unwrap().is_empty());
    }

    #[test]
    fn exact_chunk_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.bin");
        let mut f = File::create(&p).unwrap();
        f.write_all(&vec![0xAAu8; 2048]).unwrap();
        let h = chunk_hashes(&p, 1024).unwrap();
        assert_eq!(h.len(), 2);
    }

    #[test]
    fn incremental_whole_file_matches() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("b.bin");
        let mut f = File::create(&p).unwrap();
        let data: Vec<u8> = (0..5000u32).map(|i| (i & 0xFF) as u8).collect();
        f.write_all(&data).unwrap();

        let mut h = IncrementalHasher::new();
        h.update(&data);
        let (hash, bytes) = h.finalize();
        assert_eq!(bytes, data.len() as u64);
        let mut expected = [0u8; HASH_LEN];
        expected.copy_from_slice(blake3::hash(&data).as_bytes());
        assert_eq!(hash, expected);
    }
}
