//! Resume planning. Given the manifest and a destinations map, compute
//! the byte offset from which each file should resume (or mark it complete
//! and skipped).

use crate::destinations::Destinations;
use crate::hashing::IncrementalHasher;
use crate::manifest::{FileEntry, FileId, Manifest};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct ResumePlan {
    /// File IDs the receiver wants from the sender (in manifest order).
    pub accepted: Vec<FileId>,
    /// `offsets[id]` = first byte the sender must transmit for that file.
    /// Files not present here are either skipped (fully present) or absent
    /// from `accepted`.
    pub offsets: HashMap<FileId, u64>,
    /// File IDs where the file already exists locally with matching
    /// content — receiver will skip without contacting the sender for
    /// that file.
    pub complete: HashSet<FileId>,
    /// Pre-built incremental hasher states at each resume point. The
    /// receiver can continue from these states without re-hashing the
    /// verified prefix, eliminating the O(offset) double-hash on resume.
    pub hashers: HashMap<FileId, IncrementalHasher>,
}

#[derive(Debug, Error)]
pub enum ResumeError {
    #[error("io error reading {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("destination missing for manifest entry {0}")]
    MissingDestination(FileId),
}

/// Decide what to ask the sender for. Pure: the on-disk files are read but
/// not modified.
///
/// # Errors
///
/// Returns `ResumeError::MissingDestination` if a manifest entry has no
/// destination path, or `ResumeError::Io` if an on-disk file cannot be
/// stat'd or read.
pub fn plan(manifest: &Manifest, dests: &Destinations) -> Result<ResumePlan, ResumeError> {
    let mut accepted = Vec::with_capacity(manifest.files.len());
    let mut offsets = HashMap::new();
    let mut complete = HashSet::new();
    let mut hashers = HashMap::new();

    for entry in &manifest.files {
        let path = dests
            .paths
            .get(&entry.id)
            .ok_or(ResumeError::MissingDestination(entry.id))?;
        let (offset, done, hasher) = compute_resume_point(entry, path)?;
        if done {
            complete.insert(entry.id);
        } else {
            accepted.push(entry.id);
            offsets.insert(entry.id, offset);
            // The hasher state is pre-built at the resume point so the
            // receiver can continue hashing without re-reading the prefix.
            // For offset == 0 (fresh start), the hasher is still useful —
            // it's empty and ready for new data.
            hashers.insert(entry.id, hasher);
        }
    }
    Ok(ResumePlan {
        accepted,
        offsets,
        complete,
        hashers,
    })
}

fn compute_resume_point(
    entry: &FileEntry,
    dest: &Path,
) -> Result<(u64, bool, IncrementalHasher), ResumeError> {
    let meta = match std::fs::symlink_metadata(dest) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok((0, false, IncrementalHasher::new()))
        }
        Err(e) => {
            return Err(ResumeError::Io {
                path: dest.display().to_string(),
                source: e,
            })
        }
    };
    if !meta.is_file() {
        return Ok((0, false, IncrementalHasher::new()));
    }
    let size = meta.len();
    if size == 0 && entry.size == 0 {
        return Ok((0, true, IncrementalHasher::new()));
    }
    if entry.chunk_hashes.is_empty() {
        // A non-empty file must have chunk hashes to verify against;
        // otherwise a malicious manifest could mark any same-sized file
        // as complete without checking its contents.
        return Ok((0, false, IncrementalHasher::new()));
    }

    // If a valid sidecar exists, trust the verified-chunk count and
    // rebuild the incremental hasher for the prefix in one read pass.
    if let Some(sidecar) = crate::sidecar::read(dest) {
        if sidecar.is_valid_for(&entry.rel_path, entry.size, entry.chunk_size, size) {
            let verified_bytes = u64::from(sidecar.verified_chunks) * u64::from(entry.chunk_size);
            let prefix_bytes = verified_bytes.min(entry.size).min(size);
            if let Some((offset, hasher)) =
                hash_prefix(dest, prefix_bytes).map_err(|e| ResumeError::Io {
                    path: dest.display().to_string(),
                    source: e,
                })?
            {
                if offset == entry.size && size == entry.size {
                    return Ok((0, true, hasher));
                }
                return Ok((offset, false, hasher));
            }
        }
    }

    // Walk chunks; for each chunk:
    //   - if it fits in remaining bytes: hash, compare, advance.
    //   - if it doesn't: this is the resume chunk — its byte offset is the resume point.
    //   - if hashes mismatch: this is the resume point.
    //
    // We also build an IncrementalHasher alongside the per-chunk
    // verification so the receiver can reuse it without re-hashing
    // the prefix.
    let cs = u64::from(entry.chunk_size);
    let file = File::open(dest).map_err(|e| ResumeError::Io {
        path: dest.display().to_string(),
        source: e,
    })?;
    let chunk_size_usize = usize::try_from(entry.chunk_size).map_err(|_| ResumeError::Io {
        path: dest.display().to_string(),
        source: std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "chunk_size does not fit in usize",
        ),
    })?;
    let mut reader = BufReader::with_capacity(chunk_size_usize, file);
    let mut buf = vec![0u8; chunk_size_usize];
    let mut bytes_read: u64 = 0;
    let mut hasher = IncrementalHasher::new();
    for expected in &entry.chunk_hashes {
        if bytes_read >= entry.size {
            // Manifest has no more chunks to verify.
            break;
        }
        // Hash window is determined by the manifest's file size, not the
        // partial file's size. If the partial is shorter than `bytes_read +
        // want`, the read below will return fewer bytes and we'll fall
        // into the "truncated" branch.
        let want_u64 = std::cmp::min(cs, entry.size - bytes_read);
        let want = usize::try_from(want_u64).map_err(|_| ResumeError::Io {
            path: dest.display().to_string(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "remaining chunk size does not fit in usize",
            ),
        })?;
        let n = read_fully(&mut reader, &mut buf[..want]).map_err(|e| ResumeError::Io {
            path: dest.display().to_string(),
            source: e,
        })?;
        if n < want {
            // Partial file is shorter than this chunk — resume from the
            // start of this chunk so the sender re-transmits the full
            // chunk. The truncated bytes are not fed into the hasher;
            // the receiver will re-receive this chunk and hash it then.
            return Ok((bytes_read, false, hasher));
        }
        let actual = blake3::hash(&buf[..want]);
        if actual.as_bytes() != expected {
            // Hash mismatch — resume from this chunk's start. The hasher
            // has already been fed all previously verified chunks.
            return Ok((bytes_read, false, hasher));
        }
        // Feed verified bytes into the incremental hasher so the receiver
        // can continue from this state without re-reading the prefix.
        hasher.update(&buf[..want]);
        let n_u64 = u64::try_from(n).map_err(|_| ResumeError::Io {
            path: dest.display().to_string(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "bytes read do not fit in u64",
            ),
        })?;
        bytes_read += n_u64;
    }
    if bytes_read == entry.size && size == entry.size {
        Ok((0, true, hasher))
    } else {
        Ok((bytes_read, false, hasher))
    }
}

/// Hash the first `prefix_bytes` of `dest` and return the resulting byte
/// offset and hasher state. Returns `None` if `prefix_bytes` is 0.
fn hash_prefix(
    dest: &Path,
    prefix_bytes: u64,
) -> std::io::Result<Option<(u64, IncrementalHasher)>> {
    if prefix_bytes == 0 {
        return Ok(None);
    }
    let file = File::open(dest)?;
    let mut reader = BufReader::new(file);
    let mut hasher = IncrementalHasher::new();
    let mut remaining = prefix_bytes;
    let mut buf = vec![0u8; 64 * 1024];
    while remaining > 0 {
        let want = usize::try_from(remaining.min(buf.len() as u64)).unwrap_or(buf.len());
        let n = read_fully(&mut reader, &mut buf[..want])?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        remaining -= u64::try_from(n).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "bytes read do not fit in u64",
            )
        })?;
    }
    let hashed = prefix_bytes - remaining;
    Ok(Some((hashed, hasher)))
}

fn read_fully<R: Read>(r: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        let n = r.read(&mut buf[total..])?;
        if n == 0 {
            break;
        }
        total += n;
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::destinations::resolve_destinations;
    use crate::manifest::build;
    use std::fs::{self, File};
    use std::io::Write;

    fn write(path: &Path, data: &[u8]) {
        if let Some(p) = path.parent() {
            fs::create_dir_all(p).unwrap();
        }
        File::create(path).unwrap().write_all(data).unwrap();
    }

    #[test]
    fn missing_file_resumes_from_zero() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        let dst = dir.path().join("dst");
        fs::create_dir(&src).unwrap();
        let f = src.join("a.bin");
        File::create(&f)
            .unwrap()
            .write_all(&vec![1u8; 5000])
            .unwrap();
        let m = build(std::slice::from_ref(&src), 1024).unwrap();
        let d = resolve_destinations(&m, &dst).unwrap();
        let plan = plan(&m, &d).unwrap();
        assert_eq!(plan.offsets[&0], 0);
        assert!(!plan.complete.contains(&0));
    }

    #[test]
    fn full_match_marked_complete() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        let dst = dir.path().join("dst");
        fs::create_dir(&src).unwrap();
        let f = src.join("a.bin");
        let data = vec![7u8; 5000];
        File::create(&f).unwrap().write_all(&data).unwrap();
        let m = build(std::slice::from_ref(&src), 1024).unwrap();
        let d = resolve_destinations(&m, &dst).unwrap();
        let p = d.paths[&0].clone();
        write(&p, &data);
        let plan = plan(&m, &d).unwrap();
        assert!(plan.complete.contains(&0));
        assert!(!plan.offsets.contains_key(&0));
    }

    #[test]
    fn partial_resume_offset() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        let dst = dir.path().join("dst");
        fs::create_dir(&src).unwrap();
        let f = src.join("a.bin");
        let data: Vec<u8> = (0..5000u32).map(|i| (i & 0xFF) as u8).collect();
        File::create(&f).unwrap().write_all(&data).unwrap();
        let m = build(std::slice::from_ref(&src), 1024).unwrap();
        let d = resolve_destinations(&m, &dst).unwrap();
        let p = d.paths[&0].clone();
        // Simulate partial: first 2 chunks correct, third corrupt.
        let mut partial = data[..2048].to_vec();
        partial.extend_from_slice(&vec![0xFFu8; 1024]);
        partial.extend_from_slice(&data[3072..]);
        write(&p, &partial);
        let plan = plan(&m, &d).unwrap();
        assert_eq!(plan.offsets[&0], 2048);
    }

    #[test]
    fn corrupt_first_chunk_resumes_at_zero() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        let dst = dir.path().join("dst");
        fs::create_dir(&src).unwrap();
        let f = src.join("a.bin");
        let data: Vec<u8> = (0..3000u32).map(|i| (i & 0xFF) as u8).collect();
        File::create(&f).unwrap().write_all(&data).unwrap();
        let m = build(std::slice::from_ref(&src), 1024).unwrap();
        let d = resolve_destinations(&m, &dst).unwrap();
        let p = d.paths[&0].clone();
        let bad = vec![0u8; 1024];
        let mut partial = bad;
        partial.extend_from_slice(&data[1024..]);
        write(&p, &partial);
        let plan = plan(&m, &d).unwrap();
        assert_eq!(plan.offsets[&0], 0);
    }

    #[test]
    fn truncated_file_resumes_at_chunk_start() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        let dst = dir.path().join("dst");
        fs::create_dir(&src).unwrap();
        let f = src.join("a.bin");
        let data: Vec<u8> = (0..5000u32).map(|i| (i & 0xFF) as u8).collect();
        File::create(&f).unwrap().write_all(&data).unwrap();
        let m = build(std::slice::from_ref(&src), 1024).unwrap();
        let d = resolve_destinations(&m, &dst).unwrap();
        let p = d.paths[&0].clone();
        write(&p, &data[..2500]);
        let plan = plan(&m, &d).unwrap();
        // 2500 bytes: chunks 0..1 are complete (2048 bytes), chunk 2 is
        // truncated. Resume from the start of chunk 2 (byte 2048) so the
        // full chunk is re-transmitted and verified.
        assert_eq!(plan.offsets[&0], 2048);
    }

    #[test]
    fn zero_byte_file_is_complete() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        let dst = dir.path().join("dst");
        fs::create_dir(&src).unwrap();
        let f = src.join("empty.bin");
        File::create(&f).unwrap();
        let m = build(std::slice::from_ref(&src), 1024).unwrap();
        let d = resolve_destinations(&m, &dst).unwrap();
        let p = d.paths[&0].clone();
        write(&p, &[]);
        let plan = plan(&m, &d).unwrap();
        assert!(plan.complete.contains(&0));
    }

    #[test]
    fn empty_chunk_hashes_on_non_empty_file_is_not_complete() {
        // A malicious or malformed manifest could claim a non-empty file
        // with no chunk hashes. The resume plan must not treat it as
        // complete just because the sizes match.
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        let dst = dir.path().join("dst");
        fs::create_dir(&src).unwrap();
        let f = src.join("a.bin");
        let data = vec![7u8; 5000];
        File::create(&f).unwrap().write_all(&data).unwrap();
        let mut m = build(std::slice::from_ref(&src), 1024).unwrap();
        // Strip chunk hashes without changing size.
        m.files[0].chunk_hashes.clear();
        let d = resolve_destinations(&m, &dst).unwrap();
        let p = d.paths[&0].clone();
        write(&p, &data);
        let plan = plan(&m, &d).unwrap();
        assert!(!plan.complete.contains(&0));
        assert_eq!(plan.offsets[&0], 0);
    }
}
