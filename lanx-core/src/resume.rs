//! Resume planning. Given the manifest and a destinations map, compute
//! the byte offset from which each file should resume (or mark it complete
//! and skipped).

use crate::destinations::Destinations;
use crate::manifest::{FileEntry, FileId, Manifest};
use std::collections::HashMap;
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
    /// `complete[id] = true` means the file already exists locally with
    /// matching content — receiver will skip without contacting the sender
    /// for that file. The sender still walks the manifest and sends an
    /// empty `FileStart` (or we just don't put it in `accepted`).
    pub complete: HashMap<FileId, ()>,
}

#[derive(Debug, Error)]
pub enum ResumeError {
    #[error("io error reading {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

/// Decide what to ask the sender for. Pure: the on-disk files are read but
/// not modified.
pub fn plan(manifest: &Manifest, dests: &Destinations) -> Result<ResumePlan, ResumeError> {
    let mut accepted = Vec::with_capacity(manifest.files.len());
    let mut offsets = HashMap::new();
    let mut complete = HashMap::new();

    for entry in &manifest.files {
        let path = dests
            .paths
            .get(&entry.id)
            .expect("destination missing for manifest entry");
        let (offset, done) = compute_resume_point(entry, path)?;
        if done {
            complete.insert(entry.id, ());
        } else {
            accepted.push(entry.id);
            offsets.insert(entry.id, offset);
        }
    }
    Ok(ResumePlan {
        accepted,
        offsets,
        complete,
    })
}

fn compute_resume_point(entry: &FileEntry, dest: &Path) -> Result<(u64, bool), ResumeError> {
    let meta = match std::fs::symlink_metadata(dest) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((0, false)),
        Err(e) => {
            return Err(ResumeError::Io {
                path: dest.display().to_string(),
                source: e,
            })
        }
    };
    if !meta.is_file() {
        return Ok((0, false));
    }
    let size = meta.len();
    if size == entry.size && entry.chunk_hashes.is_empty() {
        return Ok((0, true));
    }

    // Walk chunks; for each chunk:
    //   - if it fits in remaining bytes: hash, compare, advance.
    //   - if it doesn't: this is the resume chunk — its byte offset is the resume point.
    //   - if hashes mismatch: this is the resume point.
    let cs = entry.chunk_size as u64;
    let file = File::open(dest).map_err(|e| ResumeError::Io {
        path: dest.display().to_string(),
        source: e,
    })?;
    let mut reader = BufReader::with_capacity(entry.chunk_size as usize, file);
    let mut buf = vec![0u8; entry.chunk_size as usize];
    let mut bytes_read: u64 = 0;
    for expected in &entry.chunk_hashes {
        if bytes_read >= entry.size {
            // Manifest has no more chunks to verify.
            break;
        }
        // Hash window is determined by the manifest's file size, not the
        // partial file's size. If the partial is shorter than `bytes_read +
        // want`, the read below will return fewer bytes and we'll fall
        // into the "truncated" branch.
        let want = std::cmp::min(cs, entry.size - bytes_read) as usize;
        let n = read_fully(&mut reader, &mut buf[..want]).map_err(|e| ResumeError::Io {
            path: dest.display().to_string(),
            source: e,
        })?;
        if n < want {
            // Partial file is shorter than this chunk — resume from the
            // actual file EOF.
            return Ok((bytes_read + n as u64, false));
        }
        let actual = blake3::hash(&buf[..want]);
        if actual.as_bytes() != expected {
            return Ok((bytes_read, false));
        }
        bytes_read += n as u64;
    }
    if bytes_read == entry.size && size == entry.size {
        Ok((0, true))
    } else {
        Ok((bytes_read, false))
    }
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
        assert!(!plan.complete.contains_key(&0));
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
        assert!(plan.complete.contains_key(&0));
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
    fn truncated_file_resumes_at_eof() {
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
        assert_eq!(plan.offsets[&0], 2500);
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
        assert!(plan.complete.contains_key(&0));
    }
}
