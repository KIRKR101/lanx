//! Manifest construction: walks the user's paths, computes per-chunk BLAKE3
//! hashes, and produces a stable `FileId` per entry.

use crate::hashing::chunk_hashes;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use thiserror::Error;

pub type FileId = u32;

/// Default chunk size when the user doesn't override.
pub const DEFAULT_CHUNK_SIZE: u32 = 1024 * 1024;

/// Maximum allowed chunk size to prevent excessive memory allocation.
pub const MAX_CHUNK_SIZE: u32 = 32 * 1024 * 1024; // 32 MiB

/// Maximum number of files allowed in a manifest to prevent `DoS` via
/// resource exhaustion on the receiver.
pub const MAX_MANIFEST_FILES: usize = 100_000;

/// Convert a wire-form `rel_path` (forward-slash separated) back into a
/// platform-native `PathBuf`.
///
/// Splitting on `/` and pushing each component is portable: on Windows,
/// the resulting `PathBuf` uses `\`; on Unix, it uses `/`. Either way,
/// `Path::join` on the receiver side won't get confused by embedded
/// separators that came from a different platform.
#[must_use]
pub fn rel_to_path(rel: &str) -> PathBuf {
    let mut out = PathBuf::new();
    for component in rel.split('/') {
        if component.is_empty() {
            continue;
        }
        // Reject path-traversal components. A malicious sender could
        // craft rel_path with ".." to write files outside the
        // destination directory.
        if component == "." || component == ".." {
            continue;
        }
        out.push(component);
    }
    out
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileEntry {
    pub id: FileId,
    /// Path of the file relative to the manifest's `source_root`, in a
    /// **forward-slash-delimited** wire form. Use `rel_to_path` to get
    /// a platform-native `PathBuf` for filesystem operations. The
    /// forward-slash form is stable across platforms, so a manifest
    /// built on Unix produces identical bytes (and identical tree
    /// shapes on disk) when consumed on Windows and vice versa.
    pub rel_path: String,
    pub size: u64,
    pub chunk_size: u32,
    pub chunk_hashes: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    pub files: Vec<FileEntry>,
    pub chunk_size: u32,
    /// Canonicalized common ancestor of the input paths. Not serialized
    /// over the wire (`#[serde(skip)]`) — this field is sender-local only
    /// and will be an empty `PathBuf` on the receiver. Used by the sender
    /// to reconstruct the original source paths from `rel_path` entries
    /// regardless of how the user originally spelled them.
    #[serde(skip)]
    pub source_root: PathBuf,
}

#[derive(Debug, Error)]
pub enum ManifestError {
    #[error("path does not exist: {0}")]
    NotFound(PathBuf),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("hashing error: {0}")]
    Hash(#[from] crate::hashing::HashError),
    #[error("no input files resolved from the given paths")]
    Empty,
    #[error("chunk_size {0} exceeds maximum {1}")]
    ChunkSizeTooLarge(u32, u32),
    #[error("manifest has {0} files, maximum is {1}")]
    TooManyFiles(usize, usize),
}

/// Build a manifest from a list of user-supplied paths (files and/or dirs).
/// Symlinks and special files are skipped with a warning via `tracing::warn`.
///
/// When `inputs` is exactly one entry that is a directory, that directory's
/// name is preserved as the first component of every `rel_path` and
/// `source_root` is set to the directory's *parent*. This means a receiver
/// will create a folder with the directory's name rather than dumping its
/// contents into the destination. For all other input shapes, behavior is
/// unchanged.
///
/// # Errors
///
/// Returns `ManifestError::Empty` if no input files are resolved,
/// `ManifestError::NotFound` if an input path does not exist,
/// `ManifestError::ChunkSizeTooLarge` if `chunk_size` is zero or exceeds
/// `MAX_CHUNK_SIZE`, `ManifestError::TooManyFiles` if the resolved file
/// count exceeds `MAX_MANIFEST_FILES`, or `ManifestError::Io` for other
/// I/O failures.
pub fn build(inputs: &[PathBuf], chunk_size: u32) -> Result<Manifest, ManifestError> {
    build_inner(inputs, chunk_size, true)
}

fn build_inner(
    inputs: &[PathBuf],
    chunk_size: u32,
    preserve_single_input_root: bool,
) -> Result<Manifest, ManifestError> {
    if inputs.is_empty() {
        return Err(ManifestError::Empty);
    }
    if chunk_size == 0 || chunk_size > MAX_CHUNK_SIZE {
        return Err(ManifestError::ChunkSizeTooLarge(chunk_size, MAX_CHUNK_SIZE));
    }

    // Detect the "single input" case: one input, that input is a file or
    // directory. In both cases we want the rel_path to be just the input's
    // basename (e.g. "myrepo.zip" or "myrepo/...") so the receiver places
    // the result at a sensible location. Without this, a single file's
    // rel_path would be empty (because the canonicalized file path equals
    // the canonicalized common root), which breaks destination resolution.
    // Symlinks are explicitly excluded: they are skipped elsewhere, and
    // the single-input fast path must not accidentally follow them.
    let single_meta: Option<std::fs::Metadata> = if preserve_single_input_root && inputs.len() == 1
    {
        Some(std::fs::symlink_metadata(&inputs[0])?)
    } else {
        None
    };
    if let Some(ref m) = single_meta {
        if m.file_type().is_symlink() {
            tracing::warn!(path = %inputs[0].display(), "skipping symlink");
            return Err(ManifestError::Empty);
        }
    }
    let single_input_basename: Option<String> = if single_meta.is_some() {
        inputs[0]
            .file_name()
            .and_then(|n| n.to_str())
            .map(String::from)
    } else {
        None
    };
    let single_input_is_dir: bool = single_meta.is_some_and(|m| m.is_dir());

    // Compute the common root. If we're preserving a single input's root,
    // the common root becomes the parent of that input.
    let common = if single_input_basename.is_some() {
        let only = std::fs::canonicalize(&inputs[0])?;
        if let Some(parent) = only.parent() {
            parent.to_path_buf()
        } else {
            only
        }
    } else {
        compute_common_root(inputs)?
    };

    // (abs, rel) where rel is forward-slash form.
    let mut sources: Vec<(PathBuf, String)> = Vec::new();
    if let Some(ref basename) = single_input_basename {
        if single_input_is_dir {
            // Walk the input directory, generating rel_paths that begin
            // with the directory's basename.
            let only = &inputs[0];
            walk_dir_with_prefix(only, basename, &mut sources)?;
        } else {
            // Single file: rel_path is just the file's basename.
            sources.push((inputs[0].clone(), basename.clone()));
        }
    } else {
        collect_files(inputs, &common, &mut sources)?;
    }

    if sources.is_empty() {
        return Err(ManifestError::Empty);
    }

    if sources.len() > MAX_MANIFEST_FILES {
        return Err(ManifestError::TooManyFiles(
            sources.len(),
            MAX_MANIFEST_FILES,
        ));
    }

    let mut files = Vec::with_capacity(sources.len());
    for (id, (abs, rel)) in sources.into_iter().enumerate() {
        let meta = std::fs::symlink_metadata(&abs)?;
        if !meta.file_type().is_file() {
            tracing::warn!(path = %abs.display(), "skipping non-regular file");
            continue;
        }
        let size = meta.len();
        let chunk_hashes = if size == 0 {
            Vec::new()
        } else {
            chunk_hashes(&abs, chunk_size)?
        };
        // `sources.len()` is bounded by `MAX_MANIFEST_FILES`, which fits in `FileId`.
        #[allow(clippy::cast_possible_truncation)]
        files.push(FileEntry {
            id: id as FileId,
            rel_path: rel,
            size,
            chunk_size,
            chunk_hashes,
        });
    }
    files.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
    // Re-id after sort so FileId matches sorted order, and remains stable
    // for resume (rebuilds will produce identical ordering).
    for (i, f) in files.iter_mut().enumerate() {
        // Same bounded-count guarantee as above.
        #[allow(clippy::cast_possible_truncation)]
        {
            f.id = i as FileId;
        }
    }
    Ok(Manifest {
        files,
        chunk_size,
        source_root: common,
    })
}

fn collect_files(
    inputs: &[PathBuf],
    common: &Path,
    out: &mut Vec<(PathBuf, String)>,
) -> Result<(), ManifestError> {
    for p in inputs {
        let meta = match std::fs::symlink_metadata(p) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(ManifestError::NotFound(p.clone()));
            }
            Err(e) => return Err(ManifestError::Io(e)),
        };
        if meta.file_type().is_symlink() {
            tracing::warn!(path = %p.display(), "skipping symlink");
            continue;
        }
        if meta.is_file() {
            let rel = rel_from(common, p);
            out.push((p.clone(), rel));
        } else if meta.is_dir() {
            walk_dir(p, common, out)?;
        } else {
            tracing::warn!(path = %p.display(), "skipping special file");
        }
    }
    Ok(())
}

fn walk_dir(
    dir: &Path,
    common: &Path,
    out: &mut Vec<(PathBuf, String)>,
) -> Result<(), ManifestError> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let meta = match std::fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "skipping");
                continue;
            }
        };
        if meta.file_type().is_symlink() {
            tracing::warn!(path = %path.display(), "skipping symlink");
            continue;
        }
        if meta.is_file() {
            out.push((path.clone(), rel_from(common, &path)));
        } else if meta.is_dir() {
            walk_dir(&path, common, out)?;
        } else {
            tracing::warn!(path = %path.display(), "skipping special file");
        }
    }
    Ok(())
}

/// Like `walk_dir`, but every `rel_path` is prefixed with `archive_prefix`
/// (e.g. the input directory's basename) so the receiver reconstructs
/// files at `<out>/<archive_prefix>/<...>`. The prefix is forward-slash
/// form; the resulting `rel_path` is also forward-slash form.
fn walk_dir_with_prefix(
    dir: &Path,
    archive_prefix: &str,
    out: &mut Vec<(PathBuf, String)>,
) -> Result<(), ManifestError> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let meta = match std::fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "skipping");
                continue;
            }
        };
        if meta.file_type().is_symlink() {
            tracing::warn!(path = %path.display(), "skipping symlink");
            continue;
        }
        let Some(file_name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let child_prefix = format!("{archive_prefix}/{file_name}");
        if meta.is_file() {
            out.push((path.clone(), child_prefix));
        } else if meta.is_dir() {
            walk_dir_with_prefix(&path, &child_prefix, out)?;
        } else {
            tracing::warn!(path = %path.display(), "skipping special file");
        }
    }
    Ok(())
}

/// Build a forward-slash-delimited `rel_path` from `common` to `abs`.
/// `common` is a canonicalized prefix; `abs` may or may not be. The
/// result has platform-portable separators (always `/`).
fn rel_from(common: &Path, abs: &Path) -> String {
    let stripped = if let Ok(p) = abs.strip_prefix(common) {
        p.to_path_buf()
    } else if let Ok(canon) = std::fs::canonicalize(abs) {
        if let Ok(p) = canon.strip_prefix(common) {
            p.to_path_buf()
        } else {
            // Fallback: try the file name. Path::components treats
            // both `/` and `\` as separators on Windows, which is
            // exactly what we want for the fallback path.
            tracing::warn!(
                abs = %abs.display(),
                common = %common.display(),
                "strip_prefix failed after canonicalize; using file name fallback"
            );
            abs.file_name()
                .map_or_else(|| abs.to_path_buf(), PathBuf::from)
        }
    } else {
        tracing::warn!(
            path = %abs.display(),
            "canonicalize failed; using file name fallback"
        );
        abs.file_name()
            .map_or_else(|| abs.to_path_buf(), PathBuf::from)
    };
    pathbuf_to_rel_string(&stripped)
}

/// Convert a `PathBuf` to a forward-slash-delimited string. Preserves
/// the multi-component structure (e.g. `sub/b.bin`) but uses `/` as
/// the separator regardless of platform. Returns an empty string for
/// an empty path.
fn pathbuf_to_rel_string(p: &Path) -> String {
    p.components()
        .filter_map(|c| match c {
            std::path::Component::Normal(s) => s.to_str(),
            std::path::Component::CurDir => Some("."),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// Compute a common ancestor directory for the input paths so relative
/// paths in the manifest are stable and unambiguous.
fn compute_common_root(inputs: &[PathBuf]) -> Result<PathBuf, ManifestError> {
    let mut iter = inputs.iter();
    let first = iter.next().expect("non-empty");
    let mut common = std::fs::canonicalize(first)?;
    for p in iter {
        let abs = std::fs::canonicalize(p)?;
        common = longest_common_prefix(&common, &abs);
    }
    Ok(common)
}

fn longest_common_prefix(a: &Path, b: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for (ca, cb) in a.components().zip(b.components()) {
        if ca == cb {
            out.push(ca.as_os_str());
        } else {
            break;
        }
    }
    if out.as_os_str().is_empty() {
        // Files at different roots (e.g. /a and /b): fall back to the first
        // path's parent so rel_path still works.
        a.parent()
            .map_or_else(|| a.to_path_buf(), |p| p.to_path_buf())
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use std::io::Write;

    #[test]
    fn single_file_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("hello.txt");
        let mut f = File::create(&p).unwrap();
        f.write_all(b"hello world").unwrap();
        let m = build(&[p], 1024).unwrap();
        assert_eq!(m.files.len(), 1);
        assert_eq!(m.files[0].size, 11);
        assert_eq!(m.files[0].chunk_hashes.len(), 1);
        // Single-file rel_path should be the file's basename (not empty,
        // not the full canonicalized path).
        assert_eq!(m.files[0].rel_path, "hello.txt");
    }

    #[test]
    fn directory_walk_preserves_rel_path() {
        // Single-directory input: the directory's name should appear as the
        // first component of every rel_path so a receiver reconstructs a
        // folder with the same name.
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("sub");
        fs::create_dir(&sub).unwrap();
        let a = sub.join("a.bin");
        let b = dir.path().join("b.bin");
        File::create(&a).unwrap().write_all(b"a").unwrap();
        File::create(&b).unwrap().write_all(b"bb").unwrap();
        let m = build(&[dir.path().to_path_buf()], 1024).unwrap();
        let dir_name = dir.path().file_name().unwrap().to_str().unwrap();
        let paths: Vec<_> = m.files.iter().map(|f| f.rel_path.clone()).collect();
        assert!(
            paths
                .iter()
                .any(|p| p.starts_with(dir_name) && p.ends_with("b.bin")),
            "expected rel_path to start with the directory name and end with b.bin, got {paths:?}"
        );
        assert!(
            paths
                .iter()
                .any(|p| p.starts_with(dir_name) && p.ends_with("sub/a.bin")),
            "expected rel_path to start with the directory name and end with sub/a.bin, got {paths:?}"
        );
        // All rel_paths must use forward slashes only — no backslashes,
        // even on Windows, so the wire format is cross-platform.
        for p in &paths {
            assert!(
                !p.contains('\\'),
                "rel_path must use forward slashes only, got {p:?}"
            );
        }
        // source_root should be the parent of the input directory.
        assert_eq!(
            m.source_root,
            dir.path().parent().unwrap().canonicalize().unwrap()
        );
    }

    #[test]
    fn directory_name_with_space_preserved() {
        // Regression: on Windows, a folder name with a space used to
        // produce rel_paths with backslashes, which the receiver's
        // Path::join then re-tokenized into extra components. Verify
        // the manifest is forward-slash only and round-trips cleanly.
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("Piete de Hooch");
        fs::create_dir(&src).unwrap();
        let sub = src.join("figures");
        fs::create_dir(&sub).unwrap();
        File::create(src.join("readme.txt"))
            .unwrap()
            .write_all(b"r")
            .unwrap();
        File::create(sub.join("fig5.jpg"))
            .unwrap()
            .write_all(b"j")
            .unwrap();
        let m = build(std::slice::from_ref(&src), 1024).unwrap();
        let paths: Vec<_> = m.files.iter().map(|f| f.rel_path.clone()).collect();
        // All rel_paths must start with the (space-containing) folder
        // name and use forward slashes only.
        for p in &paths {
            assert!(
                p.starts_with("Piete de Hooch/"),
                "rel_path must start with folder name, got {p:?}"
            );
            assert!(
                !p.contains('\\'),
                "rel_path must use forward slashes only, got {p:?}"
            );
        }
        assert!(paths.contains(&"Piete de Hooch/readme.txt".to_string()));
        assert!(paths.contains(&"Piete de Hooch/figures/fig5.jpg".to_string()));
    }

    #[test]
    fn multi_input_does_not_preserve_root() {
        // Two inputs (a file and a directory): no root is preserved, since
        // there's no obvious "container" name. The rel_paths reflect each
        // input's relationship to the common root, with no extra
        // top-level directory injected.
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("a.txt");
        File::create(&f).unwrap().write_all(b"hi").unwrap();
        let d = dir.path().join("sub");
        fs::create_dir(&d).unwrap();
        File::create(d.join("x.bin"))
            .unwrap()
            .write_all(b"x")
            .unwrap();
        let m = build(&[f.clone(), d], 1024).unwrap();
        let paths: Vec<_> = m.files.iter().map(|f| f.rel_path.clone()).collect();
        // The file shows up under its own name.
        assert!(paths.contains(&"a.txt".to_string()));
        // The directory's file shows up under sub/x.bin, NOT under any
        // wrapper directory.
        assert!(
            paths.contains(&"sub/x.bin".to_string()),
            "expected sub/x.bin, got {paths:?}"
        );
        // None of the paths should start with the directory's own name
        // (the tempdir's basename) — that would indicate we incorrectly
        // preserved a root.
        let dir_name = dir.path().file_name().unwrap().to_str().unwrap();
        for p in &paths {
            assert!(
                !p.starts_with(dir_name),
                "rel_path unexpectedly preserves the input directory: {p:?}"
            );
        }
    }

    #[test]
    fn symlinks_are_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("real.txt");
        File::create(&target).unwrap().write_all(b"hi").unwrap();
        let link = dir.path().join("link.txt");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &link).unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_file(&target, &link).unwrap();
        let m = build(&[dir.path().to_path_buf()], 1024).unwrap();
        let rels: Vec<_> = m.files.iter().map(|f| f.rel_path.clone()).collect();
        assert!(rels.iter().any(|p| p.ends_with("real.txt")));
        assert!(!rels.iter().any(|p| p.ends_with("link.txt")));
    }

    #[test]
    fn single_symlink_input_is_skipped() {
        // The single-input fast path used to call `symlink_metadata` and
        // then `canonicalize`, which followed a symlink-to-file. Ensure
        // a lone symlink input is treated as empty.
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("real.txt");
        File::create(&target).unwrap().write_all(b"hi").unwrap();
        let link = dir.path().join("link.txt");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &link).unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_file(&target, &link).unwrap();
        let r = build(std::slice::from_ref(&link), 1024);
        assert!(matches!(r, Err(ManifestError::Empty)));
    }

    #[test]
    fn empty_input_is_error() {
        let r = build(&[], 1024);
        assert!(matches!(r, Err(ManifestError::Empty)));
    }

    #[test]
    fn rel_to_path_round_trips() {
        // Forward-slash form → platform-native PathBuf. Splits on `/`
        // and pushes each component so the result is correct on every
        // platform.
        let p = rel_to_path("Piete de Hooch/figures/fig5.jpg");
        let parts: Vec<_> = p
            .components()
            .filter_map(|c| match c {
                std::path::Component::Normal(s) => s.to_str(),
                _ => None,
            })
            .collect();
        assert_eq!(
            parts,
            vec!["Piete de Hooch", "figures", "fig5.jpg"],
            "rel_to_path must preserve all components without re-tokenizing on backslashes, got {p:?}"
        );
    }
}
