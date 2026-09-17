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

/// Maximum allowed `rel_path` size in bytes. Keeps manifest entries
/// bounded and portable across platforms.
pub const MAX_REL_PATH_BYTES: usize = 4096;

/// Maximum allowed single path-component size in bytes. 255 is the
/// per-component limit on ext4, APFS, and NTFS alike.
pub const MAX_COMPONENT_BYTES: usize = 255;

/// Maximum number of files allowed in a manifest to prevent `DoS` via
/// resource exhaustion on the receiver.
pub const MAX_MANIFEST_FILES: usize = 100_000;

/// File-selection rules used while building a sender manifest.
#[derive(Debug, Clone, Default)]
pub struct FilterOptions {
    /// Exclude hidden path components unless explicitly requested.
    pub include_hidden: bool,
    /// Glob-like patterns matched against the forward-slash relative path.
    pub exclude: Vec<String>,
    /// When non-empty, only paths matching at least one pattern are kept.
    pub include: Vec<String>,
}

// Compile-time guarantee that MAX_MANIFEST_FILES fits in FileId (u32).
const _: () = assert!(
    MAX_MANIFEST_FILES <= u32::MAX as usize,
    "MAX_MANIFEST_FILES must fit in FileId (u32)"
);

/// Convert a wire-form `rel_path` (forward-slash separated) back into a
/// platform-native `PathBuf`.
///
/// Splitting on `/` and pushing each component is portable: on Windows,
/// the resulting `PathBuf` uses `\`; on Unix, it uses `/`. Either way,
/// `Path::join` on the receiver side won't get confused by embedded
/// separators that came from a different platform.
///
/// Callers must validate untrusted wire input with [`validate_rel_path`]
/// (or [`validate_manifest_paths`]) before calling this: it is a
/// best-effort conversion that skips empty, `.`, and `..` components
/// rather than rejecting them.
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
            tracing::warn!(
                component = component,
                "stripping path-traversal component from rel_path"
            );
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
    /// over the wire (`#[serde(skip)]`). This field is sender-local.
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
    #[error("invalid rel_path: {0}")]
    InvalidPath(String),
}

/// Validate a wire-form `rel_path` as a strict, portable relative path.
///
/// Accepts only plain `/`-separated relative paths. Rejects absolute
/// paths, Windows drive/UNC prefixes (e.g. `C:/x`, `C:rel`), backslash
/// separators, empty paths, empty components (`a//b`, leading or
/// trailing slashes), `.` and `..` components, and NUL bytes.
///
/// Portable default (same on Linux, macOS, and Windows): additionally
/// rejects Windows-reserved device names (`CON`, `PRN`, `AUX`, `NUL`,
/// `COM1`–`COM9`, `LPT1`–`LPT9`, matched case-insensitively on the name
/// stem before any `.` extension), trailing spaces or dots in any
/// component, ASCII control characters (`0x00`–`0x1F`), the Windows
/// reserved characters `<`, `>`, `:`, `"`, `|`, `?`, `*`, components
/// longer than [`MAX_COMPONENT_BYTES`] bytes, and whole paths longer
/// than [`MAX_REL_PATH_BYTES`] bytes.
///
/// Hidden files (`.gitignore`, `a/.hidden/b`) are accepted: a leading
/// dot is only rejected when it forms the whole component (`.`).
///
/// # Errors
///
/// Returns `ManifestError::InvalidPath` describing the first problem found.
pub fn validate_rel_path(rel: &str) -> Result<(), ManifestError> {
    // Truncate hostile input in errors: a rel can be 4KB of
    // attacker-controlled bytes.
    let shown: String = if rel.len() > 128 {
        format!("{:?}...", rel.chars().take(64).collect::<String>())
    } else {
        format!("{rel:?}")
    };
    if rel.is_empty() {
        return Err(ManifestError::InvalidPath("empty rel_path".to_string()));
    }
    if rel.contains('\0') {
        return Err(ManifestError::InvalidPath(format!(
            "rel_path contains NUL: {shown}"
        )));
    }
    if rel.len() > MAX_REL_PATH_BYTES {
        return Err(ManifestError::InvalidPath(format!(
            "rel_path exceeds {MAX_REL_PATH_BYTES} bytes (got {} bytes): {shown}",
            rel.len()
        )));
    }
    if rel.contains('\\') {
        return Err(ManifestError::InvalidPath(format!(
            "rel_path contains backslash: {shown}"
        )));
    }
    if rel.starts_with('/') {
        return Err(ManifestError::InvalidPath(format!(
            "rel_path is absolute: {shown}"
        )));
    }
    let bytes = rel.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return Err(ManifestError::InvalidPath(format!(
            "rel_path has a Windows drive prefix: {shown}"
        )));
    }
    for component in rel.split('/') {
        if component.is_empty() {
            return Err(ManifestError::InvalidPath(format!(
                "rel_path has an empty component: {shown}"
            )));
        }
        if component == "." {
            return Err(ManifestError::InvalidPath(format!(
                "rel_path contains '.' component: {shown}"
            )));
        }
        if component == ".." {
            return Err(ManifestError::InvalidPath(format!(
                "rel_path contains '..' component: {shown}"
            )));
        }
        if component.len() > MAX_COMPONENT_BYTES {
            return Err(ManifestError::InvalidPath(format!(
                "rel_path component exceeds {MAX_COMPONENT_BYTES} bytes (got {} bytes): {shown}",
                component.len()
            )));
        }
        if component.bytes().any(|b| b < 0x20) {
            return Err(ManifestError::InvalidPath(format!(
                "rel_path contains a control character: {shown}"
            )));
        }
        if component.contains(['<', '>', ':', '"', '|', '?', '*']) {
            return Err(ManifestError::InvalidPath(format!(
                "rel_path contains a Windows-reserved character (<>:\"|?*): {shown}"
            )));
        }
        if component.ends_with(' ') || component.ends_with('.') {
            return Err(ManifestError::InvalidPath(format!(
                "rel_path component has a trailing space or dot: {shown}"
            )));
        }
        if is_windows_reserved_stem(component) {
            return Err(ManifestError::InvalidPath(format!(
                "rel_path contains a Windows-reserved device name: {shown}"
            )));
        }
    }
    Ok(())
}

/// Check whether a single `/`-separated component uses a Windows-reserved
/// device-name stem (`CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`,
/// `LPT1`–`LPT9`), matched case-insensitively on the part before the
/// first `.` (so `CON`, `con.txt`, and `AUX.bin` are all reserved).
///
/// Windows strips trailing dots and spaces before comparing, so the stem
/// is normalized the same way: `CON .txt` aliases the device even though
/// it passes the trailing space/dot rule (it ends in `t`).
fn is_windows_reserved_stem(component: &str) -> bool {
    let stem = component
        .trim_end_matches([' ', '.'])
        .split('.')
        .next()
        .unwrap_or(component)
        .trim_end_matches([' ', '.']);
    let upper = stem.to_ascii_uppercase();
    match upper.as_str() {
        "CON" | "PRN" | "AUX" | "NUL" => true,
        _ => {
            let b = upper.as_bytes();
            if b.len() != 4 || !b[3].is_ascii_digit() || b[3] == b'0' {
                return false;
            }
            (b[0] == b'C' && b[1] == b'O' && b[2] == b'M')
                || (b[0] == b'L' && b[1] == b'P' && b[2] == b'T')
        }
    }
}

/// Validate every entry's `rel_path` in a manifest as a strict relative
/// path (see [`validate_rel_path`]), and reject exact-duplicate and
/// case-insensitive-colliding paths as well as duplicate file IDs.
///
/// Two entries that differ only by ASCII/Unicode case (`Report.txt` vs
/// `report.txt`) cannot coexist on Windows or default macOS APFS volumes;
/// they are rejected here so a Linux sender cannot silently overwrite one
/// with the other on the receiver. Duplicate IDs are rejected because
/// they index destination maps, resume offsets, and `id % parallel`
/// sharding — two entries sharing an ID would corrupt each other's
/// transfer (wire manifests are attacker-controlled).
///
/// # Errors
///
/// Returns the first `ManifestError::InvalidPath` encountered.
pub fn validate_manifest_paths(manifest: &Manifest) -> Result<(), ManifestError> {
    for f in &manifest.files {
        validate_rel_path(&f.rel_path)?;
    }
    validate_manifest_no_collisions(manifest)?;
    validate_manifest_ids(manifest)?;
    Ok(())
}

/// Reject manifests whose entries collide exactly or case-insensitively.
///
/// Comparison is on the Unicode-lowercased wire string, which catches the
/// `Report.txt`/`report.txt` class without requiring an OS-specific
/// normalization table.
///
/// # Errors
///
/// Returns `ManifestError::InvalidPath` naming both colliding entries.
pub fn validate_manifest_no_collisions(manifest: &Manifest) -> Result<(), ManifestError> {
    let rels: Vec<&str> = manifest
        .files
        .iter()
        .map(|f| f.rel_path.as_str())
        .collect();
    check_no_collisions(&rels, |_| String::new())
}

/// Reject manifests with duplicate file IDs.
///
/// IDs index destination maps, resume offsets, and `id % parallel`
/// sharding on both sides, so they must be unique. (Sparse but unique
/// IDs still route correctly, so only duplicates are rejected.)
///
/// # Errors
///
/// Returns `ManifestError::InvalidPath` naming the duplicate ID.
pub fn validate_manifest_ids(manifest: &Manifest) -> Result<(), ManifestError> {
    use std::collections::HashSet;
    let mut seen: HashSet<FileId> = HashSet::with_capacity(manifest.files.len());
    for f in &manifest.files {
        if !seen.insert(f.id) {
            return Err(ManifestError::InvalidPath(format!(
                "duplicate file id: {}",
                f.id
            )));
        }
    }
    Ok(())
}

/// Shared exact + case-insensitive collision check over wire-form rels.
///
/// `origin(i)` describes `rels[i]` for error messages (e.g. its source
/// path); pass `|_| String::new()` when there is no extra context. This
/// single implementation backs both [`validate_manifest_no_collisions`]
/// and the sender-side check in [`build`], so the two cannot drift.
fn check_no_collisions<R: AsRef<str>>(
    rels: &[R],
    origin: impl Fn(usize) -> String,
) -> Result<(), ManifestError> {
    use std::collections::{HashMap, HashSet};
    let mut exact: HashSet<&str> = HashSet::with_capacity(rels.len());
    let mut folded_first: HashMap<String, usize> = HashMap::with_capacity(rels.len());
    for (i, r) in rels.iter().enumerate() {
        let rel = r.as_ref();
        if !exact.insert(rel) {
            return Err(ManifestError::InvalidPath(format!(
                "duplicate rel_path: {rel:?}{}",
                origin(i)
            )));
        }
        let key = rel.to_lowercase();
        if let Some(&first_idx) = folded_first.get(&key) {
            let first = rels[first_idx].as_ref();
            if first != rel {
                return Err(ManifestError::InvalidPath(format!(
                    "case-insensitive rel_path collision: {first:?} vs {rel:?} (cannot coexist on Windows/macOS){}",
                    origin(i)
                )));
            }
        } else {
            folded_first.insert(key, i);
        }
    }
    Ok(())
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
/// count exceeds `MAX_MANIFEST_FILES`, `ManifestError::InvalidPath` if a
/// file name is not valid UTF-8, uses a Windows-reserved device name or
/// character, has a trailing space/dot, exceeds the component/total
/// length limits, collides exactly or case-insensitively with another
/// entry, spans multiple filesystem roots, or is a filesystem root
/// itself, or `ManifestError::Io` for other I/O failures.
pub fn build(inputs: &[PathBuf], chunk_size: u32) -> Result<Manifest, ManifestError> {
    build_inner(inputs, chunk_size, true)
}

/// Build a manifest and apply path-selection filters before hashing is
/// performed by callers. The default `build` API remains unfiltered for
/// library compatibility; CLI callers should use this function.
pub fn build_with_filters(
    inputs: &[PathBuf],
    chunk_size: u32,
    filters: &FilterOptions,
) -> Result<Manifest, ManifestError> {
    let mut manifest = build(inputs, chunk_size)?;
    manifest.files.retain(|entry| {
        let hidden = !filters.include_hidden
            && entry
                .rel_path
                .split('/')
                .skip(1)
                .any(|component| component.starts_with('.'));
        let excluded = filters
            .exclude
            .iter()
            .any(|pattern| matches_filter(pattern, &entry.rel_path));
        let included = filters.include.is_empty()
            || filters
                .include
                .iter()
                .any(|pattern| matches_filter(pattern, &entry.rel_path));
        !hidden && !excluded && included
    });
    if manifest.files.is_empty() {
        return Err(ManifestError::Empty);
    }
    for (id, file) in manifest.files.iter_mut().enumerate() {
        file.id = id as FileId;
    }
    Ok(manifest)
}

/// Small dependency-free glob matcher. `*` matches within one component,
/// `**` also crosses `/`, and `?` matches one non-separator character.
fn matches_filter(pattern: &str, path: &str) -> bool {
    let pattern = pattern.trim_matches('/');
    if pattern.is_empty() {
        return false;
    }
    fn matches(p: &[u8], s: &[u8]) -> bool {
        if p.is_empty() {
            return s.is_empty();
        }
        if p[0] == b'*' {
            let double = p.get(1) == Some(&b'*');
            let rest = if double { &p[2..] } else { &p[1..] };
            if matches(rest, s) {
                return true;
            }
            if let Some((&first, tail)) = s.split_first() {
                if double || first != b'/' {
                    return matches(p, tail);
                }
            }
            return false;
        }
        if let Some((&first, tail)) = s.split_first() {
            if p[0] == b'?' && first != b'/' {
                return matches(&p[1..], tail);
            }
            if p[0] == first {
                return matches(&p[1..], tail);
            }
        }
        false
    }
    matches(pattern.as_bytes(), path.as_bytes())
        || (!pattern.contains('/') && path.split('/').any(|part| matches(pattern.as_bytes(), part.as_bytes())))
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

    // Refuse to walk a filesystem root (`/` on Unix, `C:\` on Windows),
    // no matter how many inputs are given: `lanx send / /tmp/a` must not
    // walk the entire volume. A canonical path with no parent IS a root.
    // Note: `.`-style spellings (`.`, `sub/..`) are NOT roots — their
    // canonical forms still have parents — so `lanx send .` keeps working.
    // Symlinks are skipped (a dangling link is not a root; the symlink
    // handling below / in `collect_files` owns that case).
    for p in inputs {
        if let Ok(m) = std::fs::symlink_metadata(p) {
            if m.file_type().is_symlink() {
                continue;
            }
        }
        let canon = canonicalize_input(p)?;
        if canon.parent().is_none() {
            return Err(ManifestError::InvalidPath(format!(
                "refusing to send filesystem root: {}",
                canon.display()
            )));
        }
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
        match inputs[0].file_name() {
            None => None,
            Some(n) => match n.to_str() {
                Some(s) => Some(s.to_string()),
                None => {
                    return Err(ManifestError::InvalidPath(format!(
                        "input file name is not valid UTF-8: {:?}",
                        inputs[0]
                    )))
                }
            },
        }
    } else {
        None
    };
    let single_input_is_dir: bool = single_meta.as_ref().is_some_and(|m| m.is_dir());

    // A missing `single_input_basename` here means a `.`-style spelling
    // (`.`, `sub/..`): true roots were already rejected above, so fall
    // through to the generic multi-input path below, which canonicalizes
    // and walks correctly (this is the `lanx send .` shape).
    // The single-input basename (file or directory) must already be a
    // portable wire name: `CON`, `foo `, or `a:b` can never be recreated
    // on Windows. Directories are checked here too so that even an empty
    // `CON/` fails with `InvalidPath` instead of the misleading `Empty`.
    if let Some(ref basename) = single_input_basename {
        validate_rel_path(basename)?;
    }

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
    // Multi-root inputs (e.g. `C:\a` and `D:\b` on Windows) share no
    // common ancestor. The old fallback silently flattened everything to
    // basenames and could overwrite distinct files. Reject instead.
    if single_input_basename.is_none() {
        for p in inputs {
            let abs = canonicalize_input(p)?;
            if abs.strip_prefix(&common).is_err() {
                return Err(ManifestError::InvalidPath(format!(
                    "inputs span multiple filesystem roots (no common ancestor): {} vs {}",
                    p.display(),
                    common.display()
                )));
            }
        }
    }

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

    // Strict portable default: every generated rel_path must already be a
    // valid wire path (UTF-8, no reserved names, bounded length). Fail
    // here — before hashing — with the exact offending source path.
    for (abs, rel) in &sources {
        validate_rel_path(rel).map_err(|e| match e {
            ManifestError::InvalidPath(msg) => {
                ManifestError::InvalidPath(format!("{msg} (from source {})", abs.display()))
            }
            other => other,
        })?;
    }
    {
        let rels: Vec<&str> = sources.iter().map(|(_, r)| r.as_str()).collect();
        check_no_collisions(&rels, |i| {
            format!(" (from source {})", sources[i].0.display())
        })?;
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
            let rel = rel_from(common, p)?;
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
    walk_dir_inner(dir, common, None, out)
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
    walk_dir_inner(dir, Path::new(""), Some(archive_prefix), out)
}

fn walk_dir_inner(
    dir: &Path,
    common: &Path,
    archive_prefix: Option<&str>,
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
            let rel = if let Some(prefix) = archive_prefix {
                let file_name_os = match path.file_name() {
                    Some(n) => n,
                    None => {
                        return Err(ManifestError::InvalidPath(format!(
                            "path has no file name: {}",
                            path.display()
                        )))
                    }
                };
                let file_name = match file_name_os.to_str() {
                    Some(n) => n,
                    None => {
                        return Err(ManifestError::InvalidPath(format!(
                            "file name is not valid UTF-8: {}",
                            path.display()
                        )))
                    }
                };
                format!("{prefix}/{file_name}")
            } else {
                rel_from(common, &path)?
            };
            out.push((path.clone(), rel));
        } else if meta.is_dir() {
            if let Some(prefix) = archive_prefix {
                let file_name_os = match path.file_name() {
                    Some(n) => n,
                    None => {
                        return Err(ManifestError::InvalidPath(format!(
                            "path has no file name: {}",
                            path.display()
                        )))
                    }
                };
                let file_name = match file_name_os.to_str() {
                    Some(n) => n,
                    None => {
                        return Err(ManifestError::InvalidPath(format!(
                            "file name is not valid UTF-8: {}",
                            path.display()
                        )))
                    }
                };
                let child_prefix = format!("{prefix}/{file_name}");
                walk_dir_inner(&path, common, Some(&child_prefix), out)?;
            } else {
                walk_dir_inner(&path, common, None, out)?;
            }
        } else {
            tracing::warn!(path = %path.display(), "skipping special file");
        }
    }
    Ok(())
}

/// Build a forward-slash-delimited `rel_path` from `common` to `abs`.
/// `common` is a canonicalized prefix; `abs` may or may not be. The
/// result has platform-portable separators (always `/`).
///
/// Returns `ManifestError::InvalidPath` when `abs` is not under `common`
/// (multi-root inputs) or contains non-UTF-8 components, instead of
/// silently flattening to a basename (which could overwrite distinct
/// files on the receiver).
fn rel_from(common: &Path, abs: &Path) -> Result<String, ManifestError> {
    // Map canonicalize failures without discarding their kind: a missing
    // file is `NotFound`, anything else (e.g. `PermissionDenied`) stays
    // an `Io` error so debugging points at the real cause.
    let map_canon_err = |e: std::io::Error| {
        if e.kind() == std::io::ErrorKind::NotFound {
            ManifestError::NotFound(abs.to_path_buf())
        } else {
            ManifestError::Io(e)
        }
    };
    let stripped = if let Ok(p) = abs.strip_prefix(common) {
        p.to_path_buf()
    } else {
        match std::fs::canonicalize(abs) {
            Ok(canon) => match canon.strip_prefix(common) {
                Ok(p) => p.to_path_buf(),
                Err(_) => {
                    return Err(ManifestError::InvalidPath(format!(
                        "path is not under the common root (multi-root inputs are not supported): {} vs {}",
                        abs.display(),
                        common.display()
                    )));
                }
            },
            Err(e) => return Err(map_canon_err(e)),
        }
    };
    match pathbuf_to_rel_string(&stripped) {
        Ok(s) => Ok(s),
        Err(_) => {
            // Lexical spellings with `.`/`..` (e.g. `/tmp/dir/./file`,
            // `/tmp/dir/sub/../file`) strip lexically but are not valid
            // wire paths. Resolve on disk and retry once; anything still
            // invalid (non-UTF-8, genuinely escaping `..`) errors below.
            let canon = std::fs::canonicalize(abs).map_err(map_canon_err)?;
            let p = canon.strip_prefix(common).map_err(|_| {
                ManifestError::InvalidPath(format!(
                    "path is not under the common root (multi-root inputs are not supported): {} vs {}",
                    abs.display(),
                    common.display()
                ))
            })?;
            pathbuf_to_rel_string(p)
        }
    }
}

/// Convert a relative `Path` to a forward-slash-delimited string.
/// Preserves the multi-component structure (e.g. `sub/b.bin`) but uses
/// `/` as the separator regardless of platform.
///
/// Returns `ManifestError::InvalidPath` for non-UTF-8 components or for
/// non-`Normal` components (absolute prefixes, `..`, …). Never silently
/// drops components: a dropped component would change the file's
/// identity on the receiver.
fn pathbuf_to_rel_string(p: &Path) -> Result<String, ManifestError> {
    let mut parts = Vec::new();
    for c in p.components() {
        match c {
            std::path::Component::Normal(s) => match s.to_str() {
                Some(s) => parts.push(s),
                None => {
                    return Err(ManifestError::InvalidPath(format!(
                        "path component is not valid UTF-8: {}",
                        p.display()
                    )))
                }
            },
            std::path::Component::CurDir => {
                return Err(ManifestError::InvalidPath(format!(
                    "path contains '.' component: {}",
                    p.display()
                )))
            }
            std::path::Component::ParentDir
            | std::path::Component::RootDir
            | std::path::Component::Prefix(_) => {
                return Err(ManifestError::InvalidPath(format!(
                    "path escapes the common root: {}",
                    p.display()
                )))
            }
        }
    }
    if parts.is_empty() {
        return Err(ManifestError::InvalidPath(format!(
            "empty rel_path for: {}",
            p.display()
        )));
    }
    Ok(parts.join("/"))
}

/// Compute a common ancestor directory for the input paths so relative
/// paths in the manifest are stable and unambiguous.
///
/// # Errors
///
/// Returns `ManifestError::NotFound` if an input path does not exist
/// (matching `collect_files` and the root-guard mapping), or
/// `ManifestError::Io` for other canonicalization failures.
fn compute_common_root(inputs: &[PathBuf]) -> Result<PathBuf, ManifestError> {
    let mut iter = inputs.iter();
    let first = iter.next().expect("non-empty");
    let mut common = canonicalize_input(first)?;
    for p in iter {
        let abs = canonicalize_input(p)?;
        common = longest_common_prefix(&common, &abs);
    }
    Ok(common)
}

/// Canonicalize a sender input, preserving the not-found kind so missing
/// paths report as `ManifestError::NotFound` (like `collect_files`)
/// instead of a generic `Io` error.
fn canonicalize_input(p: &PathBuf) -> Result<PathBuf, ManifestError> {
    std::fs::canonicalize(p).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            ManifestError::NotFound(p.clone())
        } else {
            ManifestError::Io(e)
        }
    })
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
        // Inputs on different roots (e.g. `C:\a` vs `D:\b` on Windows)
        // share no prefix. Fall back to the first path's parent so
        // `compute_common_root` still returns a usable base; `build_inner`
        // then rejects multi-root inputs explicitly with a clear error
        // instead of silently flattening everything to basenames.
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
        // All rel_paths must use forward slashes, with no backslashes,
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
        // Relative paths use forward slashes so folder names with spaces
        // remain intact across platforms.
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
        // (the tempdir's basename). That would indicate an incorrect
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
        // A lone symlink input is treated as empty.
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
    fn strict_path_validation_rejects_hostile_paths() {
        for bad in [
            "",
            "/",
            "/abs/path",
            "a//b",
            "/leading",
            "trailing/",
            "a/./b",
            ".",
            "./a",
            "a/.",
            "..",
            "../a",
            "a/../b",
            "a/..",
            "C:/win",
            "C:rel",
            "c:\\win",
            "a\\b",
            "\\unc\\share",
            "a\0b",
            "\\\\?\\C:\\x",
            // Portable Windows-reserved rules (same on all platforms).
            "CON",
            "con.txt",
            "AUX.bin",
            "NUL",
            "COM1",
            "com9.log",
            "LPT1",
            "lpt9.txt",
            "a/CON/b",
            "a/b:c",
            "a/b<c",
            "a/b>c",
            "a/b\"c",
            "a/b|c",
            "a/b?c",
            "a/b*c",
            "foo ",
            "foo.",
            "a/foo./b",
            "a/bar /c",
            "a/b\x1fc",
            // Windows strips trailing dots/spaces before comparing, so
            // these alias devices despite passing the trailing rule.
            "CON .txt",
            "NUL .bin",
            "a/COM1 .log",
        ] {
            assert!(
                validate_rel_path(bad).is_err(),
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn strict_path_validation_accepts_normal_paths() {
        for good in [
            "f.bin",
            "hello.txt",
            "a/b.bin",
            "Piete de Hooch/figures/fig5.jpg",
            "myrepo/sub/a.bin",
            ".hidden",
            ".gitignore",
            "a/.hidden/b",
            "a...b/c",
            "a/b..c",
            "a/b c/d",
        ] {
            assert!(
                validate_rel_path(good).is_ok(),
                "{good:?} must be accepted"
            );
        }
    }

    #[test]
    fn filtered_manifest_applies_include_exclude_and_hidden_rules() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("sub")).unwrap();
        File::create(dir.path().join("keep.txt")).unwrap();
        File::create(dir.path().join("skip.log")).unwrap();
        File::create(dir.path().join(".secret")).unwrap();
        File::create(dir.path().join("sub/nested.txt")).unwrap();

        let filtered = build_with_filters(
            &[dir.path().to_path_buf()],
            1024,
            &FilterOptions {
                include_hidden: false,
                exclude: vec!["*.log".into()],
                include: vec!["*.txt".into()],
            },
        )
        .unwrap();
        let paths: Vec<_> = filtered.files.iter().map(|f| f.rel_path.as_str()).collect();
        assert!(paths.iter().any(|p| p.ends_with("keep.txt")));
        assert!(paths.iter().any(|p| p.ends_with("nested.txt")));
        assert!(!paths.iter().any(|p| p.ends_with("skip.log")));
        assert!(!paths.iter().any(|p| p.ends_with(".secret")));
    }

    #[test]
    fn manifest_path_validation_reports_first_bad_entry() {
        let m = Manifest {
            files: vec![
                FileEntry {
                    id: 0,
                    rel_path: "ok.bin".to_string(),
                    size: 0,
                    chunk_size: 1024,
                    chunk_hashes: vec![],
                },
                FileEntry {
                    id: 1,
                    rel_path: "../evil.bin".to_string(),
                    size: 0,
                    chunk_size: 1024,
                    chunk_hashes: vec![],
                },
            ],
            chunk_size: 1024,
            source_root: PathBuf::new(),
        };
        assert!(matches!(
            validate_manifest_paths(&m),
            Err(ManifestError::InvalidPath(_))
        ));
    }

    #[test]
    fn rel_to_path_round_trips() {
        // Convert the forward-slash form to a platform-native PathBuf.
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

    #[test]
    fn portable_validation_rejects_overlong_paths() {
        let long_component = "a".repeat(MAX_COMPONENT_BYTES + 1);
        assert!(validate_rel_path(&long_component).is_err());
        let long_path = format!("{}/b", "a".repeat(MAX_REL_PATH_BYTES));
        assert!(validate_rel_path(&long_path).is_err());
        // Boundary lengths are accepted.
        let ok_component = "a".repeat(MAX_COMPONENT_BYTES);
        assert!(validate_rel_path(&ok_component).is_ok());
    }

    #[test]
    fn manifest_rejects_duplicate_file_ids() {
        // IDs index destination maps, resume offsets, and `id % parallel`
        // sharding: two entries sharing an ID would corrupt each other.
        let m = Manifest {
            files: vec![
                FileEntry {
                    id: 0,
                    rel_path: "a.bin".to_string(),
                    size: 0,
                    chunk_size: 1024,
                    chunk_hashes: vec![],
                },
                FileEntry {
                    id: 0,
                    rel_path: "b.bin".to_string(),
                    size: 0,
                    chunk_size: 1024,
                    chunk_hashes: vec![],
                },
            ],
            chunk_size: 1024,
            source_root: PathBuf::new(),
        };
        assert!(matches!(
            validate_manifest_paths(&m),
            Err(ManifestError::InvalidPath(_))
        ));
        assert!(matches!(
            validate_manifest_ids(&m),
            Err(ManifestError::InvalidPath(_))
        ));
    }

    #[test]
    fn manifest_rejects_exact_and_case_collisions() {
        let dup = Manifest {
            files: vec![
                FileEntry {
                    id: 0,
                    rel_path: "a.bin".to_string(),
                    size: 0,
                    chunk_size: 1024,
                    chunk_hashes: vec![],
                },
                FileEntry {
                    id: 1,
                    rel_path: "a.bin".to_string(),
                    size: 0,
                    chunk_size: 1024,
                    chunk_hashes: vec![],
                },
            ],
            chunk_size: 1024,
            source_root: PathBuf::new(),
        };
        assert!(matches!(
            validate_manifest_paths(&dup),
            Err(ManifestError::InvalidPath(_))
        ));
        let case = Manifest {
            files: vec![
                FileEntry {
                    id: 0,
                    rel_path: "Report.txt".to_string(),
                    size: 0,
                    chunk_size: 1024,
                    chunk_hashes: vec![],
                },
                FileEntry {
                    id: 1,
                    rel_path: "report.txt".to_string(),
                    size: 0,
                    chunk_size: 1024,
                    chunk_hashes: vec![],
                },
            ],
            chunk_size: 1024,
            source_root: PathBuf::new(),
        };
        assert!(matches!(
            validate_manifest_paths(&case),
            Err(ManifestError::InvalidPath(_))
        ));
    }

    // Not on Windows: the OS itself refuses to create these names, so
    // the on-disk case is only exercisable on Unix. Wire-level rejection
    // is covered everywhere by `strict_path_validation_rejects_hostile_paths`.
    #[test]
    #[cfg(not(windows))]
    fn build_rejects_windows_reserved_names() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("CON.txt");
        File::create(&p).unwrap().write_all(b"x").unwrap();
        let r = build(std::slice::from_ref(&p), 1024);
        assert!(
            matches!(r, Err(ManifestError::InvalidPath(_))),
            "CON.txt must be rejected, got {r:?}"
        );
    }

    #[test]
    #[cfg(not(windows))]
    fn build_rejects_reserved_empty_dir_name() {
        // Even with no files inside, a single directory named `CON` must
        // fail with `InvalidPath` (not the misleading `Empty`).
        let dir = tempfile::tempdir().unwrap();
        let con = dir.path().join("CON");
        fs::create_dir(&con).unwrap();
        let r = build(std::slice::from_ref(&con), 1024);
        assert!(
            matches!(r, Err(ManifestError::InvalidPath(_))),
            "empty CON dir must be rejected with InvalidPath, got {r:?}"
        );
    }

    #[test]
    #[cfg(not(windows))]
    fn build_rejects_trailing_space_names() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("foo ");
        File::create(&p).unwrap().write_all(b"x").unwrap();
        let r = build(std::slice::from_ref(&p), 1024);
        assert!(
            matches!(r, Err(ManifestError::InvalidPath(_))),
            "trailing-space names must be rejected, got {r:?}"
        );
    }

    #[test]
    fn build_rejects_case_colliding_inputs() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("Report.txt");
        let b = dir.path().join("report.txt");
        // Case-sensitive filesystems hold both; the manifest must still
        // reject the pair for Windows/macOS receivers. On a
        // case-insensitive filesystem the second create overwrites the
        // first and only one file exists; either outcome is acceptable
        // (reject collision OR single file), but never two colliding
        // entries.
        File::create(&a).unwrap().write_all(b"a").unwrap();
        File::create(&b).unwrap().write_all(b"b").unwrap();
        let r = build(&[a, b], 1024);
        match r {
            Err(ManifestError::InvalidPath(_)) => {}
            Ok(m) => assert_eq!(
                m.files.len(),
                1,
                "case-insensitive fs keeps one file; colliding manifest with 2 entries must be rejected"
            ),
            Err(e) => panic!("expected InvalidPath or single-file Ok, got {e:?}"),
        }
    }

    #[test]
    fn build_rejects_filesystem_root() {
        #[cfg(unix)]
        {
            let r = build(std::slice::from_ref(&PathBuf::from("/")), 1024);
            assert!(
                matches!(r, Err(ManifestError::InvalidPath(_))),
                "sending / must be rejected, got {r:?}"
            );
        }
    }

    #[test]
    fn dotdot_style_spelling_is_not_a_root() {
        // `Path::file_name()` is `None` for both `/` and `sub/..`, but
        // only `/` is a filesystem root (`send .` / `send sub/..` shapes).
        // A single `sub/..` input must walk the parent directory, not
        // fail as a root.
        let dir = tempfile::tempdir().unwrap();
        File::create(dir.path().join("a.bin"))
            .unwrap()
            .write_all(b"x")
            .unwrap();
        let sub = dir.path().join("sub");
        fs::create_dir(&sub).unwrap();
        let up = sub.join("..");
        assert!(up.file_name().is_none());
        let m = build(std::slice::from_ref(&up), 1024).expect("sub/.. must build");
        assert_eq!(m.files.len(), 1);
        assert_eq!(m.files[0].rel_path, "a.bin");
    }
    #[test]
    #[cfg(unix)]
    fn build_rejects_root_among_multiple_inputs() {
        // The root guard covers every input, not just the single-input
        // case: `lanx send / /tmp/a` must not walk `/`.
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("a.bin");
        File::create(&f).unwrap().write_all(b"x").unwrap();
        let r = build(&[PathBuf::from("/"), f], 1024);
        assert!(
            matches!(r, Err(ManifestError::InvalidPath(_))),
            "a filesystem root among inputs must be rejected, got {r:?}"
        );
    }

    #[test]
    fn missing_input_reports_not_found() {
        // A missing path reports `NotFound` (not generic `Io`), whether
        // it is the only input or one of several.
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("a.bin");
        File::create(&f).unwrap().write_all(b"x").unwrap();
        let missing = dir.path().join("missing.bin");
        assert!(matches!(
            build(std::slice::from_ref(&missing), 1024),
            Err(ManifestError::NotFound(_))
        ));
        assert!(matches!(
            build(&[f, missing], 1024),
            Err(ManifestError::NotFound(_))
        ));
    }

    #[test]
    fn rel_from_resolves_dot_spellings() {
        // Lexical `.`/`..` spellings strip lexically but are not valid
        // wire paths; `rel_from` must resolve them on disk and retry
        // instead of erroring.
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("sub");
        fs::create_dir(&sub).unwrap();
        File::create(dir.path().join("a.bin"))
            .unwrap()
            .write_all(b"x")
            .unwrap();
        File::create(sub.join("b.bin"))
            .unwrap()
            .write_all(b"y")
            .unwrap();
        let common = std::fs::canonicalize(dir.path()).unwrap();
        let dotted = common.join(".").join("a.bin");
        assert_eq!(rel_from(&common, &dotted).unwrap(), "a.bin");
        let dotdot = common.join("sub").join("..").join("sub").join("b.bin");
        assert_eq!(rel_from(&common, &dotdot).unwrap(), "sub/b.bin");
    }

    // Linux-only: APFS (macOS) rejects non-UTF-8 names at the filesystem
    // level, so the on-disk case can only be exercised on Linux. The
    // portable unit test below covers the conversion layer everywhere.
    #[test]
    #[cfg(target_os = "linux")]
    fn build_rejects_non_utf8_names() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let dir = tempfile::tempdir().unwrap();
        let raw = OsStr::from_bytes(b"bad\xffname.bin");
        let p = dir.path().join(raw);
        File::create(&p).unwrap().write_all(b"x").unwrap();
        let r = build(std::slice::from_ref(&p), 1024);
        assert!(
            matches!(r, Err(ManifestError::InvalidPath(_))),
            "non-UTF-8 names must be rejected with InvalidPath, got {r:?}"
        );
    }

    #[test]
    #[cfg(unix)]
    fn rel_conversion_rejects_non_utf8_components() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let raw = OsStr::from_bytes(b"bad\xffname.bin");
        let p = PathBuf::from(raw);
        assert!(
            matches!(
                pathbuf_to_rel_string(&p),
                Err(ManifestError::InvalidPath(_))
            ),
            "non-UTF-8 components must be rejected, not skipped"
        );
    }
}
