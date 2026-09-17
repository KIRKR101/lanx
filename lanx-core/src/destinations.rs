//! Receiver-side destination resolution. Decides whether `--out` should be
//! treated as a file path or as a directory based on manifest cardinality.

use crate::manifest::{rel_to_path, Manifest, ManifestError};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct Destinations {
    /// Resolved destination path for every accepted file.
    pub paths: HashMap<crate::manifest::FileId, PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OverwritePolicy {
    /// Default: resume partial files, skip complete ones.
    #[default]
    Resume,
    /// Re-download every file from byte 0, replacing existing files.
    Overwrite,
    /// Never touch an existing destination path; skip those files.
    SkipExisting,
    /// Keep existing files; write incoming files to a numbered sibling
    /// (`photo.jpg` -> `photo.1.jpg`) instead.
    RenameExisting,
    /// Abort the transfer if any destination file already exists, without
    /// modifying anything.
    Fail,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConflictPreview {
    /// Destination paths that already exist (any file type).
    pub existing: usize,
    /// Existing paths whose size matches the manifest (likely complete;
    /// content is verified by hash during the transfer).
    pub complete_by_size: usize,
    /// Existing paths whose size differs (partial or changed files that
    /// would be resumed or replaced).
    pub resumable_by_size: usize,
    /// Destination paths that do not exist yet.
    pub new: usize,
}

/// Cheap stat-only preview of destination conflicts, without hashing.
///
/// Used by the receiver approval prompt to show existing/resumable/new
/// counts *before* confirmation. Size equality is only a heuristic for
/// "complete"; the real resume plan verifies content by hash after
/// approval.
///
/// Mirrors the failure conditions of [`resolve_destinations`] — invalid
/// paths, collisions, duplicate IDs, out-is-file, and over-long
/// destinations all return `Err` here too — so the prompt surfaces the
/// coming failure instead of showing misleading counts. Creates nothing.
///
/// # Errors
///
/// Returns `DestError::Manifest` for invalid/colliding/duplicate-ID
/// paths, `DestError::MultiFileOutIsFile` when multiple files are being
/// received but `out` points to an existing file, or
/// `DestError::PathTooLong` for over-long destinations.
pub fn preview_conflicts(manifest: &Manifest, out: &Path) -> Result<ConflictPreview, DestError> {
    crate::manifest::validate_manifest_paths(manifest)?;
    if manifest.files.len() > 1 && out.exists() && !out.is_dir() {
        return Err(DestError::MultiFileOutIsFile);
    }
    check_dest_length(out)?;
    let paths = destination_paths(manifest, out);
    // Length-check the joined destinations up front, like
    // `resolve_destinations` does before creating anything.
    for dest in paths.values() {
        check_dest_length(dest)?;
    }
    let mut existing = 0;
    let mut complete_by_size = 0;
    let mut resumable_by_size = 0;
    let mut new = 0;
    for f in &manifest.files {
        let Some(dest) = paths.get(&f.id) else {
            continue;
        };
        match std::fs::symlink_metadata(dest) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => new += 1,
            Err(_) => {
                existing += 1;
                resumable_by_size += 1;
            }
            Ok(meta) => {
                existing += 1;
                if meta.is_file() && meta.len() == f.size {
                    complete_by_size += 1;
                } else {
                    resumable_by_size += 1;
                }
            }
        }
    }
    Ok(ConflictPreview {
        existing,
        complete_by_size,
        resumable_by_size,
        new,
    })
}

/// Compute destination paths without creating any directories.
///
/// Pure: safe to call from the approval prompt before the user confirms.
///
/// Contract: the manifest must already be validated (see
/// `manifest::validate_manifest_paths`). Unvalidated `rel_path` values
/// are converted best-effort via `rel_to_path` (which skips empty/`.`
/// /`..` components), so a hostile manifest could preview as a benign
/// path here while `resolve_destinations` rejects it. Callers must
/// validate before previewing; the receiver does this at wire receipt,
/// before approval.
#[must_use]
pub fn destination_paths(
    manifest: &Manifest,
    out: &Path,
) -> HashMap<crate::manifest::FileId, PathBuf> {
    let mut map = HashMap::new();
    if manifest.files.is_empty() {
        return map;
    }
    let is_single = manifest.files.len() == 1;
    let out_is_dir = out.is_dir();
    let out_exists = out.exists();
    match (is_single, out_is_dir, out_exists) {
        (false, _, true) if !out_is_dir => return map,
        (false, _, _) => {
            for f in &manifest.files {
                map.insert(f.id, out.join(rel_to_path(&f.rel_path)));
            }
        }
        (true, true, _) => {
            let entry = &manifest.files[0];
            map.insert(entry.id, out.join(rel_to_path(&entry.rel_path)));
        }
        (true, false, false) => {
            let entry = &manifest.files[0];
            let dest = if path_ends_with_separator(out) {
                out.join(rel_to_path(&entry.rel_path))
            } else {
                out.to_path_buf()
            };
            map.insert(entry.id, dest);
        }
        (true, false, true) => {
            let entry = &manifest.files[0];
            map.insert(entry.id, out.to_path_buf());
        }
    }
    map
}

/// Pick the first unused sibling for `path` by incrementing a numeric
/// suffix before the extension: `photo.jpg` -> `photo.1.jpg` ->
/// `photo.2.jpg`. Extensionless `file` becomes `file.1`.
#[must_use]
pub fn next_available_path(path: &Path) -> PathBuf {
    if std::fs::symlink_metadata(path).is_err() {
        return path.to_path_buf();
    }
    let parent = path.parent();
    // Non-UTF-8 file name: never lossy-convert for stemming — two distinct
    // byte-names (e.g. `bad\xff.bin` vs `bad\xfe.bin`) would collapse to
    // the same lossy stem and the same `.1` sibling. Keep the raw bytes
    // and append the counter to the whole name so siblings stay distinct.
    if path.file_name().is_some_and(|n| n.to_str().is_none()) {
        let mut n = 1u32;
        loop {
            let mut name = path.file_name().unwrap_or_default().to_os_string();
            name.push(format!(".{n}"));
            let candidate = match parent {
                Some(p) if !p.as_os_str().is_empty() => p.join(name.as_os_str()),
                _ => PathBuf::from(name),
            };
            if std::fs::symlink_metadata(&candidate).is_err() {
                return candidate;
            }
            n += 1;
        }
    }
    // Below this point the file name is UTF-8 (non-UTF-8 returned
    // above), so `to_string_lossy` here is lossless in practice; it only
    // remains instead of `to_str().unwrap_or_default()` as defense in
    // depth against collapsing to `.1`/`.2` siblings.
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let (stem, ext) = match file_name.rsplit_once('.') {
        Some((s, e)) if !s.is_empty() => (s, Some(e)),
        _ => (file_name.as_str(), None),
    };
    let mut n = 1u32;
    loop {
        let candidate_name = match ext {
            Some(e) => format!("{stem}.{n}.{e}"),
            None => format!("{stem}.{n}"),
        };
        let candidate = match parent {
            Some(p) if !p.as_os_str().is_empty() => p.join(candidate_name),
            _ => PathBuf::from(candidate_name),
        };
        if std::fs::symlink_metadata(&candidate).is_err() {
            return candidate;
        }
        n += 1;
    }
}

/// Receiver-platform full-path length limit for a resolved destination:
/// Windows classic `MAX_PATH` (260), Unix `PATH_MAX` (4096).
/// The per-component (255) and `rel_path` (4096) limits are already
/// enforced by `manifest::validate_rel_path`; this guards the joined
/// `out + rel` result on the actual receiver before anything is created.
#[cfg(windows)]
const MAX_DEST_PATH_BYTES: usize = 260;
/// See above.
#[cfg(not(windows))]
const MAX_DEST_PATH_BYTES: usize = 4096;

fn check_dest_length(dest: &Path) -> Result<(), DestError> {
    // `as_os_str().len()` is bytes on Unix; on Windows it is the
    // `OsStr` byte length of the WTF-8/UTF-16 backing store, which is a
    // safe over-approximation for the `MAX_PATH` check.
    if dest.as_os_str().len() > MAX_DEST_PATH_BYTES {
        return Err(DestError::PathTooLong(
            MAX_DEST_PATH_BYTES,
            dest.to_path_buf(),
        ));
    }
    Ok(())
}
#[derive(Debug, Error)]
pub enum DestError {
    #[error("--out points to an existing file but multiple files are being received")]
    MultiFileOutIsFile,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("manifest has no files")]
    Empty,
    #[error("destination path exceeds {0} bytes: {1}")]
    PathTooLong(usize, PathBuf),
    #[error(transparent)]
    Manifest(#[from] ManifestError),
}

/// Resolve the destination path for each manifest file.
///
/// Every `rel_path` is validated as a strict, portable relative path
/// (see `manifest::validate_rel_path`, including Windows-reserved names,
/// length limits, and exact/case-insensitive collisions) before any
/// directory is created, so a hostile manifest fails without touching
/// the filesystem.
///
/// # Errors
///
/// Returns `DestError::Empty` if the manifest has no files,
/// `DestError::Manifest` if any `rel_path` is not a strict relative path,
/// `DestError::MultiFileOutIsFile` if multiple files are being received
/// but `out` points to an existing file, `DestError::PathTooLong` if a
/// joined destination exceeds the receiver-platform limit, or
/// `DestError::Io` if a parent directory cannot be created.
pub fn resolve_destinations(manifest: &Manifest, out: &Path) -> Result<Destinations, DestError> {
    if manifest.files.is_empty() {
        return Err(DestError::Empty);
    }
    crate::manifest::validate_manifest_paths(manifest)?;
    check_dest_length(out)?;
    let is_single = manifest.files.len() == 1;
    let out_is_dir = out.is_dir();
    let out_exists = out.exists();

    match (is_single, out_is_dir, out_exists) {
        (false, _, true) if !out_is_dir => Err(DestError::MultiFileOutIsFile),
        (false, _, _) => {
            // Join and length-check every destination BEFORE creating
            // anything: a `PathTooLong` must not leave an empty `out/`
            // behind.
            // rel_path is forward-slash form on the wire; convert
            // to a platform-native PathBuf before joining so a
            // folder name with a space (e.g. "Piete de Hooch")
            // doesn't get re-tokenized as path separators on
            // Windows.
            let joined: Vec<(crate::manifest::FileId, PathBuf)> = manifest
                .files
                .iter()
                .map(|f| (f.id, out.join(rel_to_path(&f.rel_path))))
                .collect();
            for (_, p) in &joined {
                check_dest_length(p)?;
            }
            std::fs::create_dir_all(out)?;
            let mut map = HashMap::new();
            for (id, p) in joined {
                if let Some(parent) = p.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                map.insert(id, p);
            }
            Ok(Destinations { paths: map })
        }
        (true, true, _) => {
            let entry = &manifest.files[0];
            let dest = out.join(rel_to_path(&entry.rel_path));
            check_dest_length(&dest)?;
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut map = HashMap::new();
            map.insert(entry.id, dest);
            Ok(Destinations { paths: map })
        }
        (true, false, false) => {
            let entry = &manifest.files[0];
            // Compute first so a `PathTooLong` fails before `out/` is
            // created (see the multi-file arm above).
            let dest = if path_ends_with_separator(out) {
                out.join(rel_to_path(&entry.rel_path))
            } else {
                out.to_path_buf()
            };
            check_dest_length(&dest)?;
            if path_ends_with_separator(out) {
                std::fs::create_dir_all(out)?;
            } else if let Some(parent) = dest.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)?;
                }
            }
            let mut map = HashMap::new();
            map.insert(entry.id, dest);
            Ok(Destinations { paths: map })
        }
        (true, false, true) => {
            let entry = &manifest.files[0];
            check_dest_length(out)?;
            let mut map = HashMap::new();
            map.insert(entry.id, out.to_path_buf());
            Ok(Destinations { paths: map })
        }
    }
}

/// Destination paths that already exist, in manifest order.
///
/// Used by `--on-conflict fail` to abort before writing anything.
#[must_use]
pub fn existing_conflicts(manifest: &Manifest, dests: &Destinations) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut ids: Vec<crate::manifest::FileId> = dests.paths.keys().copied().collect();
    ids.sort_unstable();
    for id in ids {
        if manifest.files.iter().any(|f| f.id == id) {
            if let Some(p) = dests.paths.get(&id) {
                if std::fs::symlink_metadata(p).is_ok() {
                    out.push(p.clone());
                }
            }
        }
    }
    out
}

/// Resolve destinations, applying an [`OverwritePolicy`].
///
/// Only [`OverwritePolicy::RenameExisting`] changes the paths: every
/// destination that already exists is remapped to the first unused
/// numbered sibling. [`OverwritePolicy::Fail`] also keeps the default
/// paths; the receiver aborts before writing when any of them exists.
/// The other policies keep the default paths; they
/// are enforced later against the resume plan (overwrite from byte 0,
/// or skip existing files).
///
/// Parent directories are created for the final paths, like
/// [`resolve_destinations`].
///
/// # Errors
///
/// Same errors as [`resolve_destinations`].
pub fn resolve_destinations_with_policy(
    manifest: &Manifest,
    out: &Path,
    policy: OverwritePolicy,
) -> Result<Destinations, DestError> {
    let mut dests = resolve_destinations(manifest, out)?;
    if policy != OverwritePolicy::RenameExisting {
        return Ok(dests);
    }
    // Deterministic order so numbered siblings are stable across runs.
    let mut ids: Vec<crate::manifest::FileId> = dests.paths.keys().copied().collect();
    ids.sort_unstable();
    for id in ids {
        let current = dests.paths[&id].clone();
        if std::fs::symlink_metadata(&current).is_ok() {
            let renamed = next_available_path(&current);
            check_dest_length(&renamed)?;
            if let Some(parent) = renamed.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)?;
                }
            }
            dests.paths.insert(id, renamed);
        }
    }
    Ok(dests)
}

fn path_ends_with_separator(p: &Path) -> bool {
    p.to_string_lossy().ends_with(std::path::MAIN_SEPARATOR) || p.to_string_lossy().ends_with('/')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{FileEntry, Manifest};
    use std::path::PathBuf;

    fn mfiles(n: usize) -> Manifest {
        let files = (0..n)
            .map(|i| FileEntry {
                id: u32::try_from(i).expect("test file count fits in u32"),
                rel_path: format!("f{i}.bin"),
                size: 0,
                chunk_size: 1024,
                chunk_hashes: vec![],
            })
            .collect();
        Manifest {
            files,
            chunk_size: 1024,
            source_root: PathBuf::new(),
        }
    }

    #[test]
    fn multi_file_out_dir() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("dest");
        let m = mfiles(3);
        let d = resolve_destinations(&m, &out).unwrap();
        assert_eq!(d.paths.len(), 3);
        assert!(out.is_dir());
    }

    #[test]
    fn multi_file_out_is_existing_file_errors() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("file.txt");
        std::fs::write(&out, b"x").unwrap();
        let m = mfiles(2);
        assert!(matches!(
            resolve_destinations(&m, &out),
            Err(DestError::MultiFileOutIsFile)
        ));
    }

    #[test]
    fn single_file_out_existing_dir() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("dest");
        std::fs::create_dir(&out).unwrap();
        let m = mfiles(1);
        let d = resolve_destinations(&m, &out).unwrap();
        let p = d.paths[&0].clone();
        assert!(p.starts_with(&out));
    }

    #[test]
    fn single_file_out_missing_treated_as_filename() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("file.bin");
        let m = mfiles(1);
        let d = resolve_destinations(&m, &out).unwrap();
        assert_eq!(d.paths[&0], out);
    }

    #[test]
    fn folder_name_with_space_resolves_to_nested_dir() {
        // Relative paths use forward slashes, so folder names with spaces
        // remain single path components on every platform.
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("dest");
        let m = Manifest {
            files: vec![
                FileEntry {
                    id: 0,
                    rel_path: "Piete de Hooch/readme.txt".to_string(),
                    size: 0,
                    chunk_size: 1024,
                    chunk_hashes: vec![],
                },
                FileEntry {
                    id: 1,
                    rel_path: "Piete de Hooch/figures/fig5.jpg".to_string(),
                    size: 0,
                    chunk_size: 1024,
                    chunk_hashes: vec![],
                },
            ],
            chunk_size: 1024,
            source_root: PathBuf::new(),
        };
        let d = resolve_destinations(&m, &out).unwrap();
        // Both files must land under <out>/Piete de Hooch/, with the
        // nested subdir for figures/.
        let p0 = d.paths[&0].clone();
        let p1 = d.paths[&1].clone();
        // On Windows, components() treats both / and \ as separators;
        // on Unix only /. Check that the components spell out
        // exactly: dest / "Piete de Hooch" / (readme.txt or figures/fig5.jpg).
        let p0_parts: Vec<String> = p0
            .components()
            .filter_map(|c| c.as_os_str().to_str().map(String::from))
            .collect();
        let p1_parts: Vec<String> = p1
            .components()
            .filter_map(|c| c.as_os_str().to_str().map(String::from))
            .collect();
        assert!(
            p0_parts.iter().any(|s| s == "Piete de Hooch")
                && p0_parts.last().map(String::as_str) == Some("readme.txt"),
            "expected path under <out>/Piete de Hooch/readme.txt, got {p0_parts:?}"
        );
        assert!(
            p1_parts.iter().any(|s| s == "Piete de Hooch")
                && p1_parts.iter().any(|s| s == "figures")
                && p1_parts.last().map(String::as_str) == Some("fig5.jpg"),
            "expected path under <out>/Piete de Hooch/figures/fig5.jpg, got {p1_parts:?}"
        );
    }

    #[test]
    fn rename_preserves_extension() {
        let dir = tempfile::tempdir().unwrap();
        let existing = dir.path().join("photo.jpg");
        std::fs::write(&existing, b"x").unwrap();
        assert_eq!(
            next_available_path(&existing),
            dir.path().join("photo.1.jpg")
        );
    }

    #[test]
    fn rename_increments_until_unused() {
        let dir = tempfile::tempdir().unwrap();
        let existing = dir.path().join("photo.jpg");
        std::fs::write(&existing, b"x").unwrap();
        std::fs::write(dir.path().join("photo.1.jpg"), b"x").unwrap();
        assert_eq!(
            next_available_path(&existing),
            dir.path().join("photo.2.jpg")
        );
    }

    #[test]
    fn rename_handles_extensionless_files() {
        let dir = tempfile::tempdir().unwrap();
        let existing = dir.path().join("file");
        std::fs::write(&existing, b"x").unwrap();
        assert_eq!(next_available_path(&existing), dir.path().join("file.1"));
    }

    #[test]
    fn rename_policy_remaps_only_existing() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("dest");
        let m = mfiles(2);
        let d = resolve_destinations(&m, &out).unwrap();
        std::fs::write(&d.paths[&0], b"existing").unwrap();
        let renamed =
            resolve_destinations_with_policy(&m, &out, OverwritePolicy::RenameExisting).unwrap();
        assert_eq!(
            renamed.paths[&0].file_name().unwrap().to_str().unwrap(),
            "f0.1.bin"
        );
        assert_eq!(renamed.paths[&1], d.paths[&1]);
    }

    #[test]
    fn preview_counts_existing_resumable_and_new() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("dest");
        let m = Manifest {
            files: vec![
                FileEntry {
                    id: 0,
                    rel_path: "same.bin".to_string(),
                    size: 3,
                    chunk_size: 1024,
                    chunk_hashes: vec![],
                },
                FileEntry {
                    id: 1,
                    rel_path: "partial.bin".to_string(),
                    size: 10,
                    chunk_size: 1024,
                    chunk_hashes: vec![],
                },
                FileEntry {
                    id: 2,
                    rel_path: "missing.bin".to_string(),
                    size: 5,
                    chunk_size: 1024,
                    chunk_hashes: vec![],
                },
            ],
            chunk_size: 1024,
            source_root: PathBuf::new(),
        };
        let d = resolve_destinations(&m, &out).unwrap();
        std::fs::write(&d.paths[&0], b"abc").unwrap();
        std::fs::write(&d.paths[&1], b"ab").unwrap();
        let preview = preview_conflicts(&m, &out).unwrap();
        assert_eq!(preview.existing, 2);
        assert_eq!(preview.complete_by_size, 1);
        assert_eq!(preview.resumable_by_size, 1);
        assert_eq!(preview.new, 1);
    }

    #[test]
    fn preview_reports_out_is_file_instead_of_empty_counts() {
        // Multi-file manifest with `--out` pointing at an existing file:
        // the preview must surface `MultiFileOutIsFile` (the same failure
        // `resolve_destinations` returns) instead of `0 existing / 0 new`.
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("file.txt");
        std::fs::write(&out, b"x").unwrap();
        let m = mfiles(2);
        assert!(matches!(
            preview_conflicts(&m, &out),
            Err(DestError::MultiFileOutIsFile)
        ));
    }

    #[test]
    fn preview_reports_overlong_dest_without_creating_dirs() {
        // Short `out`, but `out + rel` exceeds the receiver-platform
        // limit: the preview must fail like `resolve_destinations` does,
        // creating nothing (previously it showed normal counts and the
        // failure only surfaced after approval).
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("dest");
        let required_rel_len = MAX_DEST_PATH_BYTES.saturating_sub(out.as_os_str().len()) + 1;
        let depth = required_rel_len.div_ceil(2);
        let rel = "a/".repeat(depth) + "b.bin";
        assert!(rel.len() <= crate::manifest::MAX_REL_PATH_BYTES);
        let m = Manifest {
            files: vec![
                FileEntry {
                    id: 0,
                    rel_path: rel,
                    size: 0,
                    chunk_size: 1024,
                    chunk_hashes: vec![],
                },
                FileEntry {
                    id: 1,
                    rel_path: "other.bin".to_string(),
                    size: 0,
                    chunk_size: 1024,
                    chunk_hashes: vec![],
                },
            ],
            chunk_size: 1024,
            source_root: PathBuf::new(),
        };
        assert!(matches!(
            preview_conflicts(&m, &out),
            Err(DestError::PathTooLong(_, _))
        ));
        assert!(!out.exists());
    }

    #[test]
    fn preview_rejects_hostile_rel_without_creating_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("dest");
        let m = Manifest {
            files: vec![FileEntry {
                id: 0,
                rel_path: "../evil.bin".to_string(),
                size: 0,
                chunk_size: 1024,
                chunk_hashes: vec![],
            }],
            chunk_size: 1024,
            source_root: PathBuf::new(),
        };
        assert!(matches!(
            preview_conflicts(&m, &out),
            Err(DestError::Manifest(_))
        ));
        assert!(!out.exists());
    }

    #[test]
    fn existing_conflicts_lists_only_present_paths() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("dest");
        let m = mfiles(2);
        let d = resolve_destinations(&m, &out).unwrap();
        assert!(existing_conflicts(&m, &d).is_empty());
        std::fs::write(&d.paths[&1], b"x").unwrap();
        let conflicts = existing_conflicts(&m, &d);
        assert_eq!(conflicts, vec![d.paths[&1].clone()]);
    }

    #[test]
    fn hostile_manifest_is_rejected_before_creating_dirs() {
        for rel in [
            "../evil.bin",
            "/abs.bin",
            "a/../../evil.bin",
            "C:\\evil.bin",
            "a\\b.bin",
            "a//b.bin",
            "a/./b.bin",
            "CON",
            "con.txt",
            "a/AUX.bin",
            "COM1",
            "a/b:c",
            "a/b?c",
            "foo ",
            "foo.",
            "a/b\x1fc",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let out = dir.path().join("dest");
            let m = Manifest {
                files: vec![FileEntry {
                    id: 0,
                    rel_path: rel.to_string(),
                    size: 0,
                    chunk_size: 1024,
                    chunk_hashes: vec![],
                }],
                chunk_size: 1024,
                source_root: PathBuf::new(),
            };
            assert!(
                matches!(resolve_destinations(&m, &out), Err(DestError::Manifest(_))),
                "{rel:?} must be rejected"
            );
            assert!(
                !out.exists(),
                "no directories must be created for hostile rel_path {rel:?}"
            );
        }
    }

    #[test]
    fn colliding_manifest_is_rejected_before_creating_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("dest");
        let m = Manifest {
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
            resolve_destinations(&m, &out),
            Err(DestError::Manifest(_))
        ));
        assert!(!out.exists());
    }

    #[test]
    fn multi_file_path_too_long_creates_nothing() {
        // `out` itself is short, but `out + rel` exceeds the
        // receiver-platform limit. The length check must fire before any
        // directory is created (no empty `out/` left behind).
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("a".repeat(100));
        let depth = (crate::manifest::MAX_REL_PATH_BYTES - 40) / 2;
        let rel = "a/".repeat(depth) + "b.bin";
        assert!(rel.len() <= crate::manifest::MAX_REL_PATH_BYTES);
        let m = Manifest {
            files: vec![
                FileEntry {
                    id: 0,
                    rel_path: rel,
                    size: 0,
                    chunk_size: 1024,
                    chunk_hashes: vec![],
                },
                FileEntry {
                    id: 1,
                    rel_path: "other.bin".to_string(),
                    size: 0,
                    chunk_size: 1024,
                    chunk_hashes: vec![],
                },
            ],
            chunk_size: 1024,
            source_root: PathBuf::new(),
        };
        assert!(matches!(
            resolve_destinations(&m, &out),
            Err(DestError::PathTooLong(_, _))
        ));
        assert!(!out.exists());
    }

    #[test]
    fn overlong_destination_is_rejected() {
        // `check_dest_length` (PathTooLong), not `validate_rel_path`
        // (Manifest): the rel itself is valid, but `out + rel` exceeds
        // the receiver-platform limit.
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("a".repeat(5000));
        let m = Manifest {
            files: vec![FileEntry {
                id: 0,
                rel_path: "ok.bin".to_string(),
                size: 0,
                chunk_size: 1024,
                chunk_hashes: vec![],
            }],
            chunk_size: 1024,
            source_root: PathBuf::new(),
        };
        assert!(
            matches!(
                resolve_destinations(&m, &out),
                Err(DestError::PathTooLong(_, _))
            ),
            "overlong joined destination must be PathTooLong"
        );
        assert!(!out.exists());
    }

    #[test]
    fn overlong_rel_is_rejected_as_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("dest");
        let long_rel = "a".repeat(crate::manifest::MAX_REL_PATH_BYTES + 1);
        let m = Manifest {
            files: vec![FileEntry {
                id: 0,
                rel_path: long_rel,
                size: 0,
                chunk_size: 1024,
                chunk_hashes: vec![],
            }],
            chunk_size: 1024,
            source_root: PathBuf::new(),
        };
        assert!(matches!(
            resolve_destinations(&m, &out),
            Err(DestError::Manifest(_))
        ));
    }
}
