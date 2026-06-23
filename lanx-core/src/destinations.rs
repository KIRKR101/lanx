//! Receiver-side destination resolution. Decides whether `--out` should be
//! treated as a file path or as a directory based on manifest cardinality.

use crate::manifest::{rel_to_path, Manifest};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct Destinations {
    /// Resolved destination path for every accepted file.
    pub paths: HashMap<crate::manifest::FileId, PathBuf>,
}

#[derive(Debug, Error)]
pub enum DestError {
    #[error("--out points to an existing file but multiple files are being received")]
    MultiFileOutIsFile,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("manifest has no files")]
    Empty,
}

/// Resolve the destination path for each manifest file.
///
/// # Errors
///
/// Returns `DestError::Empty` if the manifest has no files,
/// `DestError::MultiFileOutIsFile` if multiple files are being received
/// but `out` points to an existing file, or `DestError::Io` if a parent
/// directory cannot be created.
pub fn resolve_destinations(manifest: &Manifest, out: &Path) -> Result<Destinations, DestError> {
    if manifest.files.is_empty() {
        return Err(DestError::Empty);
    }
    let is_single = manifest.files.len() == 1;
    let out_is_dir = out.is_dir();
    let out_exists = out.exists();

    match (is_single, out_is_dir, out_exists) {
        (false, _, true) if !out_is_dir => Err(DestError::MultiFileOutIsFile),
        (false, _, _) => {
            std::fs::create_dir_all(out)?;
            let mut map = HashMap::new();
            for f in &manifest.files {
                // rel_path is forward-slash form on the wire; convert
                // to a platform-native PathBuf before joining so a
                // folder name with a space (e.g. "Piete de Hooch")
                // doesn't get re-tokenized as path separators on
                // Windows.
                let p = out.join(rel_to_path(&f.rel_path));
                if let Some(parent) = p.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                map.insert(f.id, p);
            }
            Ok(Destinations { paths: map })
        }
        (true, true, _) => {
            let entry = &manifest.files[0];
            let dest = out.join(rel_to_path(&entry.rel_path));
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut map = HashMap::new();
            map.insert(entry.id, dest);
            Ok(Destinations { paths: map })
        }
        (true, false, false) => {
            let entry = &manifest.files[0];
            let dest = if path_ends_with_separator(out) {
                std::fs::create_dir_all(out)?;
                out.join(rel_to_path(&entry.rel_path))
            } else {
                if let Some(parent) = out.parent() {
                    if !parent.as_os_str().is_empty() {
                        std::fs::create_dir_all(parent)?;
                    }
                }
                out.to_path_buf()
            };
            let mut map = HashMap::new();
            map.insert(entry.id, dest);
            Ok(Destinations { paths: map })
        }
        (true, false, true) => {
            let entry = &manifest.files[0];
            let mut map = HashMap::new();
            map.insert(entry.id, out.to_path_buf());
            Ok(Destinations { paths: map })
        }
    }
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
        // Regression: on Windows, a folder with a space in its name
        // used to produce rel_paths with backslashes (because PathBuf::push
        // uses the platform separator). The receiver's Path::join then
        // re-tokenized those backslashes as additional components, so
        // the destination tree was wrong. With forward-slash rel_paths
        // and rel_to_path, the destination is a real nested folder
        // tree, regardless of platform.
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
}
