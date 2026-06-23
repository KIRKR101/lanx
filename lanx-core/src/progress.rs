//! Progress reporting trait. Implementations: `NoopProgress` (default),
//! and `lanx_cli::progress::IndicatifProgress`.

use crate::manifest::FileId;

pub trait Progress: Send + Sync {
    /// Called once on the receiver after the sender's manifest has been
    /// read and parsed, but before any file data flows. The default
    /// implementation does nothing, so simple consumers can ignore it.
    /// The implementation receives the parsed `Manifest` plus a
    /// `TransferSummary` describing what is about to be transferred —
    /// single file, multiple files, or a folder — so the UI can print a
    /// clear header (e.g. "Receiving folder `myrepo/` (12 files, …)")
    /// and pre-allocate per-file bars before the progress events start
    /// arriving. UIs that build bars from per-file `started` calls
    /// exclusively can leave this as a no-op.
    fn manifest_received(&self, _manifest: &crate::manifest::Manifest, _summary: &TransferSummary) {
    }
    fn started(&self, _id: FileId, _rel: &str, _total: u64, _offset: u64) {}
    fn chunk_done(&self, _id: FileId, _bytes: u64) {}
    fn file_done(&self, _id: FileId, _ok: bool) {}
    fn summary(&self, _verified: usize, _failed: usize, _skipped: usize) {}
}

/// High-level description of what a transfer is moving. Computed from the
/// sender's manifest and passed to `Progress::manifest_received` on the
/// receiver. Lets the UI distinguish "sending a folder" from "sending a
/// pile of unrelated files" from "sending a single file" before any
/// progress bars start.
#[derive(Debug, Clone)]
pub struct TransferSummary {
    /// What the transfer is, computed from the manifest's path shape.
    pub kind: TransferKind,
    /// Number of files in the manifest.
    pub file_count: usize,
    /// Total bytes across all files.
    pub total_bytes: u64,
    /// Display name for the transfer.
    ///
    /// - `Folder { name }` for a single-folder transfer, `name` is the
    ///   folder's basename.
    /// - `Files` for a flat multi-file transfer, with no canonical name.
    /// - `SingleFile { name }` for a one-file transfer.
    pub display_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferKind {
    /// Single directory input. All `rel_path`s in the manifest start with
    /// the same top-level directory name; the receiver will create a
    /// folder of that name.
    Folder,
    /// Single file input.
    SingleFile,
    /// Multiple, non-folder-shaped inputs (files from different parents,
    /// multiple directories, a mix).
    Files,
}

impl TransferSummary {
    /// Derive a summary from a manifest by looking at the shape of the
    /// `rel_path`s. `rel_path` is forward-slash form, so this is
    /// platform-independent.
    ///
    /// A manifest is treated as a folder transfer when every file's
    /// `rel_path` has at least two components and they all share the same
    /// first component (the folder's name). A single file with no parent
    /// component is `SingleFile`. Everything else is `Files`.
    pub fn from_manifest(m: &crate::manifest::Manifest) -> Self {
        let file_count = m.files.len();
        let total_bytes: u64 = m.files.iter().map(|f| f.size).sum();
        if file_count == 0 {
            return TransferSummary {
                kind: TransferKind::Files,
                file_count: 0,
                total_bytes: 0,
                display_name: String::new(),
            };
        }
        if file_count == 1 {
            let rel = &m.files[0].rel_path;
            let parts: Vec<&str> = rel.split('/').filter(|s| !s.is_empty()).collect();
            let (name, kind) = match parts.as_slice() {
                [] => (String::new(), TransferKind::SingleFile),
                [single] => (single.to_string(), TransferKind::SingleFile),
                [first, ..] => (first.to_string(), TransferKind::Folder),
            };
            return TransferSummary {
                kind,
                file_count,
                total_bytes,
                display_name: name,
            };
        }
        // Multiple files: all share a common first component → folder.
        let first_components: Vec<&str> = m
            .files
            .iter()
            .filter_map(|f| f.rel_path.split('/').find(|s| !s.is_empty()))
            .collect();
        if first_components.len() == file_count {
            let all_dirs = m.files.iter().all(|f| {
                f.rel_path
                    .split('/')
                    .filter(|s| !s.is_empty())
                    .nth(1)
                    .is_some()
            });
            let first_name = first_components[0];
            let same_name = first_components.iter().all(|c| *c == first_name);
            if all_dirs && same_name && !first_name.is_empty() {
                return TransferSummary {
                    kind: TransferKind::Folder,
                    file_count,
                    total_bytes,
                    display_name: first_name.to_string(),
                };
            }
        }
        TransferSummary {
            kind: TransferKind::Files,
            file_count,
            total_bytes,
            display_name: String::new(),
        }
    }
}

#[derive(Default, Clone, Copy)]
pub struct NoopProgress;

impl Progress for NoopProgress {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{FileEntry, Manifest};
    use std::path::PathBuf;

    fn entry(id: u32, rel: &str, size: u64) -> FileEntry {
        FileEntry {
            id,
            rel_path: rel.to_string(),
            size,
            chunk_size: 1024,
            chunk_hashes: Vec::new(),
        }
    }

    fn manifest_with(rels: &[&str]) -> Manifest {
        let files = rels
            .iter()
            .enumerate()
            .map(|(i, r)| entry(i as u32, r, 10))
            .collect();
        Manifest {
            files,
            chunk_size: 1024,
            source_root: PathBuf::from("/tmp"),
        }
    }

    #[test]
    fn single_file_classified_as_single_file() {
        let m = manifest_with(&["hello.txt"]);
        let s = TransferSummary::from_manifest(&m);
        assert_eq!(s.kind, TransferKind::SingleFile);
        assert_eq!(s.display_name, "hello.txt");
        assert_eq!(s.file_count, 1);
    }

    #[test]
    fn single_directory_classified_as_folder() {
        // Single dir input: rel_paths are prefixed with the dir name
        // (myrepo/a.bin, myrepo/sub/b.bin).
        let m = manifest_with(&["myrepo/a.bin", "myrepo/sub/b.bin"]);
        let s = TransferSummary::from_manifest(&m);
        assert_eq!(s.kind, TransferKind::Folder);
        assert_eq!(s.display_name, "myrepo");
        assert_eq!(s.file_count, 2);
    }

    #[test]
    fn folder_name_with_space_classified_as_folder() {
        // Regression: a folder name with a space (e.g. "Piete de Hooch")
        // used to confuse the classifier because the old code split
        // rel_path with Path::components which on Windows treats
        // backslashes as separators. With forward-slash-only rel_paths
        // the first component is the folder name as a single piece.
        let m = manifest_with(&[
            "Piete de Hooch/readme.txt",
            "Piete de Hooch/figures/fig5.jpg",
        ]);
        let s = TransferSummary::from_manifest(&m);
        assert_eq!(s.kind, TransferKind::Folder);
        assert_eq!(s.display_name, "Piete de Hooch");
    }

    #[test]
    fn mixed_inputs_classified_as_files() {
        // Multi input with file + dir → rel_paths are flat (a.txt, sub/x.bin),
        // no common top-level directory → Files.
        let m = manifest_with(&["a.txt", "sub/x.bin"]);
        let s = TransferSummary::from_manifest(&m);
        assert_eq!(s.kind, TransferKind::Files);
        assert_eq!(s.file_count, 2);
    }

    #[test]
    fn two_directories_classified_as_files() {
        // Two directory inputs (multi input case) → rel_paths are
        // dir1/a.bin, dir2/b.bin; no common root component → Files.
        let m = manifest_with(&["dir1/a.bin", "dir2/b.bin"]);
        let s = TransferSummary::from_manifest(&m);
        assert_eq!(s.kind, TransferKind::Files);
    }
}
