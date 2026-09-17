//! Machine-readable transfer progress: one JSON object per line on stdout.
//!
//! Enabled with `lanx recv --json`. While active:
//!
//! - stdout carries JSON Lines events only (no human progress);
//! - stderr carries warnings/errors only;
//! - the final event is always `summary` and includes totals plus status.
//!
//! ## Schema
//!
//! Every line is a JSON object with an `event` field. Event names are
//! stable; new optional fields may be added over time.
//!
//! ```text
//! {"event":"manifest","files":12,"bytes":1048576}
//! {"event":"file_started","id":0,"path":"docs/guide.md","size":1024,"offset":0}
//! {"event":"file_done","id":0,"ok":true}
//! {"event":"summary","verified":11,"failed":0,"skipped":1,"status":"ok"}
//! ```
//!
//! - `manifest`: emitted once when the sender's manifest is received.
//!   `files` is the file count, `bytes` the total byte count.
//! - `file_started`: a file transfer began. `id` is the manifest file id,
//!   `path` the wire-form relative path, `size` the expected bytes,
//!   `offset` the resume offset.
//! - `file_done`: a file finished (`ok: true`) or failed (`ok: false`).
//! - `summary`: the final event. `verified` / `failed` / `skipped` are
//!   file counts; `status` is `"ok"` when nothing failed, else `"error"`.

use lanx_core::manifest::{FileId, Manifest};
use lanx_core::progress::{Progress, TransferSummary};
use std::io::Write;
use std::sync::Mutex;

/// [`Progress`] implementation that emits JSON Lines events on a writer
/// (stdout in production). Safe for concurrent use across parallel
/// connections.
pub struct JsonProgress {
    out: Mutex<Box<dyn Write + Send>>,
}

impl JsonProgress {
    /// Report to stdout.
    pub fn new() -> std::sync::Arc<Self> {
        Self::with_writer(Box::new(std::io::stdout()))
    }

    /// Report to `writer`. Used by tests to capture the event stream.
    pub fn with_writer(writer: Box<dyn Write + Send>) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            out: Mutex::new(writer),
        })
    }

    fn emit(&self, value: serde_json::Value) {
        let mut out = self.out.lock().unwrap_or_else(|p| p.into_inner());
        let _ = writeln!(out, "{value}");
        let _ = out.flush();
    }
}

impl Default for JsonProgress {
    fn default() -> Self {
        Self {
            out: Mutex::new(Box::new(std::io::stdout())),
        }
    }
}

impl Progress for JsonProgress {
    fn manifest_received(&self, manifest: &Manifest, summary: &TransferSummary) {
        let _ = manifest.files.len();
        self.emit(serde_json::json!({
            "event": "manifest",
            "files": summary.file_count,
            "bytes": summary.total_bytes,
        }));
    }

    fn started(&self, id: FileId, rel: &str, total: u64, offset: u64) {
        self.emit(serde_json::json!({
            "event": "file_started",
            "id": id,
            "path": rel,
            "size": total,
            "offset": offset,
        }));
    }

    fn chunk_done(&self, _id: FileId, _bytes: u64) {}

    fn file_done(&self, id: FileId, ok: bool) {
        self.emit(serde_json::json!({
            "event": "file_done",
            "id": id,
            "ok": ok,
        }));
    }

    fn summary(&self, verified: usize, failed: usize, skipped: usize) {
        self.emit(serde_json::json!({
            "event": "summary",
            "verified": verified,
            "failed": failed,
            "skipped": skipped,
            "status": if failed == 0 { "ok" } else { "error" },
        }));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lanx_core::manifest::{FileEntry, Manifest};
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct SharedBuf(Arc<Mutex<Vec<u8>>>);

    impl Write for SharedBuf {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn manifest() -> (Manifest, TransferSummary) {
        let m = Manifest {
            files: vec![FileEntry {
                id: 0,
                rel_path: "a.txt".to_string(),
                size: 11,
                chunk_size: 1024,
                chunk_hashes: vec![],
            }],
            chunk_size: 1024,
            source_root: PathBuf::new(),
        };
        let s = TransferSummary::from_manifest(&m);
        (m, s)
    }

    #[test]
    fn emits_stable_events_and_final_summary() {
        let buf = SharedBuf::default();
        let out: Box<dyn Write + Send> = Box::new(buf.clone());
        let progress = JsonProgress::with_writer(out);
        let (m, s) = manifest();
        progress.manifest_received(&m, &s);
        progress.started(0, "a.txt", 11, 0);
        progress.file_done(0, true);
        progress.summary(1, 0, 0);

        let text = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 4, "expected 4 JSONL events, got {text:?}");
        let events: Vec<serde_json::Value> = lines
            .iter()
            .map(|l| serde_json::from_str(l).expect("each line is valid JSON"))
            .collect();
        assert_eq!(events[0]["event"], "manifest");
        assert_eq!(events[0]["files"], 1);
        assert_eq!(events[0]["bytes"], 11);
        assert_eq!(events[1]["event"], "file_started");
        assert_eq!(events[1]["path"], "a.txt");
        assert_eq!(events[2]["event"], "file_done");
        assert_eq!(events[2]["ok"], true);
        assert_eq!(events[3]["event"], "summary");
        assert_eq!(events[3]["verified"], 1);
        assert_eq!(events[3]["status"], "ok");
    }

    #[test]
    fn summary_reports_error_status_on_failure() {
        let buf = SharedBuf::default();
        let out: Box<dyn Write + Send> = Box::new(buf.clone());
        let progress = JsonProgress::with_writer(out);
        progress.summary(0, 1, 0);
        let text = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        let event: serde_json::Value = serde_json::from_str(text.trim()).unwrap();
        assert_eq!(event["event"], "summary");
        assert_eq!(event["status"], "error");
    }
}
