//! Transfer progress UI.
//!
//! Layout (one line per file, updated in place with a carriage return):
//!
//! ```text
//! lanx · receiving
//! Receiving folder `myrepo` (17 files, 36.2 MiB)
//!   [ 1/17] Berchem_fig_2.jpg           13.39 MiB / 13.39 MiB  100% ✓
//!   [ 2/17] Charles_de_hooch_fig_1.jpg   2.10 MiB /  5.34 MiB   39% ▕████▏          3.21 MiB/s
//!   [ 3/17] readme.txt                   · skipped (already present)
//!   ✓ Done — 17 verified, 0 failed, 0 skipped  (36.2 MiB / 36.2 MiB)
//! ```
//!
//! The header is printed once when the manifest arrives. Each file gets
//! one line; the in-flight file is updated in place with `\r` while
//! finished files keep their line. New files appear on a fresh line so
//! the per-file lines accumulate up the screen.
//!
//! All color/glyph styling goes through `crate::ui`, which auto-disables
//! ANSI when stderr is not a TTY — so piped output stays plain and
//! greppable (important on Windows where redirected stderr used to
//! collect stray escape sequences).

use crate::ui;
use lanx_core::manifest::{FileId, Manifest};
use lanx_core::progress::{Progress, TransferKind, TransferSummary};
use std::collections::HashMap;
use std::io::Write;
use std::sync::{Arc, Mutex};

/// Per-file state used to render a single line per file.
#[derive(Clone)]
struct FileState {
    /// Bytes transferred so far for this file.
    bytes: u64,
    /// Whether the file's transfer has finished.
    done: bool,
    /// Whether the file's transfer succeeded (only meaningful when
    /// `done` is true).
    ok: bool,
    /// True when the file was skipped because the receiver already had
    /// it (no `started` event preceded `file_done`).
    skipped: bool,
    /// Throughput tracker, seeded with the resume offset at `started`.
    rate: ui::Rate,
}

/// Transfer progress UI for both sender and receiver.
///
/// **Thread safety note:** This struct uses separate `Mutex`es for each
/// field (`state`, `sizes`, `rel_paths`, etc.) rather than a single
/// combined lock. This is safe because the wire protocol is strictly
/// sequential — one file at a time, one event at a time — so there are
/// no concurrent mutations across fields. If the protocol ever becomes
/// parallel (e.g. multiple files streamed concurrently), these must be
/// consolidated into a single `Mutex<RenderState>` or replaced with
/// lock-free atomics.
pub struct IndicatifProgress {
    verb: &'static str,
    /// Pre-computed list of `rel_paths` (for label rendering and
    /// collision detection).
    rel_paths: Mutex<Vec<String>>,
    /// Per-file state, keyed by `FileId`.
    state: Mutex<HashMap<FileId, FileState>>,
    /// Per-file sizes, populated in `manifest_received` so we can render
    /// skip lines and finalize the byte count even when a file never
    /// fires `started`.
    sizes: Mutex<HashMap<FileId, u64>>,
    /// Total bytes expected across all files.
    total_bytes: Mutex<u64>,
    /// Running total of bytes confirmed at the file level (sum of
    /// fully-completed file sizes).
    bytes_sent: Mutex<u64>,
    /// Number of files in the manifest.
    file_count: Mutex<u64>,
    /// Number of files verified successfully.
    verified: Mutex<u64>,
    /// Number of files that failed verification.
    failed: Mutex<u64>,
    /// Number of files skipped (already present).
    skipped: Mutex<u64>,
}

/// Build the one-line transfer header used by both sides. The sender
/// prints a "Sending …" line, the receiver a "Receiving …" line in
/// `IndicatifProgress::manifest_received`. Styling auto-disables when
/// stderr is not a TTY.
pub fn transfer_header(verb: &str, m: &Manifest) -> String {
    let summary = TransferSummary::from_manifest(m);
    let human_size = ui::human_bytes(summary.total_bytes);
    match &summary.kind {
        TransferKind::Folder => format!(
            "{} folder `{}` ({} files, {})",
            ui::bold(verb),
            ui::bold(&summary.display_name),
            summary.file_count,
            ui::dim(&human_size),
        ),
        TransferKind::SingleFile => format!(
            "{} file `{}` ({})",
            ui::bold(verb),
            ui::bold(&summary.display_name),
            ui::dim(&human_size),
        ),
        TransferKind::Files => format!(
            "{} {} files ({})",
            ui::bold(verb),
            summary.file_count,
            ui::dim(&human_size),
        ),
    }
}

impl IndicatifProgress {
    pub fn new(verb: &'static str) -> Arc<Self> {
        Arc::new(Self {
            verb,
            rel_paths: Mutex::new(Vec::new()),
            state: Mutex::new(HashMap::new()),
            sizes: Mutex::new(HashMap::new()),
            total_bytes: Mutex::new(0),
            bytes_sent: Mutex::new(0),
            file_count: Mutex::new(0),
            verified: Mutex::new(0),
            failed: Mutex::new(0),
            skipped: Mutex::new(0),
        })
    }

    /// Display label for a file: basename, or `parent/basename`
    /// for collisions, middle-truncated to fit `max` characters.
    fn label_for(rel_paths: &[String], rel: &str, max: usize) -> String {
        let basename = rel.rsplit('/').next().unwrap_or(rel);
        let collision_count = rel_paths.iter().filter(|r| r.ends_with(basename)).count();
        let full = if collision_count > 1 {
            let parent = rel
                .rsplit_once('/')
                .map(|(p, _)| p.rsplit('/').next().unwrap_or(""))
                .unwrap_or("");
            if parent.is_empty() {
                rel.to_string()
            } else {
                format!("{parent}/{basename}")
            }
        } else {
            basename.to_string()
        };
        truncate_middle(&full, max)
    }

    /// Render the per-file line for `id`. On first render (`fresh_line`)
    /// this prints a fresh line; on subsequent renders the previous line
    /// is overwritten with a carriage return. The file's manifest index
    /// is used as the `[N/M]` counter.
    fn render_file(&self, id: FileId, fresh_line: bool) {
        let (label, bytes, total, file_idx, file_count, done, ok, skipped, rate_bps) = {
            let state = self.state.lock().unwrap();
            let sizes = self.sizes.lock().unwrap();
            let rels = self.rel_paths.lock().unwrap();
            let entry = match state.get(&id) {
                Some(s) => s,
                None => return,
            };
            let total = sizes.get(&id).copied().unwrap_or(0);
            let rel = rels.get(id as usize).cloned().unwrap_or_default();
            let file_count = *self.file_count.lock().unwrap();
            (
                rel,
                entry.bytes,
                total,
                id.saturating_add(1),
                file_count,
                entry.done,
                entry.ok,
                entry.skipped,
                entry.rate.bps(),
            )
        };

        let width = ui::term_width();
        // Column budget: prefix + label + size + percent + bar + status.
        // Keep the label adaptive so narrow terminals still fit.
        let prefix = format!("  [{:>2}/{}]  ", file_idx, file_count);
        // Fixed cost outside the label: prefix + " X.XX MiB / Y.YY MiB  NN%" + spacing.
        let fixed = prefix.chars().count() + 23 + 6;
        let label_max = width.saturating_sub(fixed).clamp(16, 40);
        let label = Self::label_for(&self.rel_paths.lock().unwrap(), &label, label_max);

        let pct = ui::percent(bytes, total);

        let mut line = String::new();
        line.push_str(&prefix);
        line.push_str(&ui::pad_visible(&label, label_max));
        line.push_str("  ");
        line.push_str(&format!(
            "{:>8} / {:<8}",
            ui::human_bytes(bytes),
            ui::human_bytes(total),
        ));

        if skipped {
            // Skipped files have no byte flow to show; surface the
            // reason instead of a percentage.
            line.push_str(&format!("  {}", ui::dim("skipped (already present)")));
        } else if total > 0 {
            line.push_str(&format!("  {:>3}%", pct));
            // Bar only when there's room; skip on narrow terminals.
            let remaining = width.saturating_sub(ui::strip_ansi(&line).chars().count());
            if remaining >= 10 {
                let bar_w = remaining.min(20).saturating_sub(2);
                let bar = ui::mini_bar(bytes, total, bar_w);
                if !bar.is_empty() {
                    line.push(' ');
                    line.push_str(&bar);
                }
            }
            // Throughput for the in-flight file.
            if !done {
                let r = ui::human_rate(rate_bps);
                if !r.is_empty() {
                    line.push(' ');
                    line.push_str(&ui::dim(&r));
                }
            }
        }

        // Status tail. Skipped files already carry a "skipped" note in
        // the body, so they don't get a redundant trailing glyph.
        if done {
            if ok && !skipped {
                line.push(' ');
                line.push_str(&ui::green(ui::ok_sym()));
            } else if !ok {
                line.push(' ');
                line.push_str(&ui::red(ui::fail_sym()));
            }
        }

        // Pad to terminal width with spaces (visible-width-aware) so the
        // previous, longer line is fully cleared before we move on.
        let line = ui::pad_visible(&line, width);

        let stderr = std::io::stderr();
        let mut handle = stderr.lock();
        if !fresh_line {
            let _ = handle.write_all(b"\r");
        }
        let _ = write!(handle, "{line}");
        let _ = handle.flush();
    }
}

impl Progress for IndicatifProgress {
    fn manifest_received(&self, manifest: &Manifest, summary: &TransferSummary) {
        *self.rel_paths.lock().unwrap() =
            manifest.files.iter().map(|f| f.rel_path.clone()).collect();
        *self.total_bytes.lock().unwrap() = summary.total_bytes;
        *self.file_count.lock().unwrap() = manifest.files.len() as u64;
        // Pre-populate sizes so skip lines and final byte totals are
        // available even for files that never fire `started`.
        {
            let mut sizes = self.sizes.lock().unwrap();
            for f in &manifest.files {
                sizes.insert(f.id, f.size);
            }
        }

        // Single-line header.
        eprintln!("{}", transfer_header(self.verb, manifest));
    }

    fn started(&self, id: FileId, _rel: &str, total: u64, offset: u64) {
        self.sizes.lock().unwrap().insert(id, total);
        self.state.lock().unwrap().insert(
            id,
            FileState {
                bytes: offset,
                done: false,
                ok: false,
                skipped: false,
                rate: ui::Rate::new(offset),
            },
        );
        // Fresh line for each new file. We rely on the protocol being
        // sequential (one file at a time) so this only fires for the
        // *next* file, not a retry of an existing one. If it does fire
        // for a retry, the `\r ... done` will overwrite the previous
        // line — fine.
        self.render_file(id, true);
    }

    fn chunk_done(&self, id: FileId, bytes: u64) {
        {
            let mut state = self.state.lock().unwrap();
            if let Some(s) = state.get_mut(&id) {
                s.bytes = s.bytes.saturating_add(bytes);
                s.rate.observe(s.bytes);
            }
        }
        // Re-render in place.
        self.render_file(id, false);
    }

    fn file_done(&self, id: FileId, ok: bool) {
        let was_started = {
            let mut state = self.state.lock().unwrap();
            if let Some(s) = state.get_mut(&id) {
                s.done = true;
                s.ok = ok;
                if ok {
                    s.bytes = self
                        .sizes
                        .lock()
                        .unwrap()
                        .get(&id)
                        .copied()
                        .unwrap_or(s.bytes);
                }
                true
            } else {
                false
            }
        };

        if !was_started {
            // No `started` preceded this → the file was skipped because
            // the receiver already had it, or it failed before starting.
            // Record a state entry so the line renders and counts stay
            // consistent. Use the caller's `ok` value rather than
            // assuming skip = success.
            let total = self.sizes.lock().unwrap().get(&id).copied().unwrap_or(0);
            self.state.lock().unwrap().insert(
                id,
                FileState {
                    bytes: total,
                    done: true,
                    ok,
                    skipped: ok,
                    rate: ui::Rate::new(total),
                },
            );
            if ok {
                *self.skipped.lock().unwrap() += 1;
            } else {
                *self.failed.lock().unwrap() += 1;
            }
            self.render_file(id, true);
            return;
        }

        if ok {
            if let Some(size) = self.sizes.lock().unwrap().get(&id).copied() {
                let mut sent = self.bytes_sent.lock().unwrap();
                *sent = sent.saturating_add(size);
            }
            *self.verified.lock().unwrap() += 1;
        } else {
            *self.failed.lock().unwrap() += 1;
        }
        // Final render of the file's line with the status symbol.
        self.render_file(id, false);
    }

    fn summary(&self, verified: usize, failed: usize, skipped: usize) {
        // Trust the caller's counts (the receiver aggregates them
        // authoritatively) but also fold in any locally-tracked skips
        // so both sides agree when the caller passes zeros.
        let skipped = skipped.max(*self.skipped.lock().unwrap() as usize);
        let sent = *self.bytes_sent.lock().unwrap();
        let total = *self.total_bytes.lock().unwrap();

        let head = if failed == 0 {
            if ui::is_tty() {
                format!("{} {}", ui::green(ui::ok_sym()), ui::green("Done"))
            } else {
                "Done".to_string()
            }
        } else if ui::is_tty() {
            format!("{} {}", ui::red(ui::fail_sym()), ui::red("Done"))
        } else {
            "Done (with failures)".to_string()
        };

        let mut parts = Vec::new();
        parts.push(format!("{} verified", ui::green(&verified.to_string())));
        if failed > 0 {
            parts.push(format!("{} failed", ui::red(&failed.to_string())));
        } else {
            parts.push(format!("{} failed", ui::dim(&failed.to_string())));
        }
        if skipped > 0 {
            parts.push(format!("{} skipped", ui::dim(&skipped.to_string())));
        }

        let progress = format!("({} / {})", ui::human_bytes(sent), ui::human_bytes(total));
        eprintln!();
        eprintln!(
            "  {} {} {}  {}",
            head,
            ui::sep_dash(),
            parts.join(", "),
            ui::dim(&progress),
        );
    }
}

/// Middle-truncate `s` to fit within `max` characters. Preserves the
/// file extension at the end.
fn truncate_middle(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    if max < 5 {
        return s
            .chars()
            .rev()
            .take(max)
            .collect::<String>()
            .chars()
            .rev()
            .collect();
    }
    let (base, ext) = match s.rfind('.') {
        Some(i) if i > 0 && !s[i..].contains('/') => (&s[..i], &s[i..]),
        _ => (s, ""),
    };
    let ext_keep = if !ext.is_empty() {
        ext.chars().take(max.saturating_sub(4)).collect::<String>()
    } else {
        String::new()
    };
    let head_budget = max.saturating_sub(ext_keep.chars().count() + 1).max(2);
    let prefix: String = base.chars().take(head_budget).collect();
    format!("{prefix}…{ext_keep}")
}
