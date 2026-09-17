//! Transfer progress UI.
//!
//! Shape of a transfer on screen:
//!
//! ```text
//!   ✓ found sender 192.168.1.120:29320
//!   Theo_Kirk_CV.pdf          48.9 KiB      <- contents (sender lists
//!                                              them, receiver approves them)
//!   ████████████████████████  48.9 KiB / 48.9 KiB   <- live rows
//!   ✓ Done · 1 file · 48.9 KiB                     <- result
//! ```
//!
//! One live row per in-flight file, updated in place with a carriage
//! return; finished rows keep their line. Skipped files print a single
//! `– <name> already present` line and never enter a fake active
//! state.
//!
//! All color/glyph styling goes through `crate::ui`, which falls back
//! to plain ASCII when animation is unsafe (piped output, `TERM=dumb`,
//! `LANX_PLAIN`) so logs stay greppable.

use crate::ui;
use lanx_core::manifest::{FileId, Manifest};
use lanx_core::progress::{Progress, TransferSummary};
use std::collections::HashMap;
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// All mutable progress state is held under a single mutex so the UI is
/// safe when multiple TCP connections report events concurrently.
struct RenderState {
    /// Pre-computed list of `rel_paths` (for label rendering and
    /// collision detection).
    rel_paths: Vec<String>,
    /// Per-file state, keyed by `FileId`.
    state: HashMap<FileId, FileState>,
    /// Per-file sizes, populated in `manifest_received` so we can render
    /// skip lines and finalize the byte count even when a file never
    /// fires `started`.
    sizes: HashMap<FileId, u64>,
    /// Total bytes expected across all files.
    total_bytes: u64,
    /// Running total of bytes confirmed at the file level (sum of
    /// fully-completed file sizes).
    bytes_sent: u64,
    /// Number of files in the manifest.
    file_count: u64,
    /// Number of files verified successfully.
    verified: u64,
    /// Number of files that failed verification.
    failed: u64,
    /// Number of files skipped (already present).
    skipped: u64,
    /// Last printed percent per file in non-animated mode, so piped
    /// logs get one line per 10% bucket instead of one per chunk.
    last_pct: HashMap<FileId, u32>,
}

/// How often an in-flight file line re-renders on an animated
/// terminal. Chunk events can arrive hundreds of times per second;
/// faster than this the line just flickers and wastes SSH bandwidth.
const RENDER_THROTTLE: std::time::Duration = std::time::Duration::from_millis(120);

/// Percent step between printed lines in non-animated mode (piped
/// output, dumb terminals). Start/finish lines always print.
const PLAIN_PCT_STEP: u32 = 10;

/// Pure helper behind the non-animated print gate, unit tested below.
fn should_print_plain(last: u32, pct: u32, done: bool) -> bool {
    if done {
        return true;
    }
    pct >= 100 || pct >= last.saturating_add(PLAIN_PCT_STEP)
}

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
    /// Last time this file's line was drawn on an animated terminal.
    last_render: Instant,
}

/// Transfer progress UI for both sender and receiver.
pub struct IndicatifProgress {
    done_word: &'static str,
    state: Mutex<RenderState>,
}

impl IndicatifProgress {
    pub fn new(verb: &'static str) -> Arc<Self> {
        // Past-tense result word: the sender reports what it sent,
        // the receiver reports completion.
        let done_word = match verb {
            "Sending" => "Sent",
            _ => "Done",
        };
        Arc::new(Self {
            done_word,
            state: Mutex::new(RenderState {
                rel_paths: Vec::new(),
                state: HashMap::new(),
                sizes: HashMap::new(),
                total_bytes: 0,
                bytes_sent: 0,
                file_count: 0,
                verified: 0,
                failed: 0,
                skipped: 0,
                last_pct: HashMap::new(),
            }),
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
        let (label, bytes, total, file_idx, file_count, done, ok, skipped, rate_bps, rel_paths) = {
            let st = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let entry = match st.state.get(&id) {
                Some(s) => s.clone(),
                None => return,
            };
            let total = st.sizes.get(&id).copied().unwrap_or(0);
            let rel = st.rel_paths.get(id as usize).cloned().unwrap_or_default();
            let file_count = st.file_count;
            let rel_paths = st.rel_paths.clone();
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
                rel_paths,
            )
        };

        let width = ui::term_width();
        // Column budget: prefix + label + size + percent + bar + status.
        // Keep the label adaptive so narrow terminals still fit.
        let prefix = format!("  [{:>2}/{}]  ", file_idx, file_count);
        // Fixed cost outside the label: prefix + " X.XX MiB / Y.YY MiB  NN%" + spacing.
        let fixed = prefix.chars().count() + 23 + 6;
        let label_max = width.saturating_sub(fixed).clamp(16, 40);
        let label = Self::label_for(&rel_paths, &label, label_max);

        let pct = ui::percent(bytes, total);

        // Without animation (piped logs, dumb terminals) every chunk
        // would become its own log line. Start lines (`fresh_line`)
        // and finish lines always print; in-between lines print per
        // 10% bucket only.
        if !ui::animated() && !fresh_line && !skipped {
            let mut st = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let last = st.last_pct.get(&id).copied().unwrap_or(0);
            if !should_print_plain(last, pct, done) {
                return;
            }
            st.last_pct.insert(id, pct);
        }

        let mut line = String::new();
        if skipped {
            // Skipped files never enter an active state: one quiet
            // no-op line instead of a progress row.
            line.push_str("  ");
            line.push_str(ui::skip_sym());
            line.push(' ');
            line.push_str(&ui::pad_visible(&label, label_max));
            line.push_str("  ");
            line.push_str(&ui::dim("already present"));
            write_line(&line, width, fresh_line);
            return;
        }
        line.push_str(&prefix);
        line.push_str(&ui::pad_visible(&label, label_max));
        line.push_str("  ");
        line.push_str(&format!(
            "{:>8} / {:<8}",
            ui::human_bytes(bytes),
            ui::human_bytes(total),
        ));

        if total > 0 {
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

        // Status tail.
        if done {
            if ok {
                line.push(' ');
                line.push_str(&ui::green(ui::ok_sym()));
            } else {
                line.push(' ');
                line.push_str(&ui::red(ui::fail_sym()));
            }
        }

        write_line(&line, width, fresh_line);
    }
}

/// Clamp `line` to the terminal width so it never wraps (a wrapped
/// line breaks the in-place `\r` update into stacked lines), pad it
/// so a previous, longer line is fully cleared, then emit it: in
/// place on animated terminals, as its own plain line otherwise.
fn write_line(line: &str, width: usize, fresh_line: bool) {
    // Clamp to the terminal width so the line never wraps (a
    // wrapped line breaks the in-place `\r` update into stacked
    // lines), then pad to the full width so the previous, longer
    // line is fully cleared before we move on.
    let line = ui::truncate_visible(line, width);
    let line = ui::pad_visible(&line, width);

    let stderr = std::io::stderr();
    let mut handle = stderr.lock();
    if ui::animated() {
        // Erase the previous render before writing the new one.
        // `\r` alone leaves stale characters when the line shrank;
        // ESC[2K clears from the cursor to end of line. Dumb
        // terminals take the plain-line path below instead: they
        // may not understand either sequence.
        if !fresh_line {
            let _ = handle.write_all(b"\r");
            let _ = handle.write_all(b"\x1b[2K");
        }
        let _ = write!(handle, "{line}");
        let _ = handle.flush();
    } else {
        // Not animated (redirected/piped output, dumb terminal):
        // print each state as its own plain line. No carriage
        // returns, no padding, no ANSI - keeps logs greppable.
        let _ = writeln!(handle, "{}", ui::strip_ansi(&line).trim_end());
    }
}

impl Progress for IndicatifProgress {
    fn manifest_received(&self, manifest: &Manifest, summary: &TransferSummary) {
        let mut st = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // With parallel connections, multiple `run_sender` instances
        // call this with the same manifest.
        if !st.rel_paths.is_empty() {
            return;
        }
        st.rel_paths = manifest.files.iter().map(|f| f.rel_path.clone()).collect();
        st.total_bytes = summary.total_bytes;
        st.file_count = manifest.files.len() as u64;
        for f in &manifest.files {
            st.sizes.insert(f.id, f.size);
        }
        // No header line: the sender lists contents explicitly after
        // connecting and the receiver shows them in the approval
        // prompt, so a third listing here would only repeat them.
    }

    fn started(&self, id: FileId, _rel: &str, total: u64, offset: u64) {
        let mut st = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        st.sizes.insert(id, total);
        st.state.insert(
            id,
            FileState {
                bytes: offset,
                done: false,
                ok: false,
                skipped: false,
                rate: ui::Rate::new(offset),
                last_render: Instant::now(),
            },
        );
        // Fresh line for each new file. When multiple connections are
        // active, files may start out of order; `fresh_line=true` prints
        // each new file on its own line.
        drop(st);
        self.render_file(id, true);
    }

    fn chunk_done(&self, id: FileId, bytes: u64) {
        let should_render = {
            let mut st = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            match st.state.get_mut(&id) {
                Some(s) => {
                    s.bytes = s.bytes.saturating_add(bytes);
                    s.rate.observe(s.bytes);
                    // Animated terminals re-draw at most ~8Hz; faster
                    // than that the line flickers and wastes bandwidth
                    // (matters over SSH). Plain mode has its own
                    // percent-bucket gate inside `render_file`.
                    if ui::animated() {
                        let now = Instant::now();
                        if now.duration_since(s.last_render) < RENDER_THROTTLE {
                            false
                        } else {
                            s.last_render = now;
                            true
                        }
                    } else {
                        true
                    }
                }
                None => false,
            }
        };
        if should_render {
            // Re-render in place.
            self.render_file(id, false);
        }
    }

    fn file_done(&self, id: FileId, ok: bool) {
        let mut st = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let size_opt = st.sizes.get(&id).copied();
        let was_started = if let Some(s) = st.state.get_mut(&id) {
            s.done = true;
            s.ok = ok;
            if ok {
                s.bytes = size_opt.unwrap_or(s.bytes);
            }
            true
        } else {
            false
        };

        if !was_started {
            // No `started` preceded this → the file was skipped because
            // the receiver already had it, or it failed before starting.
            // Record a state entry so the line renders and counts stay
            // consistent. Use the caller's `ok` value rather than
            // assuming skip = success.
            let total = st.sizes.get(&id).copied().unwrap_or(0);
            st.state.insert(
                id,
                FileState {
                    bytes: total,
                    done: true,
                    ok,
                    skipped: ok,
                    rate: ui::Rate::new(total),
                    last_render: Instant::now(),
                },
            );
            if ok {
                st.skipped += 1;
            } else {
                st.failed += 1;
            }
            drop(st);
            self.render_file(id, true);
            return;
        }

        if ok {
            if let Some(size) = st.sizes.get(&id).copied() {
                st.bytes_sent = st.bytes_sent.saturating_add(size);
            }
            st.verified += 1;
        } else {
            st.failed += 1;
        }
        drop(st);
        // Final render of the file's line with the status symbol.
        self.render_file(id, false);
    }

    fn summary(&self, verified: usize, failed: usize, skipped: usize) {
        // Trust the caller's counts (the receiver aggregates them
        // authoritatively) but also fold in any locally-tracked skips
        // so both sides agree when the caller passes zeros.
        let st = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let skipped = skipped.max(st.skipped as usize);
        let sent = st.bytes_sent;
        let done_word = self.done_word.to_string();

        // Only counters that matter: zero-valued ones stay hidden, and
        // byte accounting appears only when bytes actually moved.
        let mut segs: Vec<String> = Vec::new();
        if verified > 0 {
            let word = if verified == 1 { "file" } else { "files" };
            segs.push(format!("{verified} {word}"));
            segs.push(ui::human_bytes(sent));
        }
        if skipped > 0 {
            segs.push(format!("{skipped} skipped"));
        }
        if failed > 0 {
            segs.push(format!("{} failed", ui::red(&failed.to_string())));
        }

        let body = segs.join(&format!(" {} ", ui::sep_dot()));
        eprintln!();
        if failed > 0 {
            let mark = if ui::animated() {
                ui::yellow("!")
            } else {
                "!".to_string()
            };
            eprintln!("  {mark} {} {body}", ui::red(&done_word));
        } else if ui::animated() {
            eprintln!(
                "  {} {} {body}",
                ui::green(ui::ok_sym()),
                ui::green(&done_word)
            );
        } else {
            eprintln!("  {done_word} {body}");
        }
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
    if ui::use_unicode() {
        format!("{prefix}…{ext_keep}")
    } else {
        format!("{prefix}...{ext_keep}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_gate_prints_start_finish_and_buckets() {
        // fresh_line (file start) and done (file finish) are handled by
        // the caller; the gate only covers in-between updates.
        assert!(should_print_plain(0, 0, true));
        assert!(should_print_plain(90, 91, true));
        // Buckets of 10%: 0->9 silent, 0->10 prints.
        assert!(!should_print_plain(0, 9, false));
        assert!(should_print_plain(0, 10, false));
        assert!(!should_print_plain(10, 19, false));
        assert!(should_print_plain(10, 20, false));
        // Completion always prints even mid-bucket.
        assert!(should_print_plain(92, 100, false));
    }
}
