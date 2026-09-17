//! Transfer progress UI.
//!
//! Shape of a transfer on screen:
//!
//! ```text
//!   ✓ found sender  192.168.1.120:29320
//!   sketch.png                48.9 KiB      <- contents (receiver
//!                                              approves them here)
//!   [1/1] sketch.png    ▕████████████████▏  100%   48.9 KiB / 48.9 KiB
//!   [1/1] sketch.png                     48.9 KiB ✓   <- collapsed result
//!   ✓ Done · 1 file · 48.9 KiB                     <- result
//! ```
//!
//! Live rows read `[n/m] name  bar  percent  size  rate  eta  mark`:
//! the bar is capped at 16 cells so the filename keeps the space,
//! and only one size value prints (both absolute values on every
//! redraw wasted the line). Skipped files print a single
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

/// Files below this size skip opening and mid-flight rows and jump
/// straight to their completed row. A 41 B file's bar conveys
/// nothing; the result row says everything.
const SMALL_FILE_MAX: u64 = 64 * 1024;

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
    /// Whether a live (in-flight) row for this file is currently
    /// displayed. Used to erase it on completion instead of leaving
    /// a redundant result row behind.
    live_shown: bool,
}

/// Transfer progress UI for both sender and receiver.
pub struct IndicatifProgress {
    done_word: &'static str,
    state: Mutex<RenderState>,
}

impl IndicatifProgress {
    pub fn new(verb: &'static str) -> Arc<Self> {
        // Past-tense result word: the sender reports what it sent,
        // the receiver reports what it received. "Done" is reserved
        // for summaries where nothing moved (see `summary`).
        let done_word = match verb {
            "Sending" => "Sent",
            "Receiving" => "Received",
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

    /// Record that `id` currently owns a live row on screen, so its
    /// completion can erase that row instead of orphaning it.
    fn mark_live_shown(&self, id: FileId) {
        let mut st = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(s) = st.state.get_mut(&id) {
            s.live_shown = true;
        }
    }

    /// Render the per-file line for `id`. On first render (`fresh_line`)
    /// this starts a new terminal line; on subsequent renders the
    /// previous line is overwritten in place. The file's manifest index
    /// is used as the `[N/M]` counter.
    fn render_file(&self, id: FileId, fresh_line: bool) {
        let (bytes, total, file_idx, file_count, done, ok, skipped, rate_bps, rel_paths) = {
            let st = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let entry = match st.state.get(&id) {
                Some(s) => s.clone(),
                None => return,
            };
            let total = st.sizes.get(&id).copied().unwrap_or(0);
            let file_count = st.file_count;
            let rel_paths = st.rel_paths.clone();
            (
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
        let animated = ui::animated();
        // Uniform counter field so `[1/5]` and `[10/15]` rows align.
        let counter_w = format!("[{file_count}/{file_count}]").len();
        let counter = format!("{:<counter_w$}", format!("[{file_idx}/{file_count}]"));

        let pct = ui::percent(bytes, total);

        // Without animation (piped logs, dumb terminals) every chunk
        // would become its own log line. Start lines (`fresh_line`)
        // and finish lines always print; in-between lines print per
        // 10% bucket only.
        if !animated && !fresh_line && !skipped {
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

        // Names share one representation everywhere: the prompt
        // listing, live rows, and result rows all show the same
        // root-stripped relative path.
        let display = ui::display_names(&rel_paths);
        let name = display.get(id as usize).cloned().unwrap_or_default();

        // A two-line row's second line is always a continuation, never
        // an in-place rewrite (which would erase the first line).
        let row = RowLayout {
            counter: &counter,
            name: &name,
            bytes,
            total,
            done,
            ok,
            skipped,
            rate_bps,
            width,
            animated,
        };
        let mut first = true;
        for line in layout_row(&row) {
            write_line(&line, width, fresh_line && first);
            first = false;
        }
    }
}

/// Below this terminal width, finished rows split in two instead of
/// squeezing the path: a deliberately stacked pair reads as
/// intentional, while edge-wrapping reads as broken.
const NARROW_W: usize = 60;
/// Live bar width in cells. Capped so the filename keeps the space.
const BAR_W: usize = 16;
/// Filename column bounds in cells of display width.
const LABEL_MAX_W: usize = 32;
const LABEL_MIN_W: usize = 8;

/// Inputs to [`layout_row`]: one file's display state plus the
/// terminal it must fit.
struct RowLayout<'a> {
    counter: &'a str,
    name: &'a str,
    bytes: u64,
    total: u64,
    done: bool,
    ok: bool,
    skipped: bool,
    rate_bps: f64,
    width: usize,
    animated: bool,
}

/// Lay out one file row for `width`. Pure: no IO, so tests pin widths
/// without a real terminal. Returns one line, or two when `width` is
/// below [`NARROW_W`]. Callers must still clamp through `write_line`
/// as a final guarantee.
///
/// ```text
/// [1/5]  docs/guide/chapter1.md       already present   (done/skip)
/// [1/1]  big.bin  ▕███████░░░░░░░░░▏   73%   18.2 MiB / 25.0 MiB   (live)
/// ```
fn layout_row(row: &RowLayout<'_>) -> Vec<String> {
    let narrow = row.width < NARROW_W;
    let counter_w = ui::visible_width(row.counter);
    let indent = " ".repeat(counter_w);

    if row.skipped {
        // Skipped files never enter an active state and keep their
        // index: the transferred item starting at [5/5] explains
        // itself. The whole row dims as a no-op.
        let status = ui::dim("already present").to_string();
        if !narrow {
            let lw = label_budget(row.width, counter_w, ui::visible_width(&status));
            let label = truncate_middle(row.name, lw);
            return vec![format!(
                "{}  {}  {status}",
                ui::dim(row.counter),
                ui::pad_visible(&ui::dim(&label), lw),
            )];
        }
        let lw = row.width.saturating_sub(counter_w + 2).max(4);
        let label = truncate_middle(row.name, lw);
        return vec![
            format!("{}  {label}", ui::dim(row.counter)),
            format!("{indent}  {status}"),
        ];
    }

    if row.done {
        // Finished rows collapse to a quiet result: no bar, no
        // percent. `✓` means BLAKE3-verified, not merely 100%:
        // file_done(true) fires only after the hash checks out on
        // the receiver (and after the receiver confirms it on the
        // sender).
        let mark = if row.ok {
            ui::green(ui::ok_sym())
        } else {
            ui::red(ui::fail_sym())
        };
        let size = ui::human_bytes(row.total);
        let result = format!("{size} {mark}");
        let result_w = ui::visible_width(&result);
        if !narrow {
            let lw = label_budget(row.width, counter_w, result_w);
            let label = truncate_middle(row.name, lw);
            return vec![format!(
                "{}  {}  {result}",
                row.counter,
                ui::pad_visible(&label, lw),
            )];
        }
        let lw = row.width.saturating_sub(counter_w + 2).max(4);
        let label = truncate_middle(row.name, lw);
        return vec![
            format!("{}  {label}", row.counter),
            format!("{indent}  {result}"),
        ];
    }

    // Live row: counter, label, capped bar, percent, done/total,
    // rate + ETA. The bar is decorative; the filename keeps whatever
    // space is left.
    let pct = ui::percent(row.bytes, row.total);
    let show_bar = row.animated && row.width > counter_w + 52;
    let mut live = String::new();
    if row.animated {
        // In flight, both byte values earn their space: the total
        // alone can't show how far along a large file is.
        let r = ui::human_rate(row.rate_bps);
        if !r.is_empty() {
            live.push_str("  ");
            live.push_str(&ui::dim(&r));
            let eta = ui::human_eta(row.total.saturating_sub(row.bytes), row.rate_bps);
            if !eta.is_empty() {
                live.push_str("  ");
                live.push_str(&ui::dim(&eta));
            }
        }
    }
    // Drop the live fields first when space is tight; the bar and
    // the filename matter more.
    let live_w = ui::visible_width(&live);
    if row.width.saturating_sub(counter_w + 50 + live_w) < LABEL_MIN_W {
        live.clear();
    }
    let mut fixed = counter_w + 2;
    if show_bar {
        fixed += BAR_W + 2 + 2;
    }
    // Percent (4) + gaps (5) + done/total + live + status gap.
    let flow = format!(
        "{} / {}",
        ui::human_bytes(row.bytes),
        ui::human_bytes(row.total)
    );
    fixed += 4 + 5 + ui::visible_width(&flow) + ui::visible_width(&live) + 2;
    let lw = row
        .width
        .saturating_sub(fixed)
        .clamp(LABEL_MIN_W, LABEL_MAX_W);
    let label = truncate_middle(row.name, lw);

    let mut line = String::from(row.counter);
    line.push_str("  ");
    line.push_str(&ui::pad_visible(&label, lw));
    if show_bar {
        line.push_str("  ");
        line.push_str(&ui::mini_bar(row.bytes, row.total, BAR_W));
    }
    line.push_str(&format!("  {:>3}%", pct));
    line.push_str("   ");
    line.push_str(&flow);
    line.push_str(&live);
    vec![line]
}

/// Filename column width for a row whose right-hand side is
/// `right_w` cells wide: whatever is left after the counter, gaps,
/// and result, bounded so tiny terminals still show something and
/// huge ones don't stretch names forever.
fn label_budget(width: usize, counter_w: usize, right_w: usize) -> usize {
    width
        .saturating_sub(counter_w + 2 + right_w + 2)
        .clamp(LABEL_MIN_W, LABEL_MAX_W)
}

/// Erase the live row currently on screen, leaving no trace. Used
/// when a transferred file completes on an animated terminal: the
/// aggregate summary is the record.
fn clear_current_line() {
    let stderr = std::io::stderr();
    let mut handle = stderr.lock();
    let _ = handle.write_all(b"\r");
    let _ = handle.write_all(b"\x1b[2K");
    let _ = handle.flush();
}

/// Emit one composed row. In-place updates on animated terminals
/// (`\r` + `ESC[2K`, no newline); fresh rows start with `\n` so
/// consecutive files never concatenate onto one terminal line (which
/// is what used to wrap at the screen edge). No padding: `ESC[2K`
/// already clears shrunk lines, and padding is what pushed status
/// columns hundreds of cells right on wide terminals. Lines are
/// clamped to `width` as a final guarantee against wrapping.
fn write_line(line: &str, width: usize, fresh_line: bool) {
    let line = ui::truncate_visible(line, width);

    let stderr = std::io::stderr();
    let mut handle = stderr.lock();
    if ui::animated() {
        // Erase the previous render before writing the new one.
        // `\r` alone leaves stale characters when the line shrank;
        // ESC[2K clears from the cursor to end of line. Dumb
        // terminals take the plain-line path below instead: they
        // may not understand either sequence.
        if fresh_line {
            let _ = write!(handle, "\n{line}");
        } else {
            let _ = handle.write_all(b"\r");
            let _ = handle.write_all(b"\x1b[2K");
            let _ = write!(handle, "{line}");
        }
        let _ = handle.flush();
    } else {
        // Not animated (redirected/piped output, dumb terminal):
        // print each state as its own plain line. No carriage
        // returns, no padding, no ANSI - keeps logs greppable.
        let _ = writeln!(handle, "{}", ui::strip_ansi(&line).trim_end());
    }
}

impl Progress for IndicatifProgress {
    fn counts(&self) -> (usize, usize, usize) {
        let st = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        (
            st.verified as usize,
            st.failed as usize,
            st.skipped as usize,
        )
    }

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
                live_shown: false,
            },
        );
        // Fresh line for each new file. When multiple connections are
        // active, files may start out of order; `fresh_line=true` prints
        // each new file on its own line. Tiny files skip the opening
        // 0% row entirely and jump straight to their result row.
        let tiny = total < SMALL_FILE_MAX;
        drop(st);
        if !tiny {
            self.render_file(id, true);
            self.mark_live_shown(id);
        }
    }

    fn chunk_done(&self, id: FileId, bytes: u64) {
        let should_render = {
            let mut st = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            // Sizes are copied out first so the borrow ends before
            // the mutable file-state borrow below begins.
            let total = st.sizes.get(&id).copied().unwrap_or(u64::MAX);
            match st.state.get_mut(&id) {
                Some(s) => {
                    s.bytes = s.bytes.saturating_add(bytes);
                    s.rate.observe(s.bytes);
                    // Tiny files never render mid-flight rows; their
                    // completion row says everything.
                    if total < SMALL_FILE_MAX {
                        false
                    } else if ui::animated() {
                        // Animated terminals re-draw at most ~8Hz; faster
                        // than that the line flickers and wastes bandwidth
                        // (matters over SSH). Plain mode has its own
                        // percent-bucket gate inside `render_file`.
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
            self.mark_live_shown(id);
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
                    live_shown: false,
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
        // A transferred file's live row is erased: the summary below
        // is the record, and only exceptional rows (skips, failures)
        // stay on screen. Plain logs keep the compact result row as
        // their record instead — there is nothing to erase there.
        let live_shown = st
            .state
            .get_mut(&id)
            .map(|s| std::mem::replace(&mut s.live_shown, false))
            .unwrap_or(false);
        drop(st);
        if ok && ui::animated() && live_shown {
            clear_current_line();
        } else if !ok || !ui::animated() {
            // Final render of the file's line with the status symbol.
            self.render_file(id, false);
        }
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
        // Nothing moved: report completion, not a send. (The sender
        // hits this when every file was already present.)
        let done_word = if verified == 0 && failed == 0 {
            "Done".to_string()
        } else {
            self.done_word.to_string()
        };

        // Only counters that matter: zero-valued ones stay hidden, and
        // byte accounting appears only when bytes actually moved. A
        // partial success counts files as transferred, not sent.
        let mut segs: Vec<String> = Vec::new();
        if verified > 0 {
            let word = if failed > 0 {
                "transferred"
            } else if verified == 1 {
                "file"
            } else {
                "files"
            };
            segs.push(format!("{verified} {word}"));
            segs.push(ui::human_bytes(sent));
        }
        if skipped > 0 {
            segs.push(format!("{skipped} skipped"));
        }
        if failed > 0 {
            segs.push(format!("{} failed", ui::red(&failed.to_string())));
        }
        if segs.is_empty() {
            segs.push("0 files".to_string());
        }

        let sep = ui::sep_dot();
        let body = segs.join(&format!(" {sep} "));
        eprintln!();
        if failed > 0 {
            let mark = if ui::animated() {
                ui::yellow("!")
            } else {
                "!".to_string()
            };
            eprintln!("  {mark} {} {sep} {body}", ui::red(&done_word));
        } else if ui::animated() {
            eprintln!(
                "  {} {} {sep} {body}",
                ui::green(ui::ok_sym()),
                ui::green(&done_word)
            );
        } else {
            eprintln!("  {done_word} {sep} {body}");
        }
    }
}

/// Middle-truncate `s` to fit within `max` display cells (not chars:
/// CJK text runs two cells per char, measured via
/// [`ui::visible_width`]). Keeps the basename end since that is
/// usually the useful part (`docs/…/chapter1.md`, never
/// `docs/guide/chapt…`), preserving the extension.
fn truncate_middle(s: &str, max: usize) -> String {
    if ui::visible_width(s) <= max {
        return s.to_string();
    }
    let marker = if ui::use_unicode() { "…" } else { "..." };
    let marker_w = ui::visible_width(marker);
    if max <= marker_w + 2 {
        return take_width(s, max);
    }
    // Prefer keeping the whole basename: shrink the directory part,
    // so `docs/guide/chapter1.md` becomes `docs/…/chapter1.md`
    // rather than `docs/guide/chapt…`.
    if let Some((dir, base)) = s.rsplit_once('/') {
        let base_w = ui::visible_width(base);
        if base_w + marker_w + 1 + 2 <= max {
            let dir_keep = take_width(dir, max - marker_w - 1 - base_w);
            return format!("{dir_keep}{marker}/{base}");
        }
    }
    let (base, ext) = match s.rfind('.') {
        Some(i) if i > 0 && !s[i..].contains('/') => (&s[..i], &s[i..]),
        _ => (s, ""),
    };
    let ext_keep = take_width(
        ext,
        max.saturating_sub(marker_w + 4).min(ui::visible_width(ext)),
    );
    let head_budget = max
        .saturating_sub(marker_w + ui::visible_width(&ext_keep))
        .max(1);
    let prefix = take_width(base, head_budget);
    format!("{prefix}{marker}{ext_keep}")
}

/// Leading substring of `s` fitting in `max` display cells.
fn take_width(s: &str, max: usize) -> String {
    let mut out = String::new();
    let mut w = 0;
    for c in s.chars() {
        let cw = ui::visible_width(&c.to_string());
        if w + cw > max {
            break;
        }
        out.push(c);
        w += cw;
    }
    out
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

    #[test]
    fn truncation_keeps_the_basename() {
        // Directory part shrinks; the file the user must recognize
        // survives. (ASCII `...` marker under test; `…` on a terminal.)
        let t = truncate_middle("docs/guide/chapter1.md", 20);
        assert!(ui::visible_width(&t) <= 20, "{t:?}");
        assert!(t.ends_with("chapter1.md"), "{t:?}");
        assert!(t.contains("..."), "{t:?}");
    }

    #[test]
    fn truncation_counts_cells_not_chars() {
        // Each kana is two cells: a char-counting cut would overflow.
        let t = truncate_middle("docs/ガイド/chapter1.md", 20);
        assert!(ui::visible_width(&t) <= 20, "{t:?}");
        assert!(t.ends_with("chapter1.md"), "{t:?}");
    }

    #[test]
    fn truncation_leaves_short_names_alone() {
        assert_eq!(truncate_middle("readme.md", 32), "readme.md");
    }

    /// Every emitted row must fit its width; finished rows split in
    /// two below [`NARROW_W`]. Layout is pure, so pin widths directly
    /// instead of needing real terminals.
    #[test]
    fn rows_fit_their_width_at_50_60_80_120() {
        let name = "docs/guide/deeply/nested/chapter1.md";
        for width in [50usize, 60, 80, 120] {
            // (done, ok, skipped): live, verified, failed, skipped.
            for (done, ok, skipped) in [
                (false, false, false),
                (true, true, false),
                (true, false, false),
                (false, false, true),
            ] {
                for animated in [false, true] {
                    let row = RowLayout {
                        counter: "[1/5]",
                        name,
                        bytes: 20,
                        total: 41,
                        done,
                        ok,
                        skipped,
                        rate_bps: 0.0,
                        width,
                        animated,
                    };
                    let rows = layout_row(&row);
                    if width < NARROW_W && (done || skipped) {
                        assert_eq!(rows.len(), 2, "width {width}");
                    } else {
                        assert_eq!(rows.len(), 1, "width {width}");
                    }
                    for r in &rows {
                        let plain = ui::strip_ansi(r);
                        assert!(
                            ui::visible_width(plain.trim_end()) <= width,
                            "width {width}: {plain:?}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn narrow_rows_keep_status_on_line_two() {
        let row = RowLayout {
            counter: "[1/5]",
            name: "docs/guide/chapter1.md",
            bytes: 41,
            total: 41,
            done: true,
            ok: true,
            skipped: false,
            rate_bps: 0.0,
            width: 50,
            animated: false,
        };
        let rows = layout_row(&row);
        assert_eq!(rows.len(), 2);
        assert!(rows[0].contains("chapter1.md"), "{rows:?}");
        assert!(rows[1].contains("41 B"), "{rows:?}");
    }
}
