//! Shared terminal UI helpers: styling, symbols, and formatting.
//!
//! All lanx UI is written to stderr. When stderr is not an interactive
//! terminal (output is piped or redirected to a file), color and
//! box-drawing glyphs are disabled automatically so captured logs
//! stay clean and greppable. This matters on Windows where redirected
//! stderr used to collect stray ANSI sequences.
//!
//! The styling is built on the `console` crate (already a transitive
//! dependency of `indicatif`), which enables virtual-terminal colors
//! on Windows 10+ and respects `NO_COLOR` / `CLICOLOR_FORCE`.

use std::time::{Duration, Instant};

use console::{measure_text_width, style, Term};
use indicatif::{ProgressBar, ProgressStyle};

/// Returns a fresh stderr terminal handle on each call.
fn term() -> Term {
    Term::stderr()
}

/// True when stderr is an interactive terminal.
pub fn is_tty() -> bool {
    term().is_term()
}

/// Wrap `s` in a cyan style (used for headings / labels) when color is on.
pub fn cyan(s: &str) -> String {
    style(s).cyan().bold().for_stderr().to_string()
}

/// Bold white/bright text — used for the most important value on a line
/// (e.g. the pairing code the user needs to copy).
pub fn bold(s: &str) -> String {
    style(s).bold().for_stderr().to_string()
}

/// Green — success.
pub fn green(s: &str) -> String {
    style(s).green().for_stderr().to_string()
}

/// Red — failure.
pub fn red(s: &str) -> String {
    style(s).red().for_stderr().to_string()
}

/// Yellow — warning / in-progress / retry.
pub fn yellow(s: &str) -> String {
    style(s).yellow().for_stderr().to_string()
}

/// Dim/grey — secondary info (loopback addresses, "done", etc.).
pub fn dim(s: &str) -> String {
    style(s).dim().for_stderr().to_string()
}

/// Status glyphs. ASCII fallbacks when not a TTY so logs remain
/// plain-text friendly.
pub fn ok_sym() -> &'static str {
    if is_tty() {
        "✓"
    } else {
        "ok"
    }
}
pub fn fail_sym() -> &'static str {
    if is_tty() {
        "✗"
    } else {
        "FAIL"
    }
}
pub fn arrow() -> &'static str {
    if is_tty() {
        "→"
    } else {
        "->"
    }
}
pub fn retry_sym() -> &'static str {
    if is_tty() {
        "⟳"
    } else {
        "retry"
    }
}
/// Mid-dot separator used in banners. ASCII fallback so non-UTF-8
/// pipes don't see a replacement character.
pub fn sep_dot() -> &'static str {
    if is_tty() {
        "·"
    } else {
        "-"
    }
}
/// Em dash used between summary segments.
pub fn sep_dash() -> &'static str {
    if is_tty() {
        "—"
    } else {
        "-"
    }
}
/// Trailing ellipsis for in-progress messages.
pub fn ellipsis() -> &'static str {
    if is_tty() {
        "…"
    } else {
        "..."
    }
}

/// Print a labeled key/value line with aligned columns, e.g.
///   `code   7-cobalt-fox`
///   `listen 192.168.1.5:51234`
/// `label` is colored cyan and right-padded to `label_width`.
pub fn kv(label: &str, value: &str, label_width: usize) {
    let lbl = format!("{:<label_width$}", label);
    eprintln!("{} {}", cyan(&lbl), value);
}

/// A short banner line introducing a phase, e.g. `lanx · sending`.
pub fn banner(verb: &str, detail: &str) {
    let head = format!("lanx {} {}", sep_dot(), verb);
    if detail.is_empty() {
        eprintln!("{}", bold(&head));
    } else {
        eprintln!("{}  {}", bold(&head), dim(detail));
    }
}

/// Usable terminal width (columns) for the progress renderer's line
/// padding. Falls back to 80 when the width can't be queried (piped
/// output). Clamps to a minimum of 40 to avoid garbled output on very
/// narrow terminals.
pub fn term_width() -> usize {
    match term().size() {
        (_, w) if w >= 40 => w as usize,
        (_, w) if w > 0 => w as usize,
        _ => 80,
    }
}

/// Pad a possibly-colored string with trailing spaces so its *visible*
/// width (ignoring ANSI escape codes) reaches `width`. Colored strings
/// have a byte length larger than their visible width, so naive
/// `{:<width$}` formatting under-pads and leaves ghosts when a line is
/// overwritten with `\r`.
pub fn pad_visible(s: &str, width: usize) -> String {
    let w = measure_text_width(s);
    if w >= width {
        s.to_string()
    } else {
        let mut out = String::from(s);
        out.push_str(&" ".repeat(width - w));
        out
    }
}

/// Strip ANSI escape sequences from `s`. Used when a colored line is
/// about to be measured for truncation purposes.
pub fn strip_ansi(s: &str) -> String {
    console::strip_ansi_codes(s).to_string()
}

/// Truncate `s` so its *visible* width (ignoring ANSI escapes) never
/// exceeds `width`. Escape sequences are copied through whole. A line
/// longer than the terminal wraps when written, and once it wraps a
/// trailing `\r` only returns to the start of the wrapped fragment,
/// so every in-place update renders as a new line. Clamping the line
/// to the measured width prevents that.
pub fn truncate_visible(s: &str, width: usize) -> String {
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        let rest = &s[i..];
        if rest.starts_with('\u{1b}') {
            // Copy the whole escape sequence (runs to the first
            // alphabetic terminator, e.g. `m` in SGR).
            let end = rest
                .find(|ch: char| ch.is_ascii_alphabetic())
                .map(|p| p + 1)
                .unwrap_or(rest.len());
            out.push_str(&rest[..end]);
            i += end;
            continue;
        }
        let c = rest.chars().next().unwrap();
        let w = console::measure_text_width(&c.to_string());
        if w + console::measure_text_width(&out) > width {
            break;
        }
        out.push(c);
        i += c.len_utf8();
    }
    out
}

/// Format a byte count with a human-friendly suffix (binary units).
pub fn human_bytes(n: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    if n < 1024 {
        return format!("{n} B");
    }
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if v >= 100.0 {
        format!("{v:.0} {}", UNITS[i])
    } else if v >= 10.0 {
        format!("{v:.1} {}", UNITS[i])
    } else {
        format!("{v:.2} {}", UNITS[i])
    }
}

/// Format a throughput in bytes/sec, e.g. `12.3 MiB/s`. Returns an
/// empty string for non-positive rates so the caller can drop the
/// field entirely instead of printing `0 B/s`.
pub fn human_rate(bytes_per_sec: f64) -> String {
    if !bytes_per_sec.is_finite() || bytes_per_sec <= 0.0 {
        return String::new();
    }
    format!("{}/s", human_bytes(bytes_per_sec as u64))
}

/// Percent of `done`/`total` as an integer in 0..=100 (100 when
/// `total` is zero, treating an empty file as trivially complete).
pub fn percent(done: u64, total: u64) -> u32 {
    if total == 0 {
        return 100;
    }
    (done as u128 * 100 / total as u128).min(100) as u32
}

/// A compact fixed-width progress bar, e.g. `▕████▏    ▎`. Width is
/// in character cells. Returns an empty string when not a TTY (the
/// percentage already conveys progress in plain-text mode).
pub fn mini_bar(done: u64, total: u64, width: usize) -> String {
    if !is_tty() || width == 0 {
        return String::new();
    }
    let frac = if total == 0 {
        1.0
    } else {
        done as f64 / total as f64
    };
    let frac = frac.clamp(0.0, 1.0);
    let filled = (frac * width as f64).round() as usize;
    let filled = filled.min(width);
    let empty = width - filled;
    let bar: String = "█".repeat(filled);
    let pad: String = " ".repeat(empty);
    format!("▕{bar}{pad}▏")
}

/// Rolling-average throughput tracker. Cheap to update on every chunk;
/// yields a smoothed bytes/sec that avoids the spikes of a raw
/// instantaneous measurement.
#[derive(Clone)]
pub struct Rate {
    start: Instant,
    origin: u64,
    last_at: Instant,
    last_bytes: u64,
    ema: f64,
}

impl Rate {
    pub fn new(origin: u64) -> Self {
        let now = Instant::now();
        Self {
            start: now,
            origin,
            last_at: now,
            last_bytes: origin,
            ema: 0.0,
        }
    }

    /// Record that `bytes` total have been transferred for this file.
    pub fn observe(&mut self, bytes: u64) {
        let now = Instant::now();
        let dt = now.saturating_duration_since(self.last_at);
        let db = bytes.saturating_sub(self.last_bytes);
        if dt > Duration::from_millis(20) && db > 0 {
            let inst = db as f64 / dt.as_secs_f64().max(1e-9);
            // EMA with ~0.5s time constant-ish smoothing.
            self.ema = self.ema * 0.7 + inst * 0.3;
            self.last_at = now;
            self.last_bytes = bytes;
        }
    }

    /// Smoothed bytes/sec. Falls back to the average since start when
    /// the EMA hasn't warmed up yet.
    pub fn bps(&self) -> f64 {
        if self.ema > 0.0 {
            return self.ema;
        }
        let elapsed = self
            .last_at
            .saturating_duration_since(self.start)
            .as_secs_f64();
        if elapsed > 1e-9 {
            (self.last_bytes.saturating_sub(self.origin)) as f64 / elapsed
        } else {
            0.0
        }
    }
}

/// A small animated spinner with the lanx house style. Caller is
/// responsible for `finish_and_clear()` / `finish_with_message(...)`.
pub fn spinner(msg: &str) -> ProgressBar {
    let bar = ProgressBar::new_spinner();
    bar.set_style(
        ProgressStyle::with_template("{spinner} {msg}")
            .unwrap_or_else(|_| ProgressStyle::default_spinner()),
    );
    bar.set_message(msg.to_string());
    bar.enable_steady_tick(Duration::from_millis(80));
    bar
}
