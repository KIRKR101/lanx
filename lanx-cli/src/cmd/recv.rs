//! `lanx recv`: connect to sender, receive files.

use anyhow::{bail, Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use lanx_core::progress::Progress;
use lanx_core::transfer::receiver::run_receiver;
use lanx_net::pairing::{parse_target, resolve_target, Target};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;

use crate::progress::IndicatifProgress;
use crate::ui;

pub async fn run(
    target: String,
    out: PathBuf,
    retry_forever: bool,
    discovery_timeout: Duration,
) -> Result<()> {
    ui::banner("recv", "");

    let parsed = parse_target(&target).context("parse target")?;
    // Only code-based targets need to wait on UDP discovery; a direct
    // `ip:port` resolves instantly, so we skip the spinner there to
    // avoid a pointless flicker.
    let needs_discovery = matches!(parsed, Target::Code(_));
    let addr = if needs_discovery {
        let s = spinner(&format!("looking for sender{}", ui::ellipsis()));
        let r = resolve_target(parsed, discovery_timeout).await;
        s.finish_and_clear();
        r.context("resolve target")?
    } else {
        resolve_target(parsed, discovery_timeout)
            .await
            .context("resolve target")?
    };
    eprintln!(
        "  {} sender {}",
        ui::green(ui::ok_sym()),
        ui::bold(&addr.to_string()),
    );

    let progress: Arc<dyn Progress> = IndicatifProgress::new("Receiving");

    let max_attempts: u32 = if retry_forever { u32::MAX } else { 5 };
    let mut attempt: u32 = 0;
    loop {
        attempt += 1;
        let result = try_once(&addr, &out, progress.clone()).await;
        match result {
            Ok(report) => {
                // `summary` is the single, styled completion line —
                // no extra "Done." echo here.
                progress.summary(report.verified, report.failed, report.skipped);
                if report.failed == 0 {
                    return Ok(());
                }
                bail!("{} file(s) failed verification", report.failed);
            }
            Err(e) => {
                eprintln!(
                    "  {} {} {}",
                    ui::red(ui::fail_sym()),
                    ui::dim("session failed:"),
                    ui::red(&format!("{e}")),
                );
                if attempt >= max_attempts {
                    eprintln!("  {} {}", ui::red(ui::fail_sym()), ui::red("giving up"));
                    return Err(e);
                }
                let backoff = Duration::from_secs((1u64 << attempt.min(4)).min(8));
                let max_label = if retry_forever {
                    String::from("∞")
                } else {
                    max_attempts.to_string()
                };
                eprintln!(
                    "  {} {} {}/{} {} {}s{}",
                    ui::yellow(ui::retry_sym()),
                    ui::dim("retry"),
                    attempt,
                    max_label,
                    ui::dim("in"),
                    backoff.as_secs(),
                    ui::ellipsis(),
                );
                tokio::time::sleep(backoff).await;
            }
        }
    }
}

async fn try_once(
    addr: &std::net::SocketAddr,
    out: &Path,
    progress: Arc<dyn Progress>,
) -> Result<lanx_core::transfer::receiver::ReceiverReport> {
    let stream = TcpStream::connect(addr)
        .await
        .with_context(|| format!("connect {addr}"))?;
    stream.set_nodelay(true).ok();
    let (mut r, mut w) = stream.into_split();
    let report = run_receiver(&mut r, &mut w, out, progress.as_ref())
        .await
        .context("run_receiver")?;
    Ok(report)
}

/// A small animated spinner matching the lanx house style.
fn spinner(msg: &str) -> ProgressBar {
    let bar = ProgressBar::new_spinner();
    bar.set_style(
        ProgressStyle::with_template("{spinner} {msg}")
            .unwrap_or_else(|_| ProgressStyle::default_spinner()),
    );
    bar.set_message(msg.to_string());
    bar.enable_steady_tick(Duration::from_millis(80));
    bar
}
