//! `lanx recv`: connect to sender, receive files.

use anyhow::{bail, Context, Result};
use lanx_core::manifest::Manifest;
use lanx_core::progress::Progress;
use lanx_core::progress::TransferSummary;
use lanx_core::transfer::receiver::{
    run_receiver, Approval, AutoAccept, ManifestApprover, ReceiverConfig, SharedApprover,
};
use lanx_core::transfer::DEFAULT_MAX_RETRIES;
use lanx_net::discovery::code_to_hash;
use lanx_net::pairing::{parse_target, resolve_target, Target};
use lanx_net::relay::{send_relay_hello, RelayHello, RelayRole};
use lanx_net::tcp::DEFAULT_SEND_PORT;
use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;

use crate::progress::IndicatifProgress;
use crate::ui;

const MANIFEST_PREVIEW_LIMIT: usize = 20;
const NOISE_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// Cap for re-resolving a pairing code between retries. The first resolve
/// uses the full discovery timeout; retries use the smaller of the two so
/// five attempts cannot stall for minutes on discovery alone.
const RERESOLVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(8);

/// Configuration for one receiver connection in a retry attempt.

#[derive(Clone)]
struct TryOnceConfig {
    addr: std::net::SocketAddr,
    relay_addr: Option<String>,
    code_hash: Option<[u8; 32]>,
    out: PathBuf,
    approver: Arc<dyn ManifestApprover>,
    progress: Arc<dyn Progress>,
    parallel: u16,
    agreed_parallel_tx: Option<tokio::sync::mpsc::UnboundedSender<u16>>,
}

/// Run the `lanx recv` subcommand. Connects to a sender (via direct
/// address, UDP discovery, or relay), receives the manifest, and
/// transfers files.
///
/// # Errors
///
/// Returns an error if the target cannot be resolved, the connection
/// fails, or the transfer encounters a protocol error.
pub async fn run(
    target: String,
    out: PathBuf,
    accept: bool,
    retry_forever: bool,
    discovery_timeout: Duration,
    parallel: u16,
    relay: Option<String>,
) -> Result<()> {
    if accept {
        eprintln!(
            "  {} {}",
            ui::yellow("!"),
            ui::yellow(
                "auto-accept enabled: all incoming transfers will be accepted without prompting"
            ),
        );
        eprintln!("    {}", ui::dim("only use this when you trust the sender"),);
    }

    let parsed = parse_target(&target).context("parse target")?;
    if relay.is_some() && !matches!(parsed, Target::Code(_)) {
        bail!("--relay requires a pairing code (e.g. 7-cobalt-fox), not an ip:port address");
    }
    let code_hash = match &parsed {
        Target::Code(code) => Some(code_to_hash(code)),
        _ => None,
    };

    // Keep the code for re-resolution on retries: a sender can restart
    // onto another port (stable port occupied, --port changed), which
    // would otherwise leave the retry loop chasing a stale SocketAddr
    // forever. Target::Addr retries the same address; Target::Code
    // re-resolves before each retry after the first.
    let code_for_rediscovery: Option<String> = match &parsed {
        Target::Code(code) => Some(code.clone()),
        _ => None,
    };

    // Determine the actual address to connect to.
    let (addr, relay_addr) = if let Some(ref relay_addr) = relay {
        // Relay mode: connect to the relay server.
        let addr: std::net::SocketAddr = relay_addr
            .parse()
            .with_context(|| format!("invalid relay address: {relay_addr}"))?;
        (addr, Some(relay_addr.clone()))
    } else {
        // Direct mode: resolve the target address.
        let needs_discovery = matches!(parsed, Target::Code(_));
        let addr = if needs_discovery {
            let s = ui::spinner(&format!("looking for sender{}", ui::ellipsis()));
            let r = resolve_target(parsed, discovery_timeout).await;
            s.finish_and_clear();
            r.context("resolve target")?
        } else {
            resolve_target(parsed, discovery_timeout)
                .await
                .context("resolve target")?
        };
        (addr, None)
    };

    if let Some(ref ra) = relay_addr {
        eprintln!("  {} {} {}", ui::dim("relay"), ui::arrow(), ui::bold(ra));
    } else {
        eprintln!(
            "  {} {:<12}  {}",
            ui::green(ui::ok_sym()),
            "found sender",
            ui::dim(&addr.to_string()),
        );
    }
    eprintln!();

    let progress: Arc<dyn Progress> = IndicatifProgress::new("Receiving");

    let base_approver: Arc<dyn ManifestApprover> = if accept {
        Arc::new(AutoAccept)
    } else {
        Arc::new(StdinApprover {
            out_dir: out.clone(),
        })
    };
    let approver: Arc<dyn ManifestApprover> = if parallel > 1 {
        SharedApprover::new(base_approver)
    } else {
        base_approver
    };

    let parallel = parallel.max(1);
    crate::cmd::validate_parallel_relay(parallel, &relay)?;
    let max_attempts: u32 = if retry_forever { u32::MAX } else { 5 };
    let mut attempt: u32 = 0;
    let (agreed_tx, mut agreed_rx) = tokio::sync::mpsc::unbounded_channel();
    let mut try_cfg = TryOnceConfig {
        addr,
        relay_addr: relay_addr.clone(),
        code_hash,
        out: out.clone(),
        approver,
        progress: progress.clone(),
        parallel,
        agreed_parallel_tx: Some(agreed_tx),
    };
    loop {
        attempt += 1;

        // Re-resolve pairing codes before retries (not before the first
        // attempt, which already resolved above). Direct mode only; relay
        // mode has a fixed relay address. On re-resolve failure keep the
        // last address so a transient discovery gap doesn't abort retries.
        if attempt > 1 {
            if let (Some(code), None) = (&code_for_rediscovery, &relay_addr) {
                let s = ui::spinner(&format!("re-resolving sender{}", ui::ellipsis()));
                let reresolve_timeout = discovery_timeout.min(RERESOLVE_TIMEOUT);
                let r = resolve_target(Target::Code(code.clone()), reresolve_timeout).await;
                s.finish_and_clear();
                match r {
                    Ok(new_addr) => {
                        if new_addr != try_cfg.addr {
                            eprintln!(
                                "  {} sender {}",
                                ui::dim("update"),
                                ui::bold(&new_addr.to_string()),
                            );
                            try_cfg.addr = new_addr;
                        }
                    }
                    Err(e) => {
                        eprintln!(
                            "  {} {} ({}; retrying {})",
                            ui::yellow(ui::retry_sym()),
                            ui::dim("re-discovery failed"),
                            e,
                            try_cfg.addr,
                        );
                    }
                }
            }
        }
        let mut set = tokio::task::JoinSet::new();
        // Spawn connection 0
        {
            let cfg = try_cfg.clone();
            set.spawn(async move { try_once(&cfg, 0).await });
        }

        // Wait to negotiate parallelism on connection 0. If it fails or exits early,
        // we fallback to agreed_parallel = 1.
        let mut first_task_result: Option<Result<lanx_core::transfer::receiver::ReceiverReport>> =
            None;
        let agreed_parallel = tokio::select! {
            Some(p) = agreed_rx.recv() => p,
            res = set.join_next() => {
                if let Some(r) = res {
                    // Flatten JoinError -> anyhow::Error so aggregate_reports gets the right type.
                    first_task_result = Some(r.context("connection task panicked").and_then(|x| x));
                }
                1
            }
        };

        // If agreed_parallel > 1, spawn connections 1..agreed_parallel
        if agreed_parallel > 1 {
            for i in 1..agreed_parallel {
                let mut cfg = try_cfg.clone();
                // Avoid sending additional agreed_parallel notifications on extra connections
                cfg.agreed_parallel_tx = None;
                set.spawn(async move { try_once(&cfg, i).await });
            }
        }

        let result = aggregate_reports(set, first_task_result).await;
        match result {
            Ok(report) => {
                if report.rejected {
                    eprintln!();
                    eprintln!(
                        "  {} {}",
                        ui::red(ui::fail_sym()),
                        ui::red("transfer declined"),
                    );
                    bail!("transfer declined by user");
                }
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
                    return Err(e.context(format!("failed after {attempt} attempt(s)")));
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

/// Hint shown when a TCP connect times out. Kept in one place so the
/// `ufw` text cannot drift from the README.
fn firewall_hint(cfg: &TryOnceConfig) -> String {
    if cfg.relay_addr.is_none() && cfg.addr.port() != DEFAULT_SEND_PORT {
        format!(
            "connect {} timed out: the sender is listening on {} for this transfer \
             (not the default port {DEFAULT_SEND_PORT}, so the stable firewall rule \
             does not cover it) — on the sender, allow that TCP port \
             (e.g. `sudo ufw allow {}/tcp`), or restart the sender on the default port \
             and retry",
            cfg.addr,
            cfg.addr.port(),
            cfg.addr.port(),
        )
    } else {
        format!(
            "connect {} timed out: the sender is not accepting TCP (host firewall?) — \
             on the sender, allow the port (e.g. `sudo ufw allow {}/tcp`), \
             or pin it with `lanx send --port N` and allow that",
            cfg.addr,
            cfg.addr.port(),
        )
    }
}

async fn try_once(
    cfg: &TryOnceConfig,
    connection_index: u16,
) -> Result<lanx_core::transfer::receiver::ReceiverReport> {
    let mut stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&cfg.addr))
        .await
        .with_context(|| firewall_hint(cfg))?
        .with_context(|| format!("connect {}", cfg.addr))?;
    if let Err(e) = stream.set_nodelay(true) {
        tracing::debug!(?e, "TCP_NODELAY failed");
    }

    // In relay mode, send a hello to register with the relay before
    // starting the Noise handshake. This must not run in direct mode
    // where code_hash is also Some (all pairing codes produce a hash).
    if let (Some(relay_addr), Some(hash)) = (&cfg.relay_addr, cfg.code_hash) {
        let hello = RelayHello {
            role: RelayRole::Receiver,
            code_hash: hash,
        };
        send_relay_hello(&mut stream, &hello).await?;
        tracing::info!("sent relay hello to {}", relay_addr);
    }

    // Wrap the TCP stream in a Noise-encrypted channel before any lanx
    // control messages are exchanged.
    let enc = tokio::time::timeout(
        NOISE_HANDSHAKE_TIMEOUT,
        lanx_core::crypto::wrap_initiator(stream),
    )
    .await
    .context("noise handshake timed out")?
    .context("noise handshake")?;

    let (mut r, w) = tokio::io::split(enc);
    let mut w = tokio::io::BufWriter::new(w);

    let recv_cfg = ReceiverConfig {
        max_retries: DEFAULT_MAX_RETRIES,
        connection_index,
        parallel: cfg.parallel,
        agreed_parallel_tx: cfg.agreed_parallel_tx.clone(),
    };

    let report = run_receiver(
        &mut r,
        &mut w,
        &cfg.out,
        cfg.progress.as_ref(),
        &recv_cfg,
        cfg.approver.clone(),
    )
    .await
    .context("run_receiver")?;
    Ok(report)
}

/// Aggregate per-connection receiver reports. Returns the first join or
/// run error; otherwise sums verified/failed/skipped across connections.
async fn aggregate_reports(
    mut set: tokio::task::JoinSet<Result<lanx_core::transfer::receiver::ReceiverReport>>,
    pre_joined: Option<Result<lanx_core::transfer::receiver::ReceiverReport>>,
) -> Result<lanx_core::transfer::receiver::ReceiverReport> {
    let mut report = lanx_core::transfer::receiver::ReceiverReport::default();
    if let Some(res) = pre_joined {
        let inner = res?;
        report.verified += inner.verified;
        report.failed += inner.failed;
        report.skipped += inner.skipped;
        report.rejected = report.rejected || inner.rejected;
    }
    while let Some(r) = set.join_next().await {
        let inner = r.context("connection task panicked")??;
        report.verified += inner.verified;
        report.failed += inner.failed;
        report.skipped += inner.skipped;
        report.rejected = report.rejected || inner.rejected;
    }
    Ok(report)
}

/// Prompts the user to accept or decline an incoming manifest by reading
/// from stdin. Used unless `--accept` is passed.
struct StdinApprover {
    out_dir: PathBuf,
}

impl ManifestApprover for StdinApprover {
    fn approve(&self, manifest: &Manifest, summary: &TransferSummary) -> Approval {
        // Non-interactive stdin cannot answer a prompt; refuse so the user
        // can rerun with `--accept` if automation is intended.
        if !io::stdin().is_terminal() {
            return Approval::Reject {
                reason: "stdin is not a TTY; pass --accept to accept automatically".to_string(),
            };
        }

        eprintln!("  {} Incoming transfer", ui::cyan("?"));
        eprintln!(
            "    {}",
            ui::bold(&ui::count_line(summary.file_count, summary.total_bytes)),
        );
        eprintln!();

        // Same `name  size` rows as the live progress that follows,
        // so the prompt flows into the transfer instead of switching
        // representations.
        for entry in manifest.files.iter().take(MANIFEST_PREVIEW_LIMIT) {
            eprintln!("{}", ui::contents_row(&entry.rel_path, entry.size));
        }
        let remaining = summary.file_count.saturating_sub(MANIFEST_PREVIEW_LIMIT);
        if remaining > 0 {
            eprintln!("  {}", ui::dim(&format!("... and {remaining} more")));
        }

        // Destination on its own line, omitted for the default (`.`).
        let out_is_default = self.out_dir.as_os_str() == ".";
        if !out_is_default {
            eprintln!("    {}  {}", ui::dim("Destination"), self.out_dir.display(),);
        }

        eprintln!();
        let prompt = "  Accept? [y/N]: ";
        eprint!("{}", prompt);
        let _ = io::stderr().flush();

        let mut line = String::new();
        match io::stdin().read_line(&mut line) {
            Ok(_) => {
                let trimmed = line.trim().to_lowercase();
                if trimmed == "y" || trimmed == "yes" {
                    Approval::Accept
                } else {
                    Approval::Reject {
                        reason: "user declined".to_string(),
                    }
                }
            }
            Err(e) => Approval::Reject {
                reason: format!("failed to read stdin: {e}"),
            },
        }
    }
}
