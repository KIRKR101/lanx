//! `lanx recv`: connect to sender, receive files.

use anyhow::{bail, Context, Result};
use lanx_core::destinations::{preview_conflicts, OverwritePolicy};
use lanx_core::manifest::Manifest;
use lanx_core::progress::Progress;
use lanx_core::progress::TransferSummary;
use lanx_core::transfer::receiver::{
    run_receiver, Approval, AutoAccept, ManifestApprover, ReceiverConfig, SharedApprover,
};
use lanx_core::transfer::DEFAULT_MAX_RETRIES;
use lanx_net::discovery::{code_to_pairing_id, code_to_psk, code_word_count};
use lanx_net::pairing::{parse_target, resolve_target, Target};
use lanx_net::relay::{send_relay_hello, RelayHello, RelayRole};
use lanx_net::tcp::DEFAULT_SEND_PORT;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;

use crate::json_progress::JsonProgress;
use crate::progress::IndicatifProgress;
use crate::ui;

/// Conflict behavior for non-interactive use (`--on-conflict`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum OnConflict {
    /// Skip files whose destination already exists.
    Skip,
    /// Overwrite existing destination files.
    Overwrite,
    /// Abort if any destination file already exists.
    Fail,
}

/// Pairing ID plus handshake PSK. `None`/`None` means unauthenticated
/// (bare `ip:port` with no `--code`).
type PairingKeys = (Option<[u8; 32]>, Option<[u8; 32]>);

/// Decide the pairing ID and handshake PSK from the target and `--code`.
///
/// * Code target (discovery/relay): both derive from the target code.
///   `--code` alongside is a hard error — the code is already the target.
/// * `ip:port` + `--code`: both derive from the flag value (validated as
///   a code, with an example on junk input).
/// * Bare `ip:port`: `(None, None)` — unauthenticated `Noise_NN`, which
///   fails against senders without `--allow-insecure-direct`.
///
/// Pure (no I/O) so it unit-tests cleanly.
///
/// # Errors
///
/// Returns an error if `--code` is combined with a code target or if the
/// flag value is not shaped like a pairing code.
pub fn resolve_handshake_psk(
    target: &Target,
    code_flag: Option<&str>,
    passphrase: Option<&str>,
) -> Result<PairingKeys> {
    match (target, code_flag) {
        (Target::Code(_), Some(_)) => {
            bail!("--code is only for ip:port targets; the pairing code is already the target")
        }
        (Target::Code(code), None) => Ok((
            Some(code_to_pairing_id(code)),
            Some(code_to_psk(code, passphrase)),
        )),
        (Target::Addr(_), Some(flag)) => match parse_target(flag) {
            Ok(Target::Code(_)) => Ok((
                Some(code_to_pairing_id(flag)),
                Some(code_to_psk(flag, passphrase)),
            )),
            _ => bail!(
                "--code must look like a pairing code (e.g. 7-cobalt-fox-tundra), got {flag:?}"
            ),
        },
        (Target::Addr(_), None) => Ok((None, None)),
    }
}

/// Resolve the effective [`OverwritePolicy`] from the granular flags and
/// `--on-conflict`. Returns an error when mutually exclusive options are
/// combined (Clap also enforces this for CLI input; this covers
/// programmatic callers).
///
/// # Errors
///
/// Returns an error if more than one policy source is set.
pub fn resolve_policy(
    overwrite: bool,
    skip_existing: bool,
    rename_existing: bool,
    on_conflict: Option<OnConflict>,
) -> Result<OverwritePolicy> {
    let granular = [overwrite, skip_existing, rename_existing]
        .iter()
        .filter(|&&b| b)
        .count();
    if granular > 1 || (granular == 1 && on_conflict.is_some()) {
        bail!("--overwrite, --skip-existing, --rename-existing and --on-conflict are mutually exclusive");
    }
    if overwrite || on_conflict == Some(OnConflict::Overwrite) {
        Ok(OverwritePolicy::Overwrite)
    } else if skip_existing || on_conflict == Some(OnConflict::Skip) {
        Ok(OverwritePolicy::SkipExisting)
    } else if rename_existing {
        Ok(OverwritePolicy::RenameExisting)
    } else if on_conflict == Some(OnConflict::Fail) {
        Ok(OverwritePolicy::Fail)
    } else {
        Ok(OverwritePolicy::Resume)
    }
}

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
    handshake_psk: Option<[u8; 32]>,
    /// True when `--code` was given for an `ip:port` target. A handshake
    /// failure then means either a wrong code *or* a policy mismatch
    /// (sender runs plain `--allow-insecure-direct` while we offered
    /// PSK), so the hint must cover both.
    addr_target_with_code: bool,
    out: PathBuf,
    approver: Arc<dyn ManifestApprover>,
    progress: Arc<dyn Progress>,
    parallel: u16,
    overwrite_policy: OverwritePolicy,
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
/// Options for one `lanx recv` invocation.
pub struct RecvOptions {
    pub target: String,
    pub code: Option<String>,
    pub out: PathBuf,
    pub accept: bool,
    pub overwrite: bool,
    pub skip_existing: bool,
    pub rename_existing: bool,
    pub dry_run: bool,
    pub json: bool,
    pub quiet: bool,
    pub on_conflict: Option<OnConflict>,
    pub retry_forever: bool,
    pub discovery_timeout: Duration,
    pub parallel: u16,
    pub relay: Option<String>,
    pub psk: Option<String>,
}

pub async fn run(opts: RecvOptions) -> Result<()> {
    let RecvOptions {
        target,
        code: code_flag,
        out,
        accept,
        overwrite,
        skip_existing,
        rename_existing,
        dry_run,
        json,
        quiet,
        on_conflict,
        retry_forever,
        discovery_timeout,
        parallel,
        relay,
        psk,
    } = opts;
    let overwrite_policy = resolve_policy(overwrite, skip_existing, rename_existing, on_conflict)?;
    // `--json` and `--quiet` suppress informational stderr; warnings and
    // errors still print.
    let human = !json && !quiet;
    if accept && human {
        eprintln!(
            "  {} {}",
            ui::yellow("!"),
            ui::yellow("auto-accept: accepting without prompting"),
        );
        eprintln!("    {}", ui::dim("only use this when you trust the sender"),);
    }
    if dry_run && human {
        eprintln!(
            "  {} {}",
            ui::yellow("!"),
            ui::yellow("dry run: showing what would be received without writing files"),
        );
    }

    let parsed = parse_target(&target).context("parse target")?;
    if relay.is_some() && !matches!(parsed, Target::Code(_)) {
        bail!("--relay requires a pairing code (e.g. 7-cobalt-fox-tundra), not an ip:port address");
    }
    let passphrase = crate::cmd::resolve_passphrase(psk);
    if let Some(ref relay_addr) = relay {
        crate::cmd::warn_if_public_relay(relay_addr);
    }
    // Pairing ID + PSK from the target code or `--code` (see
    // `resolve_handshake_psk`). Bare `ip:port` stays unauthenticated.
    let (code_hash, handshake_psk) =
        resolve_handshake_psk(&parsed, code_flag.as_deref(), passphrase.as_deref())?;
    let addr_target_with_code = matches!(&parsed, Target::Addr(_)) && code_flag.is_some();
    // The code the user effectively paired with, for strength warnings.
    let effective_code: Option<&str> = match &parsed {
        Target::Code(code) => Some(code),
        Target::Addr(_) => code_flag.as_deref(),
    };
    if let Some(code) = effective_code {
        if code_word_count(code) < 3 && human {
            eprintln!(
                "  {} {}",
                ui::yellow("!"),
                ui::yellow("short pairing code (<3 words, weak against guessing); ask the sender for a longer code for sensitive transfers"),
            );
        }
    } else if human {
        eprintln!(
            "  {} {}",
            ui::yellow("!"),
            ui::yellow("unauthenticated: no pairing code given; the sender must pass --allow-insecure-direct, and anyone on the path can impersonate either side"),
        );
    }

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
        if human {
            eprintln!("  {} {} {}", ui::dim("relay"), ui::arrow(), ui::bold(ra));
        }
    } else if human {
        eprintln!(
            "  {} found sender  {}",
            ui::green(ui::ok_sym()),
            ui::dim(&addr.to_string()),
        );
    }
    if human {
        eprintln!();
    }

    let progress: Arc<dyn Progress> = if json {
        JsonProgress::new()
    } else if quiet {
        Arc::new(lanx_core::NoopProgress)
    } else {
        IndicatifProgress::new("Receiving")
    };

    let base_approver: Arc<dyn ManifestApprover> = if dry_run {
        Arc::new(DryRunApprover {
            out_dir: out.clone(),
            overwrite_policy,
            json,
        })
    } else if accept {
        Arc::new(AutoAccept)
    } else {
        Arc::new(StdinApprover {
            out_dir: out.clone(),
            overwrite_policy,
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
        handshake_psk,
        addr_target_with_code,
        out: out.clone(),
        approver,
        progress: progress.clone(),
        parallel,
        overwrite_policy,
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
                            if human {
                                eprintln!(
                                    "  {} sender {}",
                                    ui::dim("update"),
                                    ui::bold(&new_addr.to_string()),
                                );
                            }
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
                    if dry_run {
                        if human {
                            eprintln!();
                            eprintln!(
                                "  {} {}",
                                ui::dim("dry run complete:"),
                                ui::dim("no files were written"),
                            );
                        }
                        return Ok(());
                    }
                    eprintln!();
                    eprintln!(
                        "  {} {}",
                        ui::red(ui::fail_sym()),
                        ui::red("transfer declined"),
                    );
                    bail!("transfer declined by user");
                }
                // `summary` prints the styled completion line.
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
    // control messages are exchanged. Code-based transfers use the
    // PSK-authenticated pattern; a wrong code/passphrase fails here with
    // guidance, while bare ip:port stays plain and fails against
    // senders that did not pass --allow-insecure-direct.
    let (timeout_hint, fail_hint) = if cfg.addr_target_with_code {
        (
            "noise handshake timed out (code was supplied but the sender may be using --allow-insecure-direct, or the code/passphrase is wrong)",
            "noise handshake (code was supplied but the sender may be using --allow-insecure-direct, or the code/passphrase is wrong)",
        )
    } else if cfg.handshake_psk.is_some() {
        (
            "noise handshake timed out (wrong code/passphrase, or sender gone?)",
            "noise handshake (wrong code/passphrase?)",
        )
    } else {
        (
            "noise handshake timed out (sender may require a pairing code: rerun with --code <code> from the sender screen)",
            "noise handshake (sender may require a pairing code: rerun with --code <code> from the sender screen)",
        )
    };
    let enc = tokio::time::timeout(
        NOISE_HANDSHAKE_TIMEOUT,
        lanx_core::crypto::wrap_initiator_with_psk(stream, cfg.handshake_psk),
    )
    .await
    .context(timeout_hint)?
    .context(fail_hint)?;

    let (mut r, w) = tokio::io::split(enc);
    let mut w = tokio::io::BufWriter::new(w);

    let recv_cfg = ReceiverConfig {
        max_retries: DEFAULT_MAX_RETRIES,
        connection_index,
        parallel: cfg.parallel,
        overwrite_policy: cfg.overwrite_policy,
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
    overwrite_policy: OverwritePolicy,
}

/// Prints the transfer contents without accepting it. Used for `--dry-run`.
struct DryRunApprover {
    out_dir: PathBuf,
    overwrite_policy: OverwritePolicy,
    json: bool,
}

/// Shared conflict summary printed before confirmation: how many
/// destination files already exist, how many look resumable vs complete
/// by size, and how many are new. Size equality is a heuristic; content
/// is verified by hash during the real transfer.
fn print_conflict_preview(manifest: &Manifest, out_dir: &Path, overwrite_policy: OverwritePolicy) {
    let preview = match preview_conflicts(manifest, out_dir) {
        Ok(p) => p,
        Err(e) => {
            // E.g. multi-file transfer with `--out` pointing at an
            // existing file: show the coming failure instead of
            // misleading `0 existing / 0 new` counts.
            eprintln!("    {}", ui::dim(&format!("cannot receive here: {e}")));
            return;
        }
    };
    if preview.existing == 0 && preview.new == 0 {
        return;
    }
    eprintln!(
        "    {}",
        ui::dim(&format!(
            "{} existing ({} complete, {} resumable), {} new",
            preview.existing, preview.complete_by_size, preview.resumable_by_size, preview.new,
        )),
    );
    let note = match overwrite_policy {
        OverwritePolicy::Resume => None,
        OverwritePolicy::Overwrite => Some("overwrite: existing files will be replaced"),
        OverwritePolicy::SkipExisting => {
            Some("skip-existing: existing files will be left untouched")
        }
        OverwritePolicy::RenameExisting => {
            Some("rename-existing: incoming files will be written to numbered siblings")
        }
        OverwritePolicy::Fail => {
            Some("on-conflict fail: aborting would trigger if any file exists")
        }
    };
    if let Some(note) = note {
        eprintln!("    {}", ui::dim(note));
    }
}

impl ManifestApprover for StdinApprover {
    fn approve(&self, manifest: &Manifest, summary: &TransferSummary) -> Approval {
        // Non-interactive stdin cannot answer a prompt; refuse so the user
        // can rerun with `--accept`/`--yes` if automation is intended.
        if !io::stdin().is_terminal() {
            return Approval::Reject {
                reason: "stdin is not a TTY; pass --accept (or --yes) to accept automatically"
                    .to_string(),
            };
        }

        eprintln!("  {} Incoming transfer", ui::cyan(ui::down_sym()));
        eprintln!(
            "    {}",
            ui::bold(&ui::count_line(summary.file_count, summary.total_bytes)),
        );
        eprintln!();

        // Same root-stripped `name  size` rows as the live progress
        // that follows, so the prompt flows into the transfer instead
        // of switching representations.
        let rel_paths: Vec<String> = manifest.files.iter().map(|f| f.rel_path.clone()).collect();
        let display = ui::display_names(&rel_paths);
        for (entry, name) in manifest
            .files
            .iter()
            .zip(display.iter())
            .take(MANIFEST_PREVIEW_LIMIT)
        {
            eprintln!("{}", ui::contents_row(name, entry.size));
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
        print_conflict_preview(manifest, &self.out_dir, self.overwrite_policy);

        eprintln!();
        eprint!("  {} Accept? [y/N]: ", ui::cyan("?"));
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

impl ManifestApprover for DryRunApprover {
    fn approve(&self, manifest: &Manifest, summary: &TransferSummary) -> Approval {
        if self.json {
            // Machine-readable preview on stdout; stderr stays silent.
            let (existing, complete, resumable, new, error) =
                match preview_conflicts(manifest, &self.out_dir) {
                    Ok(p) => (
                        p.existing,
                        p.complete_by_size,
                        p.resumable_by_size,
                        p.new,
                        None,
                    ),
                    Err(e) => (0, 0, 0, 0, Some(e.to_string())),
                };
            let files: Vec<serde_json::Value> = manifest
                .files
                .iter()
                .map(|f| serde_json::json!({"path": f.rel_path, "size": f.size}))
                .collect();
            println!(
                "{}",
                serde_json::json!({
                    "event": "dry_run",
                    "files": summary.file_count,
                    "bytes": summary.total_bytes,
                    "existing": existing,
                    "complete": complete,
                    "resumable": resumable,
                    "new": new,
                    "error": error,
                    "contents": files,
                })
            );
            return Approval::Reject {
                reason: "dry run: transfer not accepted".to_string(),
            };
        }
        eprintln!("  {} Incoming transfer (dry run)", ui::cyan(ui::down_sym()));
        eprintln!(
            "    {}",
            ui::bold(&ui::count_line(summary.file_count, summary.total_bytes)),
        );
        eprintln!();
        let rel_paths: Vec<String> = manifest.files.iter().map(|f| f.rel_path.clone()).collect();
        let display = ui::display_names(&rel_paths);
        for (entry, name) in manifest
            .files
            .iter()
            .zip(display.iter())
            .take(MANIFEST_PREVIEW_LIMIT)
        {
            eprintln!("{}", ui::contents_row(name, entry.size));
        }
        let remaining = summary.file_count.saturating_sub(MANIFEST_PREVIEW_LIMIT);
        if remaining > 0 {
            eprintln!("  {}", ui::dim(&format!("... and {remaining} more")));
        }
        let out_is_default = self.out_dir.as_os_str() == ".";
        if !out_is_default {
            eprintln!("    {}  {}", ui::dim("Destination"), self.out_dir.display(),);
        }
        print_conflict_preview(manifest, &self.out_dir, self.overwrite_policy);
        eprintln!();
        Approval::Reject {
            reason: "dry run: transfer not accepted".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_defaults_to_resume() {
        assert_eq!(
            resolve_policy(false, false, false, None).unwrap(),
            OverwritePolicy::Resume
        );
    }

    #[test]
    fn granular_flags_map_to_policies() {
        assert_eq!(
            resolve_policy(true, false, false, None).unwrap(),
            OverwritePolicy::Overwrite
        );
        assert_eq!(
            resolve_policy(false, true, false, None).unwrap(),
            OverwritePolicy::SkipExisting
        );
        assert_eq!(
            resolve_policy(false, false, true, None).unwrap(),
            OverwritePolicy::RenameExisting
        );
    }

    #[test]
    fn on_conflict_maps_to_policies() {
        assert_eq!(
            resolve_policy(false, false, false, Some(OnConflict::Skip)).unwrap(),
            OverwritePolicy::SkipExisting
        );
        assert_eq!(
            resolve_policy(false, false, false, Some(OnConflict::Overwrite)).unwrap(),
            OverwritePolicy::Overwrite
        );
        assert_eq!(
            resolve_policy(false, false, false, Some(OnConflict::Fail)).unwrap(),
            OverwritePolicy::Fail
        );
    }

    #[test]
    fn conflicting_policy_sources_are_rejected() {
        assert!(resolve_policy(true, true, false, None).is_err());
        assert!(resolve_policy(true, false, false, Some(OnConflict::Skip)).is_err());
        assert!(resolve_policy(false, true, false, Some(OnConflict::Fail)).is_err());
    }

    #[test]
    fn psk_from_code_target() {
        let t = parse_target("7-cobalt-fox-tundra").unwrap();
        let (id, psk) = resolve_handshake_psk(&t, None, None).unwrap();
        assert!(id.is_some() && psk.is_some());
        assert_eq!(id.unwrap(), code_to_pairing_id("7-cobalt-fox-tundra"));
    }

    #[test]
    fn psk_from_addr_plus_code_flag() {
        let t = parse_target("192.168.1.5:29320").unwrap();
        let (id, psk) = resolve_handshake_psk(&t, Some("7-cobalt-fox-tundra"), None).unwrap();
        assert!(id.is_some() && psk.is_some());
        // Same code via flag or target derives the same keys.
        let t2 = parse_target("7-cobalt-fox-tundra").unwrap();
        let (id2, psk2) = resolve_handshake_psk(&t2, None, None).unwrap();
        assert_eq!(id, id2);
        assert_eq!(psk, psk2);
    }

    #[test]
    fn bare_addr_is_unauthenticated() {
        let t = parse_target("192.168.1.5:29320").unwrap();
        let (id, psk) = resolve_handshake_psk(&t, None, None).unwrap();
        assert!(id.is_none() && psk.is_none());
    }

    #[test]
    fn code_flag_with_code_target_rejected() {
        let t = parse_target("7-cobalt-fox-tundra").unwrap();
        assert!(resolve_handshake_psk(&t, Some("7-cobalt-fox-tundra"), None).is_err());
    }

    #[test]
    fn junk_code_flag_rejected() {
        let t = parse_target("192.168.1.5:29320").unwrap();
        assert!(resolve_handshake_psk(&t, Some("not-a-code"), None).is_err());
        assert!(resolve_handshake_psk(&t, Some("192.168.1.6:1234"), None).is_err());
    }

    #[test]
    fn passphrase_changes_psk_but_not_id() {
        let t = parse_target("7-cobalt-fox-tundra").unwrap();
        let (id1, psk1) = resolve_handshake_psk(&t, None, None).unwrap();
        let (id2, psk2) = resolve_handshake_psk(&t, None, Some("pw")).unwrap();
        assert_eq!(id1, id2);
        assert_ne!(psk1, psk2);
    }
}
