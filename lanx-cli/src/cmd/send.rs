//! `lanx send`: build manifest, listen for receiver, transfer.

use anyhow::{Context, Result};
use lanx_core::manifest::{
    build_with_filters_cached, rel_to_path, validate_rel_path, FilterOptions,
};
use lanx_core::transfer::sender::{run_sender, SenderConfig};
use lanx_core::transfer::DEFAULT_MAX_RETRIES;
use lanx_net::discovery::{
    code_to_pairing_id, code_to_psk, generate_code_with_words, start_broadcasting,
};
use lanx_net::relay::{
    read_relay_challenge, relay_auth_proof, send_relay_hello, RelayHello, RelayRole,
};
use lanx_net::tcp::{listen_default, listen_on, GracefulListener, DEFAULT_SEND_PORT};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tracing::warn;
use zip::write::SimpleFileOptions;
use zip::CompressionMethod;

use crate::progress::IndicatifProgress;
use crate::ui;

fn spawn_stream(
    set: &mut tokio::task::JoinSet<Result<(), lanx_core::transfer::ProtocolError>>,
    stream: TcpStream,
    manifest: lanx_core::manifest::Manifest,
    sources: HashMap<lanx_core::manifest::FileId, PathBuf>,
    progress: Arc<dyn lanx_core::progress::Progress>,
    cfg: SenderConfig,
    psk: Option<[u8; 32]>,
) {
    set.spawn(async move {
        let enc = match tokio::time::timeout(
            Duration::from_secs(10),
            lanx_core::crypto::wrap_responder_with_psk(stream, psk),
        )
        .await
        {
            Ok(Ok(enc)) => enc,
            Ok(Err(e)) => {
                let hint = if psk.is_some() {
                    "receiver did not accept the PSK handshake (it may be using --allow-insecure-direct, or the code/passphrase is wrong)"
                } else {
                    "receiver used a wrong code, or connected with --code while this sender allows only bare direct connections"
                };
                return Err(lanx_core::transfer::ProtocolError::Unexpected(format!(
                    "noise handshake ({hint}): {e}"
                )));
            }
            Err(_) => {
                return Err(lanx_core::transfer::ProtocolError::Unexpected(
                    "noise handshake timed out".into(),
                ));
            }
        };
        let (mut reader, writer) = tokio::io::split(enc);
        let mut writer = tokio::io::BufWriter::new(writer);
        run_sender(
            &mut reader,
            &mut writer,
            &manifest,
            &sources,
            progress.as_ref(),
            &cfg,
        )
        .await
    });
}

fn should_start_discovery(
    relay: &crate::cmd::RelayMode,
    no_discovery: bool,
    allow_insecure_direct: bool,
) -> bool {
    matches!(
        relay,
        crate::cmd::RelayMode::Direct | crate::cmd::RelayMode::Auto
    ) && !no_discovery
        && !allow_insecure_direct
}

/// Failure to register as a sender with a relay.
#[derive(Debug)]
enum RegisterError {
    /// The pairing ID is already registered by another live sender. With
    /// an explicit relay this is fatal; `--relay auto` treats it as
    /// transient (usually our own stale slot still draining server-side)
    /// and retries with warn-once-then-quiet.
    CodeInUse,
    /// Dial, challenge, hello, ack, or capacity failure.
    Other(anyhow::Error),
}

impl std::fmt::Display for RegisterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CodeInUse => write!(
                f,
                "relay reports this pairing ID is already registered (another sender is waiting on it); \
                 re-run `send` for a fresh code"
            ),
            Self::Other(e) => write!(f, "{e:#}"),
        }
    }
}

impl std::error::Error for RegisterError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CodeInUse => None,
            Self::Other(e) => Some(e.as_ref()),
        }
    }
}

/// Shared deadline state for `--relay auto` arms. The deadline is fixed from
/// startup, so repeated failed authenticated sessions cannot keep an
/// abandoned send alive indefinitely.
///
/// Lock-free (atomics only) so it can be shared across async tasks without
/// blocking the executor.
#[derive(Debug, Clone)]
struct AutoState {
    inner: std::sync::Arc<AutoStateInner>,
}

#[derive(Debug)]
struct AutoStateInner {
    created: std::time::Instant,
    /// Milliseconds from `created` at which the auto-send lifetime lapses.
    deadline_offset_ms: std::sync::atomic::AtomicU64,
    had_session: std::sync::atomic::AtomicBool,
}

impl AutoState {
    fn new(overall: Duration) -> Self {
        Self {
            inner: std::sync::Arc::new(AutoStateInner {
                created: std::time::Instant::now(),
                deadline_offset_ms: std::sync::atomic::AtomicU64::new(
                    u64::try_from(overall.as_millis()).unwrap_or(u64::MAX),
                ),
                had_session: std::sync::atomic::AtomicBool::new(false),
            }),
        }
    }

    fn had_session(&self) -> bool {
        self.inner
            .had_session
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Time left before the auto-send lifetime expires.
    fn remaining(&self) -> Duration {
        let offset = self
            .inner
            .deadline_offset_ms
            .load(std::sync::atomic::Ordering::SeqCst);
        Duration::from_millis(offset).saturating_sub(self.inner.created.elapsed())
    }

    fn expired(&self) -> bool {
        self.remaining().is_zero()
    }

    /// Record that at least one authenticated session was established.
    fn note_authenticated(&self) {
        self.inner
            .had_session
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Connect to one relay and register as a sender (challenge + hello +
/// ack). Shared by explicit relay mode and `--relay auto` candidates so
/// both enforce the same auth and duplicate-registration policy.
async fn register_sender_with_relay(
    relay_addr: &str,
    proxy: Option<&lanx_net::socks::Socks5Config>,
    code_hash: [u8; 32],
) -> Result<TcpStream, RegisterError> {
    let mut stream = lanx_net::socks::dial_relay(relay_addr, proxy, Duration::from_secs(10))
        .await
        .with_context(|| crate::cmd::relay_connect_hint(relay_addr, "sender"))
        .map_err(RegisterError::Other)?;
    if let Err(e) = stream.set_nodelay(true) {
        tracing::debug!(?e, "TCP_NODELAY failed");
    }

    // Send hello to register with the relay, then read the
    // one-byte ack so "code already registered" doesn't look
    // like a generic connection failure.
    let challenge = read_relay_challenge(&mut stream)
        .await
        .context("relay did not send an authentication challenge")
        .map_err(RegisterError::Other)?;
    let hello = RelayHello {
        role: RelayRole::Sender,
        code_hash,
        auth_token: crate::cmd::relay_auth_token()
            .map(|token| relay_auth_proof(&token, &challenge, &code_hash)),
    };
    send_relay_hello(&mut stream, &hello)
        .await
        .context("failed to register sender with relay; check relay auth settings")
        .map_err(RegisterError::Other)?;
    let ack = tokio::time::timeout(
        Duration::from_secs(10),
        lanx_net::relay::read_relay_ack(&mut stream),
    )
    .await
    .context("relay registration timed out; check relay reachability and auth settings")
    .map_err(RegisterError::Other)?
    .context("relay closed before sender registration completed")
    .map_err(RegisterError::Other)?;
    match ack {
        lanx_net::relay::RELAY_ACK_OK => Ok(stream),
        lanx_net::relay::RELAY_ACK_IN_USE => Err(RegisterError::CodeInUse),
        _ => Err(RegisterError::Other(anyhow::anyhow!(
            "relay rejected sender registration (server at capacity?); try again later"
        ))),
    }
}

/// Run the `lanx send` subcommand. Builds a manifest from the given
/// paths, listens for a receiver (with optional UDP discovery), and
/// streams the files.
///
/// # Errors
///
/// Returns an error if manifest building fails, no receiver connects
/// within the grace period, or the transfer encounters a protocol error.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    paths: Vec<PathBuf>,
    text: Option<String>,
    message: Option<String>,
    chunk_size: u32,
    no_discovery: bool,
    zip: bool,
    port: Option<u16>,
    bind: Option<String>,
    exclude: Vec<String>,
    include: Vec<String>,
    hidden: bool,
    no_cache: bool,
    parallel: u16,
    relay: crate::cmd::RelayMode,
    verbose: bool,
    code_words: u8,
    psk_opt: Option<String>,
    allow_insecure_direct: bool,
    proxy: Option<lanx_net::socks::Socks5Config>,
) -> Result<()> {
    if paths.is_empty() && text.is_none() {
        anyhow::bail!("provide at least one path or use --text");
    }
    if text.is_some() && !paths.is_empty() {
        anyhow::bail!("--text cannot be combined with file paths");
    }
    if message
        .as_ref()
        .is_some_and(|value| value.len() > lanx_core::transfer::MAX_TRANSFER_MESSAGE_BYTES)
    {
        anyhow::bail!("--message is limited to 4096 bytes");
    }
    if text
        .as_ref()
        .is_some_and(|value| value.len() > lanx_core::transfer::MAX_TRANSFER_TEXT_BYTES)
    {
        anyhow::bail!("--text is limited to 1 MiB");
    }
    if allow_insecure_direct && !matches!(relay, crate::cmd::RelayMode::Direct) {
        anyhow::bail!("--allow-insecure-direct is only valid for direct transfers, not --relay");
    }

    // Optional zip mode (explicit `--zip`). When set, the input is
    // packaged into a single `.zip` file in a temp dir and that single
    // file is what gets sent. Without `--zip`, directories are sent
    // natively: the manifest builder walks them and the receiver
    // reconstructs the folder structure (Path B in lanx-core).
    let (_zip_cleanup, effective_paths) = if zip {
        let paths = paths.clone();
        let (zip_path, tmp) = tokio::task::spawn_blocking(move || zip_inputs(&paths))
            .await
            .context("zip task panicked")??;
        eprintln!(
            "  {} --zip {} {}",
            ui::dim("pack"),
            ui::arrow(),
            zip_path.display()
        );
        (Some(tmp), vec![zip_path])
    } else {
        (None, paths)
    };

    let manifest = if text.is_some() {
        lanx_core::manifest::Manifest {
            files: Vec::new(),
            chunk_size,
            source_root: PathBuf::new(),
        }
    } else {
        let hash_spinner = ui::spinner(&format!("hashing files{}", ui::ellipsis()));
        let manifest = tokio::task::spawn_blocking({
            let paths = effective_paths.clone();
            let filters = FilterOptions {
                include_hidden: hidden,
                exclude,
                include,
            };
            move || build_with_filters_cached(&paths, chunk_size, &filters, no_cache)
        })
        .await
        .context("hash task panicked")??;
        hash_spinner.finish_and_clear();
        manifest
    };
    let total_bytes: u64 = manifest.files.iter().map(|f| f.size).sum();
    let n_files = manifest.files.len();
    if text.is_some() {
        eprintln!("  {} {}", ui::green(ui::ok_sym()), ui::dim("text ready"));
    } else {
        eprintln!(
            "  {} {} {}",
            ui::green(ui::ok_sym()),
            ui::dim("hashed"),
            ui::count_line(n_files, total_bytes),
        );
    }

    // Reconstruct source paths from the manifest's canonicalized
    // `source_root`. This avoids the brittleness of computing
    // longest_common_prefix from the user's original (possibly non-canonical)
    // input spellings.
    let mut sources: HashMap<_, _> = HashMap::new();
    for f in &manifest.files {
        let src_path = manifest.source_root.join(rel_to_path(&f.rel_path));
        sources.insert(f.id, src_path);
    }

    // Bind the sender port. Default: stable service port so firewall
    // rules stay writable; fall back to ephemeral only on AddrInUse.
    // Explicit --port pins hard (fails if taken). When using a relay,
    // we still generate a code for display, but the actual connection
    // goes through the relay.
    let (listener, addr, fell_back) = match bind {
        Some(ref bind_addr) => {
            let (listener, addr) = listen_on(bind_addr, port)
                .await
                .with_context(|| format!("bind sender to {bind_addr}"))?;
            (listener, addr, false)
        }
        None => match port {
            Some(p) => {
                let listener = tokio::net::TcpListener::bind(("0.0.0.0", p))
                    .await
                    .with_context(|| format!("bind to port {p}"))?;
                let addr = listener.local_addr()?;
                (listener, addr, false)
            }
            None => listen_default().await?,
        },
    };
    let code = generate_code_with_words(code_words as usize);
    let passphrase = crate::cmd::resolve_passphrase(psk_opt);
    let code_hash = code_to_pairing_id(&code);
    let handshake_psk = code_to_psk(&code, passphrase.as_deref());

    eprintln!();
    let label_w = 7;
    if allow_insecure_direct {
        ui::kv(
            "mode",
            &ui::yellow("insecure direct: use the printed ip:port command"),
            label_w,
        );
    } else {
        ui::kv("code", &ui::bold(&code), label_w);
        if passphrase.is_some() {
            eprintln!(
                "  {} {}",
                ui::dim("psk"),
                ui::dim("passphrase set (strengthens handshake)")
            );
        }
    }
    match &relay {
        crate::cmd::RelayMode::Explicit(relay_addr) => {
            crate::cmd::warn_if_public_relay(relay_addr);
        }
        crate::cmd::RelayMode::Auto => {
            eprintln!(
                "  {} {}",
                ui::dim("mode"),
                ui::bold("auto: direct + saved relay + public pool"),
            );
        }
        crate::cmd::RelayMode::Direct => {}
    }
    // Direct-listener authentication policy. By default the direct port
    // requires the pairing code (PSK-bound handshake); bare
    // `lanx recv ip:port` receivers are told to rerun with `--code`.
    // `--allow-insecure-direct` restores the old unauthenticated direct
    // mode for trusted networks.
    let direct_psk: Option<[u8; 32]> = if allow_insecure_direct {
        eprintln!(
            "  {} {}",
            ui::yellow("!"),
            ui::yellow("allowing unauthenticated direct receivers (--allow-insecure-direct)"),
        );
        None
    } else {
        Some(handshake_psk)
    };
    if fell_back && !matches!(relay, crate::cmd::RelayMode::Explicit(_)) {
        eprintln!(
            "  {} {}",
            ui::yellow("!"),
            ui::yellow(&format!(
                "default port {DEFAULT_SEND_PORT} busy; using ephemeral {} — \
                 run `sudo ufw allow {}/tcp` on this machine or free \
                 {DEFAULT_SEND_PORT} and retry",
                addr.port(),
                addr.port(),
            )),
        );
    }

    let parallel = parallel.max(1);
    // Explicit relay mode stays single-connection; `--relay auto` allows
    // parallel for the direct route and clamps relay routes to one.
    if matches!(relay, crate::cmd::RelayMode::Explicit(_)) && parallel > 1 {
        anyhow::bail!("--parallel > 1 is not supported with --relay");
    }
    let progress: Arc<dyn lanx_core::progress::Progress> = IndicatifProgress::new("Sending");

    // Direct-mode connection details print once here, not every
    // reconnection round. Pairing code first (the normal path), then
    // the manual command in the same key/value shape; the command
    // already carries the address, so a separate `address` row would
    // only repeat it. The bare bind address is verbose-only
    // diagnostics. Loopback commands are verbose-only too: they
    // almost never help a transfer to another machine.
    if !matches!(relay, crate::cmd::RelayMode::Explicit(_)) {
        let addrs: Vec<String> = match bind
            .as_deref()
            .and_then(|value| value.parse::<std::net::IpAddr>().ok())
        {
            Some(ip) if !ip.is_unspecified() => {
                vec![std::net::SocketAddr::new(ip, addr.port()).to_string()]
            }
            _ => crate::iface::list_non_loopback_v4()
                .await
                .into_iter()
                .map(|ip| format!("{ip}:{}", addr.port()))
                .collect(),
        };
        if verbose {
            match addrs.first() {
                Some(address) => ui::kv("address", address, label_w),
                None => ui::kv("address", &format!("0.0.0.0:{}", addr.port()), label_w),
            }
        }
        let indent = " ".repeat(label_w + 1);
        // The printed direct command carries --code so it pastes and just
        // works: the direct listener requires the PSK-bound handshake
        // unless --allow-insecure-direct was passed.
        let direct_cmd = |address: &str| {
            if allow_insecure_direct {
                format!("lanx recv {address}")
            } else {
                format!("lanx recv {address} --code {code}")
            }
        };
        let mut first = true;
        for ip in &addrs {
            if first {
                ui::kv("direct", &direct_cmd(ip), label_w);
                first = false;
            } else {
                eprintln!("{indent}{}", direct_cmd(ip));
            }
        }
        if addrs.is_empty() || verbose {
            let cmd = if allow_insecure_direct {
                format!("lanx recv 127.0.0.1:{}", addr.port())
            } else {
                format!("lanx recv 127.0.0.1:{} --code {code}", addr.port())
            };
            if first {
                ui::kv("direct", &cmd, label_w);
            } else if verbose {
                eprintln!("{indent}{cmd} {}", ui::dim("(loopback)"));
            }
        }
        eprintln!();
    }

    let mut disc = None;
    if should_start_discovery(&relay, no_discovery, allow_insecure_direct) {
        match start_broadcasting(addr.port(), &code).await {
            Ok(h) => disc = Some(h),
            Err(e) => {
                warn!(?e, "discovery failed; continuing without broadcast");
                eprintln!(
                    "  {} {}",
                    ui::yellow("!"),
                    ui::yellow("discovery unavailable; share the direct command instead"),
                );
            }
        }
    }

    // `--relay auto`: offer direct and every relay route at once; the
    // receiver's ordered probing (direct, saved, pool) picks the first
    // one that connects. Each transport stays open across rounds so a
    // receiver retry can resume without re-running the sender.
    if matches!(relay, crate::cmd::RelayMode::Auto) {
        let result = run_auto_send(
            manifest.clone(),
            sources.clone(),
            listener,
            code_hash,
            handshake_psk,
            direct_psk,
            chunk_size,
            message.clone(),
            text.clone(),
            parallel,
            proxy.clone(),
            progress.clone(),
        )
        .await;
        if let Some(h) = disc {
            h.stop().await;
        }
        result?;
        let (verified, failed, skipped) = progress.counts();
        progress.summary(verified, failed, skipped);
        return Ok(());
    }

    let mut listener = GracefulListener::new(listener, Duration::from_secs(60));
    let mut had_session = false;
    let mut completed = false;

    while !completed {
        // Fresh parallelism-negotiation channel per round: streams of one
        // round report into this round's receiver only.
        let (agreed_tx, mut agreed_rx) = tokio::sync::mpsc::unbounded_channel();
        let cfg = SenderConfig {
            chunk_size,
            max_retries: DEFAULT_MAX_RETRIES,
            max_parallel: parallel,
            agreed_parallel_tx: Some(agreed_tx),
            message: message.clone(),
            text: text.clone(),
        };

        let mut set = tokio::task::JoinSet::new();
        let mut first_task_result = None;

        if let crate::cmd::RelayMode::Explicit(relay_addr) = &relay {
            // Relay mode: connect to the relay server and register as a sender.
            eprintln!(
                "  {} {} {}",
                ui::dim("relay"),
                ui::arrow(),
                ui::bold(relay_addr)
            );
            eprintln!();

            let stream = register_sender_with_relay(relay_addr, proxy.as_ref(), code_hash).await?;

            eprintln!(
                "  {} {}",
                ui::green(ui::ok_sym()),
                ui::dim("registered with relay (waiting for receiver)")
            );
            eprintln!();

            // Wait until a receiver pairs (the receiver's first Noise frame)
            // before the 10 s Noise handshake starts: registration produces
            // no traffic, so the handshake timeout must not run while
            // no receiver is there. Bounded by the server's 5-minute
            // pending TTL.
            let mut probe = [0u8; 1];
            match tokio::time::timeout(Duration::from_secs(300), stream.peek(&mut probe)).await {
                Ok(Ok(0)) => {
                    anyhow::bail!("relay connection closed while waiting for receiver");
                }
                Ok(Ok(_)) => {}
                Ok(Err(e)) => {
                    return Err(anyhow::Error::new(e)
                        .context("relay connection failed while waiting for receiver"));
                }
                Err(_) => {
                    anyhow::bail!("no receiver connected via relay {relay_addr} within 5 minutes");
                }
            }

            spawn_stream(
                &mut set,
                stream,
                manifest.clone(),
                sources.clone(),
                progress.clone(),
                cfg.clone(),
                Some(handshake_psk),
            );
        } else {
            // Fresh grace window for this round: after a failed session the
            // receiver's retry loop reconnects and resumes.
            listener.reset();
            let wait_msg = if had_session {
                format!("waiting for receiver reconnection{}", ui::ellipsis())
            } else {
                format!("waiting for receiver{}", ui::ellipsis())
            };
            let wait_spinner = ui::spinner(&wait_msg);
            let stream0 = match listener.accept().await {
                Ok(s) => s,
                Err(e) => {
                    wait_spinner.finish_and_clear();
                    eprintln!(
                        "  {} {}",
                        ui::red(ui::fail_sym()),
                        ui::dim(if had_session {
                            "no reconnection within grace period (giving up)"
                        } else {
                            "no receiver connected"
                        }),
                    );
                    if let Some(h) = disc {
                        h.stop().await;
                    }
                    return Err(anyhow::Error::new(e).context("accept receiver"));
                }
            };
            wait_spinner.finish_and_clear();
            let peer = stream0
                .peer_addr()
                .map(|a| a.ip().to_string())
                .unwrap_or_else(|_| "receiver".to_string());
            eprintln!(
                "  {} connected  {}",
                ui::green(ui::ok_sym()),
                ui::dim(&peer),
            );
            had_session = true;

            spawn_stream(
                &mut set,
                stream0,
                manifest.clone(),
                sources.clone(),
                progress.clone(),
                cfg.clone(),
                direct_psk,
            );

            // Wait to negotiate parallelism on connection 0. If it fails or exits early,
            // we fallback to agreed_parallel = 1.
            let agreed_parallel = tokio::select! {
                Some(p) = agreed_rx.recv() => p,
                res = set.join_next() => {
                    if let Some(r) = res {
                        first_task_result = Some(r);
                    }
                    1
                }
            };

            if agreed_parallel > 1 {
                let extra_wait_spinner = ui::spinner(&format!(
                    "waiting for {} additional connection{} for parallel transfer{}",
                    agreed_parallel - 1,
                    if agreed_parallel == 2 { "" } else { "s" },
                    ui::ellipsis()
                ));
                for _ in 1..agreed_parallel {
                    match listener.accept().await {
                        Ok(stream) => {
                            spawn_stream(
                                &mut set,
                                stream,
                                manifest.clone(),
                                sources.clone(),
                                progress.clone(),
                                cfg.clone(),
                                direct_psk,
                            );
                        }
                        Err(e) => {
                            extra_wait_spinner.finish_and_clear();
                            tracing::warn!(error = %e, "failed to accept additional parallel connection");
                            break;
                        }
                    }
                }
                extra_wait_spinner.finish_and_clear();
            }
        }

        // Include connection 0 in the round's error handling. Direct mode
        // retries a failed session instead of exiting.
        let mut round_error: Option<anyhow::Error> = match first_task_result {
            Some(Ok(Ok(()))) => None,
            Some(Ok(Err(e))) => Some(anyhow::Error::new(e).context("transfer session")),
            Some(Err(e)) => Some(anyhow::Error::new(e).context("transfer task")),
            None => None,
        };

        while round_error.is_none() {
            match set.join_next().await {
                Some(Ok(Ok(()))) => {}
                Some(Ok(Err(e))) => {
                    round_error = Some(anyhow::Error::new(e).context("transfer session"));
                    break;
                }
                Some(Err(e)) => {
                    round_error = Some(anyhow::Error::new(e).context("transfer task"));
                    break;
                }
                None => break,
            }
        }

        match round_error {
            None => completed = true,
            Some(e) => {
                if matches!(relay, crate::cmd::RelayMode::Explicit(_)) {
                    return Err(e);
                }
                // Keep the port open so the receiver can reconnect and resume.
                warn!(?e, "session ended with error; waiting for reconnection");
                eprintln!(
                    "  {} {} {} {}",
                    ui::red(ui::fail_sym()),
                    ui::dim("session failed:"),
                    ui::red(&format!("{e}")),
                    ui::dim("(keeping the port open for reconnection)"),
                );
            }
        }
    }

    if let Some(h) = disc {
        h.stop().await;
    }
    // `_zip_cleanup` is dropped here; `TempDir` removes the temp directory.

    // Report the progress layer's counts. The manifest does not include
    // files the receiver already has.
    let (verified, failed, skipped) = progress.counts();
    progress.summary(verified, failed, skipped);

    Ok(())
}

/// `--relay auto` sender: listen direct while registered on every relay
/// candidate (saved relay, then the public pool). Each transport loops
/// across rounds: the direct listener stays bound and idle relay
/// registrations stay open, so a receiver retry after a failed session
/// can resume on any route without re-running the sender. The first
/// transport to complete a transfer wins; the rest are aborted.
#[allow(clippy::too_many_arguments)]
async fn run_auto_send(
    manifest: lanx_core::manifest::Manifest,
    sources: HashMap<lanx_core::manifest::FileId, PathBuf>,
    listener: tokio::net::TcpListener,
    code_hash: [u8; 32],
    handshake_psk: [u8; 32],
    direct_psk: Option<[u8; 32]>,
    chunk_size: u32,
    message: Option<String>,
    text: Option<String>,
    parallel: u16,
    proxy: Option<lanx_net::socks::Socks5Config>,
    progress: Arc<dyn lanx_core::progress::Progress>,
) -> Result<()> {
    let candidates = crate::cmd::auto_relay_candidates(false);
    if candidates.is_empty() {
        eprintln!(
            "  {} {}",
            ui::yellow("!"),
            ui::yellow(&crate::cmd::empty_pool_warning()),
        );
    }
    for candidate in &candidates {
        eprintln!(
            "  {} {} {}",
            ui::dim("relay"),
            ui::arrow(),
            ui::dim(&format!("{candidate} (trying)")),
        );
    }
    eprintln!();

    let base_cfg = SenderConfig {
        chunk_size,
        max_retries: DEFAULT_MAX_RETRIES,
        max_parallel: parallel,
        agreed_parallel_tx: None,
        message: message.clone(),
        text: text.clone(),
    };
    // Fixed 10-minute lifetime for the auto send. Authenticated retries do
    // not extend it, so a crash-looping receiver cannot keep the sender
    // alive indefinitely.
    let state = AutoState::new(Duration::from_secs(600));
    // Only one route may run a transfer session at a time. This keeps the
    // shared progress UI coherent while preserving parallel streams within
    // the selected route.
    let progress_gate = Arc::new(tokio::sync::Mutex::new(()));

    let mut set = tokio::task::JoinSet::new();
    // Direct arm: owns the listener for the whole send and loops
    // accept -> transfer -> (on failure) accept again.
    {
        let manifest = manifest.clone();
        let sources = sources.clone();
        let progress = progress.clone();
        let base_cfg = base_cfg.clone();
        let state = state.clone();
        let progress_gate = progress_gate.clone();
        set.spawn(async move {
            auto_direct_loop(
                listener,
                manifest,
                sources,
                base_cfg,
                direct_psk,
                progress,
                state,
                progress_gate,
            )
            .await
        });
    }
    // Relay arms: each owns its registration for the whole send and
    // loops register -> handshake/transfer -> (on failure) re-register.
    // Idle registrations stay open across rounds; only a consumed or
    // broken stream is re-registered.
    for candidate in candidates {
        let manifest = manifest.clone();
        let sources = sources.clone();
        let progress = progress.clone();
        let base_cfg = base_cfg.clone();
        let proxy = proxy.clone();
        let state = state.clone();
        let progress_gate = progress_gate.clone();
        set.spawn(async move {
            auto_relay_loop(
                candidate,
                code_hash,
                handshake_psk,
                manifest,
                sources,
                base_cfg,
                progress,
                proxy,
                state,
                progress_gate,
            )
            .await
        });
    }

    // First completed transport wins. Each arm only exits on success or
    // when the fixed auto-send lifetime expires, so an empty set means every
    // route is exhausted.
    let mut failures = Vec::new();
    let outcome = tokio::time::timeout(state.remaining(), async {
        while !set.is_empty() {
            match set.join_next().await {
                Some(Ok(Ok(route))) => return Ok::<_, anyhow::Error>(route),
                Some(Ok(Err(e))) => failures.push(format!("{e:#}")),
                Some(Err(e)) => failures.push(format!("transfer task ({e})")),
                None => break,
            }
        }
        Err::<_, anyhow::Error>(anyhow::anyhow!(
            "all transports failed: {}",
            if failures.is_empty() {
                "no route reported an error".to_string()
            } else {
                failures.join("; ")
            }
        ))
    })
    .await;
    set.abort_all();
    match outcome {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(e.context(
            "no receiver connected via direct or relay; check the receiver ran with the same code and `--relay auto`",
        )),
        Err(_) => anyhow::bail!("auto-send lifetime expired before a transfer completed"),
    }
}

/// Accept one direct connection, bounded by `wait`. Returns `Ok(None)`
/// on timeout so the caller re-checks the shared deadline instead of
/// hanging past it.
async fn accept_bounded(
    listener: &tokio::net::TcpListener,
    wait: Duration,
) -> Result<Option<TcpStream>> {
    if wait.is_zero() {
        return Ok(None);
    }
    match tokio::time::timeout(wait, listener.accept()).await {
        Ok(Ok((stream, _))) => {
            if let Err(e) = stream.set_nodelay(true) {
                tracing::debug!(?e, "TCP_NODELAY failed");
            }
            Ok(Some(stream))
        }
        Ok(Err(e)) => Err(anyhow::Error::new(e).context("auto direct accept failed")),
        Err(_) => Ok(None),
    }
}

/// Sleep up to `duration`, returning early when the shared deadline
/// expires so backoffs never overshoot the lifetime by the full sleep.
async fn sleep_aware(state: &AutoState, duration: Duration) {
    let wait = duration.min(state.remaining());
    if !wait.is_zero() {
        tokio::time::sleep(wait).await;
    }
}

/// Acquire exclusive ownership of the shared progress UI for one route
/// session. The acquisition is bounded by the auto-send lifetime so a route
/// waiting behind another session cannot outlive the overall deadline.
async fn acquire_progress_gate(
    gate: &Arc<tokio::sync::Mutex<()>>,
    state: &AutoState,
) -> Option<tokio::sync::OwnedMutexGuard<()>> {
    let remaining = state.remaining();
    if remaining.is_zero() {
        return None;
    }
    tokio::time::timeout(remaining, gate.clone().lock_owned())
        .await
        .ok()
}

/// Log a failed authenticated session: trace warning plus the terminal
/// line noting all routes stay open for reconnection.
fn log_session_failed(route: &str, e: &anyhow::Error) {
    warn!(?e, "auto {route} session failed; waiting for reconnection");
    eprintln!(
        "  {} {} {} {}",
        ui::red(ui::fail_sym()),
        ui::dim(&format!("session failed ({route}):")),
        ui::red(&format!("{e:#}")),
        ui::dim("(keeping direct + relay routes open for reconnection)"),
    );
}

/// Direct arm for `--relay auto`: keep the listener bound across rounds.
/// Each round accepts one session (plus parallel extras), runs it, and
/// waits for a reconnection on failure. An abandoned send exits once the
/// fixed auto-send lifetime lapses.
#[allow(clippy::too_many_arguments)]
async fn auto_direct_loop(
    listener: tokio::net::TcpListener,
    manifest: lanx_core::manifest::Manifest,
    sources: HashMap<lanx_core::manifest::FileId, PathBuf>,
    base_cfg: SenderConfig,
    direct_psk: Option<[u8; 32]>,
    progress: Arc<dyn lanx_core::progress::Progress>,
    state: AutoState,
    progress_gate: Arc<tokio::sync::Mutex<()>>,
) -> Result<String> {
    /// Grace for one accept interval. The shared deadline (not this interval)
    /// decides when an abandoned send ends.
    const ROUND_GRACE: Duration = Duration::from_secs(60);
    loop {
        if state.expired() {
            if state.had_session() {
                anyhow::bail!("direct: auto-send lifetime expired before a transfer completed");
            }
            anyhow::bail!("direct: no receiver connected within 10 minutes");
        }
        let (agreed_tx, mut agreed_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut cfg = base_cfg.clone();
        cfg.agreed_parallel_tx = Some(agreed_tx);
        let mut round = tokio::task::JoinSet::new();
        // Bound this accept by the time left on the shared deadline so an
        // expiry is noticed promptly instead of up to a full grace late.
        let wait = ROUND_GRACE.min(state.remaining());
        let stream0 = match accept_bounded(&listener, wait).await {
            Ok(Some(stream)) => stream,
            // Window elapsed with no receiver; loop around and re-check
            // the shared deadline.
            Ok(None) => continue,
            Err(e) => {
                tracing::debug!(error = %e, "auto direct accept failed");
                sleep_aware(&state, Duration::from_millis(100)).await;
                continue;
            }
        };
        let Some(_progress_guard) = acquire_progress_gate(&progress_gate, &state).await else {
            continue;
        };
        let mut first_result = None;
        // Set only once connection 0 proves it is an authenticated
        // receiver (see `agreed` below). A bare port-scan or wrong-code
        // probe that fails the handshake must never lift the overall
        // wait, print a session failure, or look like a session.
        let mut authenticated = false;
        spawn_stream(
            &mut round,
            stream0,
            manifest.clone(),
            sources.clone(),
            progress.clone(),
            cfg.clone(),
            direct_psk,
        );
        // `agreed` arrives after the Noise handshake plus the Hello exchange
        // on connection 0 and marks the route as authenticated.
        let mut agreed: u16 = 1;
        tokio::select! {
            Some(p) = agreed_rx.recv() => {
                authenticated = true;
                state.note_authenticated();
                agreed = p;
            }
            res = round.join_next() => {
                if let Some(r) = res {
                    first_result = Some(r);
                }
                // `agreed` may already be queued when both branches are
                // ready in the same poll; check before concluding this
                // round never authenticated.
                if let Ok(p) = agreed_rx.try_recv() {
                    authenticated = true;
                    state.note_authenticated();
                    agreed = p;
                }
            }
        };
        // Extra parallel connections are bounded like the first accept. A
        // receiver that negotiates parallelism but never opens the rest
        // must fail the round (and retry) rather than hang past the
        // deadline or report a false partial success.
        let mut extras_error: Option<anyhow::Error> = None;
        for _ in 1..agreed {
            let wait = ROUND_GRACE.min(state.remaining());
            match accept_bounded(&listener, wait).await {
                Ok(Some(stream)) => spawn_stream(
                    &mut round,
                    stream,
                    manifest.clone(),
                    sources.clone(),
                    progress.clone(),
                    cfg.clone(),
                    direct_psk,
                ),
                Ok(None) => {
                    extras_error = Some(anyhow::anyhow!(
                        "timed out waiting for {agreed} parallel receiver connections"
                    ));
                    break;
                }
                Err(e) => {
                    extras_error = Some(e);
                    break;
                }
            }
        }
        // `agreed` arrived above, so this is always an authenticated
        // failure, never a probe.
        if let Some(e) = extras_error {
            round.abort_all();
            log_session_failed("direct", &e);
            sleep_aware(&state, Duration::from_secs(2)).await;
            continue;
        }
        match drain_sender_round(&mut round, first_result).await {
            Ok(()) => return Ok(String::from("direct")),
            Err(e) => {
                // Pre-authentication failures (port-scan, wrong code) are
                // probes, not sessions: log quietly without the
                // session-failed terminal line.
                if !authenticated {
                    tracing::debug!("auto direct connection failed before handshake: {e:#}");
                    continue;
                }
                log_session_failed("direct", &e);
                continue;
            }
        }
    }
}

/// Relay arm for `--relay auto`: keep one registration open at a time
/// and re-register only after the stream is consumed or broken. Pairing
/// is awaited with a non-destructive peek, so an idle arm holds its relay
/// slot across rounds without churning registrations. An authenticated
/// session does not extend the fixed auto-send lifetime.
#[allow(clippy::too_many_arguments)]
async fn auto_relay_loop(
    candidate: String,
    code_hash: [u8; 32],
    handshake_psk: [u8; 32],
    manifest: lanx_core::manifest::Manifest,
    sources: HashMap<lanx_core::manifest::FileId, PathBuf>,
    base_cfg: SenderConfig,
    progress: Arc<dyn lanx_core::progress::Progress>,
    proxy: Option<lanx_net::socks::Socks5Config>,
    state: AutoState,
    progress_gate: Arc<tokio::sync::Mutex<()>>,
) -> Result<String> {
    let mut warned_once = false;
    let mut announced = false;
    loop {
        if state.expired() {
            if state.had_session() {
                anyhow::bail!(
                    "relay {candidate}: auto-send lifetime expired before a transfer completed"
                );
            }
            anyhow::bail!("relay {candidate}: no receiver connected within 10 minutes");
        }
        let stream = match register_sender_with_relay(&candidate, proxy.as_ref(), code_hash).await {
            Ok(s) => {
                warned_once = false;
                if !announced {
                    eprintln!(
                        "  {} {} {}",
                        ui::dim("relay"),
                        ui::arrow(),
                        ui::dim(&format!("{candidate} (waiting for receiver)")),
                    );
                    announced = true;
                }
                s
            }
            // A duplicate registration is usually our own stale slot
            // still draining server-side after a broken stream, so it is
            // transient: warn once, then back off quietly like `Other`.
            Err(RegisterError::CodeInUse) => {
                if !warned_once {
                    eprintln!(
                        "  {} {}",
                        ui::yellow("!"),
                        ui::yellow(&format!(
                            "relay {candidate} skipped: pairing ID still registered (retrying)"
                        )),
                    );
                    warned_once = true;
                } else {
                    tracing::debug!("relay {candidate} still registered; retrying quietly");
                }
                sleep_aware(&state, Duration::from_secs(5)).await;
                continue;
            }
            Err(RegisterError::Other(e)) => {
                // Registration churns server slots if retried hot, and a
                // missing relay should not drown the direct route's logs:
                // warn once, then back off quietly.
                if !warned_once {
                    eprintln!(
                        "  {} {}",
                        ui::yellow("!"),
                        ui::yellow(&format!("relay {candidate} skipped: {e:#}")),
                    );
                    warned_once = true;
                } else {
                    tracing::debug!("relay {candidate} re-register failed: {e:#}");
                }
                sleep_aware(&state, Duration::from_secs(5)).await;
                continue;
            }
        };
        // Wait for the receiver's first Noise frame before starting the
        // handshake: registration produces no traffic, so the handshake
        // timeout must not run while no receiver is there. `peek` only
        // borrows the stream, so bounding it by the deadline never kills
        // a late pairing; the short fixed handshake timeout below owns
        // the stream and stays capped at 10 s like the direct arm.
        let remaining = state.remaining();
        if remaining.is_zero() {
            continue;
        }
        let mut probe = [0u8; 1];
        match tokio::time::timeout(remaining, stream.peek(&mut probe)).await {
            Ok(Ok(0)) => {
                tracing::debug!("relay {candidate} closed while waiting for receiver");
                sleep_aware(&state, Duration::from_secs(2)).await;
                continue;
            }
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                tracing::debug!("relay {candidate} failed while waiting for receiver: {e:#}");
                sleep_aware(&state, Duration::from_secs(2)).await;
                continue;
            }
            // Window elapsed; loop around and re-check the deadline.
            Err(_) => continue,
        }
        let handshake = lanx_core::crypto::wrap_responder_with_psk(stream, Some(handshake_psk));
        let enc = match tokio::time::timeout(Duration::from_secs(10), handshake).await {
            Ok(Ok(enc)) => enc,
            Ok(Err(e)) => {
                tracing::debug!("relay {candidate} handshake failed: {e:#}");
                // Back off so a crash-looping receiver does not churn
                // relay registrations with no delay.
                sleep_aware(&state, Duration::from_secs(2)).await;
                continue;
            }
            Err(_) => {
                tracing::debug!("relay {candidate} handshake timed out");
                sleep_aware(&state, Duration::from_secs(2)).await;
                continue;
            }
        };
        let Some(_progress_guard) = acquire_progress_gate(&progress_gate, &state).await else {
            continue;
        };
        // Run the session in a task so the Hello `agreed` signal marks
        // the authenticated session exactly like the direct arm: a
        // receiver that finishes Noise then drops before Hello is a
        // probe, not a session.
        let (agreed_tx, mut agreed_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut cfg = base_cfg.clone();
        cfg.max_parallel = 1;
        cfg.agreed_parallel_tx = Some(agreed_tx);
        let task_manifest = manifest.clone();
        let task_sources = sources.clone();
        let task_progress = progress.clone();
        let (mut reader, writer) = tokio::io::split(enc);
        let mut sender_set = tokio::task::JoinSet::new();
        sender_set.spawn(async move {
            let mut writer = tokio::io::BufWriter::new(writer);
            run_sender(
                &mut reader,
                &mut writer,
                &task_manifest,
                &task_sources,
                task_progress.as_ref(),
                &cfg,
            )
            .await
        });
        let mut first_result = None;
        let mut authenticated = false;
        tokio::select! {
            Some(_) = agreed_rx.recv() => {
                authenticated = true;
                state.note_authenticated();
            }
            res = sender_set.join_next() => {
                if let Some(r) = res {
                    first_result = Some(r);
                }
                // `agreed` may already be queued when both branches are
                // ready in the same poll; check before concluding this
                // round never authenticated.
                if agreed_rx.try_recv().is_ok() {
                    authenticated = true;
                    state.note_authenticated();
                }
            }
        }
        match drain_sender_round(&mut sender_set, first_result).await {
            Ok(()) => return Ok(candidate),
            Err(e) => {
                if !authenticated {
                    tracing::debug!("relay {candidate} failed before handshake: {e:#}");
                    sleep_aware(&state, Duration::from_secs(2)).await;
                    continue;
                }
                log_session_failed("relay", &anyhow::anyhow!("relay {candidate}: {e:#}"));
                // Back off before re-registering so a fast-failing route
                // does not hammer the relay.
                sleep_aware(&state, Duration::from_secs(2)).await;
                continue;
            }
        }
    }
}

/// Drain one sender round started by `spawn_stream`, including the
/// connection-0 task that may already have finished during parallelism
/// negotiation.
async fn drain_sender_round(
    set: &mut tokio::task::JoinSet<Result<(), lanx_core::transfer::ProtocolError>>,
    first_task_result: Option<
        Result<Result<(), lanx_core::transfer::ProtocolError>, tokio::task::JoinError>,
    >,
) -> Result<()> {
    let mut round_error: Option<anyhow::Error> = match first_task_result {
        Some(Ok(Ok(()))) => None,
        Some(Ok(Err(e))) => Some(anyhow::Error::new(e).context("transfer session")),
        Some(Err(e)) => Some(anyhow::Error::new(e).context("transfer task")),
        None => None,
    };
    while round_error.is_none() {
        match set.join_next().await {
            Some(Ok(Ok(()))) => {}
            Some(Ok(Err(e))) => {
                round_error = Some(anyhow::Error::new(e).context("transfer session"));
                break;
            }
            Some(Err(e)) => {
                round_error = Some(anyhow::Error::new(e).context("transfer task"));
                break;
            }
            None => break,
        }
    }
    match round_error {
        None => Ok(()),
        Some(e) => Err(e),
    }
}

/// Copy all bytes from `reader` into `writer` in 64 KiB chunks.
fn copy_to_zip<W: Write>(reader: &mut std::fs::File, writer: &mut W) -> Result<()> {
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        writer.write_all(&buf[..n])?;
    }
    Ok(())
}

/// Package the user's input into a single zip file in a temp directory.
/// Returns the zip path and the temp directory (to clean up later).
///
/// Only invoked when `--zip` is passed; directory input without `--zip`
/// is sent natively (the manifest builder walks it and the receiver
/// reconstructs the folder).
///
/// Behavior:
/// - One input that is a directory: zip the directory's contents under the
///   directory's name. The resulting zip is named `<dirname>.zip`.
/// - One input that is a file: zip the file under its own basename. The
///   resulting zip is named `<basename>.zip`.
/// - Multiple inputs: error (the --zip flag only makes sense for a single
///   directory or file to zip).
fn zip_inputs(inputs: &[PathBuf]) -> Result<(PathBuf, tempfile::TempDir)> {
    anyhow::ensure!(
        inputs.len() == 1,
        "--zip requires exactly one input path (got {})",
        inputs.len()
    );
    let input = &inputs[0];
    let meta = std::fs::symlink_metadata(input).with_context(|| format!("stat {input:?}"))?;

    let base_name = input
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("input has no name: {input:?}"))?
        .to_os_string();
    // Strict portable default: ZIP entry names must be UTF-8
    // forward-slash paths. A non-UTF-8 input name cannot be represented
    // inside the archive, so reject instead of lossy-converting (which
    // could collide two distinct names into one entry).
    let base_name_str = base_name
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("input file name is not valid UTF-8: {input:?}"))?;
    // The archive prefix becomes the first path component of every entry;
    // it must itself be a portable name (no reserved device names,
    // trailing spaces/dots, reserved characters, over-long names).
    validate_rel_path(base_name_str)
        .map_err(|e| anyhow::anyhow!("input file name is not portable: {e}"))?;

    let tmp = tempfile::Builder::new()
        .prefix("lanx-zip-")
        .tempdir()
        .context("create temp dir")?;
    // The name is validated UTF-8 above, so this `OsString` push is
    // equivalent to string formatting here; it avoids a lossy
    // `display()` round-trip for the archive file name itself.
    let mut zip_name = base_name.clone();
    zip_name.push(".zip");
    let zip_path = tmp.path().join(&zip_name);

    let file =
        std::fs::File::create(&zip_path).with_context(|| format!("create zip {zip_path:?}"))?;
    let mut writer = zip::ZipWriter::new(file);
    let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);

    if meta.is_dir() {
        // Walk the directory, adding every file under `<dirname>/<...>`.
        // Entry names always use `/`, regardless of host OS.
        add_directory_to_zip(&mut writer, input, base_name_str, opts)?;
    } else {
        // Single file: store it under its own basename.
        writer.start_file(base_name_str, opts)?;
        let mut f = std::fs::File::open(input).with_context(|| format!("open {input:?}"))?;
        copy_to_zip(&mut f, &mut writer)?;
    }

    writer.finish().context("finalize zip")?;
    Ok((zip_path, tmp))
}

fn add_directory_to_zip(
    writer: &mut zip::ZipWriter<std::fs::File>,
    dir: &Path,
    archive_prefix: &str,
    opts: SimpleFileOptions,
) -> Result<()> {
    for entry in std::fs::read_dir(dir).with_context(|| format!("read_dir {dir:?}"))? {
        let entry = entry?;
        let path = entry.path();
        let meta = match std::fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(e) => {
                warn!(path = %path.display(), error = %e, "skipping");
                continue;
            }
        };
        if meta.file_type().is_symlink() {
            warn!(path = %path.display(), "skipping symlink");
            continue;
        }
        let file_name_os = match path.file_name() {
            Some(n) => n,
            None => anyhow::bail!("path has no file name: {:?}", path),
        };
        // Strict default: reject non-UTF-8 names inside `--zip` instead
        // of `to_string_lossy` (which could merge distinct names).
        let file_name_str = match file_name_os.to_str() {
            Some(n) => n,
            None => anyhow::bail!("file name is not valid UTF-8: {:?}", path),
        };
        // Forward slashes on every host OS: `Path::join` would emit `\`
        // separators on Windows, which unzip tools treat as literal
        // filename characters instead of directories.
        let entry_name = format!("{archive_prefix}/{file_name_str}");
        // Same traversal / absolute / reserved-name / length checks as the
        // native manifest path: the entry becomes a filename again when a
        // user extracts the archive on Windows.
        validate_rel_path(&entry_name)
            .map_err(|e| anyhow::anyhow!("entry name is not portable: {e}"))?;
        if meta.is_dir() {
            add_directory_to_zip(writer, &path, &entry_name, opts)?;
        } else if meta.is_file() {
            writer
                .start_file(entry_name, opts)
                .with_context(|| format!("zip start_file {path:?}"))?;
            let mut f = std::fs::File::open(&path).with_context(|| format!("open {path:?}"))?;
            copy_to_zip(&mut f, writer)?;
        } else {
            warn!(path = %path.display(), "skipping special file");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::should_start_discovery;

    #[test]
    fn insecure_direct_disables_discovery() {
        assert!(!should_start_discovery(
            &crate::cmd::RelayMode::Direct,
            false,
            true
        ));
    }

    #[test]
    fn normal_direct_mode_discovers_unless_disabled() {
        assert!(should_start_discovery(
            &crate::cmd::RelayMode::Direct,
            false,
            false
        ));
        assert!(!should_start_discovery(
            &crate::cmd::RelayMode::Direct,
            true,
            false
        ));
    }

    #[test]
    fn relay_mode_never_discovers() {
        assert!(!should_start_discovery(
            &crate::cmd::RelayMode::Explicit("127.0.0.1:53318".to_string()),
            false,
            false
        ));
    }

    #[test]
    fn auto_mode_discovers_for_direct_first() {
        assert!(should_start_discovery(
            &crate::cmd::RelayMode::Auto,
            false,
            false
        ));
        assert!(!should_start_discovery(
            &crate::cmd::RelayMode::Auto,
            false,
            true
        ));
    }
}
