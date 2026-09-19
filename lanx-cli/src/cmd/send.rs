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
    relay: Option<&str>,
    no_discovery: bool,
    allow_insecure_direct: bool,
) -> bool {
    relay.is_none() && !no_discovery && !allow_insecure_direct
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
    relay: Option<String>,
    verbose: bool,
    code_words: u8,
    psk_opt: Option<String>,
    allow_insecure_direct: bool,
) -> Result<()> {
    if allow_insecure_direct && relay.is_some() {
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
    let total_bytes: u64 = manifest.files.iter().map(|f| f.size).sum();
    hash_spinner.finish_and_clear();
    let n_files = manifest.files.len();
    eprintln!(
        "  {} {} {}",
        ui::green(ui::ok_sym()),
        ui::dim("hashed"),
        ui::count_line(n_files, total_bytes),
    );

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
    if let Some(ref relay_addr) = relay {
        crate::cmd::warn_if_public_relay(relay_addr);
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
    if fell_back && relay.is_none() {
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
    crate::cmd::validate_parallel_relay(parallel, &relay)?;
    let progress: Arc<dyn lanx_core::progress::Progress> = IndicatifProgress::new("Sending");

    // Direct-mode connection details print once here, not every
    // reconnection round. Pairing code first (the normal path), then
    // the manual command in the same key/value shape; the command
    // already carries the address, so a separate `address` row would
    // only repeat it. The bare bind address is verbose-only
    // diagnostics. Loopback commands are verbose-only too: they
    // almost never help a transfer to another machine.
    if relay.is_none() {
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
    if should_start_discovery(relay.as_deref(), no_discovery, allow_insecure_direct) {
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
        };

        let mut set = tokio::task::JoinSet::new();
        let mut first_task_result = None;

        if let Some(ref relay_addr) = relay {
            // Relay mode: connect to the relay server and register as a sender.
            eprintln!(
                "  {} {} {}",
                ui::dim("relay"),
                ui::arrow(),
                ui::bold(relay_addr)
            );
            eprintln!();

            let mut stream = TcpStream::connect(relay_addr)
                .await
                .with_context(|| crate::cmd::relay_connect_hint(relay_addr, "sender"))?;
            if let Err(e) = stream.set_nodelay(true) {
                tracing::debug!(?e, "TCP_NODELAY failed");
            }

            // Send hello to register with the relay, then read the
            // one-byte ack so "code already registered" doesn't look
            // like a generic connection failure.
            let challenge = read_relay_challenge(&mut stream)
                .await
                .context("relay did not send an authentication challenge")?;
            let hello = RelayHello {
                role: RelayRole::Sender,
                code_hash,
                auth_token: crate::cmd::relay_auth_token()
                    .map(|token| relay_auth_proof(&token, &challenge, &code_hash)),
            };
            send_relay_hello(&mut stream, &hello)
                .await
                .context("failed to register sender with relay; check relay auth settings")?;
            let ack = tokio::time::timeout(
                Duration::from_secs(10),
                lanx_net::relay::read_relay_ack(&mut stream),
            )
            .await
            .context("relay registration timed out; check relay reachability and auth settings")?
            .context("relay closed before sender registration completed")?;
            match ack {
                lanx_net::relay::RELAY_ACK_OK => {}
                lanx_net::relay::RELAY_ACK_IN_USE => {
                    anyhow::bail!(
                        "relay reports this pairing ID is already registered (another sender is waiting on it); \
                         re-run `send` for a fresh code"
                    )
                }
                _ => {
                    anyhow::bail!(
                        "relay rejected sender registration (server at capacity?); try again later"
                    )
                }
            }

            eprintln!(
                "  {} {}",
                ui::green(ui::ok_sym()),
                ui::dim("registered with relay (waiting for receiver)")
            );
            eprintln!();

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
                if relay.is_some() {
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
        assert!(!should_start_discovery(None, false, true));
    }

    #[test]
    fn normal_direct_mode_discovers_unless_disabled() {
        assert!(should_start_discovery(None, false, false));
        assert!(!should_start_discovery(None, true, false));
    }

    #[test]
    fn relay_mode_never_discovers() {
        assert!(!should_start_discovery(
            Some("127.0.0.1:53318"),
            false,
            false
        ));
    }
}
