//! `lanx send`: build manifest, listen for receiver, transfer.

use anyhow::{Context, Result};
use lanx_core::manifest::{build, rel_to_path};
use lanx_core::transfer::sender::{run_sender, SenderConfig};
use lanx_core::transfer::DEFAULT_MAX_RETRIES;
use lanx_net::discovery::{code_to_hash, generate_code, start_broadcasting};
use lanx_net::relay::{send_relay_hello, RelayHello, RelayRole};
use lanx_net::tcp::{listen, GracefulListener};
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
) {
    set.spawn(async move {
        let enc = match tokio::time::timeout(
            Duration::from_secs(10),
            lanx_core::crypto::wrap_responder(stream),
        )
        .await
        {
            Ok(Ok(enc)) => enc,
            Ok(Err(e)) => {
                return Err(lanx_core::transfer::ProtocolError::Unexpected(format!(
                    "noise handshake: {e}"
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

/// Run the `lanx send` subcommand. Builds a manifest from the given
/// paths, listens for a receiver (with optional UDP discovery), and
/// streams the files.
///
/// # Errors
///
/// Returns an error if manifest building fails, no receiver connects
/// within the grace period, or the transfer encounters a protocol error.
pub async fn run(
    paths: Vec<PathBuf>,
    chunk_size: u32,
    no_discovery: bool,
    zip: bool,
    port: Option<u16>,
    parallel: u16,
    relay: Option<String>,
) -> Result<()> {
    // Optional zip mode (explicit `--zip`). When set, the input is
    // packaged into a single `.zip` file in a temp dir and that single
    // file is what gets sent. Without `--zip`, directories are sent
    // natively: the manifest builder walks them and the receiver
    // reconstructs the folder structure (Path B in lanx-core).
    ui::banner("send", "");
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
        move || build(&paths, chunk_size)
    })
    .await
    .context("hash task panicked")??;
    let total_bytes: u64 = manifest.files.iter().map(|f| f.size).sum();
    hash_spinner.finish_and_clear();
    let file_word = if manifest.files.len() == 1 {
        "file"
    } else {
        "files"
    };
    eprintln!(
        "  {} {} {} {} ({} total)",
        ui::green(ui::ok_sym()),
        ui::dim("hashed"),
        manifest.files.len(),
        file_word,
        ui::human_bytes(total_bytes),
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

    // Generate a pairing code from an ephemeral port. When using a relay,
    // we still generate a code for display, but the actual connection goes
    // through the relay.
    let (listener, addr) = match port {
        Some(p) => {
            let listener = tokio::net::TcpListener::bind(("0.0.0.0", p))
                .await
                .with_context(|| format!("bind to port {p}"))?;
            let addr = listener.local_addr()?;
            (listener, addr)
        }
        None => listen().await?,
    };
    let code = generate_code(addr.port());
    let code_hash = code_to_hash(&code);

    eprintln!();
    let label_w = 7;
    ui::kv("code", &ui::bold(&code), label_w);

    let parallel = parallel.max(1);
    crate::cmd::validate_parallel_relay(parallel, &relay)?;
    let progress: Arc<dyn lanx_core::progress::Progress> = IndicatifProgress::new("Sending");

    let mut disc = None;
    let mut set = tokio::task::JoinSet::new();
    let mut actual_parallel = 1;
    let mut first_task_result = None;

    let (agreed_tx, mut agreed_rx) = tokio::sync::mpsc::unbounded_channel();
    let cfg = SenderConfig {
        chunk_size,
        max_retries: DEFAULT_MAX_RETRIES,
        max_parallel: parallel,
        agreed_parallel_tx: Some(agreed_tx),
    };

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
            .with_context(|| format!("connect to relay {relay_addr}"))?;
        if let Err(e) = stream.set_nodelay(true) {
            tracing::debug!(?e, "TCP_NODELAY failed");
        }

        // Send hello to register with the relay.
        let hello = RelayHello {
            role: RelayRole::Sender,
            code_hash,
        };
        send_relay_hello(&mut stream, &hello).await?;

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
        );
    } else {
        // Direct mode: listen for incoming connections.
        let mut listener = GracefulListener::new(listener, Duration::from_secs(60));
        let addrs = crate::iface::list_non_loopback_v4().await;
        let indent = " ".repeat(label_w + 1);
        if addrs.is_empty() {
            ui::kv("listen", &format!("0.0.0.0:{}", addr.port()), label_w);
        } else {
            ui::kv("listen", &format!("{}:{}", addrs[0], addr.port()), label_w);
            for ip in &addrs[1..] {
                eprintln!("{indent}{ip}:{}", addr.port());
            }
        }
        eprintln!(
            "{indent}127.0.0.1:{} {}",
            addr.port(),
            ui::dim("(loopback)"),
        );
        eprintln!();

        if !no_discovery {
            match start_broadcasting(addr.port(), &code).await {
                Ok(h) => disc = Some(h),
                Err(e) => {
                    warn!(?e, "discovery failed; continuing without broadcast");
                }
            }
        }

        let wait_spinner = ui::spinner(&format!("waiting for receiver{}", ui::ellipsis()));
        let stream0 = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                wait_spinner.finish_and_clear();
                eprintln!(
                    "  {} {}",
                    ui::red(ui::fail_sym()),
                    ui::dim("no receiver connected"),
                );
                if let Some(h) = disc {
                    h.stop().await;
                }
                return Err(anyhow::Error::new(e).context("accept receiver"));
            }
        };
        wait_spinner.finish_and_clear();

        spawn_stream(
            &mut set,
            stream0,
            manifest.clone(),
            sources.clone(),
            progress.clone(),
            cfg.clone(),
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
        actual_parallel = agreed_parallel;

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

    eprintln!(
        "  {} {} {}",
        ui::green(ui::ok_sym()),
        ui::dim("receiver connected"),
        ui::dim(&format!(
            "({} stream{})",
            actual_parallel,
            if actual_parallel == 1 { "" } else { "s" }
        )),
    );

    // If connection 0 finished/failed during the select! above, check its result first.
    if let Some(res) = first_task_result {
        match res {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                return Err(anyhow::Error::new(e).context("transfer session"));
            }
            Err(e) => {
                return Err(anyhow::Error::new(e).context("transfer task"));
            }
        }
    }

    while let Some(res) = set.join_next().await {
        match res {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                return Err(anyhow::Error::new(e).context("transfer session"));
            }
            Err(e) => {
                return Err(anyhow::Error::new(e).context("transfer task"));
            }
        }
    }

    if let Some(h) = disc {
        h.stop().await;
    }
    // `_zip_cleanup` is dropped here; `TempDir` removes the temp directory.

    // Sender-side completion line. The receiver prints the authoritative
    // verified/failed/skipped summary; on the sender we surface a concise
    // "sent" confirmation so the operator sees the session ended cleanly.
    eprintln!();
    eprintln!(
        "  {} {} {} {} ({} total)",
        ui::green(ui::ok_sym()),
        ui::green("sent"),
        manifest.files.len(),
        file_word,
        ui::human_bytes(total_bytes),
    );

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

    let tmp = tempfile::Builder::new()
        .prefix("lanx-zip-")
        .tempdir()
        .context("create temp dir")?;
    let zip_path = tmp
        .path()
        .join(format!("{}.zip", Path::new(&base_name).display()));

    let file =
        std::fs::File::create(&zip_path).with_context(|| format!("create zip {zip_path:?}"))?;
    let mut writer = zip::ZipWriter::new(file);
    let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);

    if meta.is_dir() {
        // Walk the directory, adding every file under `<dirname>/<...>`.
        let prefix = Path::new(&base_name);
        add_directory_to_zip(&mut writer, input, prefix, opts)?;
    } else {
        // Single file: store it under its own basename.
        writer.start_file(Path::new(&base_name).to_string_lossy(), opts)?;
        let mut f = std::fs::File::open(input).with_context(|| format!("open {input:?}"))?;
        copy_to_zip(&mut f, &mut writer)?;
    }

    writer.finish().context("finalize zip")?;
    Ok((zip_path, tmp))
}

fn add_directory_to_zip(
    writer: &mut zip::ZipWriter<std::fs::File>,
    dir: &Path,
    archive_prefix: &Path,
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
        let file_name = match path.file_name() {
            Some(n) => n,
            None => continue,
        };
        let archive_path = archive_prefix.join(file_name);
        if meta.is_dir() {
            add_directory_to_zip(writer, &path, &archive_path, opts)?;
        } else if meta.is_file() {
            writer
                .start_file(archive_path.to_string_lossy(), opts)
                .with_context(|| format!("zip start_file {archive_path:?}"))?;
            let mut f = std::fs::File::open(&path).with_context(|| format!("open {path:?}"))?;
            copy_to_zip(&mut f, writer)?;
        } else {
            warn!(path = %path.display(), "skipping special file");
        }
    }
    Ok(())
}
