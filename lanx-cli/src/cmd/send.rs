//! `lanx send`: build manifest, listen for receiver, transfer.

use anyhow::{Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use lanx_core::manifest::{build, rel_to_path};
use lanx_core::transfer::sender::{run_sender, SenderConfig};
use lanx_net::discovery::{generate_code, start_broadcasting};
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

pub async fn run(
    paths: Vec<PathBuf>,
    chunk_size: u32,
    no_discovery: bool,
    zip: bool,
) -> Result<()> {
    // Optional zip mode (explicit `--zip`). When set, the input is
    // packaged into a single `.zip` file in a temp dir and that single
    // file is what gets sent. Without `--zip`, directories are sent
    // natively: the manifest builder walks them and the receiver
    // reconstructs the folder structure (Path B in lanx-core).
    ui::banner("send", "");
    let (_zip_cleanup, effective_paths) = if zip {
        let (zip_path, dir) = zip_inputs(&paths)?;
        eprintln!(
            "  {} --zip {} {}",
            ui::dim("pack"),
            ui::arrow(),
            zip_path.display()
        );
        (Some(ZipCleanup(dir)), vec![zip_path])
    } else {
        (None, paths)
    };

    let hash_spinner = spinner(&format!("hashing files{}", ui::ellipsis()));
    let manifest = tokio::task::spawn_blocking({
        let paths = effective_paths.clone();
        move || build(&paths, chunk_size)
    })
    .await
    .context("hash task panicked")??;
    let total_bytes: u64 = manifest.files.iter().map(|f| f.size).sum();
    hash_spinner.finish_and_clear();
    let file_word = if manifest.files.len() == 1 { "file" } else { "files" };
    eprintln!(
        "  {} {} {} {} ({} total)",
        ui::green(ui::ok_sym()),
        ui::dim("hashed"),
        manifest.files.len(),
        file_word,
        ui::human_bytes(total_bytes),
    );

    // (The "Sending folder X" header is printed once the receiver
    // connects, by the progress UI's `manifest_received` handler.
    // That way the sender and receiver both see the same header
    // line at the same moment in the transfer.)

    // Reconstruct source paths from the manifest's canonicalized
    // `source_root`. This avoids the brittleness of computing
    // longest_common_prefix from the user's original (possibly non-canonical)
    // input spellings.
    let mut sources: HashMap<_, _> = HashMap::new();
    for f in &manifest.files {
        let src_path = if f.rel_path.is_empty() || f.rel_path == "." {
            // Single file: rel_path is empty by build()'s convention
            // for the single-file case; use source_root directly
            // (avoid `Path::join("")` which adds a trailing separator
            // on Windows).
            manifest.source_root.clone()
        } else {
            // rel_path is forward-slash form on the wire; convert to a
            // platform-native PathBuf before joining source_root.
            manifest.source_root.join(rel_to_path(&f.rel_path))
        };
        sources.insert(f.id, src_path);
    }

    let (listener, addr) = listen().await?;
    let mut listener = GracefulListener::new(listener, Duration::from_secs(60));
    let code = generate_code(addr.port());

    eprintln!();
    let label_w = 7;
    ui::kv("code", &ui::bold(&code), label_w);
    let addrs = crate::iface::list_non_loopback_v4();
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

    let disc = if no_discovery {
        None
    } else {
        match start_broadcasting(addr.port(), &code).await {
            Ok(h) => Some(h),
            Err(e) => {
                warn!(?e, "discovery failed; continuing without broadcast");
                None
            }
        }
    };

    let progress: Arc<dyn lanx_core::progress::Progress> = IndicatifProgress::new("Sending");
    let wait_spinner = spinner(&format!("waiting for receiver{}", ui::ellipsis()));
    let accept_result = listener.accept().await;
    wait_spinner.finish_and_clear();
    match accept_result {
        Ok(stream) => {
            eprintln!(
                "  {} {}",
                ui::green(ui::ok_sym()),
                ui::dim("receiver connected"),
            );
            let stream = stream as TcpStream;
            let session = run_sender(
                stream,
                &manifest,
                &sources,
                progress.as_ref(),
                &SenderConfig::default(),
            )
            .await;
            if let Err(e) = session {
                warn!(?e, "session ended with error");
            }
        }
        Err(e) => {
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
    }

    if let Some(h) = disc {
        h.stop().await;
    }
    drop(_zip_cleanup);

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

    let _ = progress;
    Ok(())
}

/// A small animated spinner with the lanx house style. Caller is
/// responsible for `finish_and_clear()` / `finish_with_message(...)`.
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

/// RAII helper that removes a temp directory on drop.
struct ZipCleanup(PathBuf);
impl Drop for ZipCleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
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
fn zip_inputs(inputs: &[PathBuf]) -> Result<(PathBuf, PathBuf)> {
    anyhow::ensure!(
        inputs.len() == 1,
        "--zip requires exactly one input path (got {})",
        inputs.len()
    );
    let input = &inputs[0];
    let meta = std::fs::symlink_metadata(input)
        .with_context(|| format!("stat {input:?}"))?;

    let base_name = match meta.is_dir() {
        true => input
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("input directory has no name: {input:?}"))?
            .to_os_string(),
        false => input
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("input file has no name: {input:?}"))?
            .to_os_string(),
    };

    let tmp = tempfile::Builder::new()
        .prefix("lanx-zip-")
        .tempdir()
        .context("create temp dir")?;
    // We can't keep `tempdir` because we need a stable path to return;
    // persist the directory and clean it up via the returned `PathBuf`.
    let tmp_path = tmp.keep();
    let zip_path = tmp_path.join(format!("{}.zip", Path::new(&base_name).display()));

    let file = std::fs::File::create(&zip_path)
        .with_context(|| format!("create zip {zip_path:?}"))?;
    let mut writer = zip::ZipWriter::new(file);
    let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);

    if meta.is_dir() {
        // Walk the directory, adding every file under `<dirname>/<...>`.
        let prefix = Path::new(&base_name);
        add_directory_to_zip(&mut writer, input, prefix, opts)?;
    } else {
        // Single file: store it under its own basename.
        writer.start_file(
            Path::new(&base_name).to_string_lossy(),
            opts,
        )?;
        let mut f = std::fs::File::open(input)
            .with_context(|| format!("open {input:?}"))?;
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            writer.write_all(&buf[..n])?;
        }
    }

    writer.finish().context("finalize zip")?;
    Ok((zip_path, tmp_path))
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
            let mut f = std::fs::File::open(&path)
                .with_context(|| format!("open {path:?}"))?;
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                let n = f.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                writer.write_all(&buf[..n])?;
            }
        } else {
            warn!(path = %path.display(), "skipping special file");
        }
    }
    Ok(())
}
