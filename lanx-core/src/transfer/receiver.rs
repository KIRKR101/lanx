//! Receiver side. Reads from TCP, writes to disk; recomputes the whole-file
//! hash incrementally.

use super::{read_frame, write_frame, ControlMsg, HelloInfo, ProtocolError, PROTOCOL_VERSION};
use crate::destinations::resolve_destinations;
use crate::hashing::IncrementalHasher;
use crate::manifest::FileEntry;
use crate::progress::{Progress, TransferSummary};
use std::path::{Path, PathBuf};
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWrite, AsyncWriteExt};
use tracing::debug;

pub async fn run_receiver<R: tokio::io::AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut R,
    writer: &mut W,
    out_dir: &Path,
    progress: &dyn Progress,
) -> Result<ReceiverReport, ProtocolError> {
    // Hello handshake.
    let hello = read_frame(reader).await?;
    let sender_chunk = match hello {
        ControlMsg::Hello(HelloInfo { version, chunk_size }) => {
            if version != PROTOCOL_VERSION {
                return Err(ProtocolError::VersionMismatch {
                    sender: version,
                    receiver: PROTOCOL_VERSION,
                });
            }
            chunk_size
        }
        ControlMsg::Error { message } => return Err(ProtocolError::PeerError(message)),
        other => return Err(ProtocolError::Unexpected(format!("{other:?}"))),
    };
    write_frame(
        writer,
        &ControlMsg::Hello(HelloInfo { version: PROTOCOL_VERSION, chunk_size: sender_chunk }),
    )
    .await?;
    writer.flush().await?;

    // Read Manifest.
    let m = read_frame(reader).await?;
    let sender_manifest = match m {
        ControlMsg::Manifest(m) => m,
        ControlMsg::Error { message } => return Err(ProtocolError::PeerError(message)),
        other => return Err(ProtocolError::Unexpected(format!("{other:?}"))),
    };

    // Notify the UI about the transfer shape (folder / files / single
    // file) before any data starts moving. This lets the UI print a
    // clear header like "Receiving folder `myrepo/` (12 files, …)".
    let summary = TransferSummary::from_manifest(&sender_manifest);
    progress.manifest_received(&sender_manifest, &summary);

    // Resolve destinations and resume plan now that we know the manifest.
    let dests = resolve_destinations(&sender_manifest, out_dir)
        .map_err(|e| ProtocolError::Unexpected(format!("destinations: {e}")))?;
    let plan = crate::resume::plan(&sender_manifest, &dests)
        .map_err(|e| ProtocolError::Unexpected(format!("resume plan: {e}")))?;

    // Send ManifestAck.
    let accepted = plan.accepted.clone();
    let resume_offsets = plan.offsets.clone();
    write_frame(writer, &ControlMsg::ManifestAck { accepted, resume_offsets }).await?;
    writer.flush().await?;

    let mut report = ReceiverReport::default();
    for entry in &sender_manifest.files {
        if plan.complete.contains_key(&entry.id) {
            debug!(id = entry.id, "already complete, skipping");
            report.skipped += 1;
            progress.file_done(entry.id, true);
            continue;
        }
        if !plan.accepted.contains(&entry.id) {
            continue;
        }
        let dest_path = dests
            .paths
            .get(&entry.id)
            .ok_or_else(|| ProtocolError::Unexpected(format!("no dest for {}", entry.id)))?
            .clone();
        let verified = recv_file(reader, writer, entry, &dest_path, progress).await?;
        if verified {
            report.verified += 1;
        } else {
            report.failed += 1;
        }
    }

    // Wait for the sender's `Done` so the connection doesn't close mid-`Done`-write.
    loop {
        match read_frame(reader).await {
            Ok(ControlMsg::Done) => break,
            Ok(ControlMsg::Error { message }) => {
                return Err(ProtocolError::PeerError(message));
            }
            Ok(_) => {
                // Ignore unexpected trailing messages.
            }
            Err(ProtocolError::Io(e)) if is_benign_close(e.kind()) => break,
            Err(e) => return Err(e),
        }
    }
    Ok(report)
}

/// Error kinds that indicate a clean peer-side close after `Done` is
/// expected, not a real failure. Anything else is propagated.
fn is_benign_close(kind: std::io::ErrorKind) -> bool {
    use std::io::ErrorKind::*;
    matches!(
        kind,
        UnexpectedEof | ConnectionReset | ConnectionAborted | BrokenPipe | NotConnected
    )
}

#[derive(Default, Debug, Clone)]
pub struct ReceiverReport {
    pub verified: usize,
    pub failed: usize,
    pub skipped: usize,
}

async fn recv_file<R: tokio::io::AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut R,
    writer: &mut W,
    entry: &FileEntry,
    dest: &PathBuf,
    progress: &dyn Progress,
) -> Result<bool, ProtocolError> {
    // Loop over sender-side retries. On `FileVerified{ok: false}` the
    // sender restarts the file from offset 0; we read another FileStart
    // and re-run the receive logic.
    loop {
        let verified = recv_file_once(reader, writer, entry, dest, progress).await?;
        if verified {
            return Ok(true);
        }
        // Tell the sender and let it retry. We will read another FileStart
        // in the next iteration.
        write_frame(writer, &ControlMsg::FileVerified { id: entry.id, ok: false }).await?;
        writer.flush().await?;
        progress.file_done(entry.id, false);
        // Loop reads next FileStart.
    }
}

async fn recv_file_once<R: tokio::io::AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut R,
    writer: &mut W,
    entry: &FileEntry,
    dest: &PathBuf,
    progress: &dyn Progress,
) -> Result<bool, ProtocolError> {
    let start_msg = read_frame(reader).await?;
    let offset = match start_msg {
        ControlMsg::FileStart { id, offset } if id == entry.id => offset,
        ControlMsg::Error { message } => return Err(ProtocolError::PeerError(message)),
        other => return Err(ProtocolError::Unexpected(format!("{other:?}"))),
    };
    progress.started(entry.id, &entry.rel_path, entry.size, offset);

    let mut file = open_for_resume(dest, offset, entry.size).await?;

    let mut hasher = IncrementalHasher::new();
    if offset > 0 {
        let mut f2: File = File::open(dest).await?;
        f2.seek(std::io::SeekFrom::Start(0)).await?;
        let mut buf = vec![0u8; entry.chunk_size as usize];
        let mut left = offset;
        while left > 0 {
            let want = (left as usize).min(buf.len());
            let n = f2.read_exact(&mut buf[..want]).await?;
            hasher.update(&buf[..n]);
            left -= n as u64;
        }
    }

    let mut current = offset;
    let mut buf = vec![0u8; entry.chunk_size as usize];
    while current < entry.size {
        let header = read_frame(reader).await?;
        match header {
            ControlMsg::ChunkHeader { id, offset: hdr_off, len } if id == entry.id => {
                if hdr_off != current {
                    return Err(ProtocolError::Unexpected(format!(
                        "chunk offset mismatch: expected {current} got {hdr_off}"
                    )));
                }
                if len as usize > buf.len() {
                    return Err(ProtocolError::FrameTooLarge(len));
                }
                reader.read_exact(&mut buf[..len as usize]).await?;
                hasher.update(&buf[..len as usize]);
                file.write_all(&buf[..len as usize]).await?;
                current += len as u64;
                progress.chunk_done(entry.id, len as u64);
            }
            ControlMsg::Error { message } => return Err(ProtocolError::PeerError(message)),
            other => return Err(ProtocolError::Unexpected(format!("{other:?}"))),
        }
    }
    file.flush().await?;
    drop(file);

    let end_msg = read_frame(reader).await?;
    let sender_hash = match end_msg {
        ControlMsg::FileEnd { id, hash } if id == entry.id => hash,
        ControlMsg::Error { message } => return Err(ProtocolError::PeerError(message)),
        other => return Err(ProtocolError::Unexpected(format!("{other:?}"))),
    };
    let (local_hash, _) = hasher.finalize();
    let ok = local_hash == sender_hash;
    if ok {
        write_frame(writer, &ControlMsg::FileVerified { id: entry.id, ok: true }).await?;
        writer.flush().await?;
        progress.file_done(entry.id, true);
    }
    // On !ok, let the caller (recv_file's loop) write FileVerified{ok:false}
    // and wait for the sender's retry. Returning false signals the loop.
    Ok(ok)
}

async fn open_for_resume(
    dest: &std::path::Path,
    offset: u64,
    total: u64,
) -> Result<File, ProtocolError> {
    if let Some(parent) = dest.parent() {
        if !parent.as_os_str().is_empty() {
            tokio::fs::create_dir_all(parent).await?;
        }
    }
    if offset == 0 {
        if total == 0 {
            return File::create(dest).await.map_err(ProtocolError::Io);
        }
        let f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(dest)
            .await?;
        return Ok(f);
    }
    // We deliberately do NOT set `.truncate(true)`: on a resume with
    // offset > 0 we want to preserve existing on-disk bytes. (We seek
    // past them below.) `create(true)` only creates the file if missing.
    #[allow(clippy::suspicious_open_options)]
    let mut f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(dest)
        .await?;
    f.seek(std::io::SeekFrom::Start(offset)).await?;
    Ok(f)
}
