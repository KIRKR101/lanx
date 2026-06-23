//! Receiver side. Reads from TCP, writes to disk; recomputes the whole-file
//! hash incrementally.

use super::{read_frame, write_frame, ControlMsg, HelloInfo, ProtocolError, PROTOCOL_VERSION};
use crate::destinations::resolve_destinations;
use crate::hashing::IncrementalHasher;
use crate::manifest::{FileEntry, MAX_CHUNK_SIZE, MAX_MANIFEST_FILES};
use crate::progress::{Progress, TransferSummary};
use std::path::Path;
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWrite, AsyncWriteExt};
use tracing::debug;

/// Run the receiver side of a transfer session.
///
/// # Errors
///
/// Returns `ProtocolError` for I/O failures, unexpected or malformed
/// messages, version mismatch, peer-reported errors, or if the manifest
/// fails validation.
pub async fn run_receiver<R: tokio::io::AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut R,
    writer: &mut W,
    out_dir: &Path,
    progress: &dyn Progress,
    max_retries: u32,
) -> Result<ReceiverReport, ProtocolError> {
    // Hello handshake.
    let hello = read_frame(reader).await?;
    let sender_chunk = match hello {
        ControlMsg::Hello(HelloInfo {
            version,
            chunk_size,
        }) => {
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
        &ControlMsg::Hello(HelloInfo {
            version: PROTOCOL_VERSION,
            chunk_size: sender_chunk,
        }),
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

    // Validate manifest to prevent DoS via resource exhaustion.
    if sender_manifest.files.len() > MAX_MANIFEST_FILES {
        return Err(ProtocolError::Unexpected(format!(
            "manifest has {} files, maximum is {}",
            sender_manifest.files.len(),
            MAX_MANIFEST_FILES,
        )));
    }
    if sender_manifest.chunk_size == 0 || sender_manifest.chunk_size > MAX_CHUNK_SIZE {
        return Err(ProtocolError::Unexpected(format!(
            "chunk_size {} is out of valid range (1..{})",
            sender_manifest.chunk_size, MAX_CHUNK_SIZE,
        )));
    }
    // Reject path-traversal attempts in rel_path. A malicious sender
    // could use ".." components to write files outside the destination.
    for entry in &sender_manifest.files {
        if entry.rel_path.contains("..") {
            return Err(ProtocolError::Unexpected(format!(
                "rel_path contains '..' component: {}",
                entry.rel_path,
            )));
        }
    }

    // Notify the UI about the transfer shape (folder / files / single
    // file) before any data starts moving. This lets the UI print a
    // clear header like "Receiving folder `myrepo/` (12 files, …)".
    let summary = TransferSummary::from_manifest(&sender_manifest);
    progress.manifest_received(&sender_manifest, &summary);

    // Resolve destinations and resume plan now that we know the manifest.
    let dests = resolve_destinations(&sender_manifest, out_dir)
        .map_err(|e| ProtocolError::Unexpected(format!("destinations: {e}")))?;
    let mut plan = crate::resume::plan(&sender_manifest, &dests)
        .map_err(|e| ProtocolError::Unexpected(format!("resume plan: {e}")))?;

    // Send ManifestAck.
    let accepted = plan.accepted.clone();
    let resume_offsets = plan.offsets.clone();
    write_frame(
        writer,
        &ControlMsg::ManifestAck {
            accepted,
            resume_offsets,
        },
    )
    .await?;
    writer.flush().await?;

    let mut report = ReceiverReport::default();
    for entry in &sender_manifest.files {
        if plan.complete.contains(&entry.id) {
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
        let hasher = plan.hashers.remove(&entry.id);
        let verified = recv_file(
            reader,
            writer,
            entry,
            &dest_path,
            hasher,
            progress,
            max_retries,
        )
        .await?;
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
const fn is_benign_close(kind: std::io::ErrorKind) -> bool {
    use std::io::ErrorKind::{
        BrokenPipe, ConnectionAborted, ConnectionReset, NotConnected, UnexpectedEof,
    };
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

/// Maximum number of total attempts per file is `max_retries + 1`:
/// one initial attempt plus `max_retries` re-attempts after hash
/// mismatches. This matches the sender's `SenderConfig::max_retries`
/// semantics so both sides stop retrying at the same time.
async fn recv_file<R: tokio::io::AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut R,
    writer: &mut W,
    entry: &FileEntry,
    dest: &Path,
    hasher: Option<IncrementalHasher>,
    progress: &dyn Progress,
    max_retries: u32,
) -> Result<bool, ProtocolError> {
    // Loop over sender-side retries. On `FileVerified{ok: false}` the
    // sender restarts the file from offset 0; we read another FileStart
    // and re-run the receive logic.
    let max_attempts = max_retries.saturating_add(1);
    let mut attempts: u32 = 0;
    // The pre-built hasher is consumed on the first attempt. Retries
    // (which restart from offset 0) create a fresh hasher.
    let mut hasher = hasher;
    loop {
        let h = hasher.take();
        let verified = recv_file_once(reader, writer, entry, dest, h, progress).await?;
        if verified {
            return Ok(true);
        }
        attempts += 1;
        // Tell the sender the attempt failed. If we have exhausted the
        // allowed attempts, return false so the receiver moves on; the
        // sender will also give up after the same number of failures.
        write_frame(
            writer,
            &ControlMsg::FileVerified {
                id: entry.id,
                ok: false,
            },
        )
        .await?;
        writer.flush().await?;
        if attempts >= max_attempts {
            tracing::warn!(
                id = entry.id,
                attempts,
                max_retries,
                "max recv retries exhausted for file"
            );
            return Ok(false);
        }
        progress.file_done(entry.id, false);
        // Loop reads next FileStart.
    }
}

async fn recv_file_once<R: tokio::io::AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut R,
    writer: &mut W,
    entry: &FileEntry,
    dest: &Path,
    prebuilt_hasher: Option<IncrementalHasher>,
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

    // Use the pre-built hasher from the resume plan when available.
    // The plan already fed the verified prefix into this hasher during
    // offset computation, so we can skip the O(offset) re-hash entirely.
    // On a fresh start (offset == 0) or retry, no pre-built hasher is
    // available, so we create a new one.
    let mut hasher = prebuilt_hasher.map_or_else(IncrementalHasher::new, |h| {
        debug!(
            id = entry.id,
            offset, "using pre-built hasher from resume plan"
        );
        h
    });

    let mut current = offset;
    let chunk_size = usize::try_from(entry.chunk_size)
        .map_err(|_| ProtocolError::Unexpected("chunk_size does not fit in usize".to_string()))?;
    let mut buf = vec![0u8; chunk_size];
    while current < entry.size {
        let header = read_frame(reader).await?;
        match header {
            ControlMsg::ChunkHeader {
                id,
                offset: hdr_off,
                len,
            } if id == entry.id => {
                if hdr_off != current {
                    return Err(ProtocolError::Unexpected(format!(
                        "chunk offset mismatch: expected {current} got {hdr_off}"
                    )));
                }
                let len_usize = usize::try_from(len)
                    .map_err(|_| ProtocolError::FrameTooLarge(u64::from(len)))?;
                if len_usize > buf.len() {
                    return Err(ProtocolError::FrameTooLarge(u64::from(len)));
                }
                reader.read_exact(&mut buf[..len_usize]).await?;
                hasher.update(&buf[..len_usize]);
                file.write_all(&buf[..len_usize]).await?;
                current += u64::from(len);
                progress.chunk_done(entry.id, u64::from(len));
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
        write_frame(
            writer,
            &ControlMsg::FileVerified {
                id: entry.id,
                ok: true,
            },
        )
        .await?;
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
    // We do truncate to the manifest size so a previously longer file
    // does not leave stale trailing bytes after the transfer.
    #[allow(clippy::suspicious_open_options)]
    let mut f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(dest)
        .await?;
    f.set_len(total).await?;
    f.seek(std::io::SeekFrom::Start(offset)).await?;
    Ok(f)
}
