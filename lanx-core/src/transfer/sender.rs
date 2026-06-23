//! Sender side of a transfer session. Reads from disk, writes to the TCP
//! stream; recomputes the whole-file hash incrementally. The receiver
//! controls the retry loop (verdict after each file).

use super::{
    read_frame, write_frame, ControlMsg, HelloInfo, ProtocolError, DEFAULT_MAX_RETRIES,
    PROTOCOL_VERSION,
};
use crate::hashing::IncrementalHasher;
use crate::manifest::{FileEntry, FileId, Manifest};
use crate::progress::{Progress, TransferSummary};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use tokio::fs::File;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWrite, AsyncWriteExt};
use tracing::{debug, info, warn};

const CHUNK_BUF: usize = 1024 * 1024;

pub struct SenderConfig {
    pub chunk_size: u32,
    /// Maximum number of times a single file will be retried on hash
    /// mismatch before giving up. The receiver controls retries by
    /// sending `FileVerified { ok: false }`; each retry restarts the
    /// file from offset 0.
    pub max_retries: u32,
}

impl Default for SenderConfig {
    fn default() -> Self {
        Self {
            chunk_size: crate::manifest::DEFAULT_CHUNK_SIZE,
            max_retries: DEFAULT_MAX_RETRIES,
        }
    }
}

/// Run the sender side of a transfer session.
///
/// # Errors
///
/// Returns `ProtocolError` for I/O failures, unexpected or malformed
/// messages, peer-reported errors, missing source paths, invalid resume
/// offsets, or if retry attempts are exhausted.
pub async fn run_sender<R, W>(
    reader: &mut R,
    writer: &mut W,
    manifest: &Manifest,
    sources: &HashMap<FileId, PathBuf>,
    progress: &dyn Progress,
    cfg: &SenderConfig,
) -> Result<(), ProtocolError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    write_frame(
        writer,
        &ControlMsg::Hello(HelloInfo {
            version: PROTOCOL_VERSION,
            chunk_size: cfg.chunk_size,
        }),
    )
    .await?;
    writer.flush().await?;

    // Notify the UI about the transfer shape (folder / files / single
    // file) before the manifest is sent. This lets the UI pre-allocate
    // per-file bars and (if it wants) print a header. The receiver
    // fires the same event after it reads the manifest, so both sides
    // see consistent previews.
    let summary = TransferSummary::from_manifest(manifest);
    progress.manifest_received(manifest, &summary);

    let first = read_frame(reader).await?;
    match first {
        ControlMsg::Hello(_) => {}
        ControlMsg::Error { message } => return Err(ProtocolError::PeerError(message)),
        other => return Err(ProtocolError::Unexpected(format!("{other:?}"))),
    }
    write_frame(writer, &ControlMsg::Manifest(manifest.clone())).await?;
    writer.flush().await?;

    let ack = read_frame(reader).await?;
    let (accepted, resume_offsets): (HashSet<FileId>, HashMap<FileId, u64>) = match ack {
        ControlMsg::ManifestAck {
            accepted,
            resume_offsets,
        } => {
            info!(?accepted, "receiver accepted");
            (accepted.into_iter().collect(), resume_offsets)
        }
        ControlMsg::Error { message } => return Err(ProtocolError::PeerError(message)),
        other => return Err(ProtocolError::Unexpected(format!("{other:?}"))),
    };

    for entry in &manifest.files {
        if !accepted.contains(&entry.id) {
            debug!(
                id = entry.id,
                "skipping (receiver rejected or already has it)"
            );
            // Tell the UI this file is done (it was a no-op for the
            // sender; the receiver already verified it). Without this,
            // pre-allocated bars would never get finalized on the
            // sender side.
            progress.file_done(entry.id, true);
            continue;
        }
        send_file(
            reader,
            writer,
            entry,
            resume_offsets.get(&entry.id).copied().unwrap_or(0),
            sources,
            progress,
            cfg.max_retries,
        )
        .await?;
    }
    write_frame(writer, &ControlMsg::Done).await?;
    writer.flush().await?;
    Ok(())
}

async fn send_file<R, W>(
    reader: &mut R,
    writer: &mut W,
    entry: &FileEntry,
    resume_offset: u64,
    sources: &HashMap<FileId, PathBuf>,
    progress: &dyn Progress,
    max_retries: u32,
) -> Result<(), ProtocolError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let path = sources
        .get(&entry.id)
        .ok_or_else(|| ProtocolError::Unexpected(format!("no source for id {}", entry.id)))?
        .clone();

    if resume_offset > entry.size {
        return Err(ProtocolError::Unexpected(format!(
            "resume offset {resume_offset} exceeds file size {} for id {}",
            entry.size, entry.id
        )));
    }

    // Loop: each iteration is one attempt. The receiver controls retries
    // by sending FileVerified{ok: false}; we then re-send from offset 0.
    let mut current_offset = resume_offset;
    let mut attempts: u32 = 0;
    loop {
        let verdict =
            send_file_attempt(reader, writer, entry, &path, current_offset, progress).await?;
        match verdict {
            Verdict::Verified => {
                progress.file_done(entry.id, true);
                return Ok(());
            }
            Verdict::Failed => {
                if attempts >= max_retries {
                    warn!(
                        id = entry.id,
                        attempts, max_retries, "max retries exhausted for file"
                    );
                    return Err(ProtocolError::MaxRetries(max_retries, entry.id));
                }
                attempts += 1;
                warn!(
                    id = entry.id,
                    attempts, max_retries, "receiver reported verification failure; resending"
                );
                current_offset = 0;
            }
        }
    }
}

enum Verdict {
    Verified,
    Failed,
}

async fn send_file_attempt<R, W>(
    reader: &mut R,
    writer: &mut W,
    entry: &FileEntry,
    path: &std::path::Path,
    start_offset: u64,
    progress: &dyn Progress,
) -> Result<Verdict, ProtocolError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    progress.started(entry.id, &entry.rel_path, entry.size, start_offset);

    write_frame(
        writer,
        &ControlMsg::FileStart {
            id: entry.id,
            offset: start_offset,
        },
    )
    .await?;
    writer.flush().await?;

    let mut f = File::open(path).await?;

    let mut hasher = IncrementalHasher::new();
    let chunk_size = usize::try_from(entry.chunk_size)
        .expect("chunk_size is bounded by MAX_CHUNK_SIZE and fits in usize");
    let mut buf = vec![0u8; CHUNK_BUF.min(chunk_size).max(1)];

    // Re-hash the existing prefix (bytes 0..start_offset) so the
    // incremental hasher state matches what the receiver will compute.
    // Without this, the sender's FileEnd hash would only cover the
    // sent suffix, while the receiver hashes the entire file — causing
    // a spurious mismatch on every resume.
    if start_offset > 0 {
        f.seek(std::io::SeekFrom::Start(0)).await?;
        let mut left = start_offset;
        while left > 0 {
            let want = usize::try_from(left).map_or(buf.len(), |l| l.min(buf.len()));
            let n = f.read(&mut buf[..want]).await?;
            if n == 0 {
                return Err(ProtocolError::Closed);
            }
            hasher.update(&buf[..n]);
            let n_u64 = u64::try_from(n)
                .map_err(|_| ProtocolError::Unexpected("read length overflows u64".to_string()))?;
            left -= n_u64;
        }
    }
    f.seek(std::io::SeekFrom::Start(start_offset)).await?;

    let mut current_offset = start_offset;
    while current_offset < entry.size {
        let remaining = entry.size - current_offset;
        let want = usize::try_from(remaining).map_or(buf.len(), |r| r.min(buf.len()));
        let n = f.read(&mut buf[..want]).await?;
        if n == 0 {
            return Err(ProtocolError::Closed);
        }
        hasher.update(&buf[..n]);
        let n_u64 = u64::try_from(n)
            .map_err(|_| ProtocolError::Unexpected("read length overflows u64".to_string()))?;
        let n_u32 = u32::try_from(n)
            .map_err(|_| ProtocolError::Unexpected("read length exceeds u32::MAX".to_string()))?;
        write_frame(
            writer,
            &ControlMsg::ChunkHeader {
                id: entry.id,
                offset: current_offset,
                len: n_u32,
            },
        )
        .await?;
        writer.write_all(&buf[..n]).await?;
        current_offset += n_u64;
        progress.chunk_done(entry.id, n_u64);
    }
    let (hash, _) = hasher.finalize();
    write_frame(writer, &ControlMsg::FileEnd { id: entry.id, hash }).await?;
    writer.flush().await?;

    let resp = read_frame(reader).await?;
    match resp {
        ControlMsg::FileVerified { id, ok: true } if id == entry.id => Ok(Verdict::Verified),
        ControlMsg::FileVerified { id, ok: false } if id == entry.id => Ok(Verdict::Failed),
        ControlMsg::Error { message } => Err(ProtocolError::PeerError(message)),
        other => Err(ProtocolError::Unexpected(format!("{other:?}"))),
    }
}
