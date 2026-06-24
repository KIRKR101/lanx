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

/// Maximum parallel TCP connections the sender will honor. Values above
/// this are capped to prevent resource exhaustion.
const MAX_PARALLEL: u16 = 16;

#[derive(Clone)]
pub struct SenderConfig {
    pub chunk_size: u32,
    /// Maximum number of times a single file will be retried on hash
    /// mismatch before giving up. The receiver controls retries by
    /// sending `FileVerified { ok: false }`; each retry restarts the
    /// file from offset 0.
    pub max_retries: u32,
    /// Maximum number of parallel TCP connections the sender will
    /// honor. The receiver may propose fewer.
    pub max_parallel: u16,
    /// Optional channel to communicate the agreed parallelism count
    /// back to the coordinator.
    pub agreed_parallel_tx: Option<tokio::sync::mpsc::UnboundedSender<u16>>,
}

impl Default for SenderConfig {
    fn default() -> Self {
        Self {
            chunk_size: crate::manifest::DEFAULT_CHUNK_SIZE,
            max_retries: DEFAULT_MAX_RETRIES,
            max_parallel: MAX_PARALLEL,
            agreed_parallel_tx: None,
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
    // Send the first half of the handshake: advertise our maximum
    // supported parallelism. The receiver will reply with the count it
    // actually wants to use.
    write_frame(
        writer,
        &ControlMsg::Hello(HelloInfo {
            version: PROTOCOL_VERSION,
            chunk_size: cfg.chunk_size,
            parallel: cfg.max_parallel.clamp(1, MAX_PARALLEL),
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
    let agreed_parallel = match first {
        ControlMsg::Hello(HelloInfo {
            version,
            chunk_size: _,
            parallel,
        }) => {
            if version != PROTOCOL_VERSION {
                return Err(ProtocolError::VersionMismatch {
                    sender: version,
                    receiver: PROTOCOL_VERSION,
                });
            }
            // Treat the receiver's proposal as authoritative, capped to
            // our maximum and with 0/1 meaning "no parallelism".
            parallel.max(1).min(cfg.max_parallel).min(MAX_PARALLEL)
        }
        ControlMsg::Error { message } => return Err(ProtocolError::PeerError(message)),
        other => return Err(ProtocolError::Unexpected(format!("{other:?}"))),
    };
    // Echo the agreed parallelism back to the receiver so both sides
    // use the same count.
    write_frame(
        writer,
        &ControlMsg::Hello(HelloInfo {
            version: PROTOCOL_VERSION,
            chunk_size: cfg.chunk_size,
            parallel: agreed_parallel,
        }),
    )
    .await?;
    writer.flush().await?;
    if let Some(tx) = &cfg.agreed_parallel_tx {
        let _ = tx.send(agreed_parallel);
    }
    // Stream the manifest so the receiver can start processing entries
    // without waiting for (or buffering) one giant frame.
    let total_bytes = manifest.files.iter().map(|f| f.size).sum();
    write_frame(
        writer,
        &ControlMsg::ManifestStart {
            total_files: u64::try_from(manifest.files.len()).map_err(|_| {
                ProtocolError::Unexpected("manifest file count overflows u64".into())
            })?,
            total_bytes,
        },
    )
    .await?;
    for entry in &manifest.files {
        write_frame(writer, &ControlMsg::ManifestEntry(entry.clone())).await?;
    }
    write_frame(
        writer,
        &ControlMsg::ManifestEnd {
            chunk_size: manifest.chunk_size,
        },
    )
    .await?;
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
        ControlMsg::ManifestRejected { reason } => {
            return Err(ProtocolError::ManifestRejected(reason));
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
            // sender side. When running with parallel connections, the
            // other connection is responsible for this file's progress
            // events, so we must not double-count it here.
            if agreed_parallel <= 1 {
                progress.file_done(entry.id, true);
            }
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

    // Open the source file and seek to the resume offset. The
    // incremental hasher is built during the first send pass so we
    // avoid reading the entire file upfront for fresh transfers.
    // For resume transfers, we pre-hash the prefix (bytes before the
    // resume offset) so the hasher covers the full file — matching
    // what the receiver computes from its verified prefix + new bytes.
    let mut file = File::open(&path).await?;
    let mut whole_file_hasher = if resume_offset > 0 {
        build_prefix_hasher(&path, resume_offset).await?
    } else {
        IncrementalHasher::new()
    };
    file.seek(std::io::SeekFrom::Start(resume_offset)).await?;

    let mut attempts: u32 = 0;
    let mut current_offset = resume_offset;

    progress.started(entry.id, &entry.rel_path, entry.size, resume_offset);

    // First transmission: full file from the resume offset. The hasher
    // is built incrementally during this pass.
    whole_file_hasher = send_file_ranges(
        writer,
        entry,
        &mut file,
        current_offset,
        entry.size,
        progress,
        whole_file_hasher,
    )
    .await?;
    let (hash, _) = whole_file_hasher.finalize();
    write_frame(writer, &ControlMsg::FileEnd { id: entry.id, hash }).await?;
    writer.flush().await?;

    loop {
        let resp = read_frame(reader).await?;
        match resp {
            ControlMsg::FileVerified { id, ok: true } if id == entry.id => {
                progress.file_done(entry.id, true);
                return Ok(());
            }
            ControlMsg::FileVerified { id, ok: false } if id == entry.id => {
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
                whole_file_hasher = send_file_ranges(
                    writer,
                    entry,
                    &mut file,
                    current_offset,
                    entry.size,
                    progress,
                    IncrementalHasher::new(),
                )
                .await?;
                let (hash, _) = whole_file_hasher.finalize();
                write_frame(writer, &ControlMsg::FileEnd { id: entry.id, hash }).await?;
                writer.flush().await?;
            }
            ControlMsg::FileChunkRequest { id, ranges } if id == entry.id => {
                if attempts >= max_retries {
                    warn!(
                        id = entry.id,
                        attempts, max_retries, "max retries exhausted for file"
                    );
                    return Err(ProtocolError::MaxRetries(max_retries, entry.id));
                }
                attempts += 1;
                debug!(
                    id = entry.id,
                    range_count = ranges.len(),
                    "receiver requested chunk-level repair"
                );
                whole_file_hasher = send_requested_ranges(
                    writer,
                    entry,
                    &mut file,
                    &ranges,
                    progress,
                    whole_file_hasher,
                )
                .await?;
                let (hash, _) = whole_file_hasher.finalize();
                write_frame(writer, &ControlMsg::FileEnd { id: entry.id, hash }).await?;
                writer.flush().await?;
            }
            ControlMsg::Error { message } => return Err(ProtocolError::PeerError(message)),
            other => return Err(ProtocolError::Unexpected(format!("{other:?}"))),
        }
    }
}

/// Build an incremental hasher covering bytes `[0, prefix_len)` of the
/// given file. Used for resume transfers so the sender's whole-file hash
/// matches the receiver's (which includes the verified prefix).
async fn build_prefix_hasher(
    path: &std::path::Path,
    prefix_len: u64,
) -> Result<IncrementalHasher, ProtocolError> {
    let mut f = File::open(path).await?;
    let mut hasher = IncrementalHasher::new();
    let mut buf = vec![0u8; CHUNK_BUF];
    let mut remaining = prefix_len;
    while remaining > 0 {
        let want = usize::try_from(remaining).map_or(buf.len(), |r| r.min(buf.len()));
        let n = f.read(&mut buf[..want]).await?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        remaining -= u64::try_from(n).map_err(|_| {
            ProtocolError::Unexpected("prefix read length overflows u64".to_string())
        })?;
    }
    Ok(hasher)
}

/// Send `ChunkHeader`s and raw bytes for every byte in `[start, end)`.
/// Builds the incremental hasher incrementally during the send so the
/// caller does not need to pre-read the file. Returns the hasher for
/// reuse across retries.
async fn send_file_ranges<W: AsyncWrite + Unpin>(
    writer: &mut W,
    entry: &FileEntry,
    file: &mut File,
    start: u64,
    end: u64,
    progress: &dyn Progress,
    mut hasher: IncrementalHasher,
) -> Result<IncrementalHasher, ProtocolError> {
    write_frame(
        writer,
        &ControlMsg::FileStart {
            id: entry.id,
            offset: start,
        },
    )
    .await?;
    writer.flush().await?;

    file.seek(std::io::SeekFrom::Start(start)).await?;
    hasher = send_chunks(writer, entry, file, start, end, progress, hasher).await?;
    Ok(hasher)
}

/// Send only the requested byte ranges. Each range is sent as one or more
/// `ChunkHeader`s followed by raw bytes. Updates the incremental hasher
/// with the bytes sent so the caller's whole-file hash covers the
/// repaired data.
///
/// # Validation
///
/// Ranges are validated to be non-overlapping, in ascending order, and
/// within the file bounds. Invalid ranges from a malicious receiver are
/// rejected with a protocol error.
async fn send_requested_ranges<W: AsyncWrite + Unpin>(
    writer: &mut W,
    entry: &FileEntry,
    file: &mut File,
    ranges: &[(u64, u32)],
    progress: &dyn Progress,
    mut hasher: IncrementalHasher,
) -> Result<IncrementalHasher, ProtocolError> {
    let mut prev_end: u64 = 0;
    for &(start, len) in ranges {
        // Validate: ranges must be in ascending order and non-overlapping.
        if start < prev_end {
            return Err(ProtocolError::Unexpected(format!(
                "FileChunkRequest range ({start}, {len}) overlaps or is out of order (previous end: {prev_end})"
            )));
        }
        // Validate: range must be within file bounds.
        let end = start.saturating_add(u64::from(len));
        if end > entry.size {
            return Err(ProtocolError::Unexpected(format!(
                "FileChunkRequest range ({start}, {len}) exceeds file size {} for id {}",
                entry.size, entry.id
            )));
        }
        // Validate: range must be non-zero length.
        if len == 0 {
            return Err(ProtocolError::Unexpected(format!(
                "FileChunkRequest range ({start}, 0) has zero length"
            )));
        }
        file.seek(std::io::SeekFrom::Start(start)).await?;
        hasher = send_chunks(writer, entry, file, start, end, progress, hasher).await?;
        prev_end = end;
    }
    Ok(hasher)
}

/// Core chunk-sending loop: reads from `file` in `[start, end)` and
/// writes `ChunkHeader` + raw bytes for each chunk. Updates the
/// incremental hasher with each chunk's bytes.
async fn send_chunks<W: AsyncWrite + Unpin>(
    writer: &mut W,
    entry: &FileEntry,
    file: &mut File,
    start: u64,
    end: u64,
    progress: &dyn Progress,
    mut hasher: IncrementalHasher,
) -> Result<IncrementalHasher, ProtocolError> {
    let chunk_size = usize::try_from(entry.chunk_size)
        .map_err(|_| ProtocolError::Unexpected("chunk_size does not fit in usize".to_string()))?;
    let mut buf = vec![0u8; CHUNK_BUF.min(chunk_size).max(1)];
    let mut current = start;
    while current < end {
        let remaining = end - current;
        let want = usize::try_from(remaining).map_or(buf.len(), |r| r.min(buf.len()));
        let n = file.read(&mut buf[..want]).await?;
        if n == 0 {
            return Err(ProtocolError::Closed);
        }
        let n_u64 = u64::try_from(n)
            .map_err(|_| ProtocolError::Unexpected("read length overflows u64".to_string()))?;
        let n_u32 = u32::try_from(n)
            .map_err(|_| ProtocolError::Unexpected("read length exceeds u32::MAX".to_string()))?;
        hasher.update(&buf[..n]);
        write_frame(
            writer,
            &ControlMsg::ChunkHeader {
                id: entry.id,
                offset: current,
                len: n_u32,
            },
        )
        .await?;
        writer.write_all(&buf[..n]).await?;
        current += n_u64;
        progress.chunk_done(entry.id, n_u64);
    }
    Ok(hasher)
}
