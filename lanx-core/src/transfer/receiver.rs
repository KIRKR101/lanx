//! Receiver side. Reads from TCP, writes to disk; recomputes the whole-file
//! hash incrementally.

use super::{
    read_frame, write_frame, ControlMsg, HelloInfo, ProtocolError, DEFAULT_MAX_RETRIES,
    PROTOCOL_VERSION,
};
use crate::destinations::resolve_destinations;
use crate::hashing::IncrementalHasher;
use crate::manifest::{FileEntry, Manifest, MAX_CHUNK_SIZE, MAX_MANIFEST_FILES};
use crate::progress::{Progress, TransferSummary};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWrite, AsyncWriteExt};
use tracing::debug;

/// Maximum byte ranges in a single `FileChunkRequest`. Prevents a request
/// frame from growing unbounded for very large files with many corrupt
/// chunks.
const MAX_CHUNK_RANGES: usize = 1024;

/// Maximum parallel TCP connections the receiver will request. Values
/// above this are capped to prevent resource exhaustion.
const MAX_PARALLEL: u16 = 16;

/// Decision returned by a [`ManifestApprover`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Approval {
    /// Receiver accepts the manifest and wants to proceed with the transfer.
    Accept,
    /// Receiver declines the manifest before any file data is exchanged.
    Reject { reason: String },
}

/// Decides whether to accept an incoming manifest. Implementations live in
/// the application layer (e.g. CLI stdin prompt) so `lanx-core` stays
/// free of terminal I/O.
pub trait ManifestApprover: Send + Sync {
    fn approve(&self, manifest: &Manifest, summary: &TransferSummary) -> Approval;
}

/// Pre-accept every manifest. Used by `--accept` on the receiver.
pub struct AutoAccept;

impl ManifestApprover for AutoAccept {
    fn approve(&self, _manifest: &Manifest, _summary: &TransferSummary) -> Approval {
        Approval::Accept
    }
}

/// Caches the first approval decision and shares it with all parallel
/// connections. The first caller computes the decision (potentially
/// prompting the user); subsequent callers block until the decision is
/// ready and then return the cached value.
pub struct SharedApprover {
    inner: Arc<dyn ManifestApprover>,
    cache: std::sync::Mutex<Option<Approval>>,
}

impl SharedApprover {
    /// Wrap `inner` so the approval decision is computed once and reused
    /// across parallel connections.
    pub fn new(inner: Arc<dyn ManifestApprover>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            cache: std::sync::Mutex::new(None),
        })
    }
}

impl ManifestApprover for SharedApprover {
    fn approve(&self, manifest: &Manifest, summary: &TransferSummary) -> Approval {
        let mut guard = self
            .cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(ref approval) = *guard {
            return approval.clone();
        }
        let approval = self.inner.approve(manifest, summary);
        *guard = Some(approval.clone());
        approval
    }
}

/// Configuration for one receiver connection in a transfer session.
#[derive(Debug, Clone)]
pub struct ReceiverConfig {
    /// Maximum number of times a single file will be retried on hash
    /// mismatch before giving up.
    pub max_retries: u32,
    /// 0-based index of this connection among the parallel connections.
    pub connection_index: u16,
    /// Number of parallel TCP connections requested by this receiver.
    /// The sender may cap this value.
    pub parallel: u16,
    /// Optional channel to communicate the agreed parallelism count
    /// back to the coordinator.
    pub agreed_parallel_tx: Option<tokio::sync::mpsc::UnboundedSender<u16>>,
}

impl Default for ReceiverConfig {
    fn default() -> Self {
        Self {
            max_retries: DEFAULT_MAX_RETRIES,
            connection_index: 0,
            parallel: 1,
            agreed_parallel_tx: None,
        }
    }
}

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
    cfg: &ReceiverConfig,
    approver: Arc<dyn ManifestApprover>,
) -> Result<ReceiverReport, ProtocolError> {
    // Hello handshake. The sender advertises its max parallelism; we
    // reply with the smaller of that and our own request.
    let hello = read_frame(reader).await?;
    let (sender_chunk, mut agreed_parallel) = match hello {
        ControlMsg::Hello(HelloInfo {
            version,
            chunk_size,
            parallel,
        }) => {
            if version != PROTOCOL_VERSION {
                return Err(ProtocolError::VersionMismatch {
                    sender: version,
                    receiver: PROTOCOL_VERSION,
                });
            }
            let sender_parallel = parallel.clamp(1, MAX_PARALLEL);
            let proposed = cfg.parallel.clamp(1, sender_parallel);
            (chunk_size, proposed)
        }
        ControlMsg::Error { message } => return Err(ProtocolError::PeerError(message)),
        other => return Err(ProtocolError::Unexpected(format!("{other:?}"))),
    };
    write_frame(
        writer,
        &ControlMsg::Hello(HelloInfo {
            version: PROTOCOL_VERSION,
            chunk_size: sender_chunk,
            parallel: agreed_parallel,
        }),
    )
    .await?;
    writer.flush().await?;

    // Read the sender's agreement echo so the stream is positioned at
    // the manifest.
    let agreement = read_frame(reader).await?;
    match agreement {
        ControlMsg::Hello(HelloInfo {
            version,
            chunk_size,
            parallel,
        }) => {
            if version != PROTOCOL_VERSION {
                return Err(ProtocolError::VersionMismatch {
                    sender: version,
                    receiver: PROTOCOL_VERSION,
                });
            }
            // The sender may have capped our proposal; trust its reply.
            let _ = chunk_size;
            agreed_parallel = agreed_parallel.min(parallel.clamp(1, MAX_PARALLEL));
        }
        ControlMsg::Error { message } => return Err(ProtocolError::PeerError(message)),
        other => return Err(ProtocolError::Unexpected(format!("{other:?}"))),
    }

    let agreed_parallel = agreed_parallel.max(1);

    if let Some(tx) = &cfg.agreed_parallel_tx {
        let _ = tx.send(agreed_parallel);
    }

    // Read Manifest (streaming or legacy single-frame).
    let sender_manifest = read_manifest(reader).await?;

    // If the sender capped parallelism below our connection index, this
    // connection must not handle any files — doing so would duplicate
    // work across connections and corrupt destination files.
    let skip = u32::from(cfg.connection_index) >= u32::from(agreed_parallel);
    let connection_index = if skip {
        0
    } else {
        u32::from(cfg.connection_index)
    };

    // Compute the summary for the UI and for the approval prompt.
    let summary = TransferSummary::from_manifest(&sender_manifest);

    // Ask the application layer whether to accept this manifest. We do
    // this *before* computing the resume plan so the receiver doesn't
    // spend time hashing partial files only to discard them. The prompt
    // is run in a blocking task because implementations read from stdin.
    let approval = {
        let manifest = sender_manifest.clone();
        let summary = summary.clone();
        let approver = approver.clone();
        tokio::task::spawn_blocking(move || approver.approve(&manifest, &summary))
            .await
            .map_err(|e| ProtocolError::Unexpected(format!("manifest approver panicked: {e}")))?
    };
    match approval {
        Approval::Accept => {}
        Approval::Reject { reason } => {
            write_frame(writer, &ControlMsg::ManifestRejected { reason }).await?;
            writer.flush().await?;
            return Ok(ReceiverReport {
                rejected: true,
                ..ReceiverReport::default()
            });
        }
    }

    // Notify the UI about the transfer shape (folder / files / single
    // file) before any data starts moving. This lets the UI print a
    // clear header like "Receiving folder `myrepo/` (12 files, …)".
    progress.manifest_received(&sender_manifest, &summary);

    if skip {
        write_frame(
            writer,
            &ControlMsg::ManifestAck {
                accepted: vec![],
                resume_offsets: std::collections::HashMap::new(),
            },
        )
        .await?;
        writer.flush().await?;
        // Drain the Done frame so the sender can shut down cleanly.
        loop {
            match read_frame(reader).await {
                Ok(ControlMsg::Done) => break,
                Ok(ControlMsg::Error { message }) => {
                    return Err(ProtocolError::PeerError(message));
                }
                Ok(_) => {}
                Err(ProtocolError::Io(e)) if is_benign_close(e.kind()) => break,
                Err(e) => return Err(e),
            }
        }
        return Ok(ReceiverReport::default());
    }

    // Resolve destinations and resume plan now that we know the manifest.
    let dests = resolve_destinations(&sender_manifest, out_dir)
        .map_err(|e| ProtocolError::Unexpected(format!("destinations: {e}")))?;
    let mut plan = crate::resume::plan(&sender_manifest, &dests)
        .map_err(|e| ProtocolError::Unexpected(format!("resume plan: {e}")))?;

    // Send ManifestAck for only the files assigned to this connection.
    let accepted: Vec<_> = plan
        .accepted
        .iter()
        .filter(|&&id| id % u32::from(agreed_parallel) == connection_index)
        .copied()
        .collect();
    let resume_offsets: std::collections::HashMap<_, _> = plan
        .offsets
        .iter()
        .filter(|(id, _)| **id % u32::from(agreed_parallel) == connection_index)
        .map(|(k, v)| (*k, *v))
        .collect();
    write_frame(
        writer,
        &ControlMsg::ManifestAck {
            accepted,
            resume_offsets,
        },
    )
    .await?;
    writer.flush().await?;

    // Each parallel connection owns the files whose id matches its
    // connection index modulo the agreed parallelism.
    let assigned_ids: std::collections::HashSet<_> = sender_manifest
        .files
        .iter()
        .filter(|f| f.id % u32::from(agreed_parallel) == connection_index)
        .map(|f| f.id)
        .collect();

    let mut report = ReceiverReport::default();
    for entry in &sender_manifest.files {
        if !assigned_ids.contains(&entry.id) {
            continue;
        }
        if plan.complete.contains(&entry.id) {
            debug!(id = entry.id, "already complete, skipping");
            // A complete file should not have a stale sidecar.
            let _ = crate::sidecar::remove(&dests.paths[&entry.id]);
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
        // Cache the verified prefix so the next resume can skip the
        // chunk-by-chunk re-verification.
        if let Some(ref h) = hasher {
            let verified_chunks =
                u32::try_from(h.bytes_seen() / u64::from(entry.chunk_size)).unwrap_or(0);
            if verified_chunks > 0 {
                let sidecar = crate::sidecar::Sidecar {
                    version: crate::sidecar::SIDECAR_VERSION,
                    rel_path: entry.rel_path.clone(),
                    size: entry.size,
                    chunk_size: entry.chunk_size,
                    verified_chunks,
                };
                if let Err(e) = crate::sidecar::write(&dest_path, &sidecar) {
                    tracing::warn!(path = %dest_path.display(), error = %e, "failed to write sidecar");
                }
            }
        }
        let verified = recv_file(
            reader,
            writer,
            entry,
            &dest_path,
            hasher,
            progress,
            cfg.max_retries,
        )
        .await?;
        if verified {
            let _ = crate::sidecar::remove(&dest_path);
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

/// Read a manifest, accepting either the legacy single-frame `Manifest`
/// message or the current streaming manifest sequence.
async fn read_manifest<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Manifest, ProtocolError> {
    let first = read_frame(reader).await?;
    match first {
        ControlMsg::Manifest(m) => {
            tracing::warn!(
                "received legacy single-frame Manifest; \
                 sender should be updated to use streaming manifest"
            );
            validate_manifest(&m)?;
            Ok(m)
        }
        ControlMsg::ManifestStart {
            total_files,
            total_bytes,
        } => read_streaming_manifest(reader, total_files, total_bytes).await,
        ControlMsg::Error { message } => Err(ProtocolError::PeerError(message)),
        other => Err(ProtocolError::Unexpected(format!("{other:?}"))),
    }
}

async fn read_streaming_manifest<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
    expected_files: u64,
    expected_bytes: u64,
) -> Result<Manifest, ProtocolError> {
    if expected_files > u64::try_from(MAX_MANIFEST_FILES).unwrap_or(u64::MAX) {
        return Err(ProtocolError::Unexpected(format!(
            "manifest has {expected_files} files, maximum is {MAX_MANIFEST_FILES}",
        )));
    }

    let mut files = Vec::new();
    let mut total_bytes = 0u64;
    let mut chunk_size: Option<u32> = None;

    loop {
        let msg = read_frame(reader).await?;
        match msg {
            ControlMsg::ManifestEntry(entry) => {
                if files.len() >= MAX_MANIFEST_FILES {
                    return Err(ProtocolError::Unexpected(format!(
                        "manifest exceeded maximum {MAX_MANIFEST_FILES} files",
                    )));
                }
                validate_entry(&entry)?;
                total_bytes = total_bytes.checked_add(entry.size).ok_or_else(|| {
                    ProtocolError::Unexpected("manifest total bytes overflow".into())
                })?;
                if let Some(cs) = chunk_size {
                    if entry.chunk_size != cs {
                        return Err(ProtocolError::Unexpected(format!(
                            "manifest entry chunk_size {} does not match expected {cs}",
                            entry.chunk_size
                        )));
                    }
                } else {
                    chunk_size = Some(entry.chunk_size);
                }
                files.push(entry);
            }
            ControlMsg::ManifestEnd { chunk_size: cs } => {
                if chunk_size.is_some_and(|existing| existing != cs) {
                    return Err(ProtocolError::Unexpected(format!(
                        "ManifestEnd chunk_size {cs} does not match entry chunk_size {}",
                        chunk_size.unwrap()
                    )));
                }
                chunk_size = Some(cs);
                break;
            }
            ControlMsg::Error { message } => return Err(ProtocolError::PeerError(message)),
            other => return Err(ProtocolError::Unexpected(format!("{other:?}"))),
        }
    }

    let chunk_size = match chunk_size {
        Some(cs) => cs,
        None if files.is_empty() => {
            // Empty manifest: no files to transfer. Use a default chunk
            // size since there's nothing to chunk.
            crate::manifest::DEFAULT_CHUNK_SIZE
        }
        None => {
            return Err(ProtocolError::Unexpected(
                "manifest missing ManifestEnd".into(),
            ));
        }
    };
    if chunk_size == 0 || chunk_size > MAX_CHUNK_SIZE {
        return Err(ProtocolError::Unexpected(format!(
            "chunk_size {chunk_size} is out of valid range (1..{MAX_CHUNK_SIZE})",
        )));
    }
    if files.len() as u64 != expected_files {
        return Err(ProtocolError::Unexpected(format!(
            "manifest file count mismatch: declared {expected_files}, got {}",
            files.len(),
        )));
    }
    if total_bytes != expected_bytes {
        return Err(ProtocolError::Unexpected(format!(
            "manifest byte count mismatch: declared {expected_bytes}, got {total_bytes}",
        )));
    }
    Ok(Manifest {
        files,
        chunk_size,
        source_root: PathBuf::new(),
    })
}

fn validate_manifest(m: &Manifest) -> Result<(), ProtocolError> {
    if m.files.len() > MAX_MANIFEST_FILES {
        return Err(ProtocolError::Unexpected(format!(
            "manifest has {} files, maximum is {MAX_MANIFEST_FILES}",
            m.files.len(),
        )));
    }
    if m.chunk_size == 0 || m.chunk_size > MAX_CHUNK_SIZE {
        return Err(ProtocolError::Unexpected(format!(
            "chunk_size {} is out of valid range (1..{MAX_CHUNK_SIZE})",
            m.chunk_size,
        )));
    }
    for entry in &m.files {
        validate_entry(entry)?;
    }
    Ok(())
}

fn validate_entry(entry: &FileEntry) -> Result<(), ProtocolError> {
    // Split on both Unix and Windows separators to prevent path traversal
    // on any platform. A malicious sender could use backslashes on Windows
    // to write outside the destination directory.
    for component in entry.rel_path.split(['/', '\\']) {
        if component == ".." {
            return Err(ProtocolError::Unexpected(format!(
                "rel_path contains '..' component: {}",
                entry.rel_path,
            )));
        }
    }
    Ok(())
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
    /// True when the receiver declined the manifest before any file
    /// data was transferred.
    pub rejected: bool,
}

/// Maximum number of total attempts per file is `max_retries + 1`:
/// one initial attempt plus `max_retries` re-attempts after hash
/// mismatches. This matches the sender's `SenderConfig::max_retries`
/// semantics so both sides stop retrying at the same time.
///
/// On a mismatch we first try to repair only the bad chunks; if the bad
/// ranges cannot be identified we fall back to a full re-send from
/// offset 0.
async fn recv_file<R: tokio::io::AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut R,
    writer: &mut W,
    entry: &FileEntry,
    dest: &Path,
    hasher: Option<IncrementalHasher>,
    progress: &dyn Progress,
    max_retries: u32,
) -> Result<bool, ProtocolError> {
    let max_attempts = max_retries.saturating_add(1);
    let mut attempts: u32 = 0;
    let mut hasher = hasher;

    loop {
        let verified = recv_full_file(reader, writer, entry, dest, hasher.take(), progress).await?;
        if verified {
            return Ok(true);
        }

        attempts += 1;
        progress.file_done(entry.id, false);

        // Try to repair only the bad chunks instead of the whole file.
        let bad_ranges = tokio::task::spawn_blocking({
            let dest = dest.to_path_buf();
            let entry = entry.clone();
            move || find_bad_ranges(&entry, &dest)
        })
        .await
        .map_err(|e| ProtocolError::Unexpected(format!("bad-range finder panicked: {e}")))?;

        let exhausted = attempts >= max_attempts;
        if bad_ranges.is_empty() {
            // Could not identify bad chunks (e.g. file missing or mangled
            // beyond chunk alignment). Fall back to a full re-send.
            write_frame(
                writer,
                &ControlMsg::FileVerified {
                    id: entry.id,
                    ok: false,
                },
            )
            .await?;
            writer.flush().await?;
            if exhausted {
                tracing::warn!(
                    id = entry.id,
                    attempts,
                    max_retries,
                    "max recv retries exhausted for file"
                );
                return Ok(false);
            }
            hasher = None;
            continue;
        }

        // Request a chunk-level repair.
        write_frame(
            writer,
            &ControlMsg::FileChunkRequest {
                id: entry.id,
                ranges: bad_ranges.clone(),
            },
        )
        .await?;
        writer.flush().await?;

        let repaired = recv_chunk_repair(reader, writer, entry, dest, bad_ranges, progress).await?;
        if repaired {
            return Ok(true);
        }
        // Repair didn't fix everything. If we've exhausted attempts, signal
        // the sender to stop retrying. Otherwise, continue the loop for
        // another repair attempt (the sender already incremented attempts
        // when it processed the FileChunkRequest).
        if exhausted {
            tracing::warn!(
                id = entry.id,
                attempts,
                max_retries,
                "max recv retries exhausted for file"
            );
            return Ok(false);
        }
        // Tell the sender verification failed so it loops back to send
        // a fresh FileStart, matching the receiver's next recv_full_file
        // read. Without this both sides block on read_frame → deadlock.
        write_frame(
            writer,
            &ControlMsg::FileVerified {
                id: entry.id,
                ok: false,
            },
        )
        .await?;
        writer.flush().await?;
        hasher = None;
    }
}

/// Read a full file attempt: `FileStart`, sequential chunks, `FileEnd`.
/// Returns whether the whole-file hash matches and the hasher state at
/// that point (so chunk repair can continue from it).
async fn recv_full_file<R: tokio::io::AsyncRead + Unpin, W: AsyncWrite + Unpin>(
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
    let verified = local_hash == sender_hash;
    if verified {
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
    Ok(verified)
}

/// Receive a chunk-level repair: the sender sends `ChunkHeader`s for the
/// requested ranges followed by `FileEnd`. Writes the repaired chunks at
/// the correct offsets, re-hashes the whole file from disk, and returns
/// the verification result.
async fn recv_chunk_repair<R: tokio::io::AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut R,
    writer: &mut W,
    entry: &FileEntry,
    dest: &Path,
    requested_ranges: Vec<(u64, u32)>,
    progress: &dyn Progress,
) -> Result<bool, ProtocolError> {
    let mut file = OpenOptions::new().read(true).write(true).open(dest).await?;

    // Track which requested ranges have been received so we can detect
    // duplicates or missing ranges.
    let mut remaining: std::collections::HashMap<u64, u32> = requested_ranges.into_iter().collect();
    let chunk_size = usize::try_from(entry.chunk_size)
        .map_err(|_| ProtocolError::Unexpected("chunk_size does not fit in usize".to_string()))?;
    let mut buf = vec![0u8; chunk_size];

    while !remaining.is_empty() {
        let header = read_frame(reader).await?;
        match header {
            ControlMsg::ChunkHeader {
                id,
                offset: hdr_off,
                len,
            } if id == entry.id => {
                let expected_len = remaining.remove(&hdr_off).ok_or_else(|| {
                    ProtocolError::Unexpected(format!(
                        "unexpected repair chunk at offset {hdr_off}"
                    ))
                })?;
                if len != expected_len {
                    return Err(ProtocolError::Unexpected(format!(
                        "repair chunk length mismatch at {hdr_off}: expected {expected_len} got {len}"
                    )));
                }
                let len_usize = usize::try_from(len)
                    .map_err(|_| ProtocolError::FrameTooLarge(u64::from(len)))?;
                if len_usize > buf.len() {
                    return Err(ProtocolError::FrameTooLarge(u64::from(len)));
                }
                reader.read_exact(&mut buf[..len_usize]).await?;
                file.seek(std::io::SeekFrom::Start(hdr_off)).await?;
                file.write_all(&buf[..len_usize]).await?;
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

    // Re-hash the whole file from disk: the receiver's incremental hasher
    // still contains the old corrupt bytes, so it cannot be updated in
    // place. BLAKE3 is fast enough that this local re-hash is cheap
    // compared to re-sending the whole file over the network.
    let local_hash = tokio::task::spawn_blocking({
        let dest = dest.to_path_buf();
        move || crate::hashing::hash_file(&dest)
    })
    .await
    .map_err(|e| ProtocolError::Unexpected(format!("file hash task panicked: {e}")))?
    .map_err(|e| match e {
        crate::hashing::HashError::Io(io) => ProtocolError::Io(io),
        crate::hashing::HashError::InvalidChunkSize(cs) => {
            ProtocolError::Unexpected(format!("invalid chunk size: {cs}"))
        }
    })?;

    let verified = local_hash == sender_hash;
    if verified {
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
    Ok(verified)
}

/// Scan the destination file and compare each chunk against the manifest's
/// expected chunk hashes. Returns the (offset, len) of every chunk whose
/// on-disk bytes do not match.
fn find_bad_ranges(entry: &FileEntry, dest: &Path) -> Vec<(u64, u32)> {
    let mut bad = Vec::new();
    let file = match std::fs::File::open(dest) {
        Ok(f) => f,
        Err(e) => {
            tracing::debug!(path = %dest.display(), error = %e, "cannot open file for bad-range check");
            // Missing or unreadable file: the whole file is bad. Request
            // re-send in full-chunk ranges, respecting the final chunk size.
            let chunk_size = u64::from(entry.chunk_size);
            let mut offset = 0u64;
            for _ in &entry.chunk_hashes {
                if offset >= entry.size {
                    break;
                }
                let end = (offset + chunk_size).min(entry.size);
                let len = u32::try_from(end - offset).unwrap_or(entry.chunk_size);
                bad.push((offset, len));
                offset = end;
            }
            return bad;
        }
    };
    let chunk_size = usize::try_from(entry.chunk_size).unwrap_or(1024 * 1024);
    let mut reader = std::io::BufReader::with_capacity(chunk_size, file);
    let mut buf = vec![0u8; chunk_size];
    let mut offset = 0u64;
    for expected in &entry.chunk_hashes {
        if offset >= entry.size {
            break;
        }
        let want = (entry.size - offset).min(u64::try_from(buf.len()).unwrap_or(u64::MAX));
        let want = usize::try_from(want).unwrap_or(buf.len()).min(buf.len());
        let n = match std::io::Read::read(&mut reader, &mut buf[..want]) {
            Ok(n) => n,
            Err(e) => {
                tracing::debug!(path = %dest.display(), error = %e, "read error during bad-range scan");
                // Read error: the rest of the file is unreadable.
                // Push the remaining expected chunk and bail — further
                // iterations would also fail on the same broken stream.
                if let Ok(len) = u32::try_from(want) {
                    bad.push((offset, len));
                }
                break;
            }
        };
        if n < want {
            // Truncated chunk: the rest of the file is shorter than
            // expected. Push the remaining expected bytes and stop.
            if let Ok(len) = u32::try_from(want) {
                bad.push((offset, len));
            }
            break;
        }
        let actual = blake3::hash(&buf[..n]);
        if actual.as_bytes() != expected {
            if let Ok(len) = u32::try_from(n) {
                bad.push((offset, len));
            }
        }
        offset += u64::try_from(n).unwrap_or(0);
    }
    // Limit the number of ranges to keep the request frame small.
    bad.truncate(MAX_CHUNK_RANGES);
    bad
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
