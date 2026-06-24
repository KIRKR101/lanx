//! Transfer state machines: sender and receiver.
//!
//! Wire protocol is documented in `plan.md` §6. Control messages are
//! length-prefixed (u32 BE) postcard payloads. The data plane (file bytes)
//! follows a `ChunkHeader` control message inline on the same stream.

pub mod receiver;
pub mod sender;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const PROTOCOL_VERSION: u16 = 4;

/// Default maximum number of retries per file on hash mismatch. Both
/// sender and receiver use this value so they agree on when to give up.
pub const DEFAULT_MAX_RETRIES: u32 = 3;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HelloInfo {
    pub version: u16,
    pub chunk_size: u32,
    /// Number of parallel TCP connections requested by the peer. The
    /// receiver proposes a value; the sender replies with the value it
    /// is willing to honor (capped by its own maximum). A value of 0 or
    /// 1 means no parallelism.
    pub parallel: u16,
}

/// Control-plane message. See `plan.md` §6.2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ControlMsg {
    Hello(HelloInfo),
    /// Legacy single-frame manifest. Kept for backwards compatibility at
    /// the enum level; current protocol uses streaming manifest messages.
    Manifest(crate::manifest::Manifest),
    /// First message of a streaming manifest. `total_files` and
    /// `total_bytes` let the receiver pre-allocate UI state.
    ManifestStart {
        total_files: u64,
        total_bytes: u64,
    },
    /// One file entry in a streaming manifest. Sent between `ManifestStart`
    /// and `ManifestEnd`.
    ManifestEntry(crate::manifest::FileEntry),
    /// Final message of a streaming manifest. Carries the shared
    /// `chunk_size` that applies to all entries.
    ManifestEnd {
        chunk_size: u32,
    },
    /// `accepted` is the list of file IDs the receiver wants.
    /// `resume_offsets[id]` is the byte offset the sender must start at
    /// (0 if absent / starting fresh).
    ManifestAck {
        accepted: Vec<crate::manifest::FileId>,
        resume_offsets: std::collections::HashMap<crate::manifest::FileId, u64>,
    },
    /// Receiver declined the manifest before any file data was sent.
    ManifestRejected {
        reason: String,
    },
    /// Beginning this file at `offset` (raw bytes follow per `ChunkHeader`).
    FileStart {
        id: crate::manifest::FileId,
        offset: u64,
    },
    /// Header for the next `len` raw bytes on the wire. The bytes are NOT
    /// framed — receiver reads exactly `len` after this message.
    ChunkHeader {
        id: crate::manifest::FileId,
        offset: u64,
        len: u32,
    },
    /// Whole-file BLAKE3 hash, computed incrementally on both sides.
    FileEnd {
        id: crate::manifest::FileId,
        hash: [u8; 32],
    },
    /// Receiver's verdict after `FileEnd`. `ok=false` triggers a re-send
    /// from offset 0 on the same connection.
    FileVerified {
        id: crate::manifest::FileId,
        ok: bool,
    },
    /// Receiver asks the sender to re-send specific byte ranges of a file.
    /// Sent after `FileEnd` when the whole-file hash mismatches but the
    /// receiver can identify which chunks are corrupt.
    FileChunkRequest {
        id: crate::manifest::FileId,
        /// (offset, len) pairs. Must be non-overlapping and in ascending order.
        ranges: Vec<(u64, u32)>,
    },
    Error {
        message: String,
    },
    Done,
}

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("protocol version mismatch: sender={sender} receiver={receiver}")]
    VersionMismatch { sender: u16, receiver: u16 },
    #[error("unexpected message: {0}")]
    Unexpected(String),
    #[error("peer reported error: {0}")]
    PeerError(String),
    #[error("postcard: {0}")]
    Postcard(#[from] postcard::Error),
    #[error("frame too large: {0} bytes")]
    FrameTooLarge(u64),
    #[error("connection closed unexpectedly")]
    Closed,
    #[error("max retries ({0}) exhausted for file {1}")]
    MaxRetries(u32, crate::manifest::FileId),
    #[error("receiver declined transfer: {0}")]
    ManifestRejected(String),
}

// ---- framing ----

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Serialize `msg` to a length-prefixed postcard frame.
///
/// # Errors
///
/// Returns `ProtocolError::FrameTooLarge` if the serialized message
/// exceeds 32 MiB, or `ProtocolError::Io` / `ProtocolError::Postcard`
/// for serialization or write failures.
pub async fn write_frame<W: AsyncWrite + Unpin>(
    w: &mut W,
    msg: &ControlMsg,
) -> Result<(), ProtocolError> {
    let payload = postcard::to_allocvec(msg)?;
    let len: u32 = payload
        .len()
        .try_into()
        .map_err(|_| ProtocolError::FrameTooLarge(payload.len() as u64))?;
    if len > 32 * 1024 * 1024 {
        return Err(ProtocolError::FrameTooLarge(u64::from(len)));
    }
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(&payload).await?;
    Ok(())
}

/// Read a length-prefixed postcard frame and deserialize it.
///
/// # Errors
///
/// Returns `ProtocolError::FrameTooLarge` if the declared length exceeds
/// 32 MiB, `ProtocolError::Closed` on unexpected EOF, or
/// `ProtocolError::Io` / `ProtocolError::Postcard` for read or
/// deserialization failures.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<ControlMsg, ProtocolError> {
    let mut len_bytes = [0u8; 4];
    r.read_exact(&mut len_bytes).await?;
    let len = u32::from_be_bytes(len_bytes);
    if len > 32 * 1024 * 1024 {
        return Err(ProtocolError::FrameTooLarge(u64::from(len)));
    }
    let len_usize =
        usize::try_from(len).map_err(|_| ProtocolError::FrameTooLarge(u64::from(len)))?;
    let mut payload = vec![0u8; len_usize];
    r.read_exact(&mut payload).await?;
    Ok(postcard::from_bytes(&payload)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{FileEntry, Manifest, DEFAULT_CHUNK_SIZE};
    use std::path::PathBuf;

    fn test_manifest() -> Manifest {
        Manifest {
            files: vec![FileEntry {
                id: 0,
                rel_path: "test.bin".to_string(),
                size: 1024,
                chunk_size: DEFAULT_CHUNK_SIZE,
                chunk_hashes: vec![[0xAB; 32]],
            }],
            chunk_size: DEFAULT_CHUNK_SIZE,
            source_root: PathBuf::new(),
        }
    }

    #[test]
    fn hello_round_trip() {
        let msg = ControlMsg::Hello(HelloInfo {
            version: 1,
            chunk_size: 1024,
            parallel: 4,
        });
        let encoded = postcard::to_allocvec(&msg).unwrap();
        let decoded: ControlMsg = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(format!("{msg:?}"), format!("{decoded:?}"));
    }

    #[test]
    fn manifest_round_trip() {
        let msg = ControlMsg::Manifest(test_manifest());
        let encoded = postcard::to_allocvec(&msg).unwrap();
        let decoded: ControlMsg = postcard::from_bytes(&encoded).unwrap();
        if let ControlMsg::Manifest(m) = decoded {
            assert_eq!(m.files.len(), 1);
            assert_eq!(m.files[0].rel_path, "test.bin");
        } else {
            panic!("expected Manifest variant");
        }
    }

    #[test]
    fn manifest_start_round_trip() {
        let msg = ControlMsg::ManifestStart {
            total_files: 42,
            total_bytes: 123_456,
        };
        let encoded = postcard::to_allocvec(&msg).unwrap();
        let decoded: ControlMsg = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(format!("{msg:?}"), format!("{decoded:?}"));
    }

    #[test]
    fn manifest_entry_round_trip() {
        let msg = ControlMsg::ManifestEntry(crate::manifest::FileEntry {
            id: 5,
            rel_path: "sub/file.bin".into(),
            size: 4096,
            chunk_size: 1024,
            chunk_hashes: vec![[1; 32], [2; 32], [3; 32], [4; 32]],
        });
        let encoded = postcard::to_allocvec(&msg).unwrap();
        let decoded: ControlMsg = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(format!("{msg:?}"), format!("{decoded:?}"));
    }

    #[test]
    fn manifest_end_round_trip() {
        let msg = ControlMsg::ManifestEnd {
            chunk_size: 1024 * 1024,
        };
        let encoded = postcard::to_allocvec(&msg).unwrap();
        let decoded: ControlMsg = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(format!("{msg:?}"), format!("{decoded:?}"));
    }

    #[test]
    fn manifest_rejected_round_trip() {
        let msg = ControlMsg::ManifestRejected {
            reason: "user declined".into(),
        };
        let encoded = postcard::to_allocvec(&msg).unwrap();
        let decoded: ControlMsg = postcard::from_bytes(&encoded).unwrap();
        if let ControlMsg::ManifestRejected { reason } = decoded {
            assert_eq!(reason, "user declined");
        } else {
            panic!("expected ManifestRejected variant");
        }
    }

    #[test]
    fn manifest_ack_round_trip() {
        let mut offsets = std::collections::HashMap::new();
        offsets.insert(0, 512);
        let msg = ControlMsg::ManifestAck {
            accepted: vec![0, 2],
            resume_offsets: offsets,
        };
        let encoded = postcard::to_allocvec(&msg).unwrap();
        let decoded: ControlMsg = postcard::from_bytes(&encoded).unwrap();
        if let ControlMsg::ManifestAck {
            accepted,
            resume_offsets,
        } = decoded
        {
            assert_eq!(accepted, vec![0, 2]);
            assert_eq!(resume_offsets[&0], 512);
        } else {
            panic!("expected ManifestAck variant");
        }
    }

    #[test]
    fn file_start_round_trip() {
        let msg = ControlMsg::FileStart {
            id: 3,
            offset: 4096,
        };
        let encoded = postcard::to_allocvec(&msg).unwrap();
        let decoded: ControlMsg = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(format!("{msg:?}"), format!("{decoded:?}"));
    }

    #[test]
    fn chunk_header_round_trip() {
        let msg = ControlMsg::ChunkHeader {
            id: 1,
            offset: 1024,
            len: 512,
        };
        let encoded = postcard::to_allocvec(&msg).unwrap();
        let decoded: ControlMsg = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(format!("{msg:?}"), format!("{decoded:?}"));
    }

    #[test]
    fn file_end_round_trip() {
        let msg = ControlMsg::FileEnd {
            id: 0,
            hash: [0x42; 32],
        };
        let encoded = postcard::to_allocvec(&msg).unwrap();
        let decoded: ControlMsg = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(format!("{msg:?}"), format!("{decoded:?}"));
    }

    #[test]
    fn file_verified_round_trip() {
        let msg = ControlMsg::FileVerified { id: 1, ok: true };
        let encoded = postcard::to_allocvec(&msg).unwrap();
        let decoded: ControlMsg = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(format!("{msg:?}"), format!("{decoded:?}"));
    }

    #[test]
    fn file_chunk_request_round_trip() {
        let msg = ControlMsg::FileChunkRequest {
            id: 7,
            ranges: vec![(0, 1024), (2048, 512)],
        };
        let encoded = postcard::to_allocvec(&msg).unwrap();
        let decoded: ControlMsg = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(format!("{msg:?}"), format!("{decoded:?}"));
    }

    #[test]
    fn error_msg_round_trip() {
        let msg = ControlMsg::Error {
            message: "something went wrong".into(),
        };
        let encoded = postcard::to_allocvec(&msg).unwrap();
        let decoded: ControlMsg = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(format!("{msg:?}"), format!("{decoded:?}"));
    }

    #[test]
    fn done_round_trip() {
        let msg = ControlMsg::Done;
        let encoded = postcard::to_allocvec(&msg).unwrap();
        let decoded: ControlMsg = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(format!("{msg:?}"), format!("{decoded:?}"));
    }

    #[tokio::test]
    async fn write_read_frame_round_trip() {
        let (mut w, mut r) = tokio::io::duplex(64 * 1024);

        let msg = ControlMsg::Hello(HelloInfo {
            version: 1,
            chunk_size: 2048,
            parallel: 1,
        });
        write_frame(&mut w, &msg).await.unwrap();
        drop(w);

        let decoded = read_frame(&mut r).await.unwrap();
        assert_eq!(format!("{msg:?}"), format!("{decoded:?}"));
    }

    #[tokio::test]
    async fn multiple_frames_round_trip() {
        let (mut w, mut r) = tokio::io::duplex(64 * 1024);

        let msgs = vec![
            ControlMsg::Hello(HelloInfo {
                version: 1,
                chunk_size: 1024,
                parallel: 1,
            }),
            ControlMsg::FileStart { id: 0, offset: 0 },
            ControlMsg::ChunkHeader {
                id: 0,
                offset: 0,
                len: 512,
            },
            ControlMsg::FileEnd {
                id: 0,
                hash: [0xAA; 32],
            },
            ControlMsg::FileVerified { id: 0, ok: true },
            ControlMsg::Done,
        ];

        for msg in &msgs {
            write_frame(&mut w, msg).await.unwrap();
        }
        drop(w);

        for msg in &msgs {
            let decoded = read_frame(&mut r).await.unwrap();
            assert_eq!(format!("{msg:?}"), format!("{decoded:?}"));
        }
    }

    #[tokio::test]
    async fn frame_too_large_rejected() {
        // Manually write a frame with a length > 32 MiB.
        let (mut w, mut r) = tokio::io::duplex(64 * 1024);
        let bad_len: u32 = 32 * 1024 * 1024 + 1;
        AsyncWriteExt::write_all(&mut w, &bad_len.to_be_bytes())
            .await
            .unwrap();
        // Write some dummy payload bytes (the reader should reject before reading them).
        AsyncWriteExt::write_all(&mut w, &[0u8; 64]).await.unwrap();
        drop(w);

        let err = read_frame(&mut r).await.unwrap_err();
        assert!(matches!(err, ProtocolError::FrameTooLarge(33_554_433)));
    }
}
