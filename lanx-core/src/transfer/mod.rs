//! Transfer state machines: sender and receiver.
//!
//! Wire protocol is documented in `plan.md` §6. Control messages are
//! length-prefixed (u32 BE) postcard payloads. The data plane (file bytes)
//! follows a `ChunkHeader` control message inline on the same stream.

pub mod receiver;
pub mod sender;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const PROTOCOL_VERSION: u16 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HelloInfo {
    pub version: u16,
    pub chunk_size: u32,
}

/// Control-plane message. See `plan.md` §6.2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ControlMsg {
    Hello(HelloInfo),
    Manifest(crate::manifest::Manifest),
    /// `accepted` is the list of file IDs the receiver wants.
    /// `resume_offsets[id]` is the byte offset the sender must start at
    /// (0 if absent / starting fresh).
    ManifestAck {
        accepted: Vec<crate::manifest::FileId>,
        resume_offsets: std::collections::HashMap<crate::manifest::FileId, u64>,
    },
    /// Beginning this file at `offset` (raw bytes follow per ChunkHeader).
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
    /// from offset 0 (v1) on the same connection.
    FileVerified {
        id: crate::manifest::FileId,
        ok: bool,
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
    #[error("hash mismatch on file {0}")]
    HashMismatch(crate::manifest::FileId),
    #[error("postcard: {0}")]
    Postcard(#[from] postcard::Error),
    #[error("frame too large: {0} bytes")]
    FrameTooLarge(u32),
    #[error("connection closed unexpectedly")]
    Closed,
    #[error("max retries ({0}) exhausted for file {1}")]
    MaxRetries(u32, crate::manifest::FileId),
}

// ---- framing ----

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub async fn write_frame<W: AsyncWrite + Unpin>(
    w: &mut W,
    msg: &ControlMsg,
) -> Result<(), ProtocolError> {
    let payload = postcard::to_allocvec(msg)?;
    let len = payload.len() as u32;
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(&payload).await?;
    Ok(())
}

pub async fn read_frame<R: AsyncRead + Unpin>(
    r: &mut R,
) -> Result<ControlMsg, ProtocolError> {
    let mut len_bytes = [0u8; 4];
    r.read_exact(&mut len_bytes).await?;
    let len = u32::from_be_bytes(len_bytes);
    if len > 32 * 1024 * 1024 {
        return Err(ProtocolError::FrameTooLarge(len));
    }
    let mut payload = vec![0u8; len as usize];
    r.read_exact(&mut payload).await?;
    Ok(postcard::from_bytes(&payload)?)
}
