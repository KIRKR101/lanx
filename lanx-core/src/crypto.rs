//! Encrypted transport using the Noise protocol (`Noise_NN_25519_ChaChaPoly_BLAKE2s`).
//!
//! This module wraps a raw TCP (or any `AsyncRead + AsyncWrite`) stream in a
//! confidential, forward-secret channel before any `lanx` control messages are
//! exchanged. Authentication is limited to the peer being present on the same
//! channel at handshake time; future work can add a PSK derived from the
//! pairing code or static long-term keys.
//!
//! The design uses a pump task: the caller gets a `tokio::io::DuplexStream`
//! that implements `AsyncRead + AsyncWrite`, while a background task reads
//! plaintext from the duplex, encrypts it into Noise transport messages, and
//! writes it to the network stream. In the opposite direction it reads
//! ciphertext from the network, decrypts it, and writes plaintext into the
//! duplex. This avoids hand-rolling a full `AsyncRead`/`AsyncWrite` state
//! machine while still giving `run_sender`/`run_receiver` a normal stream.

use snow::{HandshakeState, TransportState};
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Noise pattern used for the encrypted transport.
const PATTERN: &str = "Noise_NN_25519_ChaChaPoly_BLAKE2s";

/// Maximum plaintext bytes in a single Noise transport message. Each message
/// carries a 16-byte Poly1305 tag, so the largest safe payload is 65535 - 16.
const MAX_PAYLOAD: usize = 65519;

/// Wire framing overhead: 2-byte big-endian ciphertext length.
const LENGTH_PREFIX: usize = 2;

/// Maximum seconds of network inactivity before the pump is considered
/// stalled and the connection is dropped. Prevents half-open TCP
/// connections from blocking the pump forever.
const PUMP_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5 * 60);

/// Errors from the encrypted transport.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("snow: {0}")]
    Snow(#[from] snow::Error),
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("decryption failed: {0}")]
    Decrypt(String),
}

/// Perform the Noise handshake as the initiator (typically the receiver,
/// since it dials the sender), then spawn a pump task and return a duplex
/// stream that encrypts/decrypts transparently.
pub async fn wrap_initiator<S>(stream: S) -> Result<tokio::io::DuplexStream, CryptoError>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin + Send + 'static,
{
    let (state, stream) = handshake_initiator(stream).await?;
    let (local, peer) = tokio::io::duplex(256 * 1024);
    tokio::spawn(async move {
        if let Err(e) = run_pump(state, stream, peer).await {
            tracing::warn!(error = %e, "encryption pump exited with error");
        }
    });
    Ok(local)
}

/// Perform the Noise handshake as the responder (typically the sender, since
/// it accepts the incoming TCP connection), then spawn a pump task and return
/// a duplex stream that encrypts/decrypts transparently.
pub async fn wrap_responder<S>(stream: S) -> Result<tokio::io::DuplexStream, CryptoError>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin + Send + 'static,
{
    let (state, stream) = handshake_responder(stream).await?;
    let (local, peer) = tokio::io::duplex(256 * 1024);
    tokio::spawn(async move {
        if let Err(e) = run_pump(state, stream, peer).await {
            tracing::warn!(error = %e, "encryption pump exited with error");
        }
    });
    Ok(local)
}

async fn handshake_initiator<S>(mut stream: S) -> Result<(TransportState, S), CryptoError>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let mut state = snow::Builder::new(PATTERN.parse()?).build_initiator()?;
    let mut payload = vec![0u8; 1024];

    // -> e
    send_handshake(&mut state, &mut stream, &[]).await?;
    // <- e, ee
    recv_handshake(&mut state, &mut stream, &mut payload).await?;

    Ok((state.into_transport_mode()?, stream))
}

async fn handshake_responder<S>(mut stream: S) -> Result<(TransportState, S), CryptoError>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let mut state = snow::Builder::new(PATTERN.parse()?).build_responder()?;
    let mut payload = vec![0u8; 1024];

    // <- e
    recv_handshake(&mut state, &mut stream, &mut payload).await?;
    // -> e, ee
    send_handshake(&mut state, &mut stream, &[]).await?;

    Ok((state.into_transport_mode()?, stream))
}

async fn send_handshake<S>(
    state: &mut HandshakeState,
    stream: &mut S,
    payload: &[u8],
) -> Result<(), CryptoError>
where
    S: AsyncWriteExt + Unpin,
{
    let mut msg = vec![0u8; LENGTH_PREFIX + payload.len() + 128];
    let len = state.write_message(payload, &mut msg[LENGTH_PREFIX..])?;
    let len_u16 = u16::try_from(len)
        .map_err(|_| CryptoError::Decrypt(format!("handshake message too large: {len} bytes")))?;
    msg[..LENGTH_PREFIX].copy_from_slice(&len_u16.to_be_bytes());
    write_all(stream, &msg[..LENGTH_PREFIX + len]).await
}

async fn recv_handshake<S>(
    state: &mut HandshakeState,
    stream: &mut S,
    payload_buf: &mut [u8],
) -> Result<usize, CryptoError>
where
    S: AsyncReadExt + Unpin,
{
    let ciphertext = read_framed(stream).await?;
    Ok(state.read_message(&ciphertext, payload_buf)?)
}

async fn run_pump<S>(
    mut state: TransportState,
    mut stream: S,
    mut peer: tokio::io::DuplexStream,
) -> Result<(), CryptoError>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let mut msg = vec![0u8; LENGTH_PREFIX + MAX_PAYLOAD + 16];
    let mut plain = vec![0u8; MAX_PAYLOAD];

    loop {
        tokio::select! {
            // Plaintext -> encrypt -> network.
            n = peer.read(&mut plain) => {
                let n = n?;
                if n == 0 {
                    let _ = stream.shutdown().await;
                    return Ok(());
                }
                let cipher_len = state.write_message(&plain[..n], &mut msg[LENGTH_PREFIX..])?;
                let len_u16 = u16::try_from(cipher_len).map_err(|_| {
                    CryptoError::Decrypt(format!("transport message too large: {cipher_len} bytes"))
                })?;
                msg[..LENGTH_PREFIX].copy_from_slice(&len_u16.to_be_bytes());
                write_all(&mut stream, &msg[..LENGTH_PREFIX + cipher_len]).await?;
            }
            // Network -> decrypt -> plaintext. Wrapped in a timeout to
            // detect stalled connections (half-open TCP).
            ciphertext = tokio::time::timeout(PUMP_IDLE_TIMEOUT, read_framed(&mut stream)) => {
                let ciphertext = ciphertext.map_err(|_| {
                    CryptoError::Decrypt("pump idle timeout: no data received".to_string())
                })??;
                let plain_len = state.read_message(&ciphertext, &mut plain)
                    .map_err(|e| CryptoError::Decrypt(e.to_string()))?;
                if plain_len == 0 {
                    continue;
                }
                peer.write_all(&plain[..plain_len]).await?;
            }
        }
    }
}

async fn read_framed<S>(stream: &mut S) -> Result<Vec<u8>, CryptoError>
where
    S: AsyncReadExt + Unpin,
{
    let mut len_bytes = [0u8; LENGTH_PREFIX];
    stream.read_exact(&mut len_bytes).await?;
    let len = u16::from_be_bytes(len_bytes) as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn write_all<S>(stream: &mut S, bytes: &[u8]) -> Result<(), CryptoError>
where
    S: AsyncWriteExt + Unpin,
{
    stream.write_all(bytes).await?;
    stream.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn encrypted_round_trip_over_tcp() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let init = tokio::spawn(async move {
            let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            let mut enc = wrap_initiator(stream).await.unwrap();
            enc.write_all(b"hello from initiator").await.unwrap();
            enc.flush().await.unwrap();
            let mut buf = vec![0u8; 64];
            let n = enc.read(&mut buf).await.unwrap();
            buf.truncate(n);
            buf
        });

        let resp = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut enc = wrap_responder(stream).await.unwrap();
            let mut buf = vec![0u8; 64];
            let n = enc.read(&mut buf).await.unwrap();
            buf.truncate(n);
            enc.write_all(b"hello from responder").await.unwrap();
            enc.flush().await.unwrap();
            buf
        });

        let init_read = init.await.unwrap();
        let resp_read = resp.await.unwrap();
        assert_eq!(init_read, b"hello from responder");
        assert_eq!(resp_read, b"hello from initiator");
    }
}
