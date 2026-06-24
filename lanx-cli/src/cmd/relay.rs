//! `lanx relay`: a simple TURN-like server that pairs sender and receiver
//! TCP connections by a shared pairing-code hash.
//!
//! The relay does not interpret the lanx protocol; it only forwards bytes
//! between the two sockets once they are paired. Both sides still run the
//! Noise handshake and the normal transfer state machine over the relayed
//! stream.

use anyhow::{Context, Result};
use lanx_net::relay::RelayServer;

pub async fn run(sender_bind: String, receiver_bind: String) -> Result<()> {
    let server = RelayServer::new(sender_bind, receiver_bind)
        .await
        .context("create relay server")?;
    server.run().await.context("run relay server")?;
    Ok(())
}
