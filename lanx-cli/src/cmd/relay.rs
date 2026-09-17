//! `lanx relay`: a simple TURN-like server that pairs sender and receiver
//! TCP connections by a shared pairing-code hash.
//!
//! The relay does not interpret the lanx protocol; it only forwards bytes
//! between the two sockets once they are paired. Both sides still run the
//! Noise handshake and the normal transfer state machine over the relayed
//! stream.

use anyhow::{Context, Result};
use lanx_net::relay::{RelayConfig, RelayServer, DEFAULT_IDLE_TIMEOUT};

pub async fn run(
    sender_bind: String,
    receiver_bind: String,
    max_sessions: usize,
    idle_timeout: u64,
    auth_token: Option<String>,
    metrics: bool,
) -> Result<()> {
    let idle_timeout = if idle_timeout == 0 {
        DEFAULT_IDLE_TIMEOUT
    } else {
        std::time::Duration::from_secs(idle_timeout)
    };
    let server = RelayServer::new_with_config(
        sender_bind,
        receiver_bind,
        RelayConfig {
            max_sessions,
            idle_timeout,
            auth_token: auth_token.or_else(crate::cmd::relay_auth_token),
            metrics,
        },
    )
        .await
        .context("create relay server")?;
    server.run().await.context("run relay server")?;
    Ok(())
}
