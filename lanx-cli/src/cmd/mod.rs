pub mod recv;
pub mod relay;
pub mod send;

/// Validate that parallel > 1 is not used with --relay.
pub fn validate_parallel_relay(parallel: u16, relay: &Option<String>) -> anyhow::Result<()> {
    if relay.is_some() && parallel > 1 {
        anyhow::bail!("--parallel > 1 is not supported with --relay");
    }
    Ok(())
}
