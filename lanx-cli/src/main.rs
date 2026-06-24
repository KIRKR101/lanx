use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::time::Duration;
use tracing_subscriber::EnvFilter;

mod cmd;
mod iface;
mod progress;
mod ui;

#[derive(Parser, Debug)]
#[command(name = "lanx", about = "LAN file transfer", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Send one or more files/directories.
    Send {
        /// Files or directories to send.
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        /// Chunk size in bytes (default 1 MiB).
        #[arg(long, default_value_t = lanx_core::manifest::DEFAULT_CHUNK_SIZE)]
        chunk_size: u32,
        /// Disable UDP-broadcast discovery; print only the explicit address.
        #[arg(long)]
        no_discovery: bool,
        /// Package the input into a single zip archive before sending.
        /// Only valid with a single input path. Without this flag,
        /// directories are sent natively and the receiver reconstructs
        /// the folder structure.
        #[arg(long)]
        zip: bool,
        /// Port to listen on (default: random ephemeral port).
        #[arg(long)]
        port: Option<u16>,
        /// Number of parallel TCP connections to use.
        #[arg(long, default_value_t = 1)]
        parallel: u16,
        /// Connect to a relay server instead of listening directly.
        /// The argument is the relay's sender-bind address (e.g. "192.168.1.100:53318").
        #[arg(long)]
        relay: Option<String>,
    },
    /// Receive files.
    Recv {
        /// Pairing code (e.g. "7-cobalt-fox") or ip:port.
        target: String,
        /// Output directory or file (see README for resolution rules).
        #[arg(long, default_value = ".")]
        out: PathBuf,
        /// Accept the incoming transfer automatically without prompting.
        #[arg(long)]
        accept: bool,
        /// Retry forever on connection drop.
        #[arg(long)]
        retry_forever: bool,
        /// Discovery timeout in seconds.
        #[arg(long, default_value_t = 30)]
        discovery_timeout: u64,
        /// Number of parallel TCP connections to use.
        #[arg(long, default_value_t = 1)]
        parallel: u16,
        /// Connect through a relay server instead of direct connection.
        /// The argument is the relay's receiver-bind address (e.g. "192.168.1.100:53319").
        #[arg(long)]
        relay: Option<String>,
    },
    /// Run a relay server that bridges sender and receiver connections.
    Relay {
        /// Address to listen on for sender connections.
        #[arg(long, default_value = "0.0.0.0:53318")]
        sender_bind: String,
        /// Address to listen on for receiver connections.
        #[arg(long, default_value = "0.0.0.0:53319")]
        receiver_bind: String,
    },
}

fn main() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .try_init();

    let cli = Cli::parse();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build tokio runtime")?;
    runtime.block_on(async move {
        match cli.command {
            Command::Send {
                paths,
                chunk_size,
                no_discovery,
                zip,
                port,
                parallel,
                relay,
            } => cmd::send::run(paths, chunk_size, no_discovery, zip, port, parallel, relay).await,
            Command::Recv {
                target,
                out,
                accept,
                retry_forever,
                discovery_timeout,
                parallel,
                relay,
            } => {
                cmd::recv::run(
                    target,
                    out,
                    accept,
                    retry_forever,
                    Duration::from_secs(discovery_timeout),
                    parallel,
                    relay,
                )
                .await
            }
            Command::Relay {
                sender_bind,
                receiver_bind,
            } => cmd::relay::run(sender_bind, receiver_bind).await,
        }
    })
}
