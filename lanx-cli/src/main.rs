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
    },
    /// Receive files.
    Recv {
        /// Pairing code (e.g. "7-cobalt-fox") or ip:port.
        target: String,
        /// Output directory or file (see README for resolution rules).
        #[arg(long, default_value = ".")]
        out: PathBuf,
        /// Retry forever on connection drop.
        #[arg(long)]
        retry_forever: bool,
        /// Discovery timeout in seconds.
        #[arg(long, default_value_t = 30)]
        discovery_timeout: u64,
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
            } => cmd::send::run(paths, chunk_size, no_discovery, zip, port).await,
            Command::Recv {
                target,
                out,
                retry_forever,
                discovery_timeout,
            } => {
                cmd::recv::run(
                    target,
                    out,
                    retry_forever,
                    Duration::from_secs(discovery_timeout),
                )
                .await
            }
        }
    })
}
