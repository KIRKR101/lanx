use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::time::Duration;
use tracing_subscriber::EnvFilter;

mod cmd;
mod iface;
mod json_progress;
mod progress;
mod ui;

#[derive(Parser, Debug)]
#[command(name = "lanx", about = "LAN file transfer", version)]
struct Cli {
    /// Increase log detail (-v for info, -vv for debug). Without it,
    /// only errors are shown; progress stays quiet.
    #[arg(long, short, global = true, action = clap::ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Send one or more files/directories.
    Send {
        /// Files or directories to send.
        ///
        /// Names must be valid UTF-8 and portable across Windows, macOS,
        /// and Linux: Windows-reserved device names (CON, PRN, AUX, NUL,
        /// COM1-9, LPT1-9), reserved characters (<>:"|?*), trailing
        /// spaces/dots, and case-insensitive collisions (Report.txt vs
        /// report.txt) abort the whole send with an error instead of
        /// being skipped or renamed.
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
        /// Port to listen on (default: stable 29320; falls back to an
        /// ephemeral port if busy; explicit values fail if taken).
        #[arg(long)]
        port: Option<u16>,
        /// Local IPv4 or IPv6 address to bind. Defaults to all interfaces.
        #[arg(long)]
        bind: Option<String>,
        /// Exclude files matching a path pattern. Repeatable.
        #[arg(long = "exclude", value_name = "PATTERN")]
        exclude: Vec<String>,
        /// Include only files matching a path pattern. Repeatable.
        #[arg(long = "include", value_name = "PATTERN")]
        include: Vec<String>,
        /// Include hidden files and directories (included by default when no filters are set).
        #[arg(long)]
        hidden: bool,
        /// Disable the on-disk manifest cache.
        #[arg(long)]
        no_cache: bool,
        /// Number of parallel TCP connections to use.
        #[arg(long, default_value_t = 1)]
        parallel: u16,
        /// Connect to a relay server instead of listening directly.
        /// The argument is the relay's sender-bind address (e.g. "192.168.1.100:53318").
        #[arg(long)]
        relay: Option<String>,
        /// Number of words in the pairing code (2-5, default 3).
        /// More words = more entropy against guessing (~8.2 bits each);
        /// use 4+ with public relays.
        #[arg(long, default_value_t = 3, value_parser = clap::value_parser!(u8).range(2..=5))]
        code_words: u8,
        /// Extra passphrase strengthening the Noise handshake PSK.
        /// Also read from the `LANX_PSK` env var when unset. The relay
        /// and network never see it; both sides must match.
        #[arg(long)]
        psk: Option<String>,
        /// Accept direct `ip:port` receivers without the pairing code
        /// (unauthenticated `Noise_NN`). This disables code discovery and
        /// is only valid for direct transfers on trusted networks.
        #[arg(long)]
        allow_insecure_direct: bool,
    },
    /// Receive files.
    Recv {
        /// Pairing code (e.g. "7-cobalt-fox-tundra") or ip:port.
        target: String,
        /// Pairing code for `ip:port` targets. Discovery-code and relay
        /// targets already carry the code, so `--code` with those is an
        /// error. A bare `ip:port` without `--code` connects
        /// unauthenticated (and fails against senders that did not pass
        /// `--allow-insecure-direct`).
        #[arg(long)]
        code: Option<String>,
        /// Output directory or file (see README for resolution rules).
        #[arg(long, default_value = ".")]
        out: PathBuf,
        /// Accept the incoming transfer automatically without prompting.
        /// `--yes` is an alias, so scripts can use either spelling.
        #[arg(long, visible_alias = "yes")]
        accept: bool,
        /// Overwrite existing destination files instead of resuming them.
        #[arg(long, conflicts_with_all = ["skip_existing", "rename_existing", "on_conflict"])]
        overwrite: bool,
        /// Skip files whose destination already exists, leaving them untouched.
        #[arg(long, conflicts_with_all = ["overwrite", "rename_existing", "on_conflict"])]
        skip_existing: bool,
        /// Keep existing files; write incoming files to numbered siblings
        /// (`photo.jpg` becomes `photo.1.jpg`).
        #[arg(long, conflicts_with_all = ["overwrite", "skip_existing", "on_conflict"])]
        rename_existing: bool,
        /// Show what would be received without writing any files.
        #[arg(long)]
        dry_run: bool,
        /// Emit machine-readable JSON Lines events on stdout (see
        /// `json_progress` for the schema) instead of human progress.
        /// Stdout carries events only; warnings and errors go to stderr.
        #[arg(long)]
        json: bool,
        /// Suppress informational output; warnings and errors still print.
        #[arg(long)]
        quiet: bool,
        /// Conflict behavior for automation: skip, overwrite, or fail when
        /// a destination file already exists. Mutually exclusive with the
        /// granular `--overwrite` / `--skip-existing` / `--rename-existing`
        /// flags.
        #[arg(long, value_enum, conflicts_with_all = ["overwrite", "skip_existing", "rename_existing"])]
        on_conflict: Option<cmd::recv::OnConflict>,
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
        /// Extra passphrase strengthening the Noise handshake PSK.
        /// Also read from the `LANX_PSK` env var when unset. Must match
        /// the sender's value.
        #[arg(long)]
        psk: Option<String>,
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
    let cli = Cli::parse();
    // Quiet by default: internal tracing (handshake chatter, retry
    // notes, pump errors) stays hidden unless asked for. `RUST_LOG`
    // still wins when set explicitly.
    let noisy = cli.verbose > 0 || std::env::var("RUST_LOG").is_ok();
    let filter = match std::env::var("RUST_LOG") {
        Ok(v) if !v.is_empty() => EnvFilter::new(v),
        _ => {
            let level = match cli.verbose {
                0 => "error",
                1 => "info",
                _ => "debug",
            };
            EnvFilter::new(format!("lanx={level},lanx_core={level},lanx_net={level}"))
        }
    };
    let fmt = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false);
    if noisy {
        let _ = fmt.try_init();
    } else {
        let _ = fmt.without_time().try_init();
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build tokio runtime")?;
    let verbose = cli.verbose > 0;
    runtime.block_on(async move {
        match cli.command {
            Command::Send {
                paths,
                chunk_size,
                no_discovery,
                zip,
                port,
                bind,
                exclude,
                include,
                hidden,
                no_cache,
                parallel,
                relay,
                code_words,
                psk,
                allow_insecure_direct,
            } => {
                cmd::send::run(
                    paths,
                    chunk_size,
                    no_discovery,
                    zip,
                    port,
                    bind,
                    exclude,
                    include,
                    hidden,
                    no_cache,
                    parallel,
                    relay,
                    verbose,
                    code_words,
                    psk,
                    allow_insecure_direct,
                )
                .await
            }
            Command::Recv {
                target,
                code,
                out,
                accept,
                overwrite,
                skip_existing,
                rename_existing,
                dry_run,
                json,
                quiet,
                on_conflict,
                retry_forever,
                discovery_timeout,
                parallel,
                relay,
                psk,
            } => {
                cmd::recv::run(cmd::recv::RecvOptions {
                    target,
                    code,
                    out,
                    accept,
                    overwrite,
                    skip_existing,
                    rename_existing,
                    dry_run,
                    json,
                    quiet,
                    on_conflict,
                    retry_forever,
                    discovery_timeout: Duration::from_secs(discovery_timeout),
                    parallel,
                    relay,
                    psk,
                })
                .await
            }
            Command::Relay {
                sender_bind,
                receiver_bind,
            } => cmd::relay::run(sender_bind, receiver_bind).await,
        }
    })
}
