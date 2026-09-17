# lanx

Transfer files and directories between machines over a local network. lanx
needs no account, central server, or internet connection for direct transfers.
Transfers use an encrypted connection, verify file contents with BLAKE3, and
resume after an interruption.

## Install

Build from source with Rust 1.85 or later:

```sh
git clone https://github.com/KIRKR101/lanx.git
cd lanx
cargo build --release
```

The binary is `target/release/lanx`, or `lanx.exe` on Windows. Install it on
your PATH if you want to run `lanx` from any directory:

```sh
cargo install --path lanx-cli
```

Tagged releases include Linux, macOS, and Windows archives. You can also use
`cargo-binstall lanx-cli` when a published package is available.

## Quick start

Run this command on the sending machine:

```sh
lanx send ~/Pictures/Wallpapers/
```

Disable the UDP lookup when you plan to use the direct command only:

```sh
lanx send ~/Pictures/Wallpapers/ --no-discovery
```

lanx prints a pairing code, the address it is listening on, and a direct
receiver command:

```text
code   7-cobalt-fox-tundra  (~28 bits)
direct lanx recv 192.168.1.42:29320 --code 7-cobalt-fox-tundra
```

Run this command on the receiving machine:

```sh
lanx recv 7-cobalt-fox-tundra
```

lanx discovers the sender over UDP when both machines share a network. You can
also paste the direct command printed by the sender:

```sh
lanx recv 192.168.1.42:29320 --code 7-cobalt-fox-tundra --out ~/Desktop
```

The receiver previews the incoming files and asks for confirmation before it
writes anything. Use `--accept` or its alias `--yes` to skip that prompt.

## Sending

Send several files and directories in one transfer. Directory names stay in
the destination structure:

```sh
lanx send report.pdf photos/ project/
```

Use `--zip` when one archive is more useful than the original directory tree.
The flag accepts one input path:

```sh
lanx send ~/Documents/project --zip
```

Select files with repeatable include and exclude patterns. Quote patterns so
your shell does not expand them before lanx sees them:

```sh
lanx send ~/src/project \
  --include '*.rs' \
  --include 'Cargo.toml' \
  --exclude 'target/**'
```

`*` matches within one path component, `?` matches one character, and `**`
matches across directories. A pattern without `/` also matches a component at
any depth:

```sh
lanx send ~/src/project --exclude 'node_modules' --exclude '*.log'
```

Hidden files and directories are excluded by default. Include them explicitly:

```sh
lanx send ~/src/project --hidden
```

Bind the sender to one local interface when the machine has several network
addresses:

```sh
lanx send ~/photos --bind 192.168.1.42
```

With no explicit port, lanx tries stable port `29320` and falls back to an
ephemeral port if another process already uses it. Pin a port when a firewall
rule or router rule depends on it:

```sh
lanx send ~/photos --bind 192.168.1.42 --port 51234
```

Use an IPv6 address when both machines connect over IPv6:

```sh
lanx send ~/photos --bind 2001:db8::42 --port 29320
lanx recv '[2001:db8::42]:29320' --code 7-cobalt-fox-tundra
```

The default manifest cache avoids hashing unchanged inputs on later sends. Use
`--no-cache` when another process changes files without reliable timestamps:

```sh
lanx send ~/build-output --no-cache
```

Use more than one connection for large transfers with many files:

```sh
lanx send ~/photos --parallel 4
```

Set the chunk size when you need a different hashing and resume granularity:

```sh
lanx send ~/photos --chunk-size 4194304
```

The sender and receiver negotiate down if they request different parallel
connection counts.

## Receiving

Choose the destination with `--out`. For a directory transfer, lanx preserves
the sender's directory structure:

```sh
lanx recv 7-cobalt-fox-tundra --out ~/Incoming
```

Accept an unattended transfer from a script:

```sh
lanx recv 7-cobalt-fox-tundra --accept --out ~/Incoming
```

By default, lanx resumes partial files and skips files that already match.
Choose another policy when existing files need explicit treatment:

```sh
# Leave every existing destination untouched.
lanx recv 7-cobalt-fox-tundra --skip-existing --accept --out ~/Incoming

# Replace existing files from byte zero.
lanx recv 7-cobalt-fox-tundra --overwrite --accept --out ~/Incoming

# Keep existing files and write photo.1.jpg, photo.2.jpg, and so on.
lanx recv 7-cobalt-fox-tundra --rename-existing --accept --out ~/Incoming
```

Use `--on-conflict` when a script should state its policy as a value. It accepts
`skip`, `overwrite`, or `fail`:

```sh
lanx recv 7-cobalt-fox-tundra \
  --on-conflict fail \
  --accept \
  --out ~/Incoming
```

The `fail` policy checks for conflicts before creating destination directories
or writing files.

Preview a transfer without writing files:

```sh
lanx recv 7-cobalt-fox-tundra --dry-run --out ~/Incoming
```

The preview includes the file list, total size, and existing, complete,
resumable, and new destination counts.

Use `--parallel` on the receiver as well when the sender supports parallel
connections:

```sh
lanx recv 7-cobalt-fox-tundra --parallel 4 --accept --out ~/Incoming
```

For a direct address, pass the pairing code with `--code`:

```sh
lanx recv 192.168.1.42:29320 --code 7-cobalt-fox-tundra --accept
```

Allow more time for discovery on a busy or filtered network:

```sh
lanx recv 7-cobalt-fox-tundra --discovery-timeout 90
```

Retry until the sender comes back online:

```sh
lanx recv 7-cobalt-fox-tundra --retry-forever --out ~/Incoming
```

## Automation

`--json` writes one JSON object per line to stdout. Informational messages,
warnings, and errors stay on stderr. Once lanx receives a manifest, the final
JSON event is a `summary` event:

```sh
lanx recv 7-cobalt-fox-tundra \
  --json \
  --accept \
  --on-conflict skip \
  --out ~/Incoming > transfer.jsonl
```

Inspect the final result with any JSON tool:

```sh
tail -n 1 transfer.jsonl
```

Use `--quiet` for a human-readable command that prints only warnings and
errors:

```sh
lanx recv 7-cobalt-fox-tundra --quiet --accept --out ~/Incoming
```

## Pairing and security

Pairing codes such as `7-cobalt-fox-tundra` identify a transfer. The code also
derives the PSK used by the encrypted handshake, so a peer that does not know
the full code cannot complete a code-based transfer.

Generate a longer code for an untrusted network or a relay:

```sh
lanx send ~/photos --code-words 4
```

Add a passphrase when the code needs an extra secret. Set it on both machines:

```sh
lanx send ~/photos --psk 'correct horse battery staple'
lanx recv 7-cobalt-fox-tundra --psk 'correct horse battery staple'
```

The same setting works through the `LANX_PSK` environment variable:

```sh
export LANX_PSK='correct horse battery staple'
lanx send ~/photos
lanx recv 7-cobalt-fox-tundra --accept
```

An empty passphrase is treated as unset. Use a non-empty passphrase when you
need the additional secret.

Direct `ip:port` connections still use the pairing code when you pass
`--code`. A bare address is unauthenticated and works only when the sender
explicitly enables trusted-network mode:

```sh
# Sender, direct mode without a pairing code.
lanx send ~/photos --allow-insecure-direct

# Receiver, using the bare address printed by the sender.
lanx recv 192.168.1.42:29320 --accept --out ~/Incoming
```

`--allow-insecure-direct` disables discovery and cannot be combined with
`--relay`. Use pairing codes on networks where another user might inspect or
alter traffic.

## Relays

Run a relay on a machine reachable by both endpoints when direct connections
are blocked:

```sh
lanx relay
```

The relay uses `53318` for sender connections and `53319` for receiver
connections. Start both clients with the matching relay listener addresses:

```sh
lanx send ~/photos --relay 198.51.100.1:53318
lanx recv 7-cobalt-fox-tundra --relay 198.51.100.1:53319 --accept
```

The relay forwards encrypted bytes and does not receive the transfer PSK or
file contents. It does see the public pairing ID needed to match the two
connections.

Set different listener addresses when the relay has more than one interface:

```sh
lanx relay \
  --sender-bind 192.0.2.10:53318 \
  --receiver-bind 192.0.2.10:53319
```

Limit active transfers and disconnect sessions that stop making progress:

```sh
lanx relay --max-sessions 64 --idle-timeout 900
```

Require clients to authenticate with a shared relay token. The relay sends a
fresh challenge, and each client sends a proof bound to that challenge and its
pairing ID. The token itself never crosses the network:

```sh
export LANX_RELAY_AUTH_TOKEN='relay-only-secret'
lanx relay --auth-token "$LANX_RELAY_AUTH_TOKEN" --metrics
```

Run the clients with the same environment variable:

```sh
export LANX_RELAY_AUTH_TOKEN='relay-only-secret'
lanx send ~/photos --relay 198.51.100.1:53318
lanx recv 7-cobalt-fox-tundra --relay 198.51.100.1:53319 --accept
```

Use `--metrics` to log pending and active session counts, and choose a relay
log level with `--log-level`:

```sh
lanx relay --metrics --log-level debug
```

Pending sender registrations expire after five minutes. A second sender using
the same pairing ID is rejected, and repeated wrong receiver guesses from one
IP address are rate-limited.

## Diagnostics and completions

Check interfaces, sender ports, discovery, permissions, and relay reachability:

```sh
lanx doctor
lanx doctor --port 51234 --relay 198.51.100.1:53318
```

Generate completion files for your shell:

```sh
lanx completions bash > lanx.bash
lanx completions zsh > _lanx
lanx completions fish > lanx.fish
```

Install the generated file using your shell's normal completion setup.

## Firewalls

Direct discovery needs UDP `53317` on the receiver. Direct transfers need the
sender's TCP port, which defaults to `29320`:

```sh
sudo ufw allow 53317/udp
sudo ufw allow 29320/tcp
```

If the sender uses another pinned port, open that port instead:

```sh
lanx send ~/photos --port 51234
sudo ufw allow 51234/tcp
```

When the default port is busy, lanx prints the selected ephemeral port and the
firewall command for that run. Direct addresses skip UDP discovery but still
need the sender's TCP port. A relay needs its sender and receiver listener
ports open instead.

## Protocol compatibility

The current wire protocol version is `4`. Sender and receiver exchange the
version in their first messages and stop before sending a manifest when the
peer does not support it.

The protocol uses length-prefixed postcard control frames. It streams a
manifest between `ManifestStart` and `ManifestEnd`, then sends file data using
`FileStart` and `ChunkHeader` messages. Sender, receiver, and relay builds
should come from the same release when using relay registration, because relay
registration includes a challenge and a sender acknowledgement.

## Tests

Run the workspace tests and static checks:

```sh
cargo test --workspace --all-features
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

## Licence

MIT. See [LICENSE](LICENSE).
