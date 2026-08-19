# lanx

Transfer files and directories between machines over a local network. No internet connection, central server, or account required.

Transfers are encrypted, verified with BLAKE3, and can be resumed if interrupted.

## Install

```sh
git clone https://github.com/KIRKR101/lanx.git
cd lanx
cargo build --release
```

The binary will be at `target/release/lanx` (`lanx.exe` on Windows). Copy it somewhere on your PATH if you want to use it globally.

## Usage

On the machine sending the files:

```sh
lanx send ~/Pictures/Wallpapers/
```

lanx will print a pairing code and the address it's listening on:

```text
code   7-cobalt-fox
listen 192.168.1.42:51234
```

On the receiving machine:

```sh
lanx recv 7-cobalt-fox
```

Machines on the same network can find each other automatically, so you normally don't need to enter an IP address. You can also connect directly:

```sh
lanx recv 192.168.1.42:51234 --out ~/Desktop
```

Before starting, lanx shows the incoming files and asks for confirmation. Use `--accept` to skip this.

Directories keep their structure, and multiple files or directories can be sent at once:

```sh
lanx send file.txt photos/ project/
```

Use `--zip` to send the input as a single archive instead.

## Options

### `lanx send`

| Flag | Description |
| --- | --- |
| `--no-discovery` | Disable automatic network discovery |
| `--zip` | Send the input as a single archive |
| `--parallel N` | Transfer using N parallel connections (default: 1) |
| `--relay addr` | Transfer through a relay |
| `--chunk-size bytes` | Set the hashing chunk size (default: 1 MiB) |

### `lanx recv`

| Flag | Description |
| --- | --- |
| `--out dir` | Output directory (default: `.`) |
| `--accept` | Skip the confirmation prompt |
| `--retry-forever` | Keep retrying after a connection is lost |
| `--discovery-timeout secs` | Network discovery timeout (default: 30 seconds) |
| `--parallel N` | Transfer using N parallel connections |
| `--relay addr` | Transfer through a relay |

## Resuming transfers

Interrupted transfers can be resumed by reconnecting to the same sender. Files that have already been transferred are skipped, while incomplete files continue from the missing data.

Use `--retry-forever` if you want lanx to keep trying until the connection is restored.

## Relays

If the machines can't connect directly, you can run a relay on a machine accessible to both:

```sh
lanx relay
```

Then pass its address to the sender and receiver:

```sh
lanx send ~/photos/ --relay 198.51.100.1:53318
lanx recv 7-cobalt-fox --relay 198.51.100.1:53319
```

The relay only forwards traffic; transfers remain encrypted between the sender and receiver.

By default, relay connections use port `53318` for senders and `53319` for receivers. These can be changed with `--sender-bind` and `--receiver-bind`.

## Pairing codes

Pairing codes such as `7-cobalt-fox` make it easier to connect to another machine without entering its IP address. The code is used for discovery, not as a password. Transfers themselves are protected by a Noise-encrypted connection.

## Tests

```sh
cargo test
```

## Licence

MIT. See [LICENSE](LICENSE).
