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

lanx will print a pairing code, the address it's listening on, and a
copy-pasteable receiver command:

```text
code   7-cobalt-fox
listen 192.168.1.42:29320
recv   lanx recv 192.168.1.42:29320
```

On the receiving machine:

```sh
lanx recv 7-cobalt-fox
```

Machines on the same network can find each other automatically, so you normally don't need to enter an IP address. You can also connect directly:

```sh
lanx recv 192.168.1.42:29320 --out ~/Desktop
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
| `--port N` | Listen on port N (default: stable 29320; falls back to ephemeral if busy; explicit values fail if taken) |
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

## Firewalls

If the machines cannot see each other, open two ports. The receiver
needs UDP `53317` in and the sender needs TCP `29320` in:

```sh
# receiver
sudo ufw allow 53317/udp
# sender
sudo ufw allow 29320/tcp
```

Check the rules with `sudo ufw status verbose`. Outbound needs no
change on a default `ufw` setup.

To use another sender port, pin it and allow it:

```sh
# sender
lanx send ~/photos/ --port 51234
sudo ufw allow 51234/tcp
```

If port `29320` is busy the sender picks another port and prints a
`!` warning with the exact `ufw allow` line for that run. Either run
that command or free `29320` and retry.

Other firewalls: `firewalld` needs `53317/udp` on the receiver and
`29320/tcp` on the sender; on macOS and Windows allow the same two
ports in through the system firewall prompt or settings.

Pairing codes time out when UDP `53317` is blocked. A connect timeout
after the sender is found means TCP on the sender is blocked. Direct
`ip:port` skips discovery but still needs the sender TCP rule. When
inbound stays blocked on both sides, use a relay instead.

## Tests

```sh
cargo test
```

## Licence

MIT. See [LICENSE](LICENSE).
