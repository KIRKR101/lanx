# lanx

Transfer files and directories between machines over a local network. No internet connection, central server, or account required.

Transfers are encrypted, verified with BLAKE3, and can be resumed if interrupted.

## Protocol versioning

The transfer protocol has one active wire version, currently `4`. Sender and
receiver exchange this value in the initial `Hello` messages. A version the
build does not support stops the transfer before the manifest is sent.
The crate version and CLI version identify the release; they do not negotiate
wire compatibility.

The current protocol uses length-prefixed postcard control frames. It streams
the manifest as `ManifestStart`, one `ManifestEntry` per file, and
`ManifestEnd`, then sends file data after `FileStart` and `ChunkHeader`
messages. A protocol change that alters message layout or message order
requires a new `PROTOCOL_VERSION`. To add compatibility later, add the older
version to the supported-version list, negotiate the selected version during
the handshake, and keep its decoder and message rules explicit. Do not accept
an older version without a version-specific implementation.

## Install

```sh
git clone https://github.com/KIRKR101/lanx.git
cd lanx
cargo build --release
```

The binary will be at `target/release/lanx` (`lanx.exe` on Windows). Copy it somewhere on your PATH if you want to use it globally.

Tagged GitHub releases include Linux, macOS, and Windows archives. You can also
install from source with `cargo install --path lanx-cli` or use
`cargo-binstall lanx-cli` when a published package is available.

Generate completions with, for example, `lanx completions zsh > _lanx`.
Run `lanx doctor` to check local interfaces, discovery and sender ports,
permissions, and optionally relay reachability with `--relay HOST:PORT`.

## Usage

On the machine sending the files:

```sh
lanx send ~/Pictures/Wallpapers/
```

lanx will print a pairing code, the address it's listening on, and a
copy-pasteable receiver command (the `--code` is required: the direct
listener verifies it in the encrypted handshake):

```text
code   7-cobalt-fox-tundra  (~28 bits)
direct lanx recv 192.168.1.42:29320 --code 7-cobalt-fox-tundra
```

On the receiving machine:

```sh
lanx recv 7-cobalt-fox-tundra
```

Machines on the same network can find each other automatically, so you normally don't need to enter an IP address. You can also connect directly with the command the sender printed:

```sh
lanx recv 192.168.1.42:29320 --code 7-cobalt-fox-tundra --out ~/Desktop
```

A bare `lanx recv ip:port` without `--code` only works against senders
started with `--allow-insecure-direct` (trusted networks only).

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
| `--bind address` | Bind the sender to one local IPv4 or IPv6 address instead of all interfaces |
| `--exclude PATTERN` | Exclude matching paths; repeatable (`*`, `?`, and `**` are supported) |
| `--include PATTERN` | Include only matching paths; repeatable |
| `--hidden` | Include hidden files and directories |
| `--no-cache` | Disable the local manifest cache |
| `--parallel N` | Transfer using N parallel connections (default: 1) |
| `--relay addr` | Transfer through a relay |
| `--chunk-size bytes` | Set the hashing chunk size (default: 1 MiB) |
| `--code-words N` | Pairing code words, 2-5 (default: 3; use 4+ with relays) |
| `--psk phrase` | Extra passphrase for the handshake (`LANX_PSK` env also works) |
| `--allow-insecure-direct` | Direct-only mode: accept bare `ip:port` receivers without the pairing code; disables discovery (trusted networks only) |

### `lanx recv`

| Flag | Description |
| --- | --- |
| `--out dir` | Output directory (default: `.`) |
| `--accept` | Skip the confirmation prompt |
| `--retry-forever` | Keep retrying after a connection is lost |
| `--discovery-timeout secs` | Network discovery timeout (default: 30 seconds) |
| `--parallel N` | Transfer using N parallel connections |
| `--relay addr` | Transfer through a relay |
| `--psk phrase` | Handshake passphrase, must match sender (`LANX_PSK` env also works) |

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
lanx recv 7-cobalt-fox-tundra --relay 198.51.100.1:53319
```

The relay only forwards traffic; transfers remain encrypted between the sender and receiver.

By default, relay connections use port `53318` for senders and `53319` for receivers. These can be changed with `--sender-bind` and `--receiver-bind`.

Sender registrations are acknowledged: a second sender for the same pairing
ID is rejected (`re-register` by re-running `send` for a fresh code) so an
attacker cannot steal a waiting receiver. Pending senders expire after 5
minutes, and receivers that repeatedly guess wrong IDs are rate-limited
per IP.

## Pairing codes

Pairing codes such as `7-cobalt-fox-tundra` replace manual IP entry. The
broadcast/relayed pairing ID is a *public identifier*; secrecy comes from
a PSK derived from the code and mixed into the `Noise_NNpsk0` handshake —
a peer that does not know the code cannot complete the handshake.

* Default codes are `digit + 3 words` (~28 bits). Use `lanx send
  --code-words 4` (~36 bits) on untrusted networks or with relays.
* For internet relays, additionally set `--psk <passphrase>` (or
  `LANX_PSK` env) on both sides; the passphrase is never transmitted.
* The relay rate-limits failed guesses per IP and rejects sender
  takeover, but a public relay still sees *which* pairing IDs are active.
  `lanx` warns when `--relay` points at a non-LAN address.
* Direct `ip:port` transfers also verify the code by default — paste the
  full command the sender printed (it includes `--code`). Bare `ip:port`
  without a code requires the sender to opt into `--allow-insecure-direct`
  and stays unauthenticated: prefer pairing codes on untrusted networks.
* `--allow-insecure-direct` disables code discovery and prints bare direct
  commands only. It cannot be combined with `--relay`.
* For a direct `ip:port --code` target, retries stay pinned to that explicit
  address; discovery is only re-run for pairing-code targets.
* An empty `--psk ""` is treated as unset. Use a non-empty passphrase when
  adding an out-of-band secret.

Relay operators should deploy the sender and receiver services in lock-step:
the current sender registration protocol adds one acknowledgement byte after
the sender hello, so mixed old/new relay peers are not wire-compatible.
Pending sender IDs can remain occupied for up to 5 minutes after a crashed
sender; codes are fresh-random each run, so this is an availability cost, not
code reuse.

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
