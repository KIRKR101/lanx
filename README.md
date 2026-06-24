# lanx — LAN File Transfer

**lanx** transfers files and directories between machines on the same local
network. No internet connection, no central server, no accounts. Sender acts as
a TCP listener; receiver connects and pulls. Resumable transfers, BLAKE3-based
integrity verification, pairwise human-readable codes for discovery.

## Installation

Requires Rust 1.85 or later.

```sh
git clone https://github.com/user/lanx.git
cd lanx
cargo build --release
```

The binary lands at `target/release/lanx` (or `lanx.exe` on Windows). Copy it
anywhere on your `PATH`.

## Quick Start

**Sender** (machine A):
```sh
lanx send ~/photos/  ~/documents/report.pdf
```

**Receiver** (machine B):
```sh
lanx recv 7-cobalt-fox
```

The receiver gets an exact copy of every file, verified by BLAKE3 hash.

## How It Works

```
┌────────────┐                      ┌────────────┐
│   Sender   │  TCP listen :PORT    │  Receiver  │
│  (server)  │ <─────────────────── │  (client)  │
└────────────┘    connects, pulls    └────────────┘
```

1. **Sender** builds a manifest by walking its input files/directories and
   computing per-chunk BLAKE3 hashes.
2. **Sender** picks a random free port, generates a pairing code (e.g.
   `7-cobalt-fox`), and optionally broadcasts it over UDP.
3. **Receiver** connects via code (automatic discovery) or explicit `ip:port`.
4. Both sides handshake with protocol version and agree on a parallel
   connection count, then the sender streams the manifest entry-by-entry.
5. **Receiver** reviews the manifest and accepts or declines it. Use
   `--accept` to skip the prompt.
6. **Receiver** checks its destination directory for partial files. If a file
   exists, it re-hashes the existing chunks and sends the sender a resume
   offset for each file. Fully-matching files are skipped. A `.lanx-partial.json`
   sidecar caches the verified chunk count to skip re-hashing on the next run.
7. **Sender** streams each accepted file chunk-by-chunk. **Receiver** writes
   to disk while incrementally re-hashing.
8. After each file, receiver verifies the whole-file BLAKE3 hash against the
   sender's hash. On mismatch the receiver identifies the corrupt chunks and
   asks the sender to re-send only those ranges.
9. Sender sends `Done`, both sides report the final tally.

## Commands

### `lanx send`

```
lanx send <PATHS>... [FLAGS]
```

| Flag | Default | Description |
|---|---|---|
| `<PATHS>...` | (required) | One or more files or directories to send |
| `--chunk-size <BYTES>` | `1048576` (1 MiB) | Chunk size in bytes |
| `--no-discovery` | off | Disable UDP-broadcast discovery; print only the explicit address |
| `--zip` | off | Package a single input path into a `.zip` archive before sending |
| `--parallel <N>` | `1` | Number of parallel TCP connections to use |
| `--relay <ADDR>` | (none) | Connect to a relay server instead of listening directly. The argument is the relay's sender-bind address (e.g. `192.168.1.100:53318`) |

Sender picks a random port, generates a code, and prints both:

```
lanx · send
  ✓ hashed 3 files (1.2 GiB total)

  code   7-cobalt-fox
  listen 192.168.1.42:51234
         127.0.0.1:51234 (loopback)
```

Then waits for a receiver (60-second grace period). Transfers proceed once a
receiver connects.

#### What happens to directories

By default, `lanx send` walks every directory it is given and transmits the
full folder structure. The receiver reconstructs the same tree under its
`--out` directory. For example, `lanx send myrepo/` produces files like
`myrepo/src/main.rs` → `src/main.rs` on the receiver.

#### `--zip`

When `--zip` is passed, lanx packages the single input path into a `.zip`
archive in a temp directory and transmits that archive as a single file. This
is useful when you want a single received artifact rather than a reconstructed
directory tree. Only valid with exactly one input path.

### `lanx recv`

```
lanx recv <TARGET> [FLAGS]
```

| Flag | Default | Description |
|---|---|---|
| `<TARGET>` | (required) | Pairing code (e.g. `7-cobalt-fox`) or `ip:port` |
| `--out <DIR>` | `.` | Output directory or file |
| `--accept` | off | Accept the incoming transfer automatically without prompting |
| `--retry-forever` | off | Keep retrying on connection drop indefinitely (default: 5 attempts) |
| `--discovery-timeout <SECS>` | `30` | Discovery timeout in seconds |
| `--parallel <N>` | `1` | Number of parallel TCP connections to use |
| `--relay <ADDR>` | (none) | Connect through a relay server instead of direct connection. The argument is the relay's receiver-bind address (e.g. `192.168.1.100:53319`) |

Receiver output (interactive):

```text
lanx · recv
  ✓ sender 192.168.1.42:51234
  ? Incoming transfer from 192.168.1.42:51234:
    17 files, 36.2 MiB, destination: .
    1.2 KiB  myrepo/readme.txt
    5.34 MiB myrepo/file.jpg
    ... and 15 more

    Accept? [y/N]: y
  Receiving folder `myrepo` (17 files, 36.2 MiB)
  [ 1/17]  file.jpg   5.34 MiB / 5.34 MiB  100% ✓
  [ 2/17]  data.csv   1.00 MiB / 2.50 MiB   40% ▕████▏    3.21 MiB/s
  [ 3/17]  readme.txt                   · skipped (already present)
  ...
  ✓ Done — 17 verified, 0 failed, 3 skipped  (36.2 MiB / 36.2 MiB)
```

#### Target resolution

- **Pairing code** (e.g. `7-cobalt-fox`): receiver listens for UDP broadcast
  announcements on port 53317, identifies the sender by code hash, and
  connects to the discovered address.
- **Direct address** (e.g. `192.168.1.42:51234`): connects immediately, no
  discovery needed.

#### `--out` resolution

| Manifest | `--out` points to | Behavior |
|---|---|---|
| Single file | Existing file | Overwrites that file |
| Single file | Existing directory | Creates `<out>/<filename>` |
| Single file | Missing path | Treated as filename; parent dirs created |
| Single file | Path ending in `/` | Treated as directory; `<out>/<filename>` created |
| Multiple files | Directory (existing or new) | Files placed inside, directory structures preserved |
| Multiple files | Existing file | **Error** — cannot place multiple files into a single file |

#### Retry behavior

On connection drop the receiver retries with exponential backoff: 1s, 2s, 4s,
8s (capped at 8s). Defaults to 5 attempts. Resume continues from the correct
offset via chunk-hash comparison on re-handshake.

Pass `--retry-forever` for unlimited retries.

### `lanx relay`

```
lanx relay [FLAGS]
```

| Flag | Default | Description |
|---|---|---|
| `--sender-bind <ADDR>` | `0.0.0.0:53318` | Address to listen on for sender connections |
| `--receiver-bind <ADDR>` | `0.0.0.0:53319` | Address to listen on for receiver connections |

The relay server bridges sender and receiver connections when they cannot
communicate directly (e.g. different networks, NAT). Both sender and receiver
connect to the relay, which pairs them by the BLAKE3 hash of the pairing code
and forwards bytes bidirectionally.

**Example usage:**

1. Start the relay on a public server:
   ```sh
   lanx relay --sender-bind 0.0.0.0:53318 --receiver-bind 0.0.0.0:53319
   ```

2. Sender connects through the relay:
   ```sh
   lanx send ~/photos/ --relay 198.51.100.1:53318
   ```

3. Receiver connects through the relay:
   ```sh
   lanx recv 7-cobalt-fox --relay 198.51.100.1:53319
   ```

The relay does not interpret the lanx protocol; it only forwards bytes between
the two sockets once paired. Both sides still run the Noise handshake and the
normal transfer state machine over the relayed stream.

## Resume & Integrity

- **Sender pre-computes BLAKE3 hashes for every chunk** of every file before
  transfer begins. This is the core enabler for resume.
- **On reconnect**, receiver re-hashes the partial file on disk and compares
  against the manifest's chunk hashes. The first mismatching chunk marks the
  resume offset. Only unverified bytes are re-transferred.
- **Whole-file hash verification** after each file. Both sides incrementally
  hash during transfer; receiver's final hash must match sender's. On mismatch
  the file is re-transferred from scratch.
- **Skip detection**: if the receiver already has a byte-identical file (all
  chunk hashes match), zero bytes are transferred.
- **Corrupt chunk detection**: if a file on disk has a corrupt middle chunk,
  only the corrupt portion is re-fetched, not the entire file.
- **Sidecar cache**: a `.lanx-partial.json` file per destination records the
  number of verified chunks so the next resume can skip the chunk-by-chunk
  re-hash. The sidecar is only a hint; the final whole-file BLAKE3 check is
  always authoritative.

## Pairing Codes

Codes have the format `digit-word-word`, e.g. `7-cobalt-fox`.

- The digit is `port % 10`.
- The two words come from an embedded 88-word list.
- The code string is BLAKE3-hashed; receivers match against the hash broadcast
  in UDP announcements, not the plaintext code. This means a hostile
  broadcaster cannot trivially spoof, but it is **not** cryptographic security
  (encryption is a planned v2 feature).

UDP broadcasts go out every second on port 53317 to all non-loopback IPv4
interfaces. Broadcasting is best-effort — if it fails, the sender still prints
explicit addresses and the receiver can connect by `ip:port` directly.

If you pass `--no-discovery` on the sender, no UDP broadcast is sent. This is
useful when both sides already know the address or when you want to avoid
broadcast traffic.

## Testing

```sh
cargo test
```

- **Unit tests**: manifest building, chunk-hash diffing, resume-offset
  calculation, destination resolution, discovery code format — all in
  `#[cfg(test)]` modules within each crate.
- **Integration tests**: `lanx-core/tests/integration.rs` — spins up sender +
  receiver in-process over localhost using `tempfile` directories. Covers
  clean transfer, multi-file transfer, resume after corruption, skip of
  already-complete files, directory-structure preservation, and Windows path
  handling with spaces.

## Architecture

```
lanx/
├── lanx-core/      Library: protocol-agnostic logic (manifest, hashing,
│                   transfer state machine, resume planning, destinations)
├── lanx-net/       Library: transport layer (TCP helpers, UDP discovery,
│                   pairing codes, interface enumeration, relay server)
└── lanx-cli/       Binary: CLI parsing, terminal UI, progress rendering
```

The split between `core` and `net` lets you unit-test protocol logic without
sockets, and swap the transport layer later (e.g. QUIC) without touching
business logic.

## Wire Protocol (v4)

All control messages are length-prefixed on a single TCP stream:

```
[u32 BE length][postcard-encoded payload]
```

| Message | Direction | Purpose |
|---|---|---|
| `Hello { version, chunk_size, parallel }` | Both | Handshake: version, chunk size, and requested max parallel connections |
| `ManifestStart { total_files, total_bytes }` | Sender → Receiver | Start of streaming manifest |
| `ManifestEntry(FileEntry)` | Sender → Receiver | One file in the streaming manifest |
| `ManifestEnd { chunk_size }` | Sender → Receiver | End of streaming manifest |
| `ManifestAck { accepted, resume_offsets }` | Receiver → Sender | Which files to transfer, from what offset |
| `ManifestRejected { reason }` | Receiver → Sender | Receiver declined the manifest |
| `FileStart { id, offset }` | Sender → Receiver | Begin transferring a file |
| `ChunkHeader { id, offset, len }` | Sender → Receiver | Precedes `len` raw bytes on stream |
| `FileEnd { id, hash }` | Sender → Receiver | Whole-file BLAKE3 hash for verification |
| `FileVerified { id, ok }` | Receiver → Sender | Hash match result |
| `FileChunkRequest { id, ranges }` | Receiver → Sender | Re-send specific byte ranges |
| `Error { message }` | Either | Fatal error |
| `Done` | Sender → Receiver | Transfer complete |

Frame size limit: 32 MiB. Protocol version: `4`.

## Limitations & Future Work

**Implemented in v1.1:**
- Streaming manifest transmission
- Chunk-level re-send on hash mismatch
- `.lanx-partial.json` sidecar resume cache
- Parallel TCP connections for multi-file throughput (`--parallel N`)

**Implemented in v2:**
- Encryption via Noise protocol (`Noise_NN_25519_ChaChaPoly_BLAKE2s`)
- NAT traversal / internet relay via TURN-like relay server

## License

MIT OR Apache-2.0
