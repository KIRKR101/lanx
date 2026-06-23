# lanx — LAN File Transfer

**lanx** transfers files and directories between machines on the same local
network. No internet connection, no central server, no accounts. Sender acts as
a TCP listener; receiver connects and pulls. Resumable transfers, BLAKE3-based
integrity verification, pairwise human-readable codes for discovery.

## Installation

Requires Rust 1.75 or later.

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
4. Both sides handshake with protocol version, then exchange the manifest.
5. **Receiver** checks its destination directory for partial files. If a file
   exists, it re-hashes the existing chunks and sends the sender a resume
   offset for each file. Fully-matching files are skipped.
6. **Sender** streams each accepted file chunk-by-chunk. **Receiver** writes
   to disk while incrementally re-hashing.
7. After each file, receiver verifies the whole-file BLAKE3 hash against the
   sender's hash. On mismatch it requests re-transfer from offset 0.
8. Sender sends `Done`, both sides report the final tally.

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
| `--retry-forever` | off | Keep retrying on connection drop indefinitely (default: 5 attempts) |
| `--discovery-timeout <SECS>` | `30` | Discovery timeout in seconds |

Receiver output:

```
lanx · recv
  ✓ sender 192.168.1.42:51234
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

No sidecar metadata files needed — the on-disk partial file is its own resume
state. BLAKE3 runs at multiple GB/s per thread, so re-hashing on reconnect is
fast enough for v1.

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
│                   pairing codes, interface enumeration)
└── lanx-cli/       Binary: CLI parsing, terminal UI, progress rendering
```

The split between `core` and `net` lets you unit-test protocol logic without
sockets, and swap the transport layer later (e.g. QUIC) without touching
business logic.

## Wire Protocol (v1)

All control messages are length-prefixed on a single TCP stream:

```
[u32 BE length][postcard-encoded payload]
```

| Message | Direction | Purpose |
|---|---|---|
| `Hello { version }` | Both | Handshake, version negotiation |
| `Manifest` | Sender → Receiver | File list with per-chunk BLAKE3 hashes |
| `ManifestAck { accepted, resume_offsets }` | Receiver → Sender | Which files to transfer, from what offset |
| `FileStart { id, offset }` | Sender → Receiver | Begin transferring a file |
| `ChunkHeader { id, offset, len }` | Sender → Receiver | Precedes `len` raw bytes on stream |
| `FileEnd { id, hash }` | Sender → Receiver | Whole-file BLAKE3 hash for verification |
| `FileVerified { id, ok }` | Receiver → Sender | Hash match result |
| `Error { message }` | Either | Fatal error |
| `Done` | Sender → Receiver | Transfer complete |

Frame size limit: 32 MiB. Protocol version: `1`.

## Limitations & Future Work

**Not in v1:**
- Encryption (planned for v2 via noise protocol or TLS)
- Parallel TCP connections for multi-file throughput
- Chunk-level re-send on hash mismatch (currently retransmits the entire file)
- Streaming manifest (all files are fully hashed before transfer starts)
- NAT traversal / internet relay
- Sidecar `.lanx-partial.json` to avoid re-hashing on resume

## License

MIT OR Apache-2.0
