# Architecture: `lanx` — LAN File Transfer CLI

## 1. Goals & Scope

**Core requirements:**
- Send/receive one or more files (and directories) over LAN
- Resumable transfers (interrupt/resume without re-sending completed bytes)
- Integrity verification via hashing
- Simple UX: minimal flags, sensible defaults
- No central server, no internet dependency — peer-to-peer over LAN

**Non-goals (v1):**
- NAT traversal / internet relay (later, optional)
- Encryption (add later via noise protocol or TLS — flag this as a v2 concern)
- GUI

---

## 2. High-Level Model

Two roles, one binary:

```
lanx send <files...>          # sender: listens, prints connect code/address
lanx recv <code-or-addr>      # receiver: connects, pulls files
```

Sender acts as a **TCP listener** (server role for the transfer, despite being the "sender" conceptually). This avoids needing the receiver to expose a port — simpler for typical laptop-behind-NAT-or-not LAN use. Receiver dials in.

```
┌────────────┐                      ┌────────────┐
│   Sender   │  TCP listen :PORT    │  Receiver  │
│  (server)  │ <─────────────────── │  (client)  │
└────────────┘    connects, pulls    └────────────┘
```

---

## 3. Crate Layout (Workspace)

```
lanx/
├── Cargo.toml                 (workspace)
├── lanx-cli/                  # binary crate, arg parsing, UX
│   └── src/main.rs
├── lanx-core/                 # protocol + business logic
│   ├── src/
│   │   ├── manifest.rs        # file manifest construction/parsing
│   │   ├── hashing.rs         # BLAKE3 chunked hashing
│   │   ├── resume.rs          # resume planning
│   │   ├── transfer/
│   │   │   ├── mod.rs         # wire format, framing, message enums
│   │   │   ├── sender.rs
│   │   │   └── receiver.rs
│   │   └── progress.rs        # progress event trait
│   └── Cargo.toml
└── lanx-net/                  # transport layer (TCP listener, discovery)
    ├── src/
    │   ├── discovery.rs        # simple UDP broadcast pairing code
    │   ├── pairing.rs          # code / explicit address resolution
    │   ├── interfaces.rs       # local interface enumeration
    │   └── tcp.rs
    └── Cargo.toml
```

Splitting `core` from `net` lets you unit-test protocol logic without sockets, and swap transport later (e.g. QUIC) without touching business logic.

---

## 4. Key Crates to Use

| Purpose | Crate |
|---|---|
| Async runtime | `tokio` |
| Hashing | `blake3` (fast, parallel, tree-hashing friendly for resume) |
| Serialization (control messages) | `serde` + `postcard` (compact, no_std-friendly) |
| CLI parsing | `clap` (derive) |
| Progress bars | `indicatif` |
| Discovery (optional nicety) | simple UDP broadcast |
| Random pairing codes | `rand` |
| Error handling | `thiserror` (lib), `anyhow` (bin) |

---

## 5. Pairing & Connection

For LAN-friendliness without typing IPs:

1. Sender picks a random free TCP port, generates a short **pairing code** (e.g. `7-cobalt-fox`, derived from a wordlist + port encoding, similar to magic-wormhole).
2. Sender broadcasts on UDP (e.g. port 53317-ish, pick your own) a small announcement: `{code_hash, ip, port}` every second for N seconds.
3. Receiver, given the code, listens for matching broadcast on UDP, extracts IP:port, confirms code hash matches, then opens TCP.

Fallback: receiver can just supply `ip:port` directly (`lanx recv 192.168.1.5:9000`) — no discovery needed. This should be the primary supported path; discovery is a nicety layered on top.

**Discovery in v1:** both explicit `ip:port` and UDP broadcast discovery are supported. The pairing code is a UX hint, not a security mechanism.

---

## 6. Wire Protocol

### 6.1 Framing

All messages are length-prefixed:

```
[u32 length BE][payload bytes]
```

Payload is either a serialized control message (postcard/bincode) or raw file-chunk bytes, depending on a state machine — see below. Keep control-plane and data-plane on the **same TCP stream** for simplicity in v1 (multiplexing complexity isn't worth it yet).

### 6.2 Message Enum (control plane)

```rust
#[derive(Serialize, Deserialize)]
enum ControlMsg {
    Hello { version: u16, chunk_size: u32, parallel: u16 },
    /// Legacy single-frame manifest (kept for enum-level compatibility).
    Manifest(Manifest),
    ManifestStart { total_files: u64, total_bytes: u64 }, // sender -> receiver: start streaming manifest
    ManifestEntry(FileEntry),                             // sender -> receiver: one file entry
    ManifestEnd { chunk_size: u32 },                      // sender -> receiver: end streaming manifest
    ManifestAck { accepted: Vec<FileId>, resume_offsets: HashMap<FileId, u64> },
    ManifestRejected { reason: String }, // receiver -> sender: declined before transfer
    FileStart { id: FileId, offset: u64 }, // sender -> receiver: beginning this file at offset
    ChunkHeader { id: FileId, offset: u64, len: u32 }, // precedes raw bytes
    FileEnd { id: FileId, hash: [u8; 32] },   // BLAKE3 of full file, for final verification
    FileVerified { id: FileId, ok: bool },
    FileChunkRequest { id: FileId, ranges: Vec<(u64, u32)> }, // receiver -> sender: re-send specific ranges
    Error { message: String },
    Done,
}
```

### 6.3 Manifest

```rust
struct Manifest {
    files: Vec<FileEntry>,
}

struct FileEntry {
    id: FileId,                // index or UUID, stable across resume
    rel_path: PathBuf,         // preserves directory structure
    size: u64,
    chunk_size: u32,           // e.g. 1 MiB
    chunk_hashes: Vec<[u8; 32]>, // BLAKE3 of each chunk — enables resume validation
}
```

Precomputing **per-chunk hashes** (not just whole-file) is the key resume nicety: on resume, receiver can verify which chunks it already has match, rather than trusting byte-offset alone (protects against partial/corrupt writes).

The manifest is sent as a **streaming sequence**: `ManifestStart`, zero or more `ManifestEntry` messages, then `ManifestEnd`. This keeps each wire frame small and lets the receiver start processing entries without buffering the entire manifest.

---

## 7. Transfer Flow

### 7.1 Handshake

1. Receiver connects, sends `Hello { version, chunk_size, parallel }` where
   `parallel` is the number of TCP connections it wants to use.
2. Sender replies `Hello { version, chunk_size, parallel }` with the agreed
   parallelism (capped to the sender's maximum), then streams the manifest as
   `ManifestStart`, `ManifestEntry` ... `ManifestEnd`.
3. The receiver opens the agreed number of TCP connections; on each connection
   the handshake is repeated and files are assigned by `file_id % parallel`.
4. Receiver reviews the manifest and prompts for acceptance (or auto-accepts
   when `--accept` is used). If declined, receiver sends `ManifestRejected`
   and the session ends cleanly.
5. Receiver checks its destination directory for partial files matching `rel_path`:
   - If a file exists with matching name: hash existing chunks, compare against `chunk_hashes` from manifest.
   - Build `resume_offsets`: first chunk index where hash mismatches (or file ends) = resume point.
   - Files fully matching and complete → mark "already have, skip."
   - A valid `.lanx-partial.json` sidecar can short-circuit the chunk-by-chunk
     re-hash; the final whole-file hash remains the correctness authority.
6. Receiver sends `ManifestAck` with accepted file list + resume offsets.

### 7.2 Data Transfer

For each accepted file, sender:
1. Sends `FileStart { id, offset }`.
2. Streams `ChunkHeader` + raw bytes for each chunk from `offset` onward.
3. Sends `FileEnd { id, hash }` with whole-file BLAKE3 hash.

Receiver:
1. Accepts the manifest (interactive prompt or `--accept`).
2. Opens destination file in append/write-at-offset mode (`O_APPEND` won't work well with seek-based resume — use explicit `seek` + `write_all` instead, via `tokio::fs::File` + `seek`/`write_at`).
3. Writes each chunk, **also incrementally hashing** as it writes (using BLAKE3's incremental hasher, fed from the resume point — meaning if resuming, you need to either re-hash existing prefix once at startup, or store the hasher state — see §9).
4. On `FileEnd`, finalizes hash, compares to sender's, sends `FileVerified { ok: true }`.
5. If mismatch → scan the destination file to find the bad byte ranges, send
   `FileChunkRequest { id, ranges }`, receive the repaired chunks, re-hash the
   whole file from disk, and send `FileVerified { ok: true }` on success. If the
   bad ranges cannot be identified, fall back to requesting a full re-send from
   offset 0.

### 7.3 Completion

Sender sends `Done` after all files processed. Both sides close cleanly.

---

## 8. Resume State Persistence

Two resume scenarios:

**A. Same session interrupted (connection drop mid-transfer):**
- CLI should support `--retry` / auto-reconnect loop: on TCP error, receiver reconnects to same sender (sender must stay listening for a grace period after disconnect, e.g. 60s, rather than exiting immediately).
- On reconnect, re-run the handshake (§7.1) — partial file on disk is naturally detected via chunk-hash comparison. No separate resume-file needed for this case; the destination file *is* the resume state.

**B. Process killed / restarted later:**
- Same mechanism works as long as the partial file is still on disk with correct partial content. Chunk-hash re-verification on reconnect handles it.
- A `.lanx-partial.json` sidecar per destination file caches `{rel_path, size, chunk_size, verified_chunks}`. On resume, a valid sidecar lets the receiver skip the chunk-by-chunk re-hash and resume from `verified_chunks * chunk_size`. The sidecar is deleted once the file verifies; if it is stale or missing, the receiver falls back to full chunk-hash re-verification.

---

## 9. Hashing Strategy

- **Chunk size**: fixed, e.g. 1 MiB. Configurable via flag for power users.
- **Per-chunk BLAKE3 hash**: computed by sender when building manifest (this means sender does a full read-through of every file before transfer starts — for huge files/many files this adds latency before transfer begins). 
  - Mitigation: compute manifest hashes **lazily/concurrently** with starting the transfer of the first file, using a background task pool (`tokio::task::spawn_blocking` per file, bounded concurrency) — stream manifest entries to receiver as they're ready rather than blocking on all files up front.
  - v1 simplification: just accept the upfront cost; it's a CLI tool not a hyperscaler — full pre-hash before transfer is fine to start, add streaming-manifest later.
- **Whole-file hash**: also BLAKE3, computed by both sides via incremental hashing while streaming (sender while reading off disk, receiver while writing). No extra read pass needed.
- Use `blake3::Hasher` with `update_rayon` (the `rayon` feature) for large files to parallelize hashing during manifest-build.

---

## 10. Concurrency Model

- One or more TCP streams per transfer session. By default a single stream is
  used with sequential message flow; files are sent **sequentially** on each
  stream, not interleaved — simplest correct mental model, easy to reason about
  and resume.
- With `--parallel N` the receiver opens N TCP connections; each connection
  handles a disjoint subset of files (`file_id % N`), allowing multi-file
  transfers to saturate more bandwidth. The handshake and manifest are repeated
  on every connection; the receiver shares the approval decision across
  connections so the user is prompted at most once.
- Use `tokio::io::BufWriter`/`BufReader` around the TCP stream to avoid syscall-per-chunk overhead.

---

## 11. Error Handling & Edge Cases

| Case | Handling |
|---|---|
| Connection drop mid-file | Receiver auto-reconnect loop (bounded retries, exponential backoff); resume via chunk-hash diff |
| Disk full on receiver | Abort cleanly, surface clear error, leave partial file for future resume |
| Hash mismatch on `FileEnd` | Receiver identifies corrupt chunks and requests a `FileChunkRequest` re-send; falls back to full re-send if ranges cannot be determined |
| Sender file changes during transfer | Detect via final hash mismatch; report to user rather than silently accepting |
| Duplicate filenames in manifest (different dirs) | Use `rel_path` preserving relative directory structure from the common root the user specified, not just basename |
| Receiver already has identical file | Skip entirely (zero bytes transferred), report "skipped (already present)" |
| Port already in use | Sender retries with a new random port |
| Symlinks / special files | v1: skip with a warning. Don't follow symlinks by default. |

---

## 12. CLI UX

```
lanx send file1.txt dir/ file2.iso
  → Sending 3 items (1.2 GiB total).
  → Code: 7-cobalt-fox   (or: listening on 192.168.1.42:51234)
  → Waiting for receiver...

lanx recv 7-cobalt-fox
  → Found sender at 192.168.1.42:51234
  → Manifest: 3 files, 1.2 GiB
  → [resuming file2.iso from 340 MiB]
  → [progress bars via indicatif, one per active file + overall]
  → Done. Verified: 3/3 ✓
```

Flags:
```
lanx send <paths...> [--no-discovery] [--chunk-size 1M] [--parallel N] [--zip] [--relay ADDR]
lanx recv <code|ip:port> [--out DIR] [--accept] [--retry-forever] [--parallel N] [--relay ADDR]
```

---

## 13. Testing Strategy

- **Unit**: manifest building, chunk-hash diffing logic, resume-offset calculation — all pure functions in `lanx-core`, testable without sockets.
- **Integration**: spin up sender + receiver in-process over `tokio::net::TcpListener` on `127.0.0.1`, using `tempfile` dirs; simulate:
  - Clean full transfer
  - Kill connection mid-transfer (drop the stream), reconnect, verify resume correctness
  - Corrupt a chunk on disk before resume, verify it's detected and re-fetched
- **Fuzz/property tests** (optional, v1.1): random file sizes vs. chunk sizes, ensure resume offset math never panics on edge sizes (0 bytes, exactly one chunk, chunk_size - 1 bytes, etc.)

---

## 14. Suggested Build Order

1. `lanx-core`: manifest + chunk hashing + resume-diff logic, fully unit-tested, no networking.
2. `lanx-net`: TCP framing + the message enum send/recv over a stream.
3. Wire up a single-file, no-resume happy path end-to-end.
4. Add multi-file manifest support.
5. Add resume (chunk-hash diffing + reconnect loop).
6. Add `indicatif` progress UX.

---

## 15. Relay Server

The relay server (`lanx relay`) enables NAT traversal and internet relay by
bridging sender and receiver connections through a central server.

### 15.1 Protocol

1. Sender connects to relay's sender port (default 53318).
2. Receiver connects to relay's receiver port (default 53319).
3. Both send a `RelayHello { role, code_hash }` message (length-prefixed postcard).
4. Relay pairs sender and receiver by matching `code_hash` values.
5. Once paired, relay spawns bidirectional byte-copy between the two streams.

### 15.2 Messages

```rust
enum RelayRole {
    Sender,
    Receiver,
}

struct RelayHello {
    role: RelayRole,
    code_hash: [u8; 32],  // BLAKE3 hash of the pairing code
}
```

### 15.3 CLI Usage

```sh
# Start relay on a public server
lanx relay --sender-bind 0.0.0.0:53318 --receiver-bind 0.0.0.0:53319

# Sender connects through relay
lanx send ~/photos/ --relay 198.51.100.1:53318

# Receiver connects through relay
lanx recv 7-cobalt-fox --relay 198.51.100.1:53319
```

### 15.4 Design Notes

- The relay does not interpret the lanx protocol; it only forwards bytes.
- Both sides still run the Noise handshake and normal transfer state machine.
- The relay pairs connections by code hash, so a hostile broadcaster cannot
  trivially spoof connections.
- For simplicity, if no sender is waiting when a receiver connects, the receiver
  gets an error and must retry. A production relay could queue receivers.
- Parallel connections through a relay are not yet supported; each sender/receiver
  pair uses a single connection.

---

## 16. Encryption (Noise Protocol)

All lanx traffic is encrypted using the Noise framework:

- **Pattern**: `Noise_NN_25519_ChaChaPoly_BLAKE2s`
- **Handshake**: 2-message NN pattern (initiator sends ephemeral key, responder responds)
- **Transport**: ChaChaPoly symmetric encryption after handshake

### 16.1 Implementation

The encryption layer wraps the TCP stream before any lanx control messages:

```rust
// Sender (responder in Noise NN)
let encrypted = lanx_core::crypto::wrap_responder(stream).await?;

// Receiver (initiator in Noise NN)
let encrypted = lanx_core::crypto::wrap_initiator(stream).await?;
```

The encrypted stream is then split into reader/writer for the normal transfer
protocol. A pump task handles the Noise frame encoding/decoding transparently.
