# TODO

## Close the Croc convenience gap

### Priority 1: reachability

- [ ] Add automatic connection selection: direct LAN discovery, saved relay,
      then a public relay fallback when explicitly enabled.
- [ ] Add a single-port relay mode before adding fallback transports; preserve
      the current two-port mode for compatibility during migration.
      - Acceptance: sender and receiver can share one TCP listener without
        ambiguity, and existing two-port relays still work.
- [ ] Add `--relay auto` as explicit opt-in; do not change the current direct
      default until relay fallback is proven stable.
      - Selection order: direct discovery, saved relay, then the public pool.
      - An empty public pool means no public fallback; print a clear warning
        and explain how to configure one.
- [ ] Add a configurable public relay pool, stored in the normal Lanx config
      rather than an ad hoc working-directory file.
      - Acceptance: entries support hostnames and ports, invalid entries are
        ignored with a warning, and failed relays are skipped.
- [ ] Add IPv4/IPv6 fallback for direct and relay connections.
- [ ] Add SOCKS5 proxy support, including Tor-friendly proxy-side DNS.
      - Acceptance: both relay control and transfer traffic work through a
        SOCKS5 proxy without requiring local DNS resolution of the relay.

### Priority 2: simpler transfer UX

- [ ] Make the normal flow work as `lanx send file` followed by
      `lanx recv <code>` without manual network decisions.
- [x] Add relay health/status checks and clearer fallback diagnostics.
      - Acceptance: each attempted route reports why it failed, and the final
        error names the next actionable setup step.
- [ ] Add Docker and systemd deployment examples for self-hosted relays.

### Configuration invariants

- Explicit `--relay host:port` always overrides saved or automatic relay
  selection.
- Saved self-hosted relay configuration remains supported throughout fallback
  work.
- Relay authentication and end-to-end encryption remain separate: the relay
  may authenticate clients, but never receives the transfer PSK or plaintext.

### Priority 3: browser and mobile access

- [ ] Define and document a stable browser-compatible protocol boundary before
      building the web client.
      - Acceptance: protocol versioning and capability negotiation are tested
        against the native CLI.
- [ ] Add `--qr` terminal QR output containing a browser-compatible receive URL.
      - Acceptance: scanning the QR opens the browser receiver with the pairing
        information, and the CLI still prints the copyable code and URL.
- [ ] Add a browser receiver that can join a Lanx transfer without installing
      the CLI.
      - Acceptance: a current desktop browser can receive a file or directory,
        confirm the transfer, and preserve the existing encryption and conflict
        checks.

### Priority 4: stream-oriented transfers

- [ ] Support stdin as a sender input: `lanx send -`.
- [ ] Support stdout as a receiver output: `lanx recv <code> --stdout`.
- [ ] Add short text transfer support: `lanx send --text '...'`.

## Deliberately deferred

- [ ] SSH or shared-terminal mode. Add only if Lanx expands beyond file
      transfer.

## Existing strengths to preserve

- BLAKE3 verification and resumable chunked transfers.
- Directory preservation, include/exclude filters, dry runs, and conflict
  policies.
- Parallel transfers where they improve throughput.
- End-to-end encryption independent of relay trust.
