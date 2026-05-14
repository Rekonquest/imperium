# Near-term follow-on items

Tracked items from prior rounds. Completed items are marked; open items remain
as implementation targets.

## 1. ~~Two-phase signature activation~~ (completed Round 5)

Implemented in `imperium-net-sensors/signature_engine.rs`. Engine subscribes to
`net.signatures.approved`, fetches candidate from store, compiles via yara-x,
publishes `SignatureActivated` or `SignatureActivationFailed`. Covered by
integration test 5 and three unit tests.

## 2. ~~CLI dead-topic commands~~ (completed Round 5)

Fixed in `imperium-cli/control.rs`. Removed dead `cli.signatures.*` publishers.
Pipe handler now publishes to correct `net.signatures.*` topics. Added extract,
show, and reject commands. Covered by 11 unit tests and live pipe verification.

## 3. Cross-platform control surface

Current implementation uses Windows named pipes (`\\.\pipe\imperium-control`).
The blueprint specified Unix domain sockets for Linux/macOS. Before any deployment
to a Linux node, add the Unix socket path with feature gating:

- `#[cfg(unix)]` module using `tokio::net::UnixListener`
- `#[cfg(windows)]` module using `tokio::net::windows::named_pipe`
- Shared `dispatch_command` function (already platform-agnostic)
- API surface identical between platforms

## 4. Watchtower-initiated extraction path

The current extraction loop is operator-triggered: the CLI publishes
`ExtractionRequest` via the control pipe. A natural extension is watchtower-
initiated extraction — when the watchtower observer detects a repeated pattern
of suspicious traffic, it publishes an `ExtractionRequest` automatically.

Implementation shape:
- Watchtower observer evaluates observation history for repeated signatures
- On threshold breach, publishes `ExtractionRequest` to
  `net.signatures.extraction_request` with `requested_by: "watchtower"`
- Extraction loop already subscribes to this topic — no wiring changes needed
- Candidate enters staging as `pending`, still requires operator approval
- Add a rate limiter to prevent watchtower from flooding the extraction pipeline

The extraction loop, staging area, and approval flow are already in place from
Round 5. This item only requires the watchtower-side trigger logic and a
per-observation deduplication guard.
