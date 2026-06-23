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

## 4. ~~Watchtower-initiated extraction path~~ (removed)

The watchtower subsystem has been removed. Signature extraction remains
operator-triggered through `net.signatures.extraction_request`, and candidates
still require operator approval before activation.
