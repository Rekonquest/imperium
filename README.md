# Imperium

Imperium is an adaptive defensive VPN cluster runtime. It runs as one Rust
workspace and one `imperium` binary, with subsystems communicating through the
typed in-process bus in `imperium-protocol`.

The active build includes:

- cluster membership, bootstrap tokens, config gossip, and hybrid PQC signing/key exchange
- mesh peer/session management with direct UDP, STUN-style mapping, coordinated probing, and relay fallback
- opt-in aggressive NAT probing for difficult environments
- transport hardening profiles with rekeying, padding/jitter, FEC, leak guard, kill switch, and probe deception
- sensor/signature flow, operator-gated signature extraction, and dormant toolkit activation
- auto VPN cluster deployment orchestration with Ordo-facing apply/status controls

The old watchtower subsystem has been removed. Closed-loop extraction is driven
by deterministic sensors or operator-selected events, then gated by operator
approval.

## Build And Test

```powershell
cargo check
cargo test
cargo build --release -p imperium-cli
```

Simulation coverage lives in:

- `crates/imperium-runtime/tests/hardening_simulation.rs`
- `crates/imperium-runtime/tests/cluster_vpn_simulation.rs`
- `crates/imperium-runtime/tests/bus_topic_pairs.rs`

The current verified local bridge for Ordo is `C:\Projects\ordo-device-peer`:

```powershell
cargo check
cargo test
```

## Run

Start the runtime:

```powershell
cargo run -p imperium-cli -- node start
```

On Windows, the runtime exposes its control surface at:

```text
\\.\pipe\imperium-control
```

The control pipe accepts lines such as:

```text
vpn health
vpn profile rotate [protocol]
vpn transport set-active <protocol>
vpn nat aggressive on|off
vpn killswitch arm|disarm|engage [reason]
vpn masque configure <json>
vpn hardening preset balanced|resilience|fortress [protocol]
vpn hardening apply <json>
vpn deployment apply <json>
vpn deployment status
vpn toolkit activate <tool> [trigger]
signatures pending
signatures approve <candidate_id>
signatures reject <candidate_id> [reason]
signatures extract <event_id>[,<event_id>...]
signatures show <candidate_id>
shutdown [reason]
```

`vpn deployment apply <json>` publishes a typed `VpnDeploymentPlan`.
`vpn deployment status` publishes a typed `VpnDeploymentStatusRequest`; the
runtime responds with the latest deployment status, or an explicit empty-state
status if no deployment has run yet.

`signatures pending` and `signatures show <candidate_id>` read from the live
runtime staging area when the node is running.

## Ordo Integration

`C:\Projects\ordo-device-peer` advertises Imperium as an Ordo-controllable VPN
peer. Its `imperium_vpn` adapter maps typed `VpnControlCommand` values to the
control pipe commands above, including:

- `DeploymentApply { plan_json }`
- `DeploymentStatus`
- NAT, hardening, kill switch, MASQUE, toolkit, signature, and shutdown controls

The bridge currently points at `C:\Projects\Ordo-Light-Working` for
`ordo-protocol` and `ordo-transport`.

## Ship Notes

Current release verification:

- `cargo check` passes for Imperium
- `cargo test` passes for Imperium
- `cargo check` passes for `ordo-device-peer`
- `cargo test` passes for `ordo-device-peer`

Known platform note: the control surface is currently Windows named-pipe based.
Unix socket parity is tracked in `FOLLOW_ON.md` before Linux/macOS deployment.
