---
name: cloakwise-rust
description: >-
  Cloakwise is a Rust (Tokio/Axum) adaptive VPN defense binary. Use when editing
  this repo—run cargo fmt/clippy/test, respect existing module layout, and know
  mesh + self-hosted Headscale overlay behavior.
---

# Cloakwise (Rust)

## Stack

- **Language**: Rust 2021, binary `cloakwise` (`src/main.rs`).
- **Async**: Tokio; HTTP API: Axum (`src/ui/`).
- **Config**: YAML → `src/config/schema.rs` (`Config`, `MeshConfig`, `DeployConfig`, etc.).

## Verify changes

From repo root:

```bash
cargo fmt
cargo clippy -- -D warnings
cargo test
```

Prefer fixing warnings over silencing them unless the crate already uses targeted `allow`.

## Layout (high level)

| Area | Path |
|------|------|
| Orchestration / lifecycle | `src/orchestrator.rs`, `src/main.rs` |
| VPN profiles / controllers | `src/vpn/` |
| Mesh (UDP STUN, signaling, PSK) | `src/mesh/` |
| Headscale / Tailscale CLI overlay | `src/mesh/overlay.rs` (`apply_overlay`) |
| Autonomous deploy agent | `src/deploy/` |
| Dashboard + API | `src/ui/` |
| Config schema | `src/config/schema.rs` |
| Sample config | `configs/default.yaml` |

## Mesh + NAT

- **UDP mesh** (`mesh.enabled`): STUN, optional HTTP signaling, optional PSK encryption—see `src/mesh/runtime.rs`.
- **Tailscale-style without Tailscale cloud**: set `mesh.overlay` to `kind: headscale_cli` with `login_server` pointing at your [Headscale](https://github.com/juanfont/headscale) instance. On startup (when `mesh.enabled`), Cloakwise runs `tailscale up --login-server=...` via `apply_overlay`. Auth: file `auth_key_file` or env `CLOAKWISE_TAILSCALE_AUTH_KEY`. Often requires elevated privileges; failures are logged and do not abort the process.
- API/status exposes `mesh.overlay` as a string (`none` or `headscale_cli:<url>`).

## Conventions

- Match existing patterns: tracing for logs, `anyhow` for app errors, `serde` for config/API.
- Keep changes scoped; avoid drive-by refactors in unrelated modules.
- UI strings live in `src/ui/dashboard.rs` (embedded HTML/JS).
