//! Self-hosted **Headscale** integration: runs the local `tailscale` CLI against your login server.
//!
//! This gives Tailscale-style NAT traversal and mesh **without** Tailscale’s cloud — you operate
//! [Headscale](https://github.com/juanfont/headscale) on your own infra.

use crate::config::{MeshConfig, MeshOverlay};
use std::path::Path;
use tokio::process::Command;
use tracing::{info, warn};

const AUTH_KEY_ENV: &str = "CLOAKWISE_TAILSCALE_AUTH_KEY";

fn read_auth_key(file: Option<&Path>) -> Option<String> {
    if let Some(p) = file {
        match std::fs::read_to_string(p) {
            Ok(s) => {
                let t = s.trim();
                if !t.is_empty() {
                    return Some(t.to_string());
                }
            }
            Err(e) => warn!("mesh overlay: cannot read auth_key_file {:?}: {}", p, e),
        }
    }
    std::env::var(AUTH_KEY_ENV).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

/// If `mesh.overlay` is `HeadscaleCli`, run `tailscale up` once. Best-effort; logs warnings on failure.
pub async fn apply_overlay(cfg: &MeshConfig) -> anyhow::Result<()> {
    let MeshOverlay::HeadscaleCli {
        login_server,
        auth_key_file,
        accept_routes,
        advertise_routes,
        tailscale_binary,
    } = &cfg.overlay
    else {
        return Ok(());
    };

    if !cfg.enabled {
        warn!("mesh.overlay is HeadscaleCli but mesh.enabled is false — skipping tailscale up");
        return Ok(());
    }

    let server = login_server.trim();
    if server.is_empty() {
        anyhow::bail!("mesh.overlay.headscale_cli.login_server is empty");
    }

    let auth_key = read_auth_key(auth_key_file.as_deref());

    let mut cmd = Command::new(tailscale_binary);
    cmd.arg("up");
    cmd.arg(format!("--login-server={}", server));
    if let Some(ref k) = auth_key {
        cmd.arg(format!("--auth-key={}", k));
    } else {
        warn!(
            "mesh overlay: no auth key (set {} or auth_key_file); tailscale may wait for browser login",
            AUTH_KEY_ENV
        );
    }
    if *accept_routes {
        cmd.arg("--accept-routes");
    }
    for cidr in advertise_routes {
        cmd.arg("--advertise-routes").arg(cidr);
    }
    cmd.stdin(std::process::Stdio::null());

    info!(
        "Running mesh overlay: {} up --login-server={} …",
        tailscale_binary, server
    );

    let out = cmd
        .output()
        .await
        .map_err(|e| anyhow::anyhow!("failed to spawn {}: {}", tailscale_binary, e))?;
    if out.status.success() {
        info!(
            "tailscale up finished successfully (stdout: {} bytes, stderr: {} bytes)",
            out.stdout.len(),
            out.stderr.len()
        );
        if !out.stderr.is_empty() {
            tracing::debug!("tailscale stderr: {}", String::from_utf8_lossy(&out.stderr));
        }
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&out.stderr);
        anyhow::bail!(
            "tailscale up failed ({}): {}",
            out.status.code().map(|c| c.to_string()).unwrap_or_default(),
            stderr.trim()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{MeshConfig, MeshOverlay};

    #[test]
    fn mesh_config_deserializes_headscale_overlay() {
        let yaml = r#"
enabled: true
listen_port: 19735
overlay:
  kind: headscale_cli
  login_server: "https://headscale.example.com"
  accept_routes: true
  advertise_routes:
    - "10.0.0.0/24"
"#;
        let m: MeshConfig = serde_yaml::from_str(yaml).unwrap();
        match &m.overlay {
            MeshOverlay::HeadscaleCli {
                login_server,
                accept_routes,
                advertise_routes,
                ..
            } => {
                assert_eq!(login_server, "https://headscale.example.com");
                assert!(*accept_routes);
                assert_eq!(advertise_routes, &vec!["10.0.0.0/24".to_string()]);
            }
            _ => panic!("expected HeadscaleCli"),
        }
    }
}
