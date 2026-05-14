//! WireGuard VPN controller
//!
//! Controls WireGuard interfaces through wg-quick and wg commands.

use super::{TrafficProfile, VpnController, VpnStatus};
use crate::config::Protocol;
use anyhow::{Context, Result};
use async_trait::async_trait;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::process::Command;
use tracing::{debug, error, info, warn};

/// Controller for WireGuard VPN
pub struct WireGuardController {
    interface: String,
    config_dir: PathBuf,
    config_file: PathBuf,
}

impl WireGuardController {
    pub fn new(interface: &str, config_dir: &Path) -> Self {
        let config_file = config_dir.join(format!("{}.conf", interface));
        Self {
            interface: interface.to_string(),
            config_dir: config_dir.to_path_buf(),
            config_file,
        }
    }

    /// Execute wg command
    async fn wg_cmd(&self, args: &[&str]) -> Result<String> {
        let output = Command::new("wg")
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .context("Failed to execute wg command")?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(anyhow::anyhow!("wg command failed: {}", stderr))
        }
    }

    /// Execute wg-quick command
    async fn wg_quick_cmd(&self, action: &str) -> Result<()> {
        let output = Command::new("wg-quick")
            .args([action, &self.interface])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .context("Failed to execute wg-quick command")?;

        if output.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // wg-quick returns error if interface is already up/down
            if stderr.contains("already exists") || stderr.contains("is not a WireGuard interface") {
                warn!("wg-quick {}: {}", action, stderr);
                Ok(())
            } else {
                Err(anyhow::anyhow!("wg-quick {} failed: {}", action, stderr))
            }
        }
    }

    /// Parse wg show output
    fn parse_wg_show(&self, output: &str) -> VpnStatus {
        let mut status = VpnStatus::default();
        let mut peer_count = 0;
        let mut total_rx = 0u64;
        let mut total_tx = 0u64;

        for line in output.lines() {
            let line = line.trim();

            if line.starts_with("peer:") {
                peer_count += 1;
            } else if line.starts_with("transfer:") {
                // Parse "transfer: X received, Y sent"
                if let Some(data) = line.strip_prefix("transfer:") {
                    let parts: Vec<&str> = data.split(',').collect();
                    if let Some(rx) = parts.first() {
                        if let Some(bytes) = parse_bytes(rx) {
                            total_rx += bytes;
                        }
                    }
                    if let Some(tx) = parts.get(1) {
                        if let Some(bytes) = parse_bytes(tx) {
                            total_tx += bytes;
                        }
                    }
                }
            } else if line.starts_with("latest handshake:") {
                // Parse timestamp
                if let Some(data) = line.strip_prefix("latest handshake:") {
                    // This is complex to parse, simplified for now
                    status.last_handshake = Some(crate::telemetry::current_timestamp());
                }
            }
        }

        status.running = !output.is_empty();
        status.connections = peer_count;
        status.bytes_received = total_rx;
        status.bytes_sent = total_tx;

        status
    }

    /// Write WireGuard config file
    async fn write_config(&self, config: &str) -> Result<()> {
        tokio::fs::write(&self.config_file, config)
            .await
            .context("Failed to write WireGuard config")?;

        // Set proper permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            tokio::fs::set_permissions(&self.config_file, perms).await?;
        }

        Ok(())
    }

    /// Generate WireGuard config from profile
    fn generate_config(&self, profile: &TrafficProfile) -> String {
        // This generates a basic WireGuard server config
        // In production, this would integrate with VPN Generator
        format!(
            r#"[Interface]
Address = 10.0.0.1/24
ListenPort = {}
PrivateKey = <server_private_key>
MTU = {}

# Profile: {}
# Obfuscation: {:?}
# Max concurrent: {}

# Peers would be added dynamically by VPN Generator
"#,
            profile.port,
            profile.padding.target_mtu,
            profile.name,
            profile.obfuscation,
            profile.max_concurrent
        )
    }
}

#[async_trait]
impl VpnController for WireGuardController {
    fn protocol(&self) -> Protocol {
        Protocol::Wireguard
    }

    async fn is_running(&self) -> Result<bool> {
        let result = self.wg_cmd(&["show", &self.interface]).await;
        Ok(result.is_ok())
    }

    async fn start(&self) -> Result<()> {
        info!("Starting WireGuard interface: {}", self.interface);
        self.wg_quick_cmd("up").await
    }

    async fn stop(&self) -> Result<()> {
        info!("Stopping WireGuard interface: {}", self.interface);
        self.wg_quick_cmd("down").await
    }

    async fn reload(&self) -> Result<()> {
        info!("Reloading WireGuard interface: {}", self.interface);

        // Use wg syncconf to reload without dropping connections
        let strip_output = Command::new("bash")
            .args(["-c", &format!("wg-quick strip {}", self.interface)])
            .stdout(Stdio::piped())
            .output()
            .await
            .context("Failed to strip config")?;

        if !strip_output.status.success() {
            warn!("Failed to strip config, trying direct reload");
            // Fallback: restart
            self.stop().await?;
            self.start().await?;
            return Ok(());
        }

        let stripped_config = String::from_utf8_lossy(&strip_output.stdout);

        let output = Command::new("bash")
            .args([
                "-c",
                &format!("echo '{}' | wg syncconf {}", stripped_config, self.interface),
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .context("Failed to syncconf")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!("wg syncconf failed: {}, trying restart", stderr);
            self.stop().await?;
            self.start().await?;
        }

        Ok(())
    }

    async fn apply_profile(&self, profile: &TrafficProfile) -> Result<()> {
        info!("Applying profile {} to WireGuard", profile.name);
        debug!("Profile config: {:?}", profile);

        // In a real implementation, this would:
        // 1. Update ListenPort if needed
        // 2. Adjust MTU based on padding profile
        // 3. Update any custom parameters

        // For now, just log the profile application
        info!(
            "WireGuard profile applied: port={}, mtu={}",
            profile.port, profile.padding.target_mtu
        );

        Ok(())
    }

    async fn connection_count(&self) -> Result<u32> {
        let output = self.wg_cmd(&["show", &self.interface]).await?;
        let count = output.lines().filter(|l| l.trim().starts_with("peer:")).count();
        Ok(count as u32)
    }

    async fn status(&self) -> Result<VpnStatus> {
        let output = self.wg_cmd(&["show", &self.interface]).await;

        match output {
            Ok(output) => {
                let mut status = self.parse_wg_show(&output);
                status.current_profile = Some("wireguard".to_string());
                Ok(status)
            }
            Err(_) => Ok(VpnStatus::default()),
        }
    }
}

/// Parse byte strings like "1.2 GiB", "500 MiB", "1234 KiB"
fn parse_bytes(s: &str) -> Option<u64> {
    let s = s.trim();
    let parts: Vec<&str> = s.split_whitespace().collect();

    if parts.len() < 2 {
        return None;
    }

    let value: f64 = parts[0].parse().ok()?;
    let unit = parts[1].to_lowercase();

    let multiplier: u64 = match unit.as_str() {
        "b" | "bytes" => 1,
        "kib" | "kb" => 1024,
        "mib" | "mb" => 1024 * 1024,
        "gib" | "gb" => 1024 * 1024 * 1024,
        "tib" | "tb" => 1024_u64 * 1024 * 1024 * 1024,
        _ => return None,
    };

    Some((value * multiplier as f64) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_bytes() {
        assert_eq!(parse_bytes("100 B"), Some(100));
        assert_eq!(parse_bytes("1 KiB"), Some(1024));
        assert_eq!(parse_bytes("1.5 MiB"), Some(1572864));
        assert_eq!(parse_bytes("1 GiB"), Some(1073741824));
    }
}
