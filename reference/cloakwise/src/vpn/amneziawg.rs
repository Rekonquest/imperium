//! AmneziaWG VPN controller
//!
//! Controls AmneziaWG - an obfuscated WireGuard fork that evades DPI.

use super::{TrafficProfile, VpnController, VpnStatus};
use crate::config::Protocol;
use anyhow::{Context, Result};
use async_trait::async_trait;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::process::Command;
use tracing::{debug, info, warn};

/// AmneziaWG obfuscation parameters
#[derive(Debug, Clone)]
pub struct AmneziaParams {
    /// Junk packet count (Jc)
    pub junk_packet_count: u32,
    /// Junk packet minimum size (Jmin)
    pub junk_packet_min_size: u32,
    /// Junk packet maximum size (Jmax)
    pub junk_packet_max_size: u32,
    /// Init packet junk size (S1)
    pub init_packet_junk_size: u32,
    /// Response packet junk size (S2)
    pub response_packet_junk_size: u32,
    /// Init packet magic header (H1)
    pub init_packet_magic_header: u32,
    /// Response packet magic header (H2)
    pub response_packet_magic_header: u32,
    /// Under load packet magic header (H3)
    pub under_load_packet_magic_header: u32,
    /// Transport packet magic header (H4)
    pub transport_packet_magic_header: u32,
}

impl Default for AmneziaParams {
    fn default() -> Self {
        Self {
            junk_packet_count: 4,
            junk_packet_min_size: 40,
            junk_packet_max_size: 70,
            init_packet_junk_size: 0,
            response_packet_junk_size: 0,
            init_packet_magic_header: 1,
            response_packet_magic_header: 2,
            under_load_packet_magic_header: 3,
            transport_packet_magic_header: 4,
        }
    }
}

impl AmneziaParams {
    /// Create aggressive obfuscation parameters
    pub fn aggressive() -> Self {
        Self {
            junk_packet_count: 8,
            junk_packet_min_size: 50,
            junk_packet_max_size: 1000,
            init_packet_junk_size: 100,
            response_packet_junk_size: 100,
            ..Default::default()
        }
    }

    /// Create minimal obfuscation (lower overhead)
    pub fn minimal() -> Self {
        Self {
            junk_packet_count: 1,
            junk_packet_min_size: 20,
            junk_packet_max_size: 40,
            init_packet_junk_size: 0,
            response_packet_junk_size: 0,
            ..Default::default()
        }
    }
}

/// Controller for AmneziaWG
pub struct AmneziaWgController {
    interface: String,
    config_dir: PathBuf,
    config_file: PathBuf,
    params: parking_lot::RwLock<AmneziaParams>,
}

impl AmneziaWgController {
    pub fn new(interface: &str, config_dir: &Path) -> Self {
        let config_file = config_dir.join(format!("{}.conf", interface));
        Self {
            interface: interface.to_string(),
            config_dir: config_dir.to_path_buf(),
            config_file,
            params: parking_lot::RwLock::new(AmneziaParams::default()),
        }
    }

    /// Set obfuscation parameters
    pub fn set_params(&self, params: AmneziaParams) {
        *self.params.write() = params;
    }

    /// Execute awg command (AmneziaWG variant of wg)
    async fn awg_cmd(&self, args: &[&str]) -> Result<String> {
        // First try awg (AmneziaWG), fallback to wg
        let cmd = if Self::has_awg().await { "awg" } else { "wg" };

        let output = Command::new(cmd)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .context(format!("Failed to execute {} command", cmd))?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(anyhow::anyhow!("{} command failed: {}", cmd, stderr))
        }
    }

    /// Execute awg-quick command
    async fn awg_quick_cmd(&self, action: &str) -> Result<()> {
        // First try awg-quick, fallback to wg-quick
        let cmd = if Self::has_awg().await {
            "awg-quick"
        } else {
            "wg-quick"
        };

        let output = Command::new(cmd)
            .args([action, &self.interface])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .context(format!("Failed to execute {} command", cmd))?;

        if output.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("already exists") || stderr.contains("is not a") {
                warn!("{} {}: {}", cmd, action, stderr);
                Ok(())
            } else {
                Err(anyhow::anyhow!("{} {} failed: {}", cmd, action, stderr))
            }
        }
    }

    /// Check if awg command is available
    async fn has_awg() -> bool {
        Command::new("which")
            .arg("awg")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// Generate AmneziaWG config with obfuscation parameters
    fn generate_config(&self, profile: &TrafficProfile) -> String {
        let params = self.params.read();

        format!(
            r#"[Interface]
Address = 10.0.0.1/24
ListenPort = {}
PrivateKey = <server_private_key>
MTU = {}

# AmneziaWG obfuscation parameters
Jc = {}
Jmin = {}
Jmax = {}
S1 = {}
S2 = {}
H1 = {}
H2 = {}
H3 = {}
H4 = {}

# Profile: {}
# Max concurrent: {}

# Peers would be added dynamically
"#,
            profile.port,
            profile.padding.target_mtu,
            params.junk_packet_count,
            params.junk_packet_min_size,
            params.junk_packet_max_size,
            params.init_packet_junk_size,
            params.response_packet_junk_size,
            params.init_packet_magic_header,
            params.response_packet_magic_header,
            params.under_load_packet_magic_header,
            params.transport_packet_magic_header,
            profile.name,
            profile.max_concurrent
        )
    }

    /// Write config file
    async fn write_config(&self, config: &str) -> Result<()> {
        tokio::fs::write(&self.config_file, config)
            .await
            .context("Failed to write AmneziaWG config")?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            tokio::fs::set_permissions(&self.config_file, perms).await?;
        }

        Ok(())
    }
}

#[async_trait]
impl VpnController for AmneziaWgController {
    fn protocol(&self) -> Protocol {
        Protocol::Amneziawg
    }

    async fn is_running(&self) -> Result<bool> {
        let result = self.awg_cmd(&["show", &self.interface]).await;
        Ok(result.is_ok())
    }

    async fn start(&self) -> Result<()> {
        info!("Starting AmneziaWG interface: {}", self.interface);
        self.awg_quick_cmd("up").await
    }

    async fn stop(&self) -> Result<()> {
        info!("Stopping AmneziaWG interface: {}", self.interface);
        self.awg_quick_cmd("down").await
    }

    async fn reload(&self) -> Result<()> {
        info!("Reloading AmneziaWG interface: {}", self.interface);

        // AmneziaWG supports hot reload similar to WireGuard
        let cmd = if Self::has_awg().await { "awg" } else { "wg" };
        let quick_cmd = if Self::has_awg().await {
            "awg-quick"
        } else {
            "wg-quick"
        };

        let strip_output = Command::new("bash")
            .args(["-c", &format!("{} strip {}", quick_cmd, self.interface)])
            .stdout(Stdio::piped())
            .output()
            .await?;

        if !strip_output.status.success() {
            warn!("Strip failed, doing full restart");
            self.stop().await?;
            self.start().await?;
            return Ok(());
        }

        let stripped = String::from_utf8_lossy(&strip_output.stdout);
        let result = Command::new("bash")
            .args([
                "-c",
                &format!("echo '{}' | {} syncconf {}", stripped, cmd, self.interface),
            ])
            .status()
            .await?;

        if !result.success() {
            warn!("Syncconf failed, doing full restart");
            self.stop().await?;
            self.start().await?;
        }

        Ok(())
    }

    async fn apply_profile(&self, profile: &TrafficProfile) -> Result<()> {
        info!("Applying profile {} to AmneziaWG", profile.name);

        // Adjust obfuscation parameters based on profile timing
        let params = match profile.timing.pattern {
            crate::config::TimingPattern::WebrtcPattern => AmneziaParams::aggressive(),
            crate::config::TimingPattern::GameTrafficPattern => AmneziaParams::minimal(),
            _ => AmneziaParams::default(),
        };

        self.set_params(params);
        debug!("AmneziaWG params updated: {:?}", self.params.read());

        Ok(())
    }

    async fn connection_count(&self) -> Result<u32> {
        let output = self.awg_cmd(&["show", &self.interface]).await?;
        let count = output.lines().filter(|l| l.trim().starts_with("peer:")).count();
        Ok(count as u32)
    }

    async fn status(&self) -> Result<VpnStatus> {
        match self.awg_cmd(&["show", &self.interface]).await {
            Ok(output) => {
                let mut peer_count = 0;
                let mut total_rx = 0u64;
                let mut total_tx = 0u64;

                for line in output.lines() {
                    if line.trim().starts_with("peer:") {
                        peer_count += 1;
                    }
                }

                Ok(VpnStatus {
                    running: true,
                    uptime_secs: None,
                    connections: peer_count,
                    bytes_sent: total_tx,
                    bytes_received: total_rx,
                    last_handshake: None,
                    current_profile: Some("amneziawg".to_string()),
                })
            }
            Err(_) => Ok(VpnStatus::default()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_params() {
        let params = AmneziaParams::default();
        assert!(params.junk_packet_count > 0);
    }

    #[test]
    fn test_aggressive_params() {
        let params = AmneziaParams::aggressive();
        assert!(params.junk_packet_count > AmneziaParams::default().junk_packet_count);
    }
}
