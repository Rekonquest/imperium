//! Cloak VPN controller
//!
//! Controls Cloak - a pluggable transport that makes VPN traffic look like HTTPS.

use super::{TrafficProfile, VpnController, VpnStatus};
use crate::config::Protocol;
use anyhow::{Context, Result};
use async_trait::async_trait;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::process::Command;
use tracing::{debug, error, info, warn};

/// Cloak server configuration
#[derive(Debug, Clone)]
pub struct CloakConfig {
    /// Proxy method (openvpn, wireguard, shadowsocks)
    pub proxy_method: String,
    /// Encrypted proxy listen address
    pub proxy_listen: String,
    /// Redirection address for unauthorized connections
    pub redirection_address: String,
    /// Server private key
    pub private_key: String,
    /// Admin UID for management
    pub admin_uid: Option<String>,
    /// Database path
    pub database_path: PathBuf,
    /// Stream timeout in seconds
    pub stream_timeout: u32,
    /// Keep alive interval
    pub keep_alive: u32,
}

impl Default for CloakConfig {
    fn default() -> Self {
        Self {
            proxy_method: "wireguard".to_string(),
            proxy_listen: "127.0.0.1:51821".to_string(),
            redirection_address: "www.bing.com:443".to_string(),
            private_key: String::new(),
            admin_uid: None,
            database_path: PathBuf::from("/var/lib/cloak/userinfo.db"),
            stream_timeout: 300,
            keep_alive: 30,
        }
    }
}

/// Controller for Cloak pluggable transport
pub struct CloakController {
    config_dir: PathBuf,
    config_file: PathBuf,
    pid_file: PathBuf,
    config: parking_lot::RwLock<CloakConfig>,
}

impl CloakController {
    pub fn new(config_dir: &Path) -> Self {
        Self {
            config_dir: config_dir.to_path_buf(),
            config_file: config_dir.join("ck-server.json"),
            pid_file: config_dir.join("cloak.pid"),
            config: parking_lot::RwLock::new(CloakConfig::default()),
        }
    }

    /// Update Cloak configuration
    pub fn set_config(&self, config: CloakConfig) {
        *self.config.write() = config;
    }

    /// Check if ck-server binary exists
    async fn has_cloak() -> bool {
        Command::new("which")
            .arg("ck-server")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// Get PID of running Cloak server
    async fn get_pid(&self) -> Option<u32> {
        if self.pid_file.exists() {
            if let Ok(content) = tokio::fs::read_to_string(&self.pid_file).await {
                return content.trim().parse().ok();
            }
        }

        // Try to find by process name
        let output = Command::new("pgrep")
            .args(["-f", "ck-server"])
            .stdout(Stdio::piped())
            .output()
            .await
            .ok()?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            stdout.lines().next()?.trim().parse().ok()
        } else {
            None
        }
    }

    /// Generate Cloak server config JSON
    fn generate_config(&self, profile: &TrafficProfile) -> String {
        let config = self.config.read();

        // Cloak expects JSON config
        serde_json::json!({
            "ProxyBook": {
                "wireguard": [config.proxy_method.clone(), config.proxy_listen.clone()]
            },
            "BindAddr": [format!(":{}", profile.port)],
            "BypassUID": [],
            "RedirAddr": config.redirection_address.clone(),
            "PrivateKey": config.private_key.clone(),
            "AdminUID": config.admin_uid.clone().unwrap_or_default(),
            "DatabasePath": config.database_path.to_string_lossy(),
            "StreamTimeout": config.stream_timeout,
            "KeepAlive": config.keep_alive
        })
        .to_string()
    }

    /// Write config file
    async fn write_config(&self, config: &str) -> Result<()> {
        // Ensure directory exists
        if let Some(parent) = self.config_file.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        tokio::fs::write(&self.config_file, config)
            .await
            .context("Failed to write Cloak config")?;

        Ok(())
    }

    /// Start Cloak server process
    async fn start_process(&self) -> Result<()> {
        if !Self::has_cloak().await {
            return Err(anyhow::anyhow!(
                "ck-server not found. Install Cloak from https://github.com/cbeuw/Cloak"
            ));
        }

        let config_path = self.config_file.to_string_lossy();

        // Start ck-server as daemon
        let child = Command::new("ck-server")
            .args(["-c", &config_path])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("Failed to start ck-server")?;

        // Save PID
        if let Some(pid) = child.id() {
            tokio::fs::write(&self.pid_file, pid.to_string()).await?;
        }

        // Wait a moment and check if it started
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        if self.get_pid().await.is_some() {
            info!("Cloak server started successfully");
            Ok(())
        } else {
            Err(anyhow::anyhow!("Cloak server failed to start"))
        }
    }

    /// Stop Cloak server process
    async fn stop_process(&self) -> Result<()> {
        if let Some(pid) = self.get_pid().await {
            // Send SIGTERM
            let _ = Command::new("kill")
                .args(["-TERM", &pid.to_string()])
                .status()
                .await;

            // Wait for process to exit
            for _ in 0..10 {
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                if self.get_pid().await.is_none() {
                    break;
                }
            }

            // Force kill if still running
            if self.get_pid().await.is_some() {
                let _ = Command::new("kill")
                    .args(["-KILL", &pid.to_string()])
                    .status()
                    .await;
            }

            // Remove PID file
            let _ = tokio::fs::remove_file(&self.pid_file).await;
        }

        Ok(())
    }
}

#[async_trait]
impl VpnController for CloakController {
    fn protocol(&self) -> Protocol {
        Protocol::Cloak
    }

    async fn is_running(&self) -> Result<bool> {
        Ok(self.get_pid().await.is_some())
    }

    async fn start(&self) -> Result<()> {
        info!("Starting Cloak server");

        if self.is_running().await? {
            warn!("Cloak is already running");
            return Ok(());
        }

        self.start_process().await
    }

    async fn stop(&self) -> Result<()> {
        info!("Stopping Cloak server");
        self.stop_process().await
    }

    async fn reload(&self) -> Result<()> {
        info!("Reloading Cloak server");

        // Cloak doesn't support hot reload, need to restart
        if let Some(pid) = self.get_pid().await {
            // Send SIGHUP to attempt graceful reload
            let result = Command::new("kill")
                .args(["-HUP", &pid.to_string()])
                .status()
                .await;

            if result.is_err() || !result.unwrap().success() {
                // Fallback to restart
                warn!("SIGHUP failed, doing full restart");
                self.stop().await?;
                self.start().await?;
            }
        }

        Ok(())
    }

    async fn apply_profile(&self, profile: &TrafficProfile) -> Result<()> {
        info!("Applying profile {} to Cloak", profile.name);

        // Update redirection address based on obfuscation type
        let redirection = match profile.obfuscation {
            crate::config::ObfuscationType::Tls1_3 => "www.bing.com:443",
            crate::config::ObfuscationType::Http2 => "www.google.com:443",
            crate::config::ObfuscationType::WebsocketUpgrade => "echo.websocket.org:443",
            _ => "www.cloudflare.com:443",
        };

        // Update config in a separate scope to drop the guard before await
        {
            let mut config = self.config.write();
            config.redirection_address = redirection.to_string();
        }

        // Generate and write new config (guard is dropped)
        let config_content = self.generate_config(profile);
        self.write_config(&config_content).await?;

        debug!("Cloak config updated for profile: {}", profile.name);
        Ok(())
    }

    async fn connection_count(&self) -> Result<u32> {
        // Cloak doesn't expose connection count easily
        // Would need to parse logs or use admin API
        Ok(0)
    }

    async fn status(&self) -> Result<VpnStatus> {
        let running = self.is_running().await?;

        Ok(VpnStatus {
            running,
            uptime_secs: None,
            connections: 0,
            bytes_sent: 0,
            bytes_received: 0,
            last_handshake: None,
            current_profile: if running {
                Some("cloak".to_string())
            } else {
                None
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_default_config() {
        let config = CloakConfig::default();
        assert_eq!(config.proxy_method, "wireguard");
        assert_eq!(config.stream_timeout, 300);
    }

    #[tokio::test]
    async fn test_controller_creation() {
        let dir = tempdir().unwrap();
        let controller = CloakController::new(dir.path());
        assert!(!controller.is_running().await.unwrap());
    }
}
