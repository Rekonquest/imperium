//! Briar P2P messaging controller
//!
//! Briar is a secure P2P messaging app designed for activists, journalists,
//! and anyone who needs a safe, easy way to communicate. Features:
//! - Works over Tor, Wi-Fi, or Bluetooth
//! - No central servers - truly decentralized
//! - Messages sync via Tor when internet available
//! - Can work in complete network blackout via Bluetooth/Wi-Fi mesh
//!
//! This controller manages the Briar headless daemon for server integration.

use crate::config::Protocol;
use crate::vpn::{TrafficProfile, VpnController, VpnStatus};
use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::process::Command;

/// Briar transport mode
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BriarTransport {
    /// Use Tor network only
    Tor,
    /// Use local Wi-Fi/LAN
    Lan,
    /// Use Bluetooth
    Bluetooth,
    /// All available transports
    All,
}

impl Default for BriarTransport {
    fn default() -> Self {
        Self::Tor
    }
}

/// Briar configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BriarConfig {
    /// Data directory for Briar
    pub data_dir: PathBuf,
    /// Transport mode
    #[serde(default)]
    pub transport: BriarTransport,
    /// Enable Tor transport
    #[serde(default = "default_true")]
    pub tor_enabled: bool,
    /// Enable LAN transport
    #[serde(default)]
    pub lan_enabled: bool,
    /// Enable Bluetooth transport
    #[serde(default)]
    pub bluetooth_enabled: bool,
    /// API port for headless daemon
    #[serde(default = "default_api_port")]
    pub api_port: u16,
    /// API bind address
    #[serde(default = "default_bind")]
    pub api_bind: String,
    /// Log level
    #[serde(default = "default_log_level")]
    pub log_level: String,
    /// Use embedded Tor or system Tor
    #[serde(default = "default_true")]
    pub embedded_tor: bool,
    /// Custom Tor SOCKS port (when using system Tor)
    pub tor_socks_port: Option<u16>,
}

fn default_true() -> bool {
    true
}

fn default_api_port() -> u16 {
    7000
}

fn default_bind() -> String {
    "127.0.0.1".to_string()
}

fn default_log_level() -> String {
    "INFO".to_string()
}

impl Default for BriarConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("/var/lib/briar"),
            transport: BriarTransport::Tor,
            tor_enabled: true,
            lan_enabled: false,
            bluetooth_enabled: false,
            api_port: default_api_port(),
            api_bind: default_bind(),
            log_level: default_log_level(),
            embedded_tor: true,
            tor_socks_port: None,
        }
    }
}

impl BriarConfig {
    /// Create a Tor-only configuration
    pub fn tor_only() -> Self {
        Self {
            transport: BriarTransport::Tor,
            tor_enabled: true,
            lan_enabled: false,
            bluetooth_enabled: false,
            ..Default::default()
        }
    }

    /// Create a mesh-enabled configuration (all transports)
    pub fn mesh() -> Self {
        Self {
            transport: BriarTransport::All,
            tor_enabled: true,
            lan_enabled: true,
            bluetooth_enabled: true,
            ..Default::default()
        }
    }

    /// Use system Tor instead of embedded
    pub fn with_system_tor(mut self, socks_port: u16) -> Self {
        self.embedded_tor = false;
        self.tor_socks_port = Some(socks_port);
        self
    }

    /// Convert to environment variables for the daemon
    pub fn to_env_vars(&self) -> Vec<(String, String)> {
        let mut vars = vec![
            ("BRIAR_DATA_DIR".to_string(), self.data_dir.to_string_lossy().to_string()),
            ("BRIAR_API_PORT".to_string(), self.api_port.to_string()),
            ("BRIAR_API_BIND".to_string(), self.api_bind.clone()),
            ("BRIAR_LOG_LEVEL".to_string(), self.log_level.clone()),
        ];

        if self.tor_enabled {
            vars.push(("BRIAR_TOR_ENABLED".to_string(), "true".to_string()));
        }
        if self.lan_enabled {
            vars.push(("BRIAR_LAN_ENABLED".to_string(), "true".to_string()));
        }
        if self.bluetooth_enabled {
            vars.push(("BRIAR_BLUETOOTH_ENABLED".to_string(), "true".to_string()));
        }
        if !self.embedded_tor {
            if let Some(port) = self.tor_socks_port {
                vars.push(("BRIAR_TOR_SOCKS_PORT".to_string(), port.to_string()));
            }
        }

        vars
    }
}

/// Briar VPN controller
pub struct BriarController {
    config_dir: PathBuf,
    config: parking_lot::RwLock<BriarConfig>,
    binary_path: PathBuf,
    pid_file: PathBuf,
}

impl BriarController {
    /// Create a new Briar controller
    pub fn new(config_dir: &Path) -> Self {
        Self {
            config_dir: config_dir.to_path_buf(),
            config: parking_lot::RwLock::new(BriarConfig::default()),
            binary_path: PathBuf::from("/usr/local/bin/briar-headless"),
            pid_file: config_dir.join("briar.pid"),
        }
    }

    /// Get environment variables for the daemon
    fn get_env_vars(&self) -> Vec<(String, String)> {
        let config = self.config.read();
        config.to_env_vars()
    }

    /// Get process ID if running
    async fn get_pid(&self) -> Option<u32> {
        if let Ok(content) = tokio::fs::read_to_string(&self.pid_file).await {
            content.trim().parse().ok()
        } else {
            None
        }
    }

    /// Check if process is alive
    async fn is_process_alive(&self, pid: u32) -> bool {
        tokio::fs::metadata(format!("/proc/{}", pid))
            .await
            .is_ok()
    }

    /// Configure based on traffic profile
    fn configure_from_profile(&self, profile: &TrafficProfile) {
        let mut config = self.config.write();

        // Transport mode
        if let Some(val) = profile.custom_config.get("transport") {
            if let Some(s) = val.as_str() {
                config.transport = match s.to_lowercase().as_str() {
                    "tor" => BriarTransport::Tor,
                    "lan" => BriarTransport::Lan,
                    "bluetooth" => BriarTransport::Bluetooth,
                    "all" | "mesh" => BriarTransport::All,
                    _ => BriarTransport::Tor,
                };

                // Update individual transport flags
                match config.transport {
                    BriarTransport::Tor => {
                        config.tor_enabled = true;
                        config.lan_enabled = false;
                        config.bluetooth_enabled = false;
                    }
                    BriarTransport::Lan => {
                        config.tor_enabled = false;
                        config.lan_enabled = true;
                        config.bluetooth_enabled = false;
                    }
                    BriarTransport::Bluetooth => {
                        config.tor_enabled = false;
                        config.lan_enabled = false;
                        config.bluetooth_enabled = true;
                    }
                    BriarTransport::All => {
                        config.tor_enabled = true;
                        config.lan_enabled = true;
                        config.bluetooth_enabled = true;
                    }
                }
            }
        }

        // API port from profile
        config.api_port = profile.port;

        // Data directory
        if let Some(val) = profile.custom_config.get("data_dir") {
            if let Some(s) = val.as_str() {
                config.data_dir = PathBuf::from(s);
            }
        }

        // Embedded Tor
        if let Some(val) = profile.custom_config.get("embedded_tor") {
            if let Some(b) = val.as_bool() {
                config.embedded_tor = b;
            }
        }

        // Tor SOCKS port
        if let Some(val) = profile.custom_config.get("tor_socks_port") {
            if let Some(n) = val.as_u64() {
                config.tor_socks_port = Some(n as u16);
            }
        }
    }
}

#[async_trait]
impl VpnController for BriarController {
    fn protocol(&self) -> Protocol {
        Protocol::Briar
    }

    async fn is_running(&self) -> Result<bool> {
        if let Some(pid) = self.get_pid().await {
            Ok(self.is_process_alive(pid).await)
        } else {
            let output = Command::new("pgrep")
                .args(["-f", "briar-headless"])
                .output()
                .await?;
            Ok(output.status.success())
        }
    }

    async fn start(&self) -> Result<()> {
        if self.is_running().await? {
            tracing::info!("Briar is already running");
            return Ok(());
        }

        let env_vars = self.get_env_vars();

        tracing::info!("Starting Briar headless daemon");

        tokio::fs::create_dir_all(&self.config_dir).await?;

        // Create data directory
        let data_dir = {
            let config = self.config.read();
            config.data_dir.clone()
        };
        tokio::fs::create_dir_all(&data_dir).await?;

        let mut cmd = Command::new(&self.binary_path);
        for (key, value) in &env_vars {
            cmd.env(key, value);
        }

        let child = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("Failed to start Briar")?;

        let pid = child.id().unwrap_or(0);
        tokio::fs::write(&self.pid_file, pid.to_string()).await?;

        // Briar takes longer to start (Tor bootstrap)
        tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;

        if self.is_running().await? {
            tracing::info!("Briar started successfully (PID: {})", pid);
            Ok(())
        } else {
            anyhow::bail!("Briar failed to start")
        }
    }

    async fn stop(&self) -> Result<()> {
        if let Some(pid) = self.get_pid().await {
            tracing::info!("Stopping Briar (PID: {})", pid);

            let _ = Command::new("kill")
                .args(["-15", &pid.to_string()])
                .output()
                .await;

            tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

            if self.is_process_alive(pid).await {
                let _ = Command::new("kill")
                    .args(["-9", &pid.to_string()])
                    .output()
                    .await;
            }

            let _ = tokio::fs::remove_file(&self.pid_file).await;
            tracing::info!("Briar stopped");
        } else {
            let _ = Command::new("pkill")
                .args(["-f", "briar-headless"])
                .output()
                .await;
        }

        Ok(())
    }

    async fn reload(&self) -> Result<()> {
        // Briar doesn't support reload, restart instead
        self.stop().await?;
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        self.start().await
    }

    async fn apply_profile(&self, profile: &TrafficProfile) -> Result<()> {
        tracing::info!("Applying profile to Briar: {}", profile.name);
        self.configure_from_profile(profile);
        tracing::debug!("Briar profile applied: {:?}", profile);
        Ok(())
    }

    async fn connection_count(&self) -> Result<u32> {
        // Query Briar API for contact count
        let api_url = {
            let config = self.config.read();
            format!("http://{}:{}/v1/contacts", config.api_bind, config.api_port)
        };

        if let Ok(resp) = reqwest::get(&api_url).await {
            if let Ok(json) = resp.json::<serde_json::Value>().await {
                if let Some(arr) = json.as_array() {
                    return Ok(arr.len() as u32);
                }
            }
        }

        Ok(0)
    }

    async fn status(&self) -> Result<VpnStatus> {
        let running = self.is_running().await?;
        let connections = if running {
            self.connection_count().await.unwrap_or(0)
        } else {
            0
        };

        let uptime_secs = if let Some(pid) = self.get_pid().await {
            if let Ok(stat) = tokio::fs::read_to_string(format!("/proc/{}/stat", pid)).await {
                let parts: Vec<&str> = stat.split_whitespace().collect();
                if parts.len() > 21 {
                    if let Ok(start_ticks) = parts[21].parse::<u64>() {
                        if let Ok(uptime_str) = tokio::fs::read_to_string("/proc/uptime").await {
                            uptime_str
                                .split_whitespace()
                                .next()
                                .and_then(|s| s.parse::<f64>().ok())
                                .map(|sys_uptime| {
                                    let start_secs = start_ticks / 100;
                                    sys_uptime as u64 - start_secs
                                })
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        Ok(VpnStatus {
            running,
            uptime_secs,
            connections,
            bytes_sent: 0,
            bytes_received: 0,
            last_handshake: None,
            current_profile: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_briar_env_vars() {
        let config = BriarConfig::mesh()
            .with_system_tor(9050);

        let vars = config.to_env_vars();
        assert!(vars.iter().any(|(k, _)| k == "BRIAR_TOR_ENABLED"));
        assert!(vars.iter().any(|(k, _)| k == "BRIAR_LAN_ENABLED"));
        assert!(vars.iter().any(|(k, v)| k == "BRIAR_TOR_SOCKS_PORT" && v == "9050"));
    }
}
