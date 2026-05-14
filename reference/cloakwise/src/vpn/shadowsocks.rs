//! Shadowsocks VPN controller
//!
//! Controls Shadowsocks/Outline server - fast encrypted proxy.

use super::{TrafficProfile, VpnController, VpnStatus};
use crate::config::Protocol;
use anyhow::{Context, Result};
use async_trait::async_trait;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::process::Command;
use tracing::{debug, error, info, warn};

/// Shadowsocks server configuration
#[derive(Debug, Clone)]
pub struct ShadowsocksConfig {
    /// Server address to bind
    pub server_addr: String,
    /// Server port
    pub server_port: u16,
    /// Password for encryption
    pub password: String,
    /// Encryption method
    pub method: ShadowsocksMethod,
    /// Enable UDP relay
    pub enable_udp: bool,
    /// Timeout in seconds
    pub timeout: u32,
    /// Fast open (TCP)
    pub fast_open: bool,
    /// Plugin (optional, for obfuscation)
    pub plugin: Option<String>,
    /// Plugin options
    pub plugin_opts: Option<String>,
}

impl Default for ShadowsocksConfig {
    fn default() -> Self {
        Self {
            server_addr: "0.0.0.0".to_string(),
            server_port: 8388,
            password: String::new(),
            method: ShadowsocksMethod::Aes256Gcm,
            enable_udp: true,
            timeout: 300,
            fast_open: true,
            plugin: None,
            plugin_opts: None,
        }
    }
}

/// Shadowsocks encryption methods
#[derive(Debug, Clone, Copy)]
pub enum ShadowsocksMethod {
    Aes128Gcm,
    Aes256Gcm,
    Chacha20IetfPoly1305,
    Plain, // For testing only
}

impl ShadowsocksMethod {
    fn as_str(&self) -> &'static str {
        match self {
            ShadowsocksMethod::Aes128Gcm => "aes-128-gcm",
            ShadowsocksMethod::Aes256Gcm => "aes-256-gcm",
            ShadowsocksMethod::Chacha20IetfPoly1305 => "chacha20-ietf-poly1305",
            ShadowsocksMethod::Plain => "plain",
        }
    }
}

/// Controller for Shadowsocks
pub struct ShadowsocksController {
    config_dir: PathBuf,
    config_file: PathBuf,
    pid_file: PathBuf,
    config: parking_lot::RwLock<ShadowsocksConfig>,
}

impl ShadowsocksController {
    pub fn new(config_dir: &Path) -> Self {
        Self {
            config_dir: config_dir.to_path_buf(),
            config_file: config_dir.join("shadowsocks.json"),
            pid_file: config_dir.join("shadowsocks.pid"),
            config: parking_lot::RwLock::new(ShadowsocksConfig::default()),
        }
    }

    /// Update configuration
    pub fn set_config(&self, config: ShadowsocksConfig) {
        *self.config.write() = config;
    }

    /// Check if ssserver binary exists (shadowsocks-rust)
    async fn has_shadowsocks() -> bool {
        // Try shadowsocks-rust first, then ssserver
        for cmd in &["ssserver", "ss-server"] {
            if Command::new("which")
                .arg(cmd)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .await
                .map(|s| s.success())
                .unwrap_or(false)
            {
                return true;
            }
        }
        false
    }

    /// Get the appropriate server command
    async fn server_cmd() -> &'static str {
        if Command::new("which")
            .arg("ssserver")
            .stdout(Stdio::null())
            .status()
            .await
            .map(|s| s.success())
            .unwrap_or(false)
        {
            "ssserver"
        } else {
            "ss-server"
        }
    }

    /// Get PID of running server
    async fn get_pid(&self) -> Option<u32> {
        if self.pid_file.exists() {
            if let Ok(content) = tokio::fs::read_to_string(&self.pid_file).await {
                return content.trim().parse().ok();
            }
        }

        // Try to find by process name
        for name in &["ssserver", "ss-server"] {
            let output = Command::new("pgrep")
                .args(["-f", name])
                .stdout(Stdio::piped())
                .output()
                .await
                .ok()?;

            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if let Some(pid) = stdout.lines().next()?.trim().parse().ok() {
                    return Some(pid);
                }
            }
        }

        None
    }

    /// Generate Shadowsocks config JSON
    fn generate_config(&self, profile: &TrafficProfile) -> String {
        let config = self.config.read();

        let mut json = serde_json::json!({
            "server": config.server_addr,
            "server_port": profile.port,
            "password": config.password,
            "method": config.method.as_str(),
            "timeout": config.timeout,
            "fast_open": config.fast_open,
            "mode": if config.enable_udp { "tcp_and_udp" } else { "tcp_only" }
        });

        // Add plugin if configured
        if let Some(plugin) = &config.plugin {
            json["plugin"] = serde_json::Value::String(plugin.clone());
            if let Some(opts) = &config.plugin_opts {
                json["plugin_opts"] = serde_json::Value::String(opts.clone());
            }
        }

        serde_json::to_string_pretty(&json).unwrap()
    }

    /// Write config file
    async fn write_config(&self, config: &str) -> Result<()> {
        if let Some(parent) = self.config_file.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        tokio::fs::write(&self.config_file, config)
            .await
            .context("Failed to write Shadowsocks config")?;

        Ok(())
    }

    /// Start server process
    async fn start_process(&self) -> Result<()> {
        if !Self::has_shadowsocks().await {
            return Err(anyhow::anyhow!(
                "Shadowsocks not found. Install shadowsocks-rust from https://github.com/shadowsocks/shadowsocks-rust"
            ));
        }

        let cmd = Self::server_cmd().await;
        let config_path = self.config_file.to_string_lossy();

        // Start as daemon
        let child = Command::new(cmd)
            .args(["-c", &config_path])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("Failed to start shadowsocks server")?;

        if let Some(pid) = child.id() {
            tokio::fs::write(&self.pid_file, pid.to_string()).await?;
        }

        // Wait and verify
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        if self.get_pid().await.is_some() {
            info!("Shadowsocks server started successfully");
            Ok(())
        } else {
            Err(anyhow::anyhow!("Shadowsocks server failed to start"))
        }
    }

    /// Stop server process
    async fn stop_process(&self) -> Result<()> {
        if let Some(pid) = self.get_pid().await {
            let _ = Command::new("kill")
                .args(["-TERM", &pid.to_string()])
                .status()
                .await;

            for _ in 0..10 {
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                if self.get_pid().await.is_none() {
                    break;
                }
            }

            if self.get_pid().await.is_some() {
                let _ = Command::new("kill")
                    .args(["-KILL", &pid.to_string()])
                    .status()
                    .await;
            }

            let _ = tokio::fs::remove_file(&self.pid_file).await;
        }

        Ok(())
    }
}

#[async_trait]
impl VpnController for ShadowsocksController {
    fn protocol(&self) -> Protocol {
        Protocol::Shadowsocks
    }

    async fn is_running(&self) -> Result<bool> {
        Ok(self.get_pid().await.is_some())
    }

    async fn start(&self) -> Result<()> {
        info!("Starting Shadowsocks server");

        if self.is_running().await? {
            warn!("Shadowsocks is already running");
            return Ok(());
        }

        self.start_process().await
    }

    async fn stop(&self) -> Result<()> {
        info!("Stopping Shadowsocks server");
        self.stop_process().await
    }

    async fn reload(&self) -> Result<()> {
        info!("Reloading Shadowsocks server");

        // Shadowsocks-rust doesn't support hot reload well
        // Do a full restart
        self.stop().await?;
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        self.start().await
    }

    async fn apply_profile(&self, profile: &TrafficProfile) -> Result<()> {
        info!("Applying profile {} to Shadowsocks", profile.name);

        // Configure plugin based on obfuscation type
        let (plugin, plugin_opts) = match profile.obfuscation {
            crate::config::ObfuscationType::WebsocketUpgrade => {
                (Some("v2ray-plugin".to_string()), Some("server;path=/ws".to_string()))
            }
            crate::config::ObfuscationType::Tls1_3 => (
                Some("v2ray-plugin".to_string()),
                Some("server;tls;host=www.example.com".to_string()),
            ),
            crate::config::ObfuscationType::Quic => {
                (Some("v2ray-plugin".to_string()), Some("server;mode=quic".to_string()))
            }
            _ => (None, None),
        };

        {
            let mut config = self.config.write();
            config.plugin = plugin;
            config.plugin_opts = plugin_opts;
            config.server_port = profile.port;
        }

        // Generate and write config
        let config_content = self.generate_config(profile);
        self.write_config(&config_content).await?;

        debug!("Shadowsocks config updated for profile: {}", profile.name);
        Ok(())
    }

    async fn connection_count(&self) -> Result<u32> {
        // Shadowsocks doesn't expose connection count easily
        // Would need to parse logs or use API (if available)
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
                Some("shadowsocks".to_string())
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
        let config = ShadowsocksConfig::default();
        assert_eq!(config.server_port, 8388);
        assert!(config.enable_udp);
    }

    #[test]
    fn test_method_str() {
        assert_eq!(ShadowsocksMethod::Aes256Gcm.as_str(), "aes-256-gcm");
    }

    #[tokio::test]
    async fn test_controller_creation() {
        let dir = tempdir().unwrap();
        let controller = ShadowsocksController::new(dir.path());
        assert!(!controller.is_running().await.unwrap());
    }
}
