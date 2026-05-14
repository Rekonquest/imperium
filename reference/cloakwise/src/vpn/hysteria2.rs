//! Hysteria 2 VPN controller
//!
//! Hysteria 2 is a powerful QUIC-based proxy protocol featuring:
//! - Brutal congestion control for high-speed transfers on lossy networks
//! - QUIC transport (UDP-based, encrypted by default)
//! - Built-in traffic obfuscation
//! - Multiple authentication methods (password, userpass)
//! - Bandwidth control and traffic statistics
//! - ACL for traffic routing

use crate::config::Protocol;
use crate::vpn::{TrafficProfile, VpnController, VpnStatus};
use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::process::Command;

/// Hysteria 2 authentication type
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Hysteria2Auth {
    /// Password authentication
    Password(String),
    /// Username:password authentication
    UserPass { username: String, password: String },
}

impl Default for Hysteria2Auth {
    fn default() -> Self {
        Self::Password("changeme".to_string())
    }
}

/// Hysteria 2 congestion control mode
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CongestionControl {
    /// Brutal mode - ignores packet loss, maintains high speed
    Brutal,
    /// BBR - Google's congestion control
    Bbr,
    /// Cubic - standard Linux CC
    Cubic,
}

impl Default for CongestionControl {
    fn default() -> Self {
        Self::Brutal
    }
}

/// Obfuscation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hysteria2Obfs {
    /// Obfuscation type (salamander is the primary one)
    #[serde(rename = "type")]
    pub obfs_type: String,
    /// Obfuscation password
    pub password: String,
}

impl Default for Hysteria2Obfs {
    fn default() -> Self {
        Self {
            obfs_type: "salamander".to_string(),
            password: "obfs_password".to_string(),
        }
    }
}

/// Bandwidth configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BandwidthConfig {
    /// Upload bandwidth (e.g., "100 mbps")
    pub up: String,
    /// Download bandwidth (e.g., "500 mbps")
    pub down: String,
}

impl Default for BandwidthConfig {
    fn default() -> Self {
        Self {
            up: "100 mbps".to_string(),
            down: "500 mbps".to_string(),
        }
    }
}

/// TLS configuration for Hysteria 2
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hysteria2Tls {
    /// Server name indication
    pub sni: Option<String>,
    /// Skip certificate verification (not recommended)
    #[serde(default)]
    pub insecure: bool,
    /// Certificate path (server mode)
    pub cert: Option<PathBuf>,
    /// Key path (server mode)
    pub key: Option<PathBuf>,
    /// ALPN protocols
    #[serde(default = "default_alpn")]
    pub alpn: Vec<String>,
}

fn default_alpn() -> Vec<String> {
    vec!["h3".to_string()]
}

impl Default for Hysteria2Tls {
    fn default() -> Self {
        Self {
            sni: None,
            insecure: false,
            cert: None,
            key: None,
            alpn: default_alpn(),
        }
    }
}

/// QUIC configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuicConfig {
    /// Initial stream receive window
    #[serde(default = "default_stream_window")]
    pub init_stream_receive_window: u32,
    /// Max stream receive window
    #[serde(default = "default_max_stream_window")]
    pub max_stream_receive_window: u32,
    /// Initial connection receive window
    #[serde(default = "default_conn_window")]
    pub init_conn_receive_window: u32,
    /// Max connection receive window
    #[serde(default = "default_max_conn_window")]
    pub max_conn_receive_window: u32,
    /// Max idle timeout
    #[serde(default = "default_idle_timeout")]
    pub max_idle_timeout: String,
    /// Keep alive period
    #[serde(default = "default_keep_alive")]
    pub keep_alive_period: String,
}

fn default_stream_window() -> u32 {
    8388608 // 8MB
}
fn default_max_stream_window() -> u32 {
    8388608
}
fn default_conn_window() -> u32 {
    20971520 // 20MB
}
fn default_max_conn_window() -> u32 {
    20971520
}
fn default_idle_timeout() -> String {
    "30s".to_string()
}
fn default_keep_alive() -> String {
    "10s".to_string()
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            init_stream_receive_window: default_stream_window(),
            max_stream_receive_window: default_max_stream_window(),
            init_conn_receive_window: default_conn_window(),
            max_conn_receive_window: default_max_conn_window(),
            max_idle_timeout: default_idle_timeout(),
            keep_alive_period: default_keep_alive(),
        }
    }
}

/// Complete Hysteria 2 configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hysteria2Config {
    /// Server address (client) or listen address (server)
    pub server: String,
    /// Authentication
    pub auth: Hysteria2Auth,
    /// TLS configuration
    #[serde(default)]
    pub tls: Hysteria2Tls,
    /// Obfuscation (optional)
    #[serde(default)]
    pub obfs: Option<Hysteria2Obfs>,
    /// Bandwidth limits
    #[serde(default)]
    pub bandwidth: BandwidthConfig,
    /// QUIC settings
    #[serde(default)]
    pub quic: QuicConfig,
    /// Congestion control
    #[serde(default)]
    pub congestion: CongestionControl,
    /// Lazy start (client)
    #[serde(default)]
    pub lazy: bool,
    /// Fast open (reduce latency)
    #[serde(default = "default_true")]
    pub fast_open: bool,
    /// SOCKS5 listen address (client mode)
    pub socks5_listen: Option<String>,
    /// HTTP listen address (client mode)
    pub http_listen: Option<String>,
}

fn default_true() -> bool {
    true
}

impl Default for Hysteria2Config {
    fn default() -> Self {
        Self {
            server: "example.com:443".to_string(),
            auth: Hysteria2Auth::default(),
            tls: Hysteria2Tls::default(),
            obfs: None,
            bandwidth: BandwidthConfig::default(),
            quic: QuicConfig::default(),
            congestion: CongestionControl::Brutal,
            lazy: false,
            fast_open: true,
            socks5_listen: Some("127.0.0.1:1080".to_string()),
            http_listen: Some("127.0.0.1:8080".to_string()),
        }
    }
}

impl Hysteria2Config {
    /// Create a client configuration
    pub fn client(server: &str, password: &str) -> Self {
        Self {
            server: server.to_string(),
            auth: Hysteria2Auth::Password(password.to_string()),
            ..Default::default()
        }
    }

    /// Create a server configuration
    pub fn server(listen: &str, password: &str, cert: &Path, key: &Path) -> Self {
        Self {
            server: listen.to_string(),
            auth: Hysteria2Auth::Password(password.to_string()),
            tls: Hysteria2Tls {
                cert: Some(cert.to_path_buf()),
                key: Some(key.to_path_buf()),
                ..Default::default()
            },
            socks5_listen: None,
            http_listen: None,
            ..Default::default()
        }
    }

    /// Enable obfuscation
    pub fn with_obfs(mut self, password: &str) -> Self {
        self.obfs = Some(Hysteria2Obfs {
            obfs_type: "salamander".to_string(),
            password: password.to_string(),
        });
        self
    }

    /// Set bandwidth limits
    pub fn with_bandwidth(mut self, up: &str, down: &str) -> Self {
        self.bandwidth = BandwidthConfig {
            up: up.to_string(),
            down: down.to_string(),
        };
        self
    }

    /// Convert to YAML config format
    pub fn to_yaml(&self) -> Result<String> {
        serde_yaml::to_string(self).context("Failed to serialize Hysteria2 config")
    }
}

/// Hysteria 2 VPN controller
pub struct Hysteria2Controller {
    config_dir: PathBuf,
    config: parking_lot::RwLock<Hysteria2Config>,
    binary_path: PathBuf,
    pid_file: PathBuf,
}

impl Hysteria2Controller {
    /// Create a new Hysteria 2 controller
    pub fn new(config_dir: &Path) -> Self {
        Self {
            config_dir: config_dir.to_path_buf(),
            config: parking_lot::RwLock::new(Hysteria2Config::default()),
            binary_path: PathBuf::from("/usr/local/bin/hysteria"),
            pid_file: config_dir.join("hysteria2.pid"),
        }
    }

    /// Get the config file path
    fn config_file(&self) -> PathBuf {
        self.config_dir.join("hysteria2.yaml")
    }

    /// Write configuration to file
    async fn write_config(&self) -> Result<()> {
        let yaml = {
            let config = self.config.read();
            config.to_yaml()?
        };

        tokio::fs::create_dir_all(&self.config_dir).await?;
        tokio::fs::write(self.config_file(), yaml).await?;

        Ok(())
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

        // Extract server from port
        if let Some(val) = profile.custom_config.get("server") {
            if let Some(s) = val.as_str() {
                config.server = s.to_string();
            }
        } else {
            // Use port from profile for listen address
            config.server = format!("0.0.0.0:{}", profile.port);
        }

        // Password
        if let Some(val) = profile.custom_config.get("password") {
            if let Some(s) = val.as_str() {
                config.auth = Hysteria2Auth::Password(s.to_string());
            }
        }

        // SNI
        if let Some(val) = profile.custom_config.get("sni") {
            if let Some(s) = val.as_str() {
                config.tls.sni = Some(s.to_string());
            }
        }

        // Obfuscation
        if let Some(val) = profile.custom_config.get("obfs_password") {
            if let Some(s) = val.as_str() {
                config.obfs = Some(Hysteria2Obfs {
                    obfs_type: "salamander".to_string(),
                    password: s.to_string(),
                });
            }
        }

        // Bandwidth
        if let Some(val) = profile.custom_config.get("bandwidth_up") {
            if let Some(s) = val.as_str() {
                config.bandwidth.up = s.to_string();
            }
        }
        if let Some(val) = profile.custom_config.get("bandwidth_down") {
            if let Some(s) = val.as_str() {
                config.bandwidth.down = s.to_string();
            }
        }

        // Congestion control
        if let Some(val) = profile.custom_config.get("congestion") {
            if let Some(s) = val.as_str() {
                config.congestion = match s.to_lowercase().as_str() {
                    "bbr" => CongestionControl::Bbr,
                    "cubic" => CongestionControl::Cubic,
                    _ => CongestionControl::Brutal,
                };
            }
        }

        // TLS cert/key
        if let Some(val) = profile.custom_config.get("cert") {
            if let Some(s) = val.as_str() {
                config.tls.cert = Some(PathBuf::from(s));
            }
        }
        if let Some(val) = profile.custom_config.get("key") {
            if let Some(s) = val.as_str() {
                config.tls.key = Some(PathBuf::from(s));
            }
        }
    }
}

#[async_trait]
impl VpnController for Hysteria2Controller {
    fn protocol(&self) -> Protocol {
        Protocol::Hysteria2
    }

    async fn is_running(&self) -> Result<bool> {
        if let Some(pid) = self.get_pid().await {
            Ok(self.is_process_alive(pid).await)
        } else {
            let output = Command::new("pgrep")
                .args(["-f", "hysteria"])
                .output()
                .await?;
            Ok(output.status.success())
        }
    }

    async fn start(&self) -> Result<()> {
        if self.is_running().await? {
            tracing::info!("Hysteria 2 is already running");
            return Ok(());
        }

        self.write_config().await?;

        tracing::info!("Starting Hysteria 2 with config: {:?}", self.config_file());

        let child = Command::new(&self.binary_path)
            .args(["server", "-c", &self.config_file().to_string_lossy()])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("Failed to start Hysteria 2")?;

        let pid = child.id().unwrap_or(0);
        tokio::fs::write(&self.pid_file, pid.to_string()).await?;

        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        if self.is_running().await? {
            tracing::info!("Hysteria 2 started successfully (PID: {})", pid);
            Ok(())
        } else {
            anyhow::bail!("Hysteria 2 failed to start")
        }
    }

    async fn stop(&self) -> Result<()> {
        if let Some(pid) = self.get_pid().await {
            tracing::info!("Stopping Hysteria 2 (PID: {})", pid);

            let _ = Command::new("kill")
                .args(["-15", &pid.to_string()])
                .output()
                .await;

            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

            if self.is_process_alive(pid).await {
                let _ = Command::new("kill")
                    .args(["-9", &pid.to_string()])
                    .output()
                    .await;
            }

            let _ = tokio::fs::remove_file(&self.pid_file).await;
            tracing::info!("Hysteria 2 stopped");
        } else {
            let _ = Command::new("pkill")
                .args(["-f", "hysteria"])
                .output()
                .await;
        }

        Ok(())
    }

    async fn reload(&self) -> Result<()> {
        self.write_config().await?;

        if let Some(pid) = self.get_pid().await {
            tracing::info!("Reloading Hysteria 2 configuration (PID: {})", pid);
            Command::new("kill")
                .args(["-1", &pid.to_string()])
                .output()
                .await
                .context("Failed to send SIGHUP to Hysteria 2")?;
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            tracing::info!("Hysteria 2 configuration reloaded");
            Ok(())
        } else {
            self.start().await
        }
    }

    async fn apply_profile(&self, profile: &TrafficProfile) -> Result<()> {
        tracing::info!("Applying profile to Hysteria 2: {}", profile.name);
        self.configure_from_profile(profile);
        self.write_config().await?;
        tracing::debug!("Hysteria 2 profile applied: {:?}", profile);
        Ok(())
    }

    async fn connection_count(&self) -> Result<u32> {
        // Hysteria 2 API endpoint for stats
        let output = Command::new("ss")
            .args(["-un", "state", "established"])
            .output()
            .await?;

        let port = {
            let config = self.config.read();
            config
                .server
                .split(':')
                .last()
                .and_then(|p| p.parse::<u16>().ok())
                .unwrap_or(443)
        };

        let stdout = String::from_utf8_lossy(&output.stdout);
        let count = stdout
            .lines()
            .filter(|line| line.contains(&format!(":{}", port)))
            .count();

        Ok(count as u32)
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
    fn test_hysteria2_config_yaml() {
        let config = Hysteria2Config::client("example.com:443", "mypassword")
            .with_obfs("obfs_secret")
            .with_bandwidth("50 mbps", "200 mbps");

        let yaml = config.to_yaml().unwrap();
        assert!(yaml.contains("example.com:443"));
        assert!(yaml.contains("mypassword"));
        assert!(yaml.contains("salamander"));
    }
}
