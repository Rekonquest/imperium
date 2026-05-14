//! Snowflake (Tor Pluggable Transport) controller
//!
//! Snowflake is a Tor pluggable transport that uses WebRTC to relay traffic
//! through volunteer browsers. This makes it extremely difficult to block
//! because:
//! - Traffic appears as regular WebRTC video/voice calls
//! - Relays are ephemeral volunteer browsers, constantly changing
//! - Uses domain fronting to reach the broker
//!
//! Components:
//! - Client: Connects to Tor via Snowflake proxies
//! - Proxy: Volunteer browser that relays traffic
//! - Broker: Matches clients with proxies

use crate::config::Protocol;
use crate::vpn::{TrafficProfile, VpnController, VpnStatus};
use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::process::Command;

/// Snowflake mode (client or proxy)
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SnowflakeMode {
    /// Client mode - connect via Snowflake proxies
    Client,
    /// Proxy mode - volunteer to relay traffic
    Proxy,
}

impl Default for SnowflakeMode {
    fn default() -> Self {
        Self::Client
    }
}

/// ICE server configuration for WebRTC
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IceServer {
    /// Server URL (stun: or turn:)
    pub url: String,
    /// Username (for TURN)
    pub username: Option<String>,
    /// Credential (for TURN)
    pub credential: Option<String>,
}

impl Default for IceServer {
    fn default() -> Self {
        Self {
            url: "stun:stun.l.google.com:19302".to_string(),
            username: None,
            credential: None,
        }
    }
}

/// Snowflake configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnowflakeConfig {
    /// Operating mode
    #[serde(default)]
    pub mode: SnowflakeMode,
    /// Broker URL
    #[serde(default = "default_broker")]
    pub broker: String,
    /// Relay URL (for AMP cache fronting)
    #[serde(default = "default_relay")]
    pub relay: String,
    /// STUN servers for WebRTC
    #[serde(default = "default_stun")]
    pub stun: String,
    /// Front domain for domain fronting
    #[serde(default = "default_front")]
    pub front: String,
    /// ICE servers
    #[serde(default = "default_ice_servers")]
    pub ice_servers: Vec<IceServer>,
    /// Listen address (client mode SOCKS proxy)
    #[serde(default = "default_listen")]
    pub listen: String,
    /// Keep local addresses (for proxies behind NAT)
    #[serde(default)]
    pub keep_local_addresses: bool,
    /// Unsafe logging (include IPs in logs)
    #[serde(default)]
    pub unsafe_logging: bool,
    /// Max peers (proxy mode)
    #[serde(default = "default_max_peers")]
    pub max_peers: u32,
    /// Capacity (proxy mode - bandwidth in KB/s)
    #[serde(default)]
    pub capacity: Option<u32>,
    /// AMP cache URL (alternative to broker)
    pub amp_cache: Option<String>,
    /// SOCKS fallback address
    pub socks_fallback: Option<String>,
}

fn default_broker() -> String {
    "https://snowflake-broker.torproject.net/".to_string()
}

fn default_relay() -> String {
    "wss://snowflake.torproject.net/".to_string()
}

fn default_stun() -> String {
    "stun:stun.l.google.com:19302".to_string()
}

fn default_front() -> String {
    "cdn.sstatic.net".to_string()
}

fn default_ice_servers() -> Vec<IceServer> {
    vec![
        IceServer {
            url: "stun:stun.l.google.com:19302".to_string(),
            username: None,
            credential: None,
        },
        IceServer {
            url: "stun:stun.voip.blackberry.com:3478".to_string(),
            username: None,
            credential: None,
        },
    ]
}

fn default_listen() -> String {
    "127.0.0.1:9050".to_string()
}

fn default_max_peers() -> u32 {
    10
}

impl Default for SnowflakeConfig {
    fn default() -> Self {
        Self {
            mode: SnowflakeMode::Client,
            broker: default_broker(),
            relay: default_relay(),
            stun: default_stun(),
            front: default_front(),
            ice_servers: default_ice_servers(),
            listen: default_listen(),
            keep_local_addresses: false,
            unsafe_logging: false,
            max_peers: default_max_peers(),
            capacity: None,
            amp_cache: None,
            socks_fallback: None,
        }
    }
}

impl SnowflakeConfig {
    /// Create a client configuration
    pub fn client() -> Self {
        Self {
            mode: SnowflakeMode::Client,
            ..Default::default()
        }
    }

    /// Create a proxy configuration (volunteer mode)
    pub fn proxy() -> Self {
        Self {
            mode: SnowflakeMode::Proxy,
            ..Default::default()
        }
    }

    /// Use custom broker with domain fronting
    pub fn with_fronted_broker(mut self, broker: &str, front: &str) -> Self {
        self.broker = broker.to_string();
        self.front = front.to_string();
        self
    }

    /// Use AMP cache fronting (alternative censorship evasion)
    pub fn with_amp_cache(mut self, amp_cache_url: &str) -> Self {
        self.amp_cache = Some(amp_cache_url.to_string());
        self
    }

    /// Build command line arguments
    pub fn to_args(&self) -> Vec<String> {
        let mut args = Vec::new();

        match self.mode {
            SnowflakeMode::Client => {
                args.push("-url".to_string());
                args.push(self.broker.clone());
                args.push("-front".to_string());
                args.push(self.front.clone());
                args.push("-ice".to_string());
                args.push(self.stun.clone());
                args.push("-listen".to_string());
                args.push(self.listen.clone());

                if let Some(ref amp) = self.amp_cache {
                    args.push("-ampcache".to_string());
                    args.push(amp.clone());
                }

                if self.keep_local_addresses {
                    args.push("-keep-local-addresses".to_string());
                }

                if self.unsafe_logging {
                    args.push("-unsafe-logging".to_string());
                }
            }
            SnowflakeMode::Proxy => {
                args.push("-broker".to_string());
                args.push(self.broker.clone());
                args.push("-relay".to_string());
                args.push(self.relay.clone());
                args.push("-stun".to_string());
                args.push(self.stun.clone());

                if self.max_peers > 0 {
                    args.push("-capacity".to_string());
                    args.push(self.max_peers.to_string());
                }

                if let Some(cap) = self.capacity {
                    args.push("-bandwidth".to_string());
                    args.push(cap.to_string());
                }

                if self.keep_local_addresses {
                    args.push("-keep-local-addresses".to_string());
                }

                if self.unsafe_logging {
                    args.push("-unsafe-logging".to_string());
                }
            }
        }

        args
    }
}

/// Snowflake VPN controller
pub struct SnowflakeController {
    config_dir: PathBuf,
    config: parking_lot::RwLock<SnowflakeConfig>,
    client_binary: PathBuf,
    proxy_binary: PathBuf,
    pid_file: PathBuf,
}

impl SnowflakeController {
    /// Create a new Snowflake controller
    pub fn new(config_dir: &Path) -> Self {
        Self {
            config_dir: config_dir.to_path_buf(),
            config: parking_lot::RwLock::new(SnowflakeConfig::default()),
            client_binary: PathBuf::from("/usr/local/bin/snowflake-client"),
            proxy_binary: PathBuf::from("/usr/local/bin/snowflake-proxy"),
            pid_file: config_dir.join("snowflake.pid"),
        }
    }

    /// Get the appropriate binary based on mode
    fn binary_path(&self) -> PathBuf {
        let config = self.config.read();
        match config.mode {
            SnowflakeMode::Client => self.client_binary.clone(),
            SnowflakeMode::Proxy => self.proxy_binary.clone(),
        }
    }

    /// Get command line arguments
    fn get_args(&self) -> Vec<String> {
        let config = self.config.read();
        config.to_args()
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

        // Mode
        if let Some(val) = profile.custom_config.get("mode") {
            if let Some(s) = val.as_str() {
                config.mode = match s.to_lowercase().as_str() {
                    "proxy" => SnowflakeMode::Proxy,
                    _ => SnowflakeMode::Client,
                };
            }
        }

        // Listen address (use profile port)
        config.listen = format!("127.0.0.1:{}", profile.port);

        // Broker
        if let Some(val) = profile.custom_config.get("broker") {
            if let Some(s) = val.as_str() {
                config.broker = s.to_string();
            }
        }

        // Front domain
        if let Some(val) = profile.custom_config.get("front") {
            if let Some(s) = val.as_str() {
                config.front = s.to_string();
            }
        }

        // Relay
        if let Some(val) = profile.custom_config.get("relay") {
            if let Some(s) = val.as_str() {
                config.relay = s.to_string();
            }
        }

        // STUN servers
        if let Some(val) = profile.custom_config.get("stun") {
            if let Some(s) = val.as_str() {
                config.stun = s.to_string();
            }
        }

        // AMP cache
        if let Some(val) = profile.custom_config.get("amp_cache") {
            if let Some(s) = val.as_str() {
                config.amp_cache = Some(s.to_string());
            }
        }

        // Max peers (proxy mode)
        if let Some(val) = profile.custom_config.get("max_peers") {
            if let Some(n) = val.as_u64() {
                config.max_peers = n as u32;
            }
        }

        // Capacity (proxy mode)
        if let Some(val) = profile.custom_config.get("capacity") {
            if let Some(n) = val.as_u64() {
                config.capacity = Some(n as u32);
            }
        }
    }
}

#[async_trait]
impl VpnController for SnowflakeController {
    fn protocol(&self) -> Protocol {
        Protocol::Snowflake
    }

    async fn is_running(&self) -> Result<bool> {
        if let Some(pid) = self.get_pid().await {
            Ok(self.is_process_alive(pid).await)
        } else {
            let output = Command::new("pgrep")
                .args(["-f", "snowflake"])
                .output()
                .await?;
            Ok(output.status.success())
        }
    }

    async fn start(&self) -> Result<()> {
        if self.is_running().await? {
            tracing::info!("Snowflake is already running");
            return Ok(());
        }

        let binary = self.binary_path();
        let args = self.get_args();

        tracing::info!("Starting Snowflake with binary: {:?}, args: {:?}", binary, args);

        tokio::fs::create_dir_all(&self.config_dir).await?;

        let child = Command::new(&binary)
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("Failed to start Snowflake")?;

        let pid = child.id().unwrap_or(0);
        tokio::fs::write(&self.pid_file, pid.to_string()).await?;

        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

        if self.is_running().await? {
            tracing::info!("Snowflake started successfully (PID: {})", pid);
            Ok(())
        } else {
            anyhow::bail!("Snowflake failed to start")
        }
    }

    async fn stop(&self) -> Result<()> {
        if let Some(pid) = self.get_pid().await {
            tracing::info!("Stopping Snowflake (PID: {})", pid);

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
            tracing::info!("Snowflake stopped");
        } else {
            let _ = Command::new("pkill")
                .args(["-f", "snowflake"])
                .output()
                .await;
        }

        Ok(())
    }

    async fn reload(&self) -> Result<()> {
        // Snowflake doesn't support reload, restart instead
        self.stop().await?;
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        self.start().await
    }

    async fn apply_profile(&self, profile: &TrafficProfile) -> Result<()> {
        tracing::info!("Applying profile to Snowflake: {}", profile.name);
        self.configure_from_profile(profile);
        tracing::debug!("Snowflake profile applied: {:?}", profile);
        Ok(())
    }

    async fn connection_count(&self) -> Result<u32> {
        let port = {
            let config = self.config.read();
            config
                .listen
                .split(':')
                .last()
                .and_then(|p| p.parse::<u16>().ok())
                .unwrap_or(9050)
        };

        let output = Command::new("ss")
            .args(["-tn", "state", "established"])
            .output()
            .await?;

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
    fn test_snowflake_client_args() {
        let config = SnowflakeConfig::client()
            .with_fronted_broker("https://broker.example.com/", "cdn.example.com");

        let args = config.to_args();
        assert!(args.contains(&"-url".to_string()));
        assert!(args.contains(&"-front".to_string()));
    }

    #[test]
    fn test_snowflake_proxy_args() {
        let config = SnowflakeConfig::proxy();
        let args = config.to_args();
        assert!(args.contains(&"-broker".to_string()));
        assert!(args.contains(&"-relay".to_string()));
    }
}
