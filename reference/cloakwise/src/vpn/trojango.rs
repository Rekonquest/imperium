//! Trojan-Go VPN controller
//!
//! Trojan-Go is an enhanced Trojan protocol implementation with unique features:
//! - Multiplexing (smux) for connection reuse
//! - WebSocket transport for CDN bypass
//! - Shadowsocks plugin support
//! - XTLS for reduced TLS overhead
//! - Router for traffic routing decisions
//! - Native API for remote management

use crate::config::Protocol;
use crate::vpn::{ProfileId, TrafficProfile, VpnController, VpnStatus};
use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::process::Command;

/// Trojan-Go transport type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrojanGoTransport {
    /// Original Trojan protocol (TLS)
    Original,
    /// WebSocket transport (CDN compatible)
    Ws,
    /// HTTP/2 transport
    H2,
    /// gRPC transport
    Grpc,
}

impl Default for TrojanGoTransport {
    fn default() -> Self {
        Self::Original
    }
}

/// Multiplexing configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MuxConfig {
    /// Enable multiplexing
    pub enabled: bool,
    /// Multiplexing concurrency (1-1024)
    #[serde(default = "default_mux_concurrency")]
    pub concurrency: u32,
    /// Idle timeout in seconds
    #[serde(default = "default_mux_idle_timeout")]
    pub idle_timeout: u32,
}

fn default_mux_concurrency() -> u32 {
    8
}

fn default_mux_idle_timeout() -> u32 {
    60
}

impl Default for MuxConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            concurrency: 8,
            idle_timeout: 60,
        }
    }
}

/// WebSocket configuration for CDN bypass
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsConfig {
    /// Enable WebSocket transport
    pub enabled: bool,
    /// WebSocket path
    #[serde(default = "default_ws_path")]
    pub path: String,
    /// WebSocket host header
    pub host: Option<String>,
}

fn default_ws_path() -> String {
    "/trojan".to_string()
}

impl Default for WsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: "/trojan".to_string(),
            host: None,
        }
    }
}

/// TLS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Enable TLS
    pub enabled: bool,
    /// Server name indication (SNI)
    pub sni: Option<String>,
    /// ALPN protocols
    #[serde(default = "default_alpn")]
    pub alpn: Vec<String>,
    /// Certificate path (for server)
    pub cert_path: Option<PathBuf>,
    /// Key path (for server)
    pub key_path: Option<PathBuf>,
    /// Skip certificate verification (client only, not recommended)
    #[serde(default)]
    pub verify: bool,
    /// Enable XTLS (reduced TLS overhead)
    #[serde(default)]
    pub xtls: bool,
    /// Fingerprint to mimic (chrome, firefox, safari, ios, android, edge, 360, qq)
    pub fingerprint: Option<String>,
}

fn default_alpn() -> Vec<String> {
    vec!["h2".to_string(), "http/1.1".to_string()]
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            sni: None,
            alpn: default_alpn(),
            cert_path: None,
            key_path: None,
            verify: true,
            xtls: false,
            fingerprint: Some("chrome".to_string()),
        }
    }
}

/// Router configuration for traffic routing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouterConfig {
    /// Enable router
    pub enabled: bool,
    /// Bypass local addresses
    #[serde(default = "default_true")]
    pub bypass_local: bool,
    /// Bypass China addresses (uses geoip)
    #[serde(default)]
    pub bypass_china: bool,
    /// Block ads
    #[serde(default)]
    pub block_ads: bool,
    /// Custom bypass domains
    #[serde(default)]
    pub bypass_domains: Vec<String>,
    /// Custom block domains
    #[serde(default)]
    pub block_domains: Vec<String>,
}

fn default_true() -> bool {
    true
}

impl Default for RouterConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bypass_local: true,
            bypass_china: false,
            block_ads: false,
            bypass_domains: vec![],
            block_domains: vec![],
        }
    }
}

/// Shadowsocks plugin configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowsocksPluginConfig {
    /// Enable Shadowsocks AEAD plugin
    pub enabled: bool,
    /// Shadowsocks method (aes-128-gcm, aes-256-gcm, chacha20-ietf-poly1305)
    #[serde(default = "default_ss_method")]
    pub method: String,
    /// Shadowsocks password (separate from Trojan password)
    pub password: Option<String>,
}

fn default_ss_method() -> String {
    "aes-128-gcm".to_string()
}

impl Default for ShadowsocksPluginConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            method: "aes-128-gcm".to_string(),
            password: None,
        }
    }
}

/// Complete Trojan-Go server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrojanGoConfig {
    /// Run mode (server/client)
    pub run_type: String,
    /// Local address to bind
    pub local_addr: String,
    /// Local port
    pub local_port: u16,
    /// Remote server address (client mode)
    pub remote_addr: Option<String>,
    /// Remote port (client mode)
    pub remote_port: Option<u16>,
    /// Trojan password(s)
    pub passwords: Vec<String>,
    /// Transport type
    #[serde(default)]
    pub transport: TrojanGoTransport,
    /// TLS configuration
    #[serde(default)]
    pub tls: TlsConfig,
    /// WebSocket configuration
    #[serde(default)]
    pub websocket: WsConfig,
    /// Multiplexing configuration
    #[serde(default)]
    pub mux: MuxConfig,
    /// Router configuration
    #[serde(default)]
    pub router: RouterConfig,
    /// Shadowsocks plugin
    #[serde(default)]
    pub shadowsocks: ShadowsocksPluginConfig,
    /// TCP settings
    #[serde(default)]
    pub tcp: TcpConfig,
    /// API configuration
    #[serde(default)]
    pub api: ApiConfig,
}

/// TCP optimization settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpConfig {
    /// Enable TCP fast open
    #[serde(default)]
    pub fast_open: bool,
    /// Enable TCP no delay
    #[serde(default = "default_true")]
    pub no_delay: bool,
    /// Keep alive interval
    #[serde(default = "default_keep_alive")]
    pub keep_alive: u32,
}

fn default_keep_alive() -> u32 {
    30
}

impl Default for TcpConfig {
    fn default() -> Self {
        Self {
            fast_open: false,
            no_delay: true,
            keep_alive: 30,
        }
    }
}

/// API configuration for remote management
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    /// Enable API
    pub enabled: bool,
    /// API listen address
    #[serde(default = "default_api_addr")]
    pub api_addr: String,
    /// API port
    #[serde(default = "default_api_port")]
    pub api_port: u16,
}

fn default_api_addr() -> String {
    "127.0.0.1".to_string()
}

fn default_api_port() -> u16 {
    10000
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            api_addr: "127.0.0.1".to_string(),
            api_port: 10000,
        }
    }
}

impl Default for TrojanGoConfig {
    fn default() -> Self {
        Self {
            run_type: "server".to_string(),
            local_addr: "0.0.0.0".to_string(),
            local_port: 443,
            remote_addr: None,
            remote_port: None,
            passwords: vec![],
            transport: TrojanGoTransport::Original,
            tls: TlsConfig::default(),
            websocket: WsConfig::default(),
            mux: MuxConfig::default(),
            router: RouterConfig::default(),
            shadowsocks: ShadowsocksPluginConfig::default(),
            tcp: TcpConfig::default(),
            api: ApiConfig::default(),
        }
    }
}

impl TrojanGoConfig {
    /// Create a basic server configuration
    pub fn server(port: u16, passwords: Vec<String>, cert_path: &Path, key_path: &Path) -> Self {
        Self {
            run_type: "server".to_string(),
            local_addr: "0.0.0.0".to_string(),
            local_port: port,
            passwords,
            tls: TlsConfig {
                enabled: true,
                cert_path: Some(cert_path.to_path_buf()),
                key_path: Some(key_path.to_path_buf()),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// Create a WebSocket configuration for CDN bypass
    pub fn with_websocket(mut self, path: &str, host: Option<String>) -> Self {
        self.transport = TrojanGoTransport::Ws;
        self.websocket = WsConfig {
            enabled: true,
            path: path.to_string(),
            host,
        };
        self
    }

    /// Enable multiplexing
    pub fn with_mux(mut self, concurrency: u32) -> Self {
        self.mux = MuxConfig {
            enabled: true,
            concurrency,
            idle_timeout: 60,
        };
        self
    }

    /// Enable XTLS
    pub fn with_xtls(mut self) -> Self {
        self.tls.xtls = true;
        self
    }

    /// Enable Shadowsocks plugin
    pub fn with_shadowsocks(mut self, method: &str, password: &str) -> Self {
        self.shadowsocks = ShadowsocksPluginConfig {
            enabled: true,
            method: method.to_string(),
            password: Some(password.to_string()),
        };
        self
    }

    /// Convert to Trojan-Go JSON config format
    pub fn to_json(&self) -> Result<String> {
        // Build the native Trojan-Go config format
        let mut config = serde_json::json!({
            "run_type": self.run_type,
            "local_addr": self.local_addr,
            "local_port": self.local_port,
            "password": self.passwords,
        });

        if let Some(ref remote) = self.remote_addr {
            config["remote_addr"] = serde_json::json!(remote);
        }
        if let Some(port) = self.remote_port {
            config["remote_port"] = serde_json::json!(port);
        }

        // TLS settings
        let mut ssl = serde_json::json!({
            "verify": self.tls.verify,
            "alpn": self.tls.alpn,
        });
        if let Some(ref sni) = self.tls.sni {
            ssl["sni"] = serde_json::json!(sni);
        }
        if let Some(ref cert) = self.tls.cert_path {
            ssl["cert"] = serde_json::json!(cert.to_string_lossy());
        }
        if let Some(ref key) = self.tls.key_path {
            ssl["key"] = serde_json::json!(key.to_string_lossy());
        }
        if let Some(ref fp) = self.tls.fingerprint {
            ssl["fingerprint"] = serde_json::json!(fp);
        }
        config["ssl"] = ssl;

        // Transport settings
        match self.transport {
            TrojanGoTransport::Ws => {
                config["websocket"] = serde_json::json!({
                    "enabled": true,
                    "path": self.websocket.path,
                    "host": self.websocket.host.as_deref().unwrap_or("")
                });
            }
            TrojanGoTransport::H2 => {
                config["transport_plugin"] = serde_json::json!({
                    "enabled": true,
                    "type": "h2"
                });
            }
            TrojanGoTransport::Grpc => {
                config["transport_plugin"] = serde_json::json!({
                    "enabled": true,
                    "type": "grpc",
                    "command": "",
                    "arg": []
                });
            }
            TrojanGoTransport::Original => {}
        }

        // Mux settings
        if self.mux.enabled {
            config["mux"] = serde_json::json!({
                "enabled": true,
                "concurrency": self.mux.concurrency,
                "idle_timeout": self.mux.idle_timeout
            });
        }

        // Router settings
        if self.router.enabled {
            let mut router = serde_json::json!({
                "enabled": true,
                "bypass": [],
                "block": [],
                "proxy": []
            });

            if self.router.bypass_local {
                router["bypass"]
                    .as_array_mut()
                    .unwrap()
                    .push(serde_json::json!("geoip:private"));
            }
            if self.router.bypass_china {
                router["bypass"]
                    .as_array_mut()
                    .unwrap()
                    .push(serde_json::json!("geoip:cn"));
                router["bypass"]
                    .as_array_mut()
                    .unwrap()
                    .push(serde_json::json!("geosite:cn"));
            }
            if self.router.block_ads {
                router["block"]
                    .as_array_mut()
                    .unwrap()
                    .push(serde_json::json!("geosite:category-ads"));
            }

            for domain in &self.router.bypass_domains {
                router["bypass"]
                    .as_array_mut()
                    .unwrap()
                    .push(serde_json::json!(domain));
            }
            for domain in &self.router.block_domains {
                router["block"]
                    .as_array_mut()
                    .unwrap()
                    .push(serde_json::json!(domain));
            }

            config["router"] = router;
        }

        // Shadowsocks plugin
        if self.shadowsocks.enabled {
            config["shadowsocks"] = serde_json::json!({
                "enabled": true,
                "method": self.shadowsocks.method,
                "password": self.shadowsocks.password.as_deref().unwrap_or("")
            });
        }

        // TCP settings
        config["tcp"] = serde_json::json!({
            "fast_open": self.tcp.fast_open,
            "no_delay": self.tcp.no_delay,
            "keep_alive": self.tcp.keep_alive > 0
        });

        // API settings
        if self.api.enabled {
            config["api"] = serde_json::json!({
                "enabled": true,
                "api_addr": self.api.api_addr,
                "api_port": self.api.api_port
            });
        }

        serde_json::to_string_pretty(&config).context("Failed to serialize Trojan-Go config")
    }
}

/// Trojan-Go VPN controller
pub struct TrojanGoController {
    config_dir: PathBuf,
    config: parking_lot::RwLock<TrojanGoConfig>,
    binary_path: PathBuf,
    pid_file: PathBuf,
}

impl TrojanGoController {
    /// Create a new Trojan-Go controller
    pub fn new(config_dir: &Path) -> Self {
        Self {
            config_dir: config_dir.to_path_buf(),
            config: parking_lot::RwLock::new(TrojanGoConfig::default()),
            binary_path: PathBuf::from("/usr/local/bin/trojan-go"),
            pid_file: config_dir.join("trojan-go.pid"),
        }
    }

    /// Get the config file path
    fn config_file(&self) -> PathBuf {
        self.config_dir.join("trojan-go.json")
    }

    /// Write configuration to file
    async fn write_config(&self) -> Result<()> {
        let json = {
            let config = self.config.read();
            config.to_json()?
        };

        tokio::fs::create_dir_all(&self.config_dir).await?;
        tokio::fs::write(self.config_file(), json).await?;

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

        config.local_port = profile.port;

        // Configure transport based on obfuscation
        match profile.obfuscation {
            crate::config::ObfuscationType::WebsocketUpgrade => {
                config.transport = TrojanGoTransport::Ws;
                config.websocket = WsConfig {
                    enabled: true,
                    path: "/trojan-ws".to_string(),
                    host: None,
                };
            }
            crate::config::ObfuscationType::Http2 => {
                config.transport = TrojanGoTransport::H2;
            }
            crate::config::ObfuscationType::Grpc => {
                config.transport = TrojanGoTransport::Grpc;
            }
            _ => {
                config.transport = TrojanGoTransport::Original;
            }
        }

        // Enable multiplexing for better performance
        config.mux.enabled = true;
        config.mux.concurrency = 8;

        // Apply custom config overrides
        if let Some(val) = profile.custom_config.get("passwords") {
            if let Some(arr) = val.as_sequence() {
                config.passwords = arr
                    .iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect();
            }
        }

        if let Some(val) = profile.custom_config.get("sni") {
            if let Some(s) = val.as_str() {
                config.tls.sni = Some(s.to_string());
            }
        }

        if let Some(val) = profile.custom_config.get("xtls") {
            if let Some(b) = val.as_bool() {
                config.tls.xtls = b;
            }
        }

        if let Some(val) = profile.custom_config.get("fingerprint") {
            if let Some(s) = val.as_str() {
                config.tls.fingerprint = Some(s.to_string());
            }
        }

        if let Some(val) = profile.custom_config.get("ws_path") {
            if let Some(s) = val.as_str() {
                config.websocket.path = s.to_string();
            }
        }

        if let Some(val) = profile.custom_config.get("ws_host") {
            if let Some(s) = val.as_str() {
                config.websocket.host = Some(s.to_string());
            }
        }

        if let Some(val) = profile.custom_config.get("mux_concurrency") {
            if let Some(n) = val.as_u64() {
                config.mux.concurrency = n as u32;
            }
        }

        if let Some(val) = profile.custom_config.get("shadowsocks_enabled") {
            if let Some(b) = val.as_bool() {
                config.shadowsocks.enabled = b;
            }
        }

        if let Some(val) = profile.custom_config.get("shadowsocks_method") {
            if let Some(s) = val.as_str() {
                config.shadowsocks.method = s.to_string();
            }
        }

        if let Some(val) = profile.custom_config.get("shadowsocks_password") {
            if let Some(s) = val.as_str() {
                config.shadowsocks.password = Some(s.to_string());
            }
        }

        if let Some(val) = profile.custom_config.get("cert") {
            if let Some(s) = val.as_str() {
                config.tls.cert_path = Some(PathBuf::from(s));
            }
        }

        if let Some(val) = profile.custom_config.get("key") {
            if let Some(s) = val.as_str() {
                config.tls.key_path = Some(PathBuf::from(s));
            }
        }

        if let Some(val) = profile.custom_config.get("api_enabled") {
            if let Some(b) = val.as_bool() {
                config.api.enabled = b;
            }
        }
    }
}

#[async_trait]
impl VpnController for TrojanGoController {
    fn protocol(&self) -> Protocol {
        Protocol::TrojanGo
    }

    async fn is_running(&self) -> Result<bool> {
        if let Some(pid) = self.get_pid().await {
            Ok(self.is_process_alive(pid).await)
        } else {
            // Check via pgrep as fallback
            let output = Command::new("pgrep")
                .args(["-f", "trojan-go"])
                .output()
                .await?;

            Ok(output.status.success())
        }
    }

    async fn start(&self) -> Result<()> {
        if self.is_running().await? {
            tracing::info!("Trojan-Go is already running");
            return Ok(());
        }

        // Write config
        self.write_config().await?;

        tracing::info!("Starting Trojan-Go with config: {:?}", self.config_file());

        // Start trojan-go process
        let child = Command::new(&self.binary_path)
            .args(["-config", &self.config_file().to_string_lossy()])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("Failed to start Trojan-Go")?;

        // Write PID file
        let pid = child.id().unwrap_or(0);
        tokio::fs::write(&self.pid_file, pid.to_string()).await?;

        // Wait for startup
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        if self.is_running().await? {
            tracing::info!("Trojan-Go started successfully (PID: {})", pid);
            Ok(())
        } else {
            anyhow::bail!("Trojan-Go failed to start")
        }
    }

    async fn stop(&self) -> Result<()> {
        if let Some(pid) = self.get_pid().await {
            tracing::info!("Stopping Trojan-Go (PID: {})", pid);

            // Send SIGTERM
            let _ = Command::new("kill")
                .args(["-15", &pid.to_string()])
                .output()
                .await;

            // Wait for graceful shutdown
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

            // Force kill if still running
            if self.is_process_alive(pid).await {
                let _ = Command::new("kill")
                    .args(["-9", &pid.to_string()])
                    .output()
                    .await;
            }

            // Remove PID file
            let _ = tokio::fs::remove_file(&self.pid_file).await;

            tracing::info!("Trojan-Go stopped");
        } else {
            // Try pkill as fallback
            let _ = Command::new("pkill")
                .args(["-f", "trojan-go"])
                .output()
                .await;
        }

        Ok(())
    }

    async fn reload(&self) -> Result<()> {
        // Write updated config
        self.write_config().await?;

        if let Some(pid) = self.get_pid().await {
            tracing::info!("Reloading Trojan-Go configuration (PID: {})", pid);

            // Send SIGHUP to reload
            Command::new("kill")
                .args(["-1", &pid.to_string()])
                .output()
                .await
                .context("Failed to send SIGHUP to Trojan-Go")?;

            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

            tracing::info!("Trojan-Go configuration reloaded");
            Ok(())
        } else {
            // Not running, just start
            self.start().await
        }
    }

    async fn apply_profile(&self, profile: &TrafficProfile) -> Result<()> {
        tracing::info!("Applying profile to Trojan-Go: {}", profile.name);

        self.configure_from_profile(profile);
        self.write_config().await?;

        tracing::debug!("Trojan-Go profile applied: {:?}", profile);
        Ok(())
    }

    async fn connection_count(&self) -> Result<u32> {
        // Extract config values before any await points
        let (api_enabled, api_url, port) = {
            let config = self.config.read();
            let url = if config.api.enabled {
                Some(format!(
                    "http://{}:{}/api/traffic",
                    config.api.api_addr, config.api.api_port
                ))
            } else {
                None
            };
            (config.api.enabled, url, config.local_port)
        };

        // If API is enabled, query it
        if api_enabled {
            if let Some(url) = api_url {
                // Try to query API
                if let Ok(resp) = reqwest::get(&url).await {
                    if let Ok(json) = resp.json::<serde_json::Value>().await {
                        if let Some(count) = json.get("connection_count").and_then(|v| v.as_u64()) {
                            return Ok(count as u32);
                        }
                    }
                }
            }
        }

        // Fallback: count established connections
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

        // Extract API config before await
        let api_url = {
            let config = self.config.read();
            if config.api.enabled {
                Some(format!(
                    "http://{}:{}/api/traffic",
                    config.api.api_addr, config.api.api_port
                ))
            } else {
                None
            }
        };

        // Get traffic stats from API if available
        let (bytes_sent, bytes_received) = if let Some(url) = api_url {
            if let Ok(resp) = reqwest::get(&url).await {
                if let Ok(json) = resp.json::<serde_json::Value>().await {
                    let up = json.get("upload").and_then(|v| v.as_u64()).unwrap_or(0);
                    let down = json.get("download").and_then(|v| v.as_u64()).unwrap_or(0);
                    (up, down)
                } else {
                    (0, 0)
                }
            } else {
                (0, 0)
            }
        } else {
            (0, 0)
        };

        // Get uptime from process
        let uptime_secs = if let Some(pid) = self.get_pid().await {
            if let Ok(stat) = tokio::fs::read_to_string(format!("/proc/{}/stat", pid)).await {
                // Parse start time from /proc/pid/stat
                let parts: Vec<&str> = stat.split_whitespace().collect();
                if parts.len() > 21 {
                    if let Ok(start_ticks) = parts[21].parse::<u64>() {
                        // Get system uptime
                        if let Ok(uptime_str) = tokio::fs::read_to_string("/proc/uptime").await {
                            if let Some(sys_uptime) = uptime_str
                                .split_whitespace()
                                .next()
                                .and_then(|s| s.parse::<f64>().ok())
                            {
                                let ticks_per_sec = 100u64; // Usually 100 on Linux
                                let start_secs = start_ticks / ticks_per_sec;
                                let proc_uptime = sys_uptime as u64 - start_secs;
                                Some(proc_uptime)
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
            }
        } else {
            None
        };

        Ok(VpnStatus {
            running,
            uptime_secs,
            connections,
            bytes_sent,
            bytes_received,
            last_handshake: None,
            current_profile: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trojan_go_config_json() {
        let config = TrojanGoConfig {
            run_type: "server".to_string(),
            local_addr: "0.0.0.0".to_string(),
            local_port: 443,
            passwords: vec!["password123".to_string()],
            tls: TlsConfig {
                enabled: true,
                sni: Some("example.com".to_string()),
                cert_path: Some(PathBuf::from("/etc/trojan-go/cert.pem")),
                key_path: Some(PathBuf::from("/etc/trojan-go/key.pem")),
                ..Default::default()
            },
            ..Default::default()
        };

        let json = config.to_json().unwrap();
        assert!(json.contains("password123"));
        assert!(json.contains("example.com"));
    }

    #[test]
    fn test_websocket_config() {
        let config = TrojanGoConfig::default().with_websocket("/ws", Some("cdn.example.com".to_string()));

        let json = config.to_json().unwrap();
        assert!(json.contains("websocket"));
        assert!(json.contains("/ws"));
    }

    #[test]
    fn test_mux_config() {
        let config = TrojanGoConfig::default().with_mux(16);

        let json = config.to_json().unwrap();
        assert!(json.contains("\"mux\""));
        assert!(json.contains("\"concurrency\": 16"));
    }
}
