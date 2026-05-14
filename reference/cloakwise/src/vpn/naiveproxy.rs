//! NaïveProxy VPN controller
//!
//! NaïveProxy uses Chrome's network stack to disguise traffic as regular
//! Chrome browser traffic. This makes it extremely difficult to detect
//! through traffic analysis because:
//! - Uses the exact same TLS fingerprint as Chrome
//! - Implements HTTP/2 multiplexing identically to Chrome
//! - Padding and timing patterns match real browser behavior
//!
//! Server requires Caddy with forwardproxy plugin.

use crate::config::Protocol;
use crate::vpn::{TrafficProfile, VpnController, VpnStatus};
use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::process::Command;

/// NaïveProxy protocol type
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NaiveProtocol {
    /// HTTPS proxy (most common)
    Https,
    /// QUIC-based proxy
    Quic,
}

impl Default for NaiveProtocol {
    fn default() -> Self {
        Self::Https
    }
}

/// Padding configuration to further disguise traffic
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaddingConfig {
    /// Enable padding
    pub enabled: bool,
    /// Padding header name
    #[serde(default = "default_padding_header")]
    pub header: String,
}

fn default_padding_header() -> String {
    "padding".to_string()
}

impl Default for PaddingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            header: default_padding_header(),
        }
    }
}

/// Complete NaïveProxy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NaiveProxyConfig {
    /// Listen address for local proxy
    pub listen: String,
    /// Remote proxy server URL (e.g., https://user:pass@example.com)
    pub proxy: String,
    /// Protocol (https or quic)
    #[serde(default)]
    pub protocol: NaiveProtocol,
    /// Padding configuration
    #[serde(default)]
    pub padding: PaddingConfig,
    /// Log level
    #[serde(default = "default_log")]
    pub log: String,
    /// Extra headers to send
    #[serde(default)]
    pub extra_headers: Vec<(String, String)>,
    /// Host header override
    pub host_resolver_rules: Option<String>,
    /// Insecure mode (skip cert verification)
    #[serde(default)]
    pub insecure: bool,
    /// Concurrent connections limit
    #[serde(default = "default_concurrency")]
    pub concurrency: u32,
}

fn default_log() -> String {
    "".to_string()
}

fn default_concurrency() -> u32 {
    16
}

impl Default for NaiveProxyConfig {
    fn default() -> Self {
        Self {
            listen: "socks://127.0.0.1:1080".to_string(),
            proxy: "https://user:pass@example.com".to_string(),
            protocol: NaiveProtocol::Https,
            padding: PaddingConfig::default(),
            log: default_log(),
            extra_headers: vec![],
            host_resolver_rules: None,
            insecure: false,
            concurrency: default_concurrency(),
        }
    }
}

impl NaiveProxyConfig {
    /// Create a client configuration
    pub fn client(proxy_url: &str) -> Self {
        Self {
            proxy: proxy_url.to_string(),
            ..Default::default()
        }
    }

    /// Create a client with SOCKS5 listener
    pub fn socks5(listen_addr: &str, proxy_url: &str) -> Self {
        Self {
            listen: format!("socks://{}", listen_addr),
            proxy: proxy_url.to_string(),
            ..Default::default()
        }
    }

    /// Create a client with HTTP listener
    pub fn http(listen_addr: &str, proxy_url: &str) -> Self {
        Self {
            listen: format!("http://{}", listen_addr),
            proxy: proxy_url.to_string(),
            ..Default::default()
        }
    }

    /// Use QUIC protocol instead of HTTPS
    pub fn with_quic(mut self) -> Self {
        self.protocol = NaiveProtocol::Quic;
        // Update proxy URL scheme
        if self.proxy.starts_with("https://") {
            self.proxy = self.proxy.replace("https://", "quic://");
        }
        self
    }

    /// Add extra header
    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.extra_headers.push((name.to_string(), value.to_string()));
        self
    }

    /// Build command line arguments
    pub fn to_args(&self) -> Vec<String> {
        let mut args = vec![
            format!("--listen={}", self.listen),
            format!("--proxy={}", self.proxy),
        ];

        if self.padding.enabled {
            args.push(format!("--extra-headers={}:1500", self.padding.header));
        }

        for (name, value) in &self.extra_headers {
            args.push(format!("--extra-headers={}:{}", name, value));
        }

        if let Some(ref rules) = self.host_resolver_rules {
            args.push(format!("--host-resolver-rules={}", rules));
        }

        if self.insecure {
            args.push("--insecure-concurrency=1".to_string());
        }

        if !self.log.is_empty() {
            args.push(format!("--log={}", self.log));
        }

        args
    }

    /// Convert to JSON config format
    pub fn to_json(&self) -> Result<String> {
        let config = serde_json::json!({
            "listen": self.listen,
            "proxy": self.proxy,
            "log": self.log,
            "insecure-concurrency": if self.insecure { 1 } else { 0 },
            "extra-headers": self.extra_headers.iter()
                .map(|(k, v)| format!("{}:{}", k, v))
                .chain(
                    if self.padding.enabled {
                        Some(format!("{}:1500", self.padding.header))
                    } else {
                        None
                    }
                )
                .collect::<Vec<_>>()
                .join("\n"),
        });

        serde_json::to_string_pretty(&config).context("Failed to serialize NaiveProxy config")
    }
}

/// NaïveProxy VPN controller
pub struct NaiveProxyController {
    config_dir: PathBuf,
    config: parking_lot::RwLock<NaiveProxyConfig>,
    binary_path: PathBuf,
    pid_file: PathBuf,
}

impl NaiveProxyController {
    /// Create a new NaïveProxy controller
    pub fn new(config_dir: &Path) -> Self {
        Self {
            config_dir: config_dir.to_path_buf(),
            config: parking_lot::RwLock::new(NaiveProxyConfig::default()),
            binary_path: PathBuf::from("/usr/local/bin/naive"),
            pid_file: config_dir.join("naive.pid"),
        }
    }

    /// Get the config file path
    fn config_file(&self) -> PathBuf {
        self.config_dir.join("naive.json")
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

        // Proxy URL
        if let Some(val) = profile.custom_config.get("proxy") {
            if let Some(s) = val.as_str() {
                config.proxy = s.to_string();
            }
        }

        // Listen address
        if let Some(val) = profile.custom_config.get("listen") {
            if let Some(s) = val.as_str() {
                config.listen = s.to_string();
            }
        } else {
            config.listen = format!("socks://127.0.0.1:{}", profile.port);
        }

        // Protocol (https/quic)
        if let Some(val) = profile.custom_config.get("protocol") {
            if let Some(s) = val.as_str() {
                config.protocol = match s.to_lowercase().as_str() {
                    "quic" => NaiveProtocol::Quic,
                    _ => NaiveProtocol::Https,
                };
            }
        }

        // Use QUIC based on obfuscation setting
        if profile.obfuscation == crate::config::ObfuscationType::Quic {
            config.protocol = NaiveProtocol::Quic;
            if config.proxy.starts_with("https://") {
                config.proxy = config.proxy.replace("https://", "quic://");
            }
        }

        // Padding
        if let Some(val) = profile.custom_config.get("padding") {
            if let Some(b) = val.as_bool() {
                config.padding.enabled = b;
            }
        }

        // Extra headers
        if let Some(val) = profile.custom_config.get("extra_headers") {
            if let Some(arr) = val.as_sequence() {
                config.extra_headers = arr
                    .iter()
                    .filter_map(|v| {
                        v.as_str().and_then(|s| {
                            let parts: Vec<&str> = s.splitn(2, ':').collect();
                            if parts.len() == 2 {
                                Some((parts[0].to_string(), parts[1].to_string()))
                            } else {
                                None
                            }
                        })
                    })
                    .collect();
            }
        }

        // Concurrency
        if let Some(val) = profile.custom_config.get("concurrency") {
            if let Some(n) = val.as_u64() {
                config.concurrency = n as u32;
            }
        }
    }
}

#[async_trait]
impl VpnController for NaiveProxyController {
    fn protocol(&self) -> Protocol {
        Protocol::NaiveProxy
    }

    async fn is_running(&self) -> Result<bool> {
        if let Some(pid) = self.get_pid().await {
            Ok(self.is_process_alive(pid).await)
        } else {
            let output = Command::new("pgrep")
                .args(["-f", "naive"])
                .output()
                .await?;
            Ok(output.status.success())
        }
    }

    async fn start(&self) -> Result<()> {
        if self.is_running().await? {
            tracing::info!("NaïveProxy is already running");
            return Ok(());
        }

        self.write_config().await?;
        let args = self.get_args();

        tracing::info!("Starting NaïveProxy with args: {:?}", args);

        let child = Command::new(&self.binary_path)
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("Failed to start NaïveProxy")?;

        let pid = child.id().unwrap_or(0);
        tokio::fs::write(&self.pid_file, pid.to_string()).await?;

        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        if self.is_running().await? {
            tracing::info!("NaïveProxy started successfully (PID: {})", pid);
            Ok(())
        } else {
            anyhow::bail!("NaïveProxy failed to start")
        }
    }

    async fn stop(&self) -> Result<()> {
        if let Some(pid) = self.get_pid().await {
            tracing::info!("Stopping NaïveProxy (PID: {})", pid);

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
            tracing::info!("NaïveProxy stopped");
        } else {
            let _ = Command::new("pkill")
                .args(["-f", "naive"])
                .output()
                .await;
        }

        Ok(())
    }

    async fn reload(&self) -> Result<()> {
        // NaïveProxy doesn't support reload, restart instead
        self.stop().await?;
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        self.start().await
    }

    async fn apply_profile(&self, profile: &TrafficProfile) -> Result<()> {
        tracing::info!("Applying profile to NaïveProxy: {}", profile.name);
        self.configure_from_profile(profile);
        self.write_config().await?;
        tracing::debug!("NaïveProxy profile applied: {:?}", profile);
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
                .unwrap_or(1080)
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
    fn test_naive_config_args() {
        let config = NaiveProxyConfig::socks5("127.0.0.1:1080", "https://user:pass@example.com")
            .with_header("X-Custom", "value");

        let args = config.to_args();
        assert!(args.iter().any(|a| a.contains("socks://127.0.0.1:1080")));
        assert!(args.iter().any(|a| a.contains("example.com")));
    }

    #[test]
    fn test_naive_quic() {
        let config = NaiveProxyConfig::client("https://user:pass@example.com").with_quic();
        assert!(config.proxy.starts_with("quic://"));
    }
}
