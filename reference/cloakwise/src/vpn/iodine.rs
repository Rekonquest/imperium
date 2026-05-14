//! Iodine IP-over-DNS tunnel controller
//!
//! Iodine tunnels IPv4 data through DNS queries and responses.
//! This is useful for bypassing captive portals and firewalls that
//! allow DNS traffic. Features:
//! - Tunnels IP traffic through DNS TXT, NULL, PRIVATE, MX, CNAME, A records
//! - Automatic encoding selection (base32, base64, base128)
//! - Automatic MTU probing
//! - Password authentication
//! - Works even when only DNS port 53 is allowed
//!
//! Note: Requires a domain with NS records pointing to your server.

use crate::config::Protocol;
use crate::vpn::{TrafficProfile, VpnController, VpnStatus};
use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::process::Command;

/// Iodine mode (server or client)
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IodineMode {
    Server,
    Client,
}

impl Default for IodineMode {
    fn default() -> Self {
        Self::Client
    }
}

/// DNS record type for tunneling
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DnsRecordType {
    /// NULL record (best performance, but sometimes blocked)
    Null,
    /// PRIVATE record
    Private,
    /// TXT record (most compatible)
    Txt,
    /// CNAME record
    Cname,
    /// MX record
    Mx,
    /// A record (most compatible, but slowest)
    A,
    /// Auto-detect best type
    Auto,
}

impl Default for DnsRecordType {
    fn default() -> Self {
        Self::Auto
    }
}

/// Encoding type
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IodineEncoding {
    /// Base32 (most compatible)
    Base32,
    /// Base64 (faster, but may not work with all DNS servers)
    Base64,
    /// Base128 (fastest, but least compatible)
    Base128,
    /// Raw encoding (fastest, requires compatible DNS server)
    Raw,
    /// Auto-detect
    Auto,
}

impl Default for IodineEncoding {
    fn default() -> Self {
        Self::Auto
    }
}

/// Iodine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IodineConfig {
    /// Operating mode
    #[serde(default)]
    pub mode: IodineMode,
    /// Tunnel domain (e.g., t.example.com)
    pub domain: String,
    /// Nameserver to use (client mode)
    pub nameserver: Option<String>,
    /// Password for authentication
    pub password: Option<String>,
    /// Tunnel interface IP (server: assigns to clients, client: local)
    #[serde(default = "default_tunnel_ip")]
    pub tunnel_ip: String,
    /// MTU size
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    /// DNS record type
    #[serde(default)]
    pub record_type: DnsRecordType,
    /// Encoding type
    #[serde(default)]
    pub encoding: IodineEncoding,
    /// Listen address (server mode)
    #[serde(default = "default_listen")]
    pub listen: String,
    /// Lazy mode (reduced bandwidth usage)
    #[serde(default)]
    pub lazy: bool,
    /// Raw mode (send minimum DNS headers)
    #[serde(default)]
    pub raw: bool,
    /// Foreground mode (don't fork)
    #[serde(default = "default_true")]
    pub foreground: bool,
    /// TUN device name
    pub device: Option<String>,
    /// Max downstream fragment size
    #[serde(default = "default_fragment")]
    pub max_downstream_frag: u16,
}

fn default_tunnel_ip() -> String {
    "10.0.0.1".to_string()
}

fn default_mtu() -> u16 {
    1130
}

fn default_listen() -> String {
    "0.0.0.0".to_string()
}

fn default_true() -> bool {
    true
}

fn default_fragment() -> u16 {
    1232
}

impl Default for IodineConfig {
    fn default() -> Self {
        Self {
            mode: IodineMode::Client,
            domain: "t.example.com".to_string(),
            nameserver: None,
            password: None,
            tunnel_ip: default_tunnel_ip(),
            mtu: default_mtu(),
            record_type: DnsRecordType::Auto,
            encoding: IodineEncoding::Auto,
            listen: default_listen(),
            lazy: false,
            raw: false,
            foreground: true,
            device: None,
            max_downstream_frag: default_fragment(),
        }
    }
}

impl IodineConfig {
    /// Create a client configuration
    pub fn client(domain: &str, nameserver: Option<&str>) -> Self {
        Self {
            mode: IodineMode::Client,
            domain: domain.to_string(),
            nameserver: nameserver.map(|s| s.to_string()),
            ..Default::default()
        }
    }

    /// Create a server configuration
    pub fn server(domain: &str, tunnel_ip: &str) -> Self {
        Self {
            mode: IodineMode::Server,
            domain: domain.to_string(),
            tunnel_ip: tunnel_ip.to_string(),
            ..Default::default()
        }
    }

    /// Set password
    pub fn with_password(mut self, password: &str) -> Self {
        self.password = Some(password.to_string());
        self
    }

    /// Set DNS record type
    pub fn with_record_type(mut self, record_type: DnsRecordType) -> Self {
        self.record_type = record_type;
        self
    }

    /// Build command line arguments for iodine
    pub fn to_args(&self) -> Vec<String> {
        let mut args = Vec::new();

        // Foreground mode
        if self.foreground {
            args.push("-f".to_string());
        }

        // Password
        if let Some(ref pass) = self.password {
            args.push("-P".to_string());
            args.push(pass.clone());
        }

        // MTU
        args.push("-m".to_string());
        args.push(self.mtu.to_string());

        // Record type
        match self.record_type {
            DnsRecordType::Null => args.push("-Tnull".to_string()),
            DnsRecordType::Private => args.push("-Tprivate".to_string()),
            DnsRecordType::Txt => args.push("-Ttxt".to_string()),
            DnsRecordType::Cname => args.push("-Tcname".to_string()),
            DnsRecordType::Mx => args.push("-Tmx".to_string()),
            DnsRecordType::A => args.push("-Ta".to_string()),
            DnsRecordType::Auto => {}
        }

        // Encoding
        match self.encoding {
            IodineEncoding::Base32 => args.push("-Obase32".to_string()),
            IodineEncoding::Base64 => args.push("-Obase64".to_string()),
            IodineEncoding::Base128 => args.push("-Obase128".to_string()),
            IodineEncoding::Raw => args.push("-Oraw".to_string()),
            IodineEncoding::Auto => {}
        }

        // Lazy mode
        if self.lazy {
            args.push("-L".to_string());
            args.push("1".to_string());
        }

        // Raw mode
        if self.raw {
            args.push("-r".to_string());
        }

        // Device
        if let Some(ref dev) = self.device {
            args.push("-d".to_string());
            args.push(dev.clone());
        }

        // Max fragment size
        args.push("-M".to_string());
        args.push(self.max_downstream_frag.to_string());

        match self.mode {
            IodineMode::Server => {
                // Server-specific args
                args.push("-l".to_string());
                args.push(self.listen.clone());

                // Tunnel IP range
                args.push(self.tunnel_ip.clone());

                // Domain
                args.push(self.domain.clone());
            }
            IodineMode::Client => {
                // Nameserver (optional, uses system DNS if not specified)
                if let Some(ref ns) = self.nameserver {
                    args.push(ns.clone());
                }

                // Domain
                args.push(self.domain.clone());
            }
        }

        args
    }
}

/// Iodine VPN controller
pub struct IodineController {
    config_dir: PathBuf,
    config: parking_lot::RwLock<IodineConfig>,
    server_binary: PathBuf,
    client_binary: PathBuf,
    pid_file: PathBuf,
}

impl IodineController {
    /// Create a new Iodine controller
    pub fn new(config_dir: &Path) -> Self {
        Self {
            config_dir: config_dir.to_path_buf(),
            config: parking_lot::RwLock::new(IodineConfig::default()),
            server_binary: PathBuf::from("/usr/sbin/iodined"),
            client_binary: PathBuf::from("/usr/sbin/iodine"),
            pid_file: config_dir.join("iodine.pid"),
        }
    }

    /// Get the appropriate binary based on mode
    fn binary_path(&self) -> PathBuf {
        let config = self.config.read();
        match config.mode {
            IodineMode::Server => self.server_binary.clone(),
            IodineMode::Client => self.client_binary.clone(),
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
                    "server" => IodineMode::Server,
                    _ => IodineMode::Client,
                };
            }
        }

        // Domain
        if let Some(val) = profile.custom_config.get("domain") {
            if let Some(s) = val.as_str() {
                config.domain = s.to_string();
            }
        }

        // Nameserver
        if let Some(val) = profile.custom_config.get("nameserver") {
            if let Some(s) = val.as_str() {
                config.nameserver = Some(s.to_string());
            }
        }

        // Password
        if let Some(val) = profile.custom_config.get("password") {
            if let Some(s) = val.as_str() {
                config.password = Some(s.to_string());
            }
        }

        // Tunnel IP
        if let Some(val) = profile.custom_config.get("tunnel_ip") {
            if let Some(s) = val.as_str() {
                config.tunnel_ip = s.to_string();
            }
        }

        // MTU
        if let Some(val) = profile.custom_config.get("mtu") {
            if let Some(n) = val.as_u64() {
                config.mtu = n as u16;
            }
        }

        // Record type
        if let Some(val) = profile.custom_config.get("record_type") {
            if let Some(s) = val.as_str() {
                config.record_type = match s.to_lowercase().as_str() {
                    "null" => DnsRecordType::Null,
                    "private" => DnsRecordType::Private,
                    "txt" => DnsRecordType::Txt,
                    "cname" => DnsRecordType::Cname,
                    "mx" => DnsRecordType::Mx,
                    "a" => DnsRecordType::A,
                    _ => DnsRecordType::Auto,
                };
            }
        }

        // Encoding
        if let Some(val) = profile.custom_config.get("encoding") {
            if let Some(s) = val.as_str() {
                config.encoding = match s.to_lowercase().as_str() {
                    "base32" => IodineEncoding::Base32,
                    "base64" => IodineEncoding::Base64,
                    "base128" => IodineEncoding::Base128,
                    "raw" => IodineEncoding::Raw,
                    _ => IodineEncoding::Auto,
                };
            }
        }

        // Lazy mode
        if let Some(val) = profile.custom_config.get("lazy") {
            if let Some(b) = val.as_bool() {
                config.lazy = b;
            }
        }

        // Device name
        if let Some(val) = profile.custom_config.get("device") {
            if let Some(s) = val.as_str() {
                config.device = Some(s.to_string());
            }
        }
    }
}

#[async_trait]
impl VpnController for IodineController {
    fn protocol(&self) -> Protocol {
        Protocol::Iodine
    }

    async fn is_running(&self) -> Result<bool> {
        if let Some(pid) = self.get_pid().await {
            Ok(self.is_process_alive(pid).await)
        } else {
            let output = Command::new("pgrep")
                .args(["-f", "iodine"])
                .output()
                .await?;
            Ok(output.status.success())
        }
    }

    async fn start(&self) -> Result<()> {
        if self.is_running().await? {
            tracing::info!("Iodine is already running");
            return Ok(());
        }

        let binary = self.binary_path();
        let args = self.get_args();

        tracing::info!("Starting Iodine with binary: {:?}, args: {:?}", binary, args);

        tokio::fs::create_dir_all(&self.config_dir).await?;

        // Iodine requires root privileges for TUN device
        let child = Command::new("sudo")
            .arg(&binary)
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("Failed to start Iodine")?;

        let pid = child.id().unwrap_or(0);
        tokio::fs::write(&self.pid_file, pid.to_string()).await?;

        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

        if self.is_running().await? {
            tracing::info!("Iodine started successfully (PID: {})", pid);
            Ok(())
        } else {
            anyhow::bail!("Iodine failed to start")
        }
    }

    async fn stop(&self) -> Result<()> {
        if let Some(pid) = self.get_pid().await {
            tracing::info!("Stopping Iodine (PID: {})", pid);

            let _ = Command::new("sudo")
                .args(["kill", "-15", &pid.to_string()])
                .output()
                .await;

            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

            if self.is_process_alive(pid).await {
                let _ = Command::new("sudo")
                    .args(["kill", "-9", &pid.to_string()])
                    .output()
                    .await;
            }

            let _ = tokio::fs::remove_file(&self.pid_file).await;
            tracing::info!("Iodine stopped");
        } else {
            let _ = Command::new("sudo")
                .args(["pkill", "-f", "iodine"])
                .output()
                .await;
        }

        Ok(())
    }

    async fn reload(&self) -> Result<()> {
        // Iodine doesn't support reload, restart instead
        self.stop().await?;
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        self.start().await
    }

    async fn apply_profile(&self, profile: &TrafficProfile) -> Result<()> {
        tracing::info!("Applying profile to Iodine: {}", profile.name);
        self.configure_from_profile(profile);
        tracing::debug!("Iodine profile applied: {:?}", profile);
        Ok(())
    }

    async fn connection_count(&self) -> Result<u32> {
        // For DNS tunnel, count active tunnel interfaces or estimate from traffic
        let output = Command::new("ip")
            .args(["addr", "show"])
            .output()
            .await?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let has_dns_tunnel = stdout.contains("dns") || stdout.contains("tun");

        Ok(if has_dns_tunnel { 1 } else { 0 })
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
    fn test_iodine_client_args() {
        let config = IodineConfig::client("t.example.com", Some("8.8.8.8"))
            .with_password("secret")
            .with_record_type(DnsRecordType::Txt);

        let args = config.to_args();
        assert!(args.contains(&"-Ttxt".to_string()));
        assert!(args.contains(&"-P".to_string()));
        assert!(args.contains(&"secret".to_string()));
        assert!(args.contains(&"t.example.com".to_string()));
    }

    #[test]
    fn test_iodine_server_args() {
        let config = IodineConfig::server("t.example.com", "10.0.0.1/24")
            .with_password("secret");

        let args = config.to_args();
        assert!(args.contains(&"-l".to_string()));
        assert!(args.contains(&"10.0.0.1/24".to_string()));
    }
}
