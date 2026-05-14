//! V2Ray/Xray VPN controller
//!
//! Controls V2Ray and its fork Xray - versatile proxy platforms supporting
//! VMess, VLESS, Trojan protocols with multiple transports (WS, H2, gRPC, QUIC).

use super::{TrafficProfile, VpnController, VpnStatus};
use crate::config::{ObfuscationType, Protocol};
use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::process::Command;
use tracing::{debug, error, info, warn};

/// V2Ray protocol types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum V2RayProtocol {
    /// VMess - V2Ray's original encrypted protocol
    Vmess,
    /// VLESS - Lightweight protocol without built-in encryption (uses TLS)
    Vless,
    /// Trojan - Mimics HTTPS traffic
    Trojan,
    /// Shadowsocks (V2Ray plugin)
    Shadowsocks,
}

impl Default for V2RayProtocol {
    fn default() -> Self {
        Self::Vless
    }
}

/// V2Ray transport types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum V2RayTransport {
    /// Raw TCP
    Tcp,
    /// WebSocket
    Ws,
    /// HTTP/2
    H2,
    /// gRPC
    Grpc,
    /// QUIC (UDP-based)
    Quic,
    /// mKCP (KCP over UDP)
    Kcp,
}

impl Default for V2RayTransport {
    fn default() -> Self {
        Self::Ws
    }
}

/// V2Ray server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct V2RayConfig {
    /// Server listen address
    pub listen: String,
    /// Server port
    pub port: u16,
    /// Protocol (vmess/vless/trojan)
    pub protocol: V2RayProtocol,
    /// Transport type
    pub transport: V2RayTransport,
    /// User UUID
    pub uuid: String,
    /// Encryption (for VMess: auto, aes-128-gcm, chacha20-poly1305, none)
    pub encryption: String,
    /// Flow control (for VLESS with XTLS: xtls-rprx-vision, etc.)
    pub flow: Option<String>,
    /// TLS settings
    pub tls: TlsConfig,
    /// Transport-specific settings
    pub transport_settings: TransportSettings,
    /// Fallback addresses (for VLESS/Trojan)
    pub fallbacks: Vec<FallbackConfig>,
}

impl Default for V2RayConfig {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0".to_string(),
            port: 443,
            protocol: V2RayProtocol::Vless,
            transport: V2RayTransport::Ws,
            uuid: uuid::Uuid::new_v4().to_string(),
            encryption: "none".to_string(),
            flow: None,
            tls: TlsConfig::default(),
            transport_settings: TransportSettings::default(),
            fallbacks: Vec::new(),
        }
    }
}

/// TLS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    pub enabled: bool,
    pub server_name: String,
    pub alpn: Vec<String>,
    pub cert_file: Option<PathBuf>,
    pub key_file: Option<PathBuf>,
    /// XTLS/Reality settings (Xray-specific)
    pub reality: Option<RealityConfig>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            server_name: "www.microsoft.com".to_string(),
            alpn: vec!["h2".to_string(), "http/1.1".to_string()],
            cert_file: None,
            key_file: None,
            reality: None,
        }
    }
}

/// Reality configuration (Xray's TLS camouflage)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealityConfig {
    pub enabled: bool,
    pub dest: String, // Target server to mimic (e.g., "www.microsoft.com:443")
    pub server_names: Vec<String>,
    pub private_key: String,
    pub short_ids: Vec<String>,
}

/// Transport-specific settings
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TransportSettings {
    /// WebSocket path
    pub ws_path: Option<String>,
    /// WebSocket host header
    pub ws_host: Option<String>,
    /// HTTP/2 path
    pub h2_path: Option<String>,
    /// HTTP/2 host
    pub h2_host: Option<Vec<String>>,
    /// gRPC service name
    pub grpc_service_name: Option<String>,
    /// gRPC multi-mode
    pub grpc_multi_mode: Option<bool>,
    /// QUIC security (none, aes-128-gcm, chacha20-poly1305)
    pub quic_security: Option<String>,
    /// QUIC key
    pub quic_key: Option<String>,
    /// QUIC header type
    pub quic_header: Option<String>,
    /// KCP settings
    pub kcp_seed: Option<String>,
    pub kcp_header: Option<String>,
}

/// Fallback configuration for VLESS/Trojan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FallbackConfig {
    pub name: Option<String>,
    pub alpn: Option<String>,
    pub path: Option<String>,
    pub dest: String,
    pub xver: u8,
}

/// V2Ray controller
pub struct V2RayController {
    /// Whether to use Xray (fork with Reality support) or V2Ray
    use_xray: bool,
    config_dir: PathBuf,
    config_file: PathBuf,
    pid_file: PathBuf,
    config: parking_lot::RwLock<V2RayConfig>,
}

impl V2RayController {
    pub fn new(config_dir: &Path, use_xray: bool) -> Self {
        let config_file = config_dir.join(if use_xray {
            "xray_config.json"
        } else {
            "v2ray_config.json"
        });
        let pid_file = config_dir.join(if use_xray { "xray.pid" } else { "v2ray.pid" });

        Self {
            use_xray,
            config_dir: config_dir.to_path_buf(),
            config_file,
            pid_file,
            config: parking_lot::RwLock::new(V2RayConfig::default()),
        }
    }

    /// Create controller for Xray
    pub fn xray(config_dir: &Path) -> Self {
        Self::new(config_dir, true)
    }

    /// Create controller for V2Ray
    pub fn v2ray(config_dir: &Path) -> Self {
        Self::new(config_dir, false)
    }

    /// Set configuration
    pub fn set_config(&self, config: V2RayConfig) {
        *self.config.write() = config;
    }

    /// Get the binary name
    fn binary_name(&self) -> &'static str {
        if self.use_xray {
            "xray"
        } else {
            "v2ray"
        }
    }

    /// Check if the binary is available
    async fn has_binary(&self) -> bool {
        Command::new("which")
            .arg(self.binary_name())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// Get PID of running process
    async fn get_pid(&self) -> Option<u32> {
        if self.pid_file.exists() {
            if let Ok(content) = tokio::fs::read_to_string(&self.pid_file).await {
                return content.trim().parse().ok();
            }
        }

        // Try to find by process name
        let name = self.binary_name();
        let output = Command::new("pgrep")
            .args(["-f", name])
            .stdout(Stdio::piped())
            .output()
            .await
            .ok()?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            return stdout.lines().next()?.trim().parse().ok();
        }

        None
    }

    /// Generate V2Ray/Xray config JSON
    fn generate_config(&self, profile: &TrafficProfile) -> String {
        let config = self.config.read();

        // Build inbound configuration
        let inbound = self.build_inbound(&config, profile);

        // Build full config
        let full_config = serde_json::json!({
            "log": {
                "loglevel": "warning",
                "access": "/var/log/v2ray/access.log",
                "error": "/var/log/v2ray/error.log"
            },
            "inbounds": [inbound],
            "outbounds": [{
                "protocol": "freedom",
                "tag": "direct"
            }, {
                "protocol": "blackhole",
                "tag": "block"
            }],
            "routing": {
                "rules": [{
                    "type": "field",
                    "ip": ["geoip:private"],
                    "outboundTag": "block"
                }]
            }
        });

        serde_json::to_string_pretty(&full_config).unwrap()
    }

    /// Build inbound configuration
    fn build_inbound(&self, config: &V2RayConfig, profile: &TrafficProfile) -> serde_json::Value {
        let protocol_str = match config.protocol {
            V2RayProtocol::Vmess => "vmess",
            V2RayProtocol::Vless => "vless",
            V2RayProtocol::Trojan => "trojan",
            V2RayProtocol::Shadowsocks => "shadowsocks",
        };

        // Build user/client settings based on protocol
        let settings = match config.protocol {
            V2RayProtocol::Vmess => {
                serde_json::json!({
                    "clients": [{
                        "id": config.uuid,
                        "alterId": 0,
                        "security": config.encryption
                    }]
                })
            }
            V2RayProtocol::Vless => {
                let mut client = serde_json::json!({
                    "id": config.uuid,
                    "encryption": "none"
                });
                if let Some(ref flow) = config.flow {
                    client["flow"] = serde_json::Value::String(flow.clone());
                }
                let mut settings = serde_json::json!({
                    "clients": [client],
                    "decryption": "none"
                });
                if !config.fallbacks.is_empty() {
                    settings["fallbacks"] = serde_json::json!(
                        config.fallbacks.iter().map(|f| {
                            let mut fb = serde_json::json!({
                                "dest": f.dest,
                                "xver": f.xver
                            });
                            if let Some(ref alpn) = f.alpn {
                                fb["alpn"] = serde_json::Value::String(alpn.clone());
                            }
                            if let Some(ref path) = f.path {
                                fb["path"] = serde_json::Value::String(path.clone());
                            }
                            fb
                        }).collect::<Vec<_>>()
                    );
                }
                settings
            }
            V2RayProtocol::Trojan => {
                let mut settings = serde_json::json!({
                    "clients": [{
                        "password": config.uuid
                    }]
                });
                if !config.fallbacks.is_empty() {
                    settings["fallbacks"] = serde_json::json!(
                        config.fallbacks.iter().map(|f| {
                            serde_json::json!({
                                "dest": f.dest,
                                "xver": f.xver
                            })
                        }).collect::<Vec<_>>()
                    );
                }
                settings
            }
            V2RayProtocol::Shadowsocks => {
                serde_json::json!({
                    "method": "aes-256-gcm",
                    "password": config.uuid,
                    "network": "tcp,udp"
                })
            }
        };

        // Build stream settings
        let stream_settings = self.build_stream_settings(config, profile);

        let mut inbound = serde_json::json!({
            "listen": config.listen,
            "port": profile.port,
            "protocol": protocol_str,
            "settings": settings,
            "streamSettings": stream_settings,
            "tag": "inbound-main"
        });

        // Add sniffing
        inbound["sniffing"] = serde_json::json!({
            "enabled": true,
            "destOverride": ["http", "tls", "quic"]
        });

        inbound
    }

    /// Build stream settings (transport + security)
    fn build_stream_settings(
        &self,
        config: &V2RayConfig,
        profile: &TrafficProfile,
    ) -> serde_json::Value {
        let network = match config.transport {
            V2RayTransport::Tcp => "tcp",
            V2RayTransport::Ws => "ws",
            V2RayTransport::H2 => "h2",
            V2RayTransport::Grpc => "grpc",
            V2RayTransport::Quic => "quic",
            V2RayTransport::Kcp => "kcp",
        };

        let mut stream = serde_json::json!({
            "network": network
        });

        // Add transport-specific settings
        match config.transport {
            V2RayTransport::Ws => {
                stream["wsSettings"] = serde_json::json!({
                    "path": config.transport_settings.ws_path.as_deref().unwrap_or("/ws"),
                    "headers": {
                        "Host": config.transport_settings.ws_host.as_deref()
                            .unwrap_or(&config.tls.server_name)
                    }
                });
            }
            V2RayTransport::H2 => {
                stream["httpSettings"] = serde_json::json!({
                    "path": config.transport_settings.h2_path.as_deref().unwrap_or("/h2"),
                    "host": config.transport_settings.h2_host.as_ref()
                        .unwrap_or(&vec![config.tls.server_name.clone()])
                });
            }
            V2RayTransport::Grpc => {
                stream["grpcSettings"] = serde_json::json!({
                    "serviceName": config.transport_settings.grpc_service_name
                        .as_deref().unwrap_or("grpc"),
                    "multiMode": config.transport_settings.grpc_multi_mode.unwrap_or(false)
                });
            }
            V2RayTransport::Quic => {
                stream["quicSettings"] = serde_json::json!({
                    "security": config.transport_settings.quic_security
                        .as_deref().unwrap_or("none"),
                    "key": config.transport_settings.quic_key.as_deref().unwrap_or(""),
                    "header": {
                        "type": config.transport_settings.quic_header
                            .as_deref().unwrap_or("none")
                    }
                });
            }
            V2RayTransport::Kcp => {
                stream["kcpSettings"] = serde_json::json!({
                    "mtu": profile.padding.target_mtu,
                    "tti": profile.timing.min_interval_ms.max(10),
                    "uplinkCapacity": 100,
                    "downlinkCapacity": 100,
                    "congestion": true,
                    "readBufferSize": 2,
                    "writeBufferSize": 2,
                    "seed": config.transport_settings.kcp_seed.as_deref().unwrap_or(""),
                    "header": {
                        "type": config.transport_settings.kcp_header
                            .as_deref().unwrap_or("none")
                    }
                });
            }
            V2RayTransport::Tcp => {
                // TCP can have header obfuscation
                stream["tcpSettings"] = serde_json::json!({
                    "header": {
                        "type": "none"
                    }
                });
            }
        }

        // Add TLS/Reality settings
        if config.tls.enabled {
            if let Some(ref reality) = config.tls.reality {
                if reality.enabled && self.use_xray {
                    // Xray Reality
                    stream["security"] = serde_json::Value::String("reality".to_string());
                    stream["realitySettings"] = serde_json::json!({
                        "show": false,
                        "dest": reality.dest,
                        "xver": 0,
                        "serverNames": reality.server_names,
                        "privateKey": reality.private_key,
                        "shortIds": reality.short_ids
                    });
                } else {
                    // Standard TLS
                    stream["security"] = serde_json::Value::String("tls".to_string());
                    let mut tls_settings = serde_json::json!({
                        "serverName": config.tls.server_name,
                        "alpn": config.tls.alpn
                    });
                    if let Some(ref cert) = config.tls.cert_file {
                        tls_settings["certificates"] = serde_json::json!([{
                            "certificateFile": cert,
                            "keyFile": config.tls.key_file
                        }]);
                    }
                    stream["tlsSettings"] = tls_settings;
                }
            } else {
                stream["security"] = serde_json::Value::String("tls".to_string());
                let mut tls_settings = serde_json::json!({
                    "serverName": config.tls.server_name,
                    "alpn": config.tls.alpn
                });
                if let Some(ref cert) = config.tls.cert_file {
                    tls_settings["certificates"] = serde_json::json!([{
                        "certificateFile": cert,
                        "keyFile": config.tls.key_file
                    }]);
                }
                stream["tlsSettings"] = tls_settings;
            }
        } else {
            stream["security"] = serde_json::Value::String("none".to_string());
        }

        stream
    }

    /// Write configuration file
    async fn write_config(&self, content: &str) -> Result<()> {
        if let Some(parent) = self.config_file.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        tokio::fs::write(&self.config_file, content)
            .await
            .context("Failed to write V2Ray config")?;

        debug!("V2Ray config written to {:?}", self.config_file);
        Ok(())
    }

    /// Start the process
    async fn start_process(&self) -> Result<()> {
        if !self.has_binary().await {
            return Err(anyhow::anyhow!(
                "{} not found. Install from https://github.com/{}",
                self.binary_name(),
                if self.use_xray {
                    "XTLS/Xray-core"
                } else {
                    "v2fly/v2ray-core"
                }
            ));
        }

        let binary = self.binary_name();
        let config_path = self.config_file.to_string_lossy();

        let child = Command::new(binary)
            .args(["run", "-c", &config_path])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context(format!("Failed to start {}", binary))?;

        if let Some(pid) = child.id() {
            tokio::fs::write(&self.pid_file, pid.to_string()).await?;
        }

        // Wait and verify
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        if self.get_pid().await.is_some() {
            info!("{} started successfully", binary);
            Ok(())
        } else {
            Err(anyhow::anyhow!("{} failed to start", binary))
        }
    }

    /// Stop the process
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

    /// Map obfuscation type to transport
    fn obfuscation_to_transport(obfs: ObfuscationType) -> V2RayTransport {
        match obfs {
            ObfuscationType::WebsocketUpgrade => V2RayTransport::Ws,
            ObfuscationType::Http2 => V2RayTransport::H2,
            ObfuscationType::Grpc => V2RayTransport::Grpc,
            ObfuscationType::Quic => V2RayTransport::Quic,
            _ => V2RayTransport::Ws, // Default to WebSocket
        }
    }
}

#[async_trait]
impl VpnController for V2RayController {
    fn protocol(&self) -> Protocol {
        if self.use_xray {
            Protocol::Xray
        } else {
            Protocol::V2ray
        }
    }

    async fn is_running(&self) -> Result<bool> {
        Ok(self.get_pid().await.is_some())
    }

    async fn start(&self) -> Result<()> {
        info!("Starting {}", self.binary_name());

        if self.is_running().await? {
            warn!("{} is already running", self.binary_name());
            return Ok(());
        }

        self.start_process().await
    }

    async fn stop(&self) -> Result<()> {
        info!("Stopping {}", self.binary_name());
        self.stop_process().await
    }

    async fn reload(&self) -> Result<()> {
        info!("Reloading {}", self.binary_name());

        // V2Ray/Xray can reload config via SIGHUP, but full restart is more reliable
        self.stop().await?;
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
        self.start().await
    }

    async fn apply_profile(&self, profile: &TrafficProfile) -> Result<()> {
        info!(
            "Applying profile {} to {}",
            profile.name,
            self.binary_name()
        );

        // Map profile obfuscation to V2Ray transport
        let transport = Self::obfuscation_to_transport(profile.obfuscation);

        // Update config based on profile
        {
            let mut config = self.config.write();
            config.port = profile.port;
            config.transport = transport;

            // Update transport settings based on profile
            match transport {
                V2RayTransport::Ws => {
                    config.transport_settings.ws_path =
                        Some(format!("/{}", profile.id.replace("_", "-")));
                }
                V2RayTransport::H2 => {
                    config.transport_settings.h2_path =
                        Some(format!("/{}", profile.id.replace("_", "-")));
                }
                V2RayTransport::Grpc => {
                    config.transport_settings.grpc_service_name =
                        Some(profile.id.replace("_", "-").replace("-", ""));
                }
                _ => {}
            }

            // Enable TLS for TLS-based obfuscation
            config.tls.enabled = matches!(
                profile.obfuscation,
                ObfuscationType::Tls1_3
                    | ObfuscationType::Http2
                    | ObfuscationType::Grpc
                    | ObfuscationType::WebsocketUpgrade
            );
        }

        // Generate and write config
        let config_content = self.generate_config(profile);
        self.write_config(&config_content).await?;

        debug!("{} config updated for profile: {}", self.binary_name(), profile.name);
        Ok(())
    }

    async fn connection_count(&self) -> Result<u32> {
        // V2Ray API would need to be enabled to get this
        // For now return 0
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
                Some(self.binary_name().to_string())
            } else {
                None
            },
        })
    }
}

/// Helper to create a VLESS + Reality configuration (Xray's most advanced evasion)
pub fn create_reality_config(
    dest_server: &str,
    server_names: Vec<String>,
) -> (V2RayConfig, String, String) {
    // Generate Reality keys (in production, use xray x25519 command)
    let private_key = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        &rand::random::<[u8; 32]>(),
    );
    let short_id = format!("{:016x}", rand::random::<u64>());

    let config = V2RayConfig {
        protocol: V2RayProtocol::Vless,
        transport: V2RayTransport::Tcp,
        flow: Some("xtls-rprx-vision".to_string()),
        tls: TlsConfig {
            enabled: true,
            server_name: server_names.first().cloned().unwrap_or_default(),
            alpn: vec!["h2".to_string(), "http/1.1".to_string()],
            cert_file: None,
            key_file: None,
            reality: Some(RealityConfig {
                enabled: true,
                dest: dest_server.to_string(),
                server_names,
                private_key: private_key.clone(),
                short_ids: vec![short_id.clone()],
            }),
        },
        ..Default::default()
    };

    (config, private_key, short_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_default_config() {
        let config = V2RayConfig::default();
        assert_eq!(config.protocol, V2RayProtocol::Vless);
        assert_eq!(config.transport, V2RayTransport::Ws);
        assert!(config.tls.enabled);
    }

    #[tokio::test]
    async fn test_controller_creation() {
        let dir = tempdir().unwrap();
        let controller = V2RayController::xray(dir.path());
        assert!(!controller.is_running().await.unwrap());
    }

    #[test]
    fn test_config_generation() {
        let dir = tempdir().unwrap();
        let controller = V2RayController::v2ray(dir.path());

        let profile = TrafficProfile {
            id: "test_profile".to_string(),
            name: "Test".to_string(),
            protocol: Protocol::V2ray,
            port: 443,
            obfuscation: ObfuscationType::WebsocketUpgrade,
            timing: crate::vpn::profiles::TimingProfile::default(),
            padding: crate::vpn::profiles::PaddingProfile::default(),
            max_concurrent: 100,
            custom_config: HashMap::new(),
        };

        let config_json = controller.generate_config(&profile);
        assert!(config_json.contains("vless"));
        assert!(config_json.contains("443"));
    }

    #[test]
    fn test_obfuscation_mapping() {
        assert_eq!(
            V2RayController::obfuscation_to_transport(ObfuscationType::WebsocketUpgrade),
            V2RayTransport::Ws
        );
        assert_eq!(
            V2RayController::obfuscation_to_transport(ObfuscationType::Http2),
            V2RayTransport::H2
        );
        assert_eq!(
            V2RayController::obfuscation_to_transport(ObfuscationType::Grpc),
            V2RayTransport::Grpc
        );
    }
}
