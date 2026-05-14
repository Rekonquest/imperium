//! Configuration schema definitions for Cloakwise
//!
//! This module defines all configuration structures that are loaded from YAML config files.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;

/// Root configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub node: NodeConfig,
    pub models: ModelsConfig,
    pub confidence: ConfidenceConfig,
    pub fallback: FallbackConfig,
    pub profiles: HashMap<String, ProfileConfig>,
    pub vpn: VpnConfig,
    pub clients: ClientsConfig,
    pub telemetry: TelemetryConfig,
    pub logging: LoggingConfig,
    /// Autonomous LLM-driven cluster / Docker deployment (optional)
    #[serde(default)]
    pub deploy: DeployConfig,
    /// P2P mesh + NAT (STUN) + optional cloud HTTP signaling
    #[serde(default)]
    pub mesh: MeshConfig,
}

/// Tailscale-compatible overlay via **self-hosted Headscale** (no Tailscale SaaS).
/// Requires the `tailscale` client binary on PATH; coordination runs on your own server.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MeshOverlay {
    #[default]
    None,
    /// Run `tailscale up --login-server=<your Headscale URL>`. Auth key from file or env `CLOAKWISE_TAILSCALE_AUTH_KEY`.
    HeadscaleCli {
        /// Headscale public base URL (e.g. `https://headscale.example.com`)
        login_server: String,
        #[serde(default)]
        auth_key_file: Option<PathBuf>,
        #[serde(default)]
        accept_routes: bool,
        /// CIDRs to pass to `--advertise-routes` (repeatable)
        #[serde(default)]
        advertise_routes: Vec<String>,
        #[serde(default = "default_tailscale_binary")]
        tailscale_binary: String,
    },
}

fn default_tailscale_binary() -> String {
    "tailscale".to_string()
}

/// UDP mesh for cluster control-plane style messaging behind NAT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_mesh_listen_port")]
    pub listen_port: u16,
    /// STUN servers as `host:port` (UDP binding discovery)
    #[serde(default = "default_mesh_stun_servers")]
    pub stun_servers: Vec<String>,
    /// Optional cloud rendezvous, e.g. `https://mesh.example.com/v1` — implements register + peers JSON API
    #[serde(default)]
    pub signaling_base_url: Option<String>,
    #[serde(default)]
    pub signaling_token: Option<String>,
    /// Pre-shared key (UTF-8) for ChaCha20-Poly1305 payloads; if empty, control messages are plaintext (dev only)
    #[serde(default)]
    pub psk: Option<String>,
    /// Static peers `ip:port` or `hostname:port` to ping
    #[serde(default)]
    pub bootstrap_peer_addrs: Vec<String>,
    #[serde(default = "default_mesh_stun_refresh")]
    pub stun_refresh_secs: u32,
    #[serde(default = "default_mesh_signal_poll")]
    pub signaling_poll_secs: u32,
    /// Self-hosted Headscale + tailscale CLI (see `MeshOverlay`)
    #[serde(default)]
    pub overlay: MeshOverlay,
}

fn default_mesh_listen_port() -> u16 {
    19735
}

fn default_mesh_stun_servers() -> Vec<String> {
    vec![
        "stun.l.google.com:19302".to_string(),
        "stun1.l.google.com:19302".to_string(),
    ]
}

fn default_mesh_stun_refresh() -> u32 {
    120
}

fn default_mesh_signal_poll() -> u32 {
    45
}

impl Default for MeshConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_port: default_mesh_listen_port(),
            stun_servers: default_mesh_stun_servers(),
            signaling_base_url: None,
            signaling_token: None,
            psk: None,
            bootstrap_peer_addrs: vec![],
            stun_refresh_secs: default_mesh_stun_refresh(),
            signaling_poll_secs: default_mesh_signal_poll(),
            overlay: MeshOverlay::default(),
        }
    }
}

/// LLM agent deployment: writes files under `workspace_dir` and optionally runs Docker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployConfig {
    /// Root directory for generated compose, configs, scripts (created if missing)
    #[serde(default = "default_deploy_workspace")]
    pub workspace_dir: PathBuf,
    /// Max LLM↔tool rounds per `/api/deploy/autonomous` request
    #[serde(default = "default_deploy_max_rounds")]
    pub max_tool_rounds: u32,
    /// Max tokens for deployment chat completions (often higher than reflex models)
    #[serde(default = "default_deploy_max_tokens")]
    pub max_completion_tokens: u32,
    /// When false, `docker_compose` tool only logs what would run
    #[serde(default)]
    pub allow_docker_exec: bool,
    /// Override Docker CLI (default `docker`)
    #[serde(default)]
    pub docker_cli: Option<String>,
}

fn default_deploy_workspace() -> PathBuf {
    PathBuf::from("./data/deploy_workspace")
}

fn default_deploy_max_rounds() -> u32 {
    24
}

fn default_deploy_max_tokens() -> u32 {
    4096
}

impl Default for DeployConfig {
    fn default() -> Self {
        Self {
            workspace_dir: default_deploy_workspace(),
            max_tool_rounds: default_deploy_max_rounds(),
            max_completion_tokens: default_deploy_max_tokens(),
            allow_docker_exec: false,
            docker_cli: None,
        }
    }
}

/// Node identification and contact info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    pub id: String,
    pub admin_contact: String,
    #[serde(default)]
    pub cluster_peers: Vec<String>,
}

/// Model paths and inference settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelsConfig {
    pub specialists_dir: PathBuf,
    pub big_momma: PathBuf,
    pub inference: InferenceConfig,
    /// OpenAI-compatible API endpoint (e.g. LM Studio at http://localhost:1234/v1)
    /// If set, Big Momma uses this instead of loading a GGUF directly
    #[serde(default)]
    pub api_endpoint: Option<String>,
    /// Model name to request from the API (optional, some servers auto-select)
    #[serde(default)]
    pub api_model: Option<String>,
}

/// Model inference parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceConfig {
    #[serde(default = "default_threads")]
    pub threads: u32,
    #[serde(default = "default_context_size")]
    pub context_size: u32,
    #[serde(default = "default_batch_size")]
    pub batch_size: u32,
    #[serde(default = "default_temperature")]
    pub temperature: f32,
    #[serde(default = "default_max_tokens")]
    pub max_tokens: u32,
}

fn default_threads() -> u32 {
    4
}
fn default_context_size() -> u32 {
    2048
}
fn default_batch_size() -> u32 {
    512
}
fn default_temperature() -> f32 {
    0.1
}
fn default_max_tokens() -> u32 {
    256
}

/// Confidence thresholds for AI decision making
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceConfig {
    #[serde(default = "default_specialist_threshold")]
    pub specialist_threshold: f32,
    #[serde(default = "default_escalation_timeout")]
    pub escalation_timeout_ms: u64,
    #[serde(default = "default_min_specialists")]
    pub min_specialists_for_consensus: u32,
}

fn default_specialist_threshold() -> f32 {
    0.95
}
fn default_escalation_timeout() -> u64 {
    5000
}
fn default_min_specialists() -> u32 {
    3
}

/// Fallback algorithm settings (deterministic backup)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FallbackConfig {
    #[serde(default = "default_rotation_hours")]
    pub timed_rotation_hours: u32,
    #[serde(default = "default_failure_threshold")]
    pub failure_threshold: u32,
    #[serde(default = "default_failure_window")]
    pub failure_window_minutes: u32,
    #[serde(default = "default_health_check_interval")]
    pub health_check_interval_secs: u32,
    pub health_check_endpoints: Vec<String>,
    pub profile_rotation_order: Vec<String>,
    pub safe_mode_profile: String,
    #[serde(default = "default_safe_mode_lock_minutes")]
    pub safe_mode_lock_minutes: u32,
}

fn default_rotation_hours() -> u32 {
    4
}
fn default_failure_threshold() -> u32 {
    50
}
fn default_failure_window() -> u32 {
    10
}
fn default_health_check_interval() -> u32 {
    60
}
fn default_safe_mode_lock_minutes() -> u32 {
    30
}

/// Traffic profile configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileConfig {
    pub protocol: Protocol,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default)]
    pub obfuscation: Option<ObfuscationType>,
    #[serde(default)]
    pub timing: Option<TimingPattern>,
    #[serde(default)]
    pub padding: Option<PaddingType>,
    #[serde(default = "default_max_concurrent")]
    pub max_concurrent: u32,
    #[serde(default)]
    pub custom_config: HashMap<String, serde_yaml::Value>,
}

fn default_port() -> u16 {
    443
}
fn default_max_concurrent() -> u32 {
    100
}

/// Supported VPN/proxy protocols
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Wireguard,
    Amneziawg,
    Cloak,
    Shadowsocks,
    Outline,
    V2ray,
    Xray,
    TrojanGo,
    /// Hysteria 2 - QUIC-based with brutal congestion control
    Hysteria2,
    /// NaïveProxy - Chrome's network stack camouflage
    NaiveProxy,
    /// Snowflake - Tor pluggable transport via WebRTC
    Snowflake,
    /// Iodine - IP-over-DNS tunneling
    Iodine,
    /// Briar - P2P encrypted messaging over Tor
    Briar,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Wireguard => write!(f, "wireguard"),
            Protocol::Amneziawg => write!(f, "amneziawg"),
            Protocol::Cloak => write!(f, "cloak"),
            Protocol::Shadowsocks => write!(f, "shadowsocks"),
            Protocol::Outline => write!(f, "outline"),
            Protocol::V2ray => write!(f, "v2ray"),
            Protocol::Xray => write!(f, "xray"),
            Protocol::TrojanGo => write!(f, "trojan-go"),
            Protocol::Hysteria2 => write!(f, "hysteria2"),
            Protocol::NaiveProxy => write!(f, "naiveproxy"),
            Protocol::Snowflake => write!(f, "snowflake"),
            Protocol::Iodine => write!(f, "iodine"),
            Protocol::Briar => write!(f, "briar"),
        }
    }
}

/// Traffic obfuscation types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObfuscationType {
    None,
    Tls1_3,
    WebsocketUpgrade,
    Http2,
    Quic,
    Grpc,
    Meek,
    /// TLS Record Fragmentation - splits TLS records to evade DPI
    TlsFragmentation,
    /// DNS tunneling obfuscation
    DnsTunnel,
    /// WebRTC-based obfuscation (for Snowflake)
    WebRtc,
    Custom,
}

/// Timing patterns to mimic legitimate traffic
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimingPattern {
    Constant,
    WebrtcPattern,
    GameTrafficPattern,
    VideoStream,
    WebBrowsing,
    Bursty,
}

/// Packet padding strategies
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaddingType {
    None,
    FixedMtu,
    Variable,
    Random,
}

/// VPN interface configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnConfig {
    pub interface: String,
    pub config_dir: PathBuf,
    pub reload_command: String,
    #[serde(default)]
    pub pre_switch_hook: Option<String>,
    #[serde(default)]
    pub post_switch_hook: Option<String>,
}

/// Client management configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientsConfig {
    #[serde(default = "default_api_port")]
    pub config_api_port: u16,
    #[serde(default)]
    pub push_notifications: bool,
    #[serde(default)]
    pub api_bind_address: Option<IpAddr>,
    #[serde(default)]
    pub api_auth_token: Option<String>,
}

fn default_api_port() -> u16 {
    8080
}

/// Telemetry collection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryConfig {
    #[serde(default = "default_capture_method")]
    pub capture_method: CaptureMethod,
    pub log_path: PathBuf,
    #[serde(default = "default_sample_rate")]
    pub sample_rate: f64,
    #[serde(default)]
    pub packet_capture_interface: Option<String>,
}

fn default_capture_method() -> CaptureMethod {
    CaptureMethod::VpnLogs
}
fn default_sample_rate() -> f64 {
    1.0
}

/// Method for collecting telemetry data
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureMethod {
    VpnLogs,
    PacketCapture,
    Both,
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    pub file: PathBuf,
    #[serde(default)]
    pub json_format: bool,
    #[serde(default = "default_max_log_size")]
    pub max_size_mb: u32,
    #[serde(default = "default_max_log_files")]
    pub max_files: u32,
}

fn default_log_level() -> String {
    "info".to_string()
}
fn default_max_log_size() -> u32 {
    100
}
fn default_max_log_files() -> u32 {
    5
}

impl Config {
    /// Load configuration from a YAML file
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = serde_yaml::from_str(&content)?;
        config.validate()?;
        Ok(config)
    }

    /// Validate configuration values
    pub fn validate(&self) -> anyhow::Result<()> {
        // Validate confidence threshold
        if !(0.0..=1.0).contains(&self.confidence.specialist_threshold) {
            anyhow::bail!("specialist_threshold must be between 0.0 and 1.0");
        }

        // Validate profiles referenced in fallback exist
        for profile_name in &self.fallback.profile_rotation_order {
            if !self.profiles.contains_key(profile_name) {
                anyhow::bail!(
                    "Profile '{}' in profile_rotation_order not found in profiles",
                    profile_name
                );
            }
        }

        if !self.profiles.contains_key(&self.fallback.safe_mode_profile) {
            anyhow::bail!(
                "safe_mode_profile '{}' not found in profiles",
                self.fallback.safe_mode_profile
            );
        }

        // Validate at least one health check endpoint
        if self.fallback.health_check_endpoints.is_empty() {
            anyhow::bail!("At least one health_check_endpoint is required");
        }

        // Validate sample rate
        if !(0.0..=1.0).contains(&self.telemetry.sample_rate) {
            anyhow::bail!("sample_rate must be between 0.0 and 1.0");
        }

        Ok(())
    }

    /// Create a default configuration for testing
    #[cfg(test)]
    pub fn default_test() -> Self {
        use std::collections::HashMap;

        Config {
            node: NodeConfig {
                id: "test-node".to_string(),
                admin_contact: "test@example.com".to_string(),
                cluster_peers: vec![],
            },
            models: ModelsConfig {
                specialists_dir: PathBuf::from("./models/specialists/"),
                big_momma: PathBuf::from("./models/big_momma.gguf"),
                inference: InferenceConfig {
                    threads: 4,
                    context_size: 2048,
                    batch_size: 512,
                    temperature: 0.1,
                    max_tokens: 256,
                },
                api_endpoint: None,
                api_model: None,
            },
            confidence: ConfidenceConfig {
                specialist_threshold: 0.95,
                escalation_timeout_ms: 5000,
                min_specialists_for_consensus: 3,
            },
            fallback: FallbackConfig {
                timed_rotation_hours: 4,
                failure_threshold: 50,
                failure_window_minutes: 10,
                health_check_interval_secs: 60,
                health_check_endpoints: vec!["https://www.google.com".to_string()],
                profile_rotation_order: vec!["https_clone".to_string()],
                safe_mode_profile: "https_clone".to_string(),
                safe_mode_lock_minutes: 30,
            },
            profiles: {
                let mut map = HashMap::new();
                map.insert(
                    "https_clone".to_string(),
                    ProfileConfig {
                        protocol: Protocol::Cloak,
                        port: 443,
                        obfuscation: Some(ObfuscationType::Tls1_3),
                        timing: None,
                        padding: None,
                        max_concurrent: 100,
                        custom_config: HashMap::new(),
                    },
                );
                map
            },
            vpn: VpnConfig {
                interface: "wg0".to_string(),
                config_dir: PathBuf::from("/etc/wireguard/"),
                reload_command: "wg syncconf wg0 <(wg-quick strip wg0)".to_string(),
                pre_switch_hook: None,
                post_switch_hook: None,
            },
            clients: ClientsConfig {
                config_api_port: 8080,
                push_notifications: false,
                api_bind_address: None,
                api_auth_token: None,
            },
            telemetry: TelemetryConfig {
                capture_method: CaptureMethod::VpnLogs,
                log_path: PathBuf::from("/var/log/wireguard/"),
                sample_rate: 1.0,
                packet_capture_interface: None,
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                file: PathBuf::from("/var/log/cloakwise/cloakwise.log"),
                json_format: false,
                max_size_mb: 100,
                max_files: 5,
            },
            deploy: DeployConfig::default(),
            mesh: MeshConfig::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_validation() {
        let config = Config::default_test();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_invalid_threshold() {
        let mut config = Config::default_test();
        config.confidence.specialist_threshold = 1.5;
        assert!(config.validate().is_err());
    }
}
