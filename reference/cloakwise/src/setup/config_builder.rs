//! Configuration builder from user choices

use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::hardware_detect::HardwareTier;

/// User's setup choices
#[derive(Debug, Clone, Default)]
pub struct SetupChoices {
    /// Node ID
    pub node_id: String,

    /// Admin contact email
    pub admin_email: String,

    /// Selected hardware tier
    pub hardware_tier: Option<HardwareTier>,

    /// Selected protocols
    pub protocols: Vec<ProtocolChoice>,

    /// AI configuration
    pub ai_config: AiConfig,

    /// Security tools to enable
    pub security_tools: Vec<SecurityToolChoice>,

    /// SDR configuration
    pub sdr_config: Option<SdrConfig>,

    /// Network configuration
    pub network_config: NetworkConfig,

    /// Logging configuration
    pub logging_config: LoggingConfig,
}

/// Protocol selection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolChoice {
    pub protocol: Protocol,
    pub enabled: bool,
    pub port: u16,
    pub priority: u8, // Lower = higher priority in rotation
}

/// Available protocols
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol {
    WireGuard,
    AmneziaWg,
    Cloak,
    Shadowsocks,
    V2Ray,
    Xray,
    TrojanGo,
    Hysteria2,
    NaiveProxy,
    Snowflake,
    Iodine,
    Briar,
}

impl Protocol {
    pub fn name(&self) -> &'static str {
        match self {
            Protocol::WireGuard => "WireGuard",
            Protocol::AmneziaWg => "AmneziaWG",
            Protocol::Cloak => "Cloak",
            Protocol::Shadowsocks => "Shadowsocks",
            Protocol::V2Ray => "V2Ray",
            Protocol::Xray => "Xray (VLESS+Reality)",
            Protocol::TrojanGo => "Trojan-Go",
            Protocol::Hysteria2 => "Hysteria 2",
            Protocol::NaiveProxy => "NaïveProxy",
            Protocol::Snowflake => "Snowflake (Tor)",
            Protocol::Iodine => "Iodine (DNS Tunnel)",
            Protocol::Briar => "Briar (P2P Mesh)",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Protocol::WireGuard => "Fast, simple, modern VPN",
            Protocol::AmneziaWg => "WireGuard with DPI evasion",
            Protocol::Cloak => "TLS 1.3 camouflage",
            Protocol::Shadowsocks => "Encrypted proxy with plugins",
            Protocol::V2Ray => "Versatile proxy platform",
            Protocol::Xray => "Advanced TLS camouflage (recommended)",
            Protocol::TrojanGo => "HTTPS mimicry with CDN support",
            Protocol::Hysteria2 => "QUIC-based, high-speed on lossy networks",
            Protocol::NaiveProxy => "Chrome network stack camouflage",
            Protocol::Snowflake => "Tor via WebRTC, hard to block",
            Protocol::Iodine => "Works when only DNS is open",
            Protocol::Briar => "P2P mesh, works offline",
        }
    }

    pub fn default_port(&self) -> u16 {
        match self {
            Protocol::WireGuard => 51820,
            Protocol::AmneziaWg => 51821,
            Protocol::Cloak => 443,
            Protocol::Shadowsocks => 8388,
            Protocol::V2Ray => 443,
            Protocol::Xray => 443,
            Protocol::TrojanGo => 443,
            Protocol::Hysteria2 => 443,
            Protocol::NaiveProxy => 443,
            Protocol::Snowflake => 9050,
            Protocol::Iodine => 53,
            Protocol::Briar => 7000,
        }
    }

    pub fn stealth_level(&self) -> u8 {
        // Higher = harder to detect
        match self {
            Protocol::WireGuard => 2,
            Protocol::AmneziaWg => 5,
            Protocol::Cloak => 7,
            Protocol::Shadowsocks => 4,
            Protocol::V2Ray => 6,
            Protocol::Xray => 9,
            Protocol::TrojanGo => 8,
            Protocol::Hysteria2 => 7,
            Protocol::NaiveProxy => 9,
            Protocol::Snowflake => 8,
            Protocol::Iodine => 6,
            Protocol::Briar => 7,
        }
    }

    pub fn all() -> Vec<Protocol> {
        vec![
            Protocol::WireGuard,
            Protocol::AmneziaWg,
            Protocol::Cloak,
            Protocol::Shadowsocks,
            Protocol::V2Ray,
            Protocol::Xray,
            Protocol::TrojanGo,
            Protocol::Hysteria2,
            Protocol::NaiveProxy,
            Protocol::Snowflake,
            Protocol::Iodine,
            Protocol::Briar,
        ]
    }

    /// Recommended protocols for high-censorship environments
    pub fn recommended_stealth() -> Vec<Protocol> {
        vec![
            Protocol::Xray,
            Protocol::TrojanGo,
            Protocol::Hysteria2,
            Protocol::NaiveProxy,
            Protocol::Snowflake,
        ]
    }
}

/// AI configuration
#[derive(Debug, Clone, Default)]
pub struct AiConfig {
    /// Enable AI decision making
    pub enabled: bool,

    /// Enable threat detector micro-model
    pub threat_detector: bool,

    /// Enable pattern matcher micro-model
    pub pattern_matcher: bool,

    /// Enable action selector micro-model
    pub action_selector: bool,

    /// Decision timeout in milliseconds
    pub timeout_ms: u32,

    /// Confidence threshold for AI decisions
    pub confidence_threshold: f32,

    /// Path to models directory
    pub models_dir: PathBuf,
}

impl AiConfig {
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Default::default()
        }
    }

    pub fn micro_models() -> Self {
        Self {
            enabled: true,
            threat_detector: true,
            pattern_matcher: true,
            action_selector: true,
            timeout_ms: 100,
            confidence_threshold: 0.7,
            models_dir: PathBuf::from("./models/micro/"),
        }
    }

    pub fn full() -> Self {
        Self {
            enabled: true,
            threat_detector: true,
            pattern_matcher: true,
            action_selector: true,
            timeout_ms: 500,
            confidence_threshold: 0.6,
            models_dir: PathBuf::from("./models/"),
        }
    }
}

/// Security tool selection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityToolChoice {
    pub tool: SecurityTool,
    pub enabled: bool,
    pub auto_activate: bool,
}

/// Available security tools
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityTool {
    PacketCapture,
    DeepCapture,
    FlowCollector,
    Suricata,
    YaraScanner,
    DpiDetector,
    ProbeDetector,
    RateLimiter,
    IpBlocker,
    GeoBlocker,
}

impl SecurityTool {
    pub fn name(&self) -> &'static str {
        match self {
            SecurityTool::PacketCapture => "Packet Capture",
            SecurityTool::DeepCapture => "Deep Packet Inspection",
            SecurityTool::FlowCollector => "Flow Collector",
            SecurityTool::Suricata => "Suricata IDS",
            SecurityTool::YaraScanner => "YARA Scanner",
            SecurityTool::DpiDetector => "DPI Detection",
            SecurityTool::ProbeDetector => "Probe Detection",
            SecurityTool::RateLimiter => "Rate Limiter",
            SecurityTool::IpBlocker => "IP Blocker",
            SecurityTool::GeoBlocker => "Geo Blocker",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            SecurityTool::PacketCapture => "Capture packets for analysis",
            SecurityTool::DeepCapture => "Deep inspection with tshark",
            SecurityTool::FlowCollector => "NetFlow/IPFIX collection",
            SecurityTool::Suricata => "Network intrusion detection",
            SecurityTool::YaraScanner => "Malware pattern matching",
            SecurityTool::DpiDetector => "Detect when you're being analyzed",
            SecurityTool::ProbeDetector => "Detect active probing (GFW-style)",
            SecurityTool::RateLimiter => "Protect against floods",
            SecurityTool::IpBlocker => "Block malicious IPs",
            SecurityTool::GeoBlocker => "Block by country",
        }
    }

    pub fn recommended() -> Vec<SecurityTool> {
        vec![
            SecurityTool::DpiDetector,
            SecurityTool::ProbeDetector,
            SecurityTool::RateLimiter,
        ]
    }
}

/// SDR configuration
#[derive(Debug, Clone, Default)]
pub struct SdrConfig {
    pub enabled: bool,
    pub primary_protocol: String,
    pub callsign: String,
    pub auto_activate_on_blackout: bool,
    pub mesh_enabled: bool,
}

/// Network configuration
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    pub api_port: u16,
    pub api_bind: String,
    pub enable_dashboard: bool,
    pub vpn_interface: String,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            api_port: 8080,
            api_bind: "127.0.0.1".to_string(),
            enable_dashboard: true,
            vpn_interface: "wg0".to_string(),
        }
    }
}

/// Logging configuration
#[derive(Debug, Clone)]
pub struct LoggingConfig {
    pub level: String,
    pub log_file: PathBuf,
    pub json_format: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            log_file: PathBuf::from("/var/log/cloakwise/cloakwise.log"),
            json_format: false,
        }
    }
}

/// Build YAML configuration from choices
pub fn build_config_yaml(choices: &SetupChoices) -> String {
    let mut config = String::new();

    // Header
    config.push_str("# Cloakwise Configuration\n");
    config.push_str("# Generated by setup wizard\n\n");

    // Node section
    config.push_str("node:\n");
    config.push_str(&format!("  id: \"{}\"\n", choices.node_id));
    config.push_str(&format!("  admin_contact: \"{}\"\n", choices.admin_email));
    config.push_str("  cluster_peers: []\n\n");

    // Models section
    config.push_str("models:\n");
    if choices.ai_config.enabled {
        config.push_str(&format!(
            "  micro_models_dir: \"{}\"\n",
            choices.ai_config.models_dir.display()
        ));
        if choices.ai_config.threat_detector {
            config.push_str("  threat_detector: \"./models/micro/threat_detector.gguf\"\n");
        }
        if choices.ai_config.pattern_matcher {
            config.push_str("  pattern_matcher: \"./models/micro/pattern_matcher.gguf\"\n");
        }
        if choices.ai_config.action_selector {
            config.push_str("  action_selector: \"./models/micro/action_selector.gguf\"\n");
        }
        config.push_str("  inference:\n");
        config.push_str("    threads: 2\n");
        config.push_str("    context_size: 512\n");
        config.push_str("    temperature: 0.0\n");
    } else {
        config.push_str("  # AI disabled - using rule-based fallback only\n");
        config.push_str("  enabled: false\n");
    }
    config.push_str("\n");

    // Decision section
    config.push_str("decision:\n");
    config.push_str(&format!("  action_timeout_ms: {}\n", choices.ai_config.timeout_ms));
    config.push_str(&format!(
        "  confidence_threshold: {}\n",
        choices.ai_config.confidence_threshold
    ));
    config.push_str(&format!("  enable_ai: {}\n\n", choices.ai_config.enabled));

    // Fallback section
    config.push_str("fallback:\n");
    config.push_str("  timed_rotation_hours: 4\n");
    config.push_str("  failure_threshold: 50\n");
    config.push_str("  failure_window_minutes: 10\n");
    config.push_str("  health_check_interval_secs: 60\n");
    config.push_str("  health_check_endpoints:\n");
    config.push_str("    - \"https://www.google.com\"\n");
    config.push_str("    - \"https://cloudflare.com/cdn-cgi/trace\"\n");

    // Profile rotation order based on enabled protocols
    config.push_str("  profile_rotation_order:\n");
    for proto in &choices.protocols {
        if proto.enabled {
            config.push_str(&format!("    - \"{}\"\n", proto.protocol.name().to_lowercase().replace(' ', "_")));
        }
    }
    config.push_str("  safe_mode_profile: \"xray\"\n");
    config.push_str("  safe_mode_lock_minutes: 30\n\n");

    // Profiles section
    config.push_str("profiles:\n");
    for proto in &choices.protocols {
        if proto.enabled {
            let name = proto.protocol.name().to_lowercase().replace(' ', "_").replace("(", "").replace(")", "");
            config.push_str(&format!("  {}:\n", name));
            config.push_str(&format!("    protocol: {}\n", format!("{:?}", proto.protocol).to_lowercase()));
            config.push_str(&format!("    port: {}\n", proto.port));
            config.push_str("    obfuscation: tls1_3\n");
            config.push_str("    timing: web_browsing\n");
            config.push_str("    max_concurrent: 100\n\n");
        }
    }

    // VPN section
    config.push_str("vpn:\n");
    config.push_str(&format!("  interface: \"{}\"\n", choices.network_config.vpn_interface));
    config.push_str("  config_dir: \"/etc/cloakwise/vpn/\"\n");
    config.push_str("  reload_command: \"systemctl reload cloakwise-vpn\"\n\n");

    // Clients section
    config.push_str("clients:\n");
    config.push_str(&format!("  config_api_port: {}\n", choices.network_config.api_port));
    config.push_str(&format!(
        "  api_bind_address: \"{}\"\n",
        if choices.network_config.api_bind == "0.0.0.0" {
            "null".to_string()
        } else {
            format!("\"{}\"", choices.network_config.api_bind)
        }
    ));
    config.push_str("  push_notifications: false\n\n");

    // Telemetry section
    config.push_str("telemetry:\n");
    config.push_str("  capture_method: vpn_logs\n");
    config.push_str("  log_path: \"/var/log/wireguard/\"\n");
    config.push_str("  sample_rate: 1.0\n\n");

    // Logging section
    config.push_str("logging:\n");
    config.push_str(&format!("  level: \"{}\"\n", choices.logging_config.level));
    config.push_str(&format!("  file: \"{}\"\n", choices.logging_config.log_file.display()));
    config.push_str(&format!("  json_format: {}\n", choices.logging_config.json_format));
    config.push_str("  max_size_mb: 100\n");
    config.push_str("  max_files: 5\n");

    // SDR section (if enabled)
    if let Some(sdr) = &choices.sdr_config {
        if sdr.enabled {
            config.push_str("\n# SDR Radio Bridge Configuration\n");
            config.push_str("radio_bridge:\n");
            config.push_str(&format!("  primary_protocol: {}\n", sdr.primary_protocol));
            config.push_str(&format!("  callsign: \"{}\"\n", sdr.callsign));
            config.push_str(&format!("  auto_activate_on_blackout: {}\n", sdr.auto_activate_on_blackout));
            config.push_str(&format!("  mesh_enabled: {}\n", sdr.mesh_enabled));
        }
    }

    config
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_info() {
        assert_eq!(Protocol::Xray.stealth_level(), 9);
        assert_eq!(Protocol::WireGuard.default_port(), 51820);
    }

    #[test]
    fn test_config_generation() {
        let mut choices = SetupChoices::default();
        choices.node_id = "test-node".to_string();
        choices.admin_email = "admin@test.com".to_string();
        choices.ai_config = AiConfig::disabled();

        let yaml = build_config_yaml(&choices);
        assert!(yaml.contains("test-node"));
        assert!(yaml.contains("admin@test.com"));
    }
}
