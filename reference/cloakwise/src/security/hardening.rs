//! Defense Hardening Tools
//!
//! Active defense measures that can be activated on-demand:
//! - Firewall rules (iptables/nftables)
//! - Rate limiting
//! - IP blocking/allowlisting
//! - Port knocking
//! - Network segmentation

use super::toolkit::{DormantTool, ResourceBudget, ToolCategory, AutoTriggerConfig};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Interface to apply limits on
    pub interface: String,
    /// Connections per second limit
    pub conn_per_sec: u32,
    /// Packets per second limit
    pub packets_per_sec: u32,
    /// Bandwidth limit in Kbps
    pub bandwidth_kbps: Option<u32>,
    /// Burst allowance
    pub burst: u32,
    /// Whitelist IPs
    pub whitelist: Vec<String>,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            interface: "eth0".to_string(),
            conn_per_sec: 100,
            packets_per_sec: 1000,
            bandwidth_kbps: None,
            burst: 50,
            whitelist: vec![],
        }
    }
}

/// IP blocking configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpBlockConfig {
    /// Blocklist file path
    pub blocklist_file: PathBuf,
    /// Auto-update interval in hours
    pub update_interval_hours: u32,
    /// Blocklist sources (URLs)
    pub sources: Vec<String>,
    /// Action (drop, reject, tarpit)
    pub action: String,
}

impl Default for IpBlockConfig {
    fn default() -> Self {
        Self {
            blocklist_file: PathBuf::from("/var/lib/cloakwise/blocklist.txt"),
            update_interval_hours: 24,
            sources: vec![
                "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt".to_string(),
            ],
            action: "drop".to_string(),
        }
    }
}

/// Port knocking configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortKnockConfig {
    /// Knock sequence (ports to hit in order)
    pub sequence: Vec<u16>,
    /// Timeout between knocks in seconds
    pub timeout: u32,
    /// Port to open on successful knock
    pub target_port: u16,
    /// Duration to keep port open in seconds
    pub open_duration: u32,
    /// Command to run on successful knock
    pub open_command: String,
    /// Command to run when closing
    pub close_command: String,
}

impl Default for PortKnockConfig {
    fn default() -> Self {
        Self {
            sequence: vec![7000, 8000, 9000],
            timeout: 5,
            target_port: 22,
            open_duration: 30,
            open_command: "iptables -A INPUT -s %IP% -p tcp --dport %PORT% -j ACCEPT".to_string(),
            close_command: "iptables -D INPUT -s %IP% -p tcp --dport %PORT% -j ACCEPT".to_string(),
        }
    }
}

/// Create rate limiter tool
pub fn create_rate_limiter_tool(config: RateLimitConfig) -> DormantTool {
    let mut env_vars = HashMap::new();
    env_vars.insert("RL_INTERFACE".to_string(), config.interface.clone());
    env_vars.insert("RL_CONN_RATE".to_string(), config.conn_per_sec.to_string());
    env_vars.insert("RL_PKT_RATE".to_string(), config.packets_per_sec.to_string());
    env_vars.insert("RL_BURST".to_string(), config.burst.to_string());
    if let Some(bw) = config.bandwidth_kbps {
        env_vars.insert("RL_BANDWIDTH".to_string(), bw.to_string());
    }

    DormantTool {
        id: "rate_limiter".to_string(),
        name: "Rate Limiter".to_string(),
        category: ToolCategory::DefenseHardening,
        description: "Applies connection and packet rate limits to prevent DoS and abuse.".to_string(),
        binary: PathBuf::from("/usr/local/bin/cloakwise-ratelimit"),
        args_template: vec![
            "--interface".to_string(),
            config.interface,
            "--conn-rate".to_string(),
            config.conn_per_sec.to_string(),
            "--pkt-rate".to_string(),
            config.packets_per_sec.to_string(),
        ],
        env_vars,
        work_dir: None,
        budget: ResourceBudget {
            max_memory_mb: 64,
            max_cpu_percent: 5,
            max_disk_mb: 10,
            max_bandwidth_kbps: None,
            max_runtime: None,
        },
        dependencies: vec![],
        idle_timeout: None,
        auto_triggers: vec![
            AutoTriggerConfig {
                trigger_type: "threshold_breach".to_string(),
                conditions: {
                    let mut m = HashMap::new();
                    m.insert("metric".to_string(), serde_json::json!("connection_rate"));
                    m.insert("threshold".to_string(), serde_json::json!(500));
                    m
                },
                enabled: true,
            },
        ],
        state: super::toolkit::ToolState::Dormant,
        pid: None,
        activated_at: None,
        last_activity: None,
    }
}

/// Create IP blocker tool
pub fn create_ip_blocker_tool(config: IpBlockConfig) -> DormantTool {
    let mut env_vars = HashMap::new();
    env_vars.insert("BLOCK_FILE".to_string(), config.blocklist_file.to_string_lossy().to_string());
    env_vars.insert("BLOCK_ACTION".to_string(), config.action.clone());

    DormantTool {
        id: "ip_blocker".to_string(),
        name: "IP Blocker".to_string(),
        category: ToolCategory::DefenseHardening,
        description: "Blocks known malicious IPs using threat intelligence feeds.".to_string(),
        binary: PathBuf::from("/usr/local/bin/cloakwise-ipblock"),
        args_template: vec![
            "--blocklist".to_string(),
            config.blocklist_file.to_string_lossy().to_string(),
            "--action".to_string(),
            config.action,
        ],
        env_vars,
        work_dir: None,
        budget: ResourceBudget {
            max_memory_mb: 128,
            max_cpu_percent: 5,
            max_disk_mb: 100,
            max_bandwidth_kbps: None,
            max_runtime: None,
        },
        dependencies: vec![],
        idle_timeout: None,
        auto_triggers: vec![],
        state: super::toolkit::ToolState::Dormant,
        pid: None,
        activated_at: None,
        last_activity: None,
    }
}

/// Create port knocker daemon
pub fn create_port_knocker_tool(config: PortKnockConfig) -> DormantTool {
    let sequence_str = config.sequence.iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(",");

    DormantTool {
        id: "port_knocker".to_string(),
        name: "Port Knocker".to_string(),
        category: ToolCategory::DefenseHardening,
        description: "Implements port knocking for hidden service access.".to_string(),
        binary: PathBuf::from("/usr/sbin/knockd"),
        args_template: vec![
            "-c".to_string(),
            "/etc/knockd.conf".to_string(),
            "-d".to_string(),
        ],
        env_vars: {
            let mut m = HashMap::new();
            m.insert("KNOCK_SEQUENCE".to_string(), sequence_str);
            m.insert("KNOCK_TIMEOUT".to_string(), config.timeout.to_string());
            m.insert("KNOCK_TARGET".to_string(), config.target_port.to_string());
            m
        },
        work_dir: None,
        budget: ResourceBudget {
            max_memory_mb: 32,
            max_cpu_percent: 2,
            max_disk_mb: 10,
            max_bandwidth_kbps: None,
            max_runtime: None,
        },
        dependencies: vec![],
        idle_timeout: None,
        auto_triggers: vec![],
        state: super::toolkit::ToolState::Dormant,
        pid: None,
        activated_at: None,
        last_activity: None,
    }
}

/// Create firewall hardening tool
pub fn create_firewall_hardener_tool() -> DormantTool {
    DormantTool {
        id: "firewall_hardener".to_string(),
        name: "Firewall Hardener".to_string(),
        category: ToolCategory::DefenseHardening,
        description: "Applies strict firewall rules to harden the network stack.".to_string(),
        binary: PathBuf::from("/usr/local/bin/cloakwise-fw-harden"),
        args_template: vec![
            "--mode".to_string(),
            "strict".to_string(),
            "--allow-established".to_string(),
            "--drop-invalid".to_string(),
        ],
        env_vars: HashMap::new(),
        work_dir: None,
        budget: ResourceBudget {
            max_memory_mb: 32,
            max_cpu_percent: 2,
            max_disk_mb: 10,
            max_bandwidth_kbps: None,
            max_runtime: None,
        },
        dependencies: vec![],
        idle_timeout: None,
        auto_triggers: vec![
            AutoTriggerConfig {
                trigger_type: "big_momma_decision".to_string(),
                conditions: {
                    let mut m = HashMap::new();
                    m.insert("action".to_string(), serde_json::json!("harden_network"));
                    m
                },
                enabled: true,
            },
        ],
        state: super::toolkit::ToolState::Dormant,
        pid: None,
        activated_at: None,
        last_activity: None,
    }
}

/// Create geo-blocking tool
pub fn create_geo_blocker_tool() -> DormantTool {
    DormantTool {
        id: "geo_blocker".to_string(),
        name: "Geo Blocker".to_string(),
        category: ToolCategory::DefenseHardening,
        description: "Blocks or allows traffic based on geographic location.".to_string(),
        binary: PathBuf::from("/usr/local/bin/cloakwise-geoblock"),
        args_template: vec![
            "--geoip-db".to_string(),
            "/var/lib/cloakwise/GeoLite2-Country.mmdb".to_string(),
            "--config".to_string(),
            "/etc/cloakwise/geoblock.yaml".to_string(),
        ],
        env_vars: HashMap::new(),
        work_dir: None,
        budget: ResourceBudget {
            max_memory_mb: 128,
            max_cpu_percent: 5,
            max_disk_mb: 50,
            max_bandwidth_kbps: None,
            max_runtime: None,
        },
        dependencies: vec![],
        idle_timeout: None,
        auto_triggers: vec![],
        state: super::toolkit::ToolState::Dormant,
        pid: None,
        activated_at: None,
        last_activity: None,
    }
}

/// Create connection drainer (for graceful shutdown under attack)
pub fn create_connection_drainer_tool() -> DormantTool {
    DormantTool {
        id: "conn_drainer".to_string(),
        name: "Connection Drainer".to_string(),
        category: ToolCategory::DefenseHardening,
        description: "Gracefully drains existing connections while blocking new ones.".to_string(),
        binary: PathBuf::from("/usr/local/bin/cloakwise-drain"),
        args_template: vec![
            "--timeout".to_string(),
            "30".to_string(),
            "--block-new".to_string(),
        ],
        env_vars: HashMap::new(),
        work_dir: None,
        budget: ResourceBudget {
            max_memory_mb: 32,
            max_cpu_percent: 5,
            max_disk_mb: 10,
            max_bandwidth_kbps: None,
            max_runtime: Some(Duration::from_secs(300)),
        },
        dependencies: vec![],
        idle_timeout: Some(Duration::from_secs(60)),
        auto_triggers: vec![
            AutoTriggerConfig {
                trigger_type: "big_momma_decision".to_string(),
                conditions: {
                    let mut m = HashMap::new();
                    m.insert("action".to_string(), serde_json::json!("safe_mode"));
                    m
                },
                enabled: true,
            },
        ],
        state: super::toolkit::ToolState::Dormant,
        pid: None,
        activated_at: None,
        last_activity: None,
    }
}

/// Get all default hardening tools
pub fn default_hardening_tools() -> Vec<DormantTool> {
    vec![
        create_rate_limiter_tool(RateLimitConfig::default()),
        create_ip_blocker_tool(IpBlockConfig::default()),
        create_port_knocker_tool(PortKnockConfig::default()),
        create_firewall_hardener_tool(),
        create_geo_blocker_tool(),
        create_connection_drainer_tool(),
    ]
}
