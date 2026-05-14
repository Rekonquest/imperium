//! Threat Detection Tools
//!
//! Dormant tools for detecting malicious activity:
//! - Suricata IDS/IPS
//! - YARA rule scanning
//! - Signature-based detection
//! - Anomaly detection
//! - Reputation checking

use super::toolkit::{DormantTool, ResourceBudget, ToolCategory, AutoTriggerConfig};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

/// Suricata IDS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuricataConfig {
    /// Network interface to monitor
    pub interface: String,
    /// Rules directory
    pub rules_dir: PathBuf,
    /// Log directory
    pub log_dir: PathBuf,
    /// Run in IDS mode (false) or IPS mode (true)
    pub ips_mode: bool,
    /// Enable flow logging
    pub flow_logging: bool,
    /// Enable HTTP logging
    pub http_logging: bool,
    /// Enable TLS logging
    pub tls_logging: bool,
    /// Enable DNS logging
    pub dns_logging: bool,
    /// Custom rule file
    pub custom_rules: Option<PathBuf>,
}

impl Default for SuricataConfig {
    fn default() -> Self {
        Self {
            interface: "any".to_string(),
            rules_dir: PathBuf::from("/etc/suricata/rules"),
            log_dir: PathBuf::from("/var/log/suricata"),
            ips_mode: false,
            flow_logging: true,
            http_logging: true,
            tls_logging: true,
            dns_logging: true,
            custom_rules: None,
        }
    }
}

impl SuricataConfig {
    /// Build Suricata arguments
    pub fn to_args(&self) -> Vec<String> {
        let mut args = vec![
            "-c".to_string(),
            "/etc/suricata/suricata.yaml".to_string(),
            "-i".to_string(),
            self.interface.clone(),
            "-l".to_string(),
            self.log_dir.to_string_lossy().to_string(),
        ];

        if self.ips_mode {
            args.push("-q".to_string());
            args.push("0".to_string()); // NFQUEUE mode
        }

        if let Some(ref rules) = self.custom_rules {
            args.push("-S".to_string());
            args.push(rules.to_string_lossy().to_string());
        }

        args
    }
}

/// YARA scanner configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraConfig {
    /// Rules directory or file
    pub rules_path: PathBuf,
    /// Target to scan (file, directory, or process)
    pub target: String,
    /// Recursive scanning
    pub recursive: bool,
    /// Include metadata in output
    pub print_meta: bool,
    /// Include strings in output
    pub print_strings: bool,
    /// Timeout per file in seconds
    pub timeout: u32,
    /// Number of threads
    pub threads: u32,
}

impl Default for YaraConfig {
    fn default() -> Self {
        Self {
            rules_path: PathBuf::from("/etc/yara/rules"),
            target: "/".to_string(),
            recursive: true,
            print_meta: true,
            print_strings: false,
            timeout: 60,
            threads: 4,
        }
    }
}

impl YaraConfig {
    /// Build YARA arguments
    pub fn to_args(&self) -> Vec<String> {
        let mut args = vec![];

        if self.recursive {
            args.push("-r".to_string());
        }

        if self.print_meta {
            args.push("-m".to_string());
        }

        if self.print_strings {
            args.push("-s".to_string());
        }

        args.push("-p".to_string());
        args.push(self.threads.to_string());

        args.push("-a".to_string());
        args.push(self.timeout.to_string());

        args.push(self.rules_path.to_string_lossy().to_string());
        args.push(self.target.clone());

        args
    }
}

/// ClamAV scanner configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClamavConfig {
    /// Target to scan
    pub target: PathBuf,
    /// Recursive scanning
    pub recursive: bool,
    /// Remove infected files
    pub remove_infected: bool,
    /// Move infected to quarantine
    pub quarantine_dir: Option<PathBuf>,
    /// Exclude patterns
    pub exclude_patterns: Vec<String>,
    /// Maximum file size to scan in MB
    pub max_filesize_mb: u32,
}

impl Default for ClamavConfig {
    fn default() -> Self {
        Self {
            target: PathBuf::from("/"),
            recursive: true,
            remove_infected: false,
            quarantine_dir: Some(PathBuf::from("/var/lib/cloakwise/quarantine")),
            exclude_patterns: vec![
                "^/proc".to_string(),
                "^/sys".to_string(),
                "^/dev".to_string(),
            ],
            max_filesize_mb: 100,
        }
    }
}

impl ClamavConfig {
    /// Build clamscan arguments
    pub fn to_args(&self) -> Vec<String> {
        let mut args = vec![];

        if self.recursive {
            args.push("-r".to_string());
        }

        if self.remove_infected {
            args.push("--remove".to_string());
        } else if let Some(ref qdir) = self.quarantine_dir {
            args.push("--move".to_string());
            args.push(qdir.to_string_lossy().to_string());
        }

        for pattern in &self.exclude_patterns {
            args.push("--exclude".to_string());
            args.push(pattern.clone());
        }

        args.push("--max-filesize".to_string());
        args.push(format!("{}M", self.max_filesize_mb));

        args.push(self.target.to_string_lossy().to_string());

        args
    }
}

/// Create Suricata IDS tool
pub fn create_suricata_tool(config: SuricataConfig) -> DormantTool {
    DormantTool {
        id: "suricata_ids".to_string(),
        name: "Suricata IDS".to_string(),
        category: ToolCategory::ThreatDetection,
        description: "Network intrusion detection system with protocol analysis and threat detection.".to_string(),
        binary: PathBuf::from("/usr/bin/suricata"),
        args_template: config.to_args(),
        env_vars: HashMap::new(),
        work_dir: Some(config.log_dir.clone()),
        budget: ResourceBudget {
            max_memory_mb: 1024,
            max_cpu_percent: 50,
            max_disk_mb: 5120,
            max_bandwidth_kbps: None,
            max_runtime: None, // Run indefinitely when active
        },
        dependencies: vec![],
        idle_timeout: None, // IDS shouldn't timeout
        auto_triggers: vec![
            AutoTriggerConfig {
                trigger_type: "specialist_escalation".to_string(),
                conditions: {
                    let mut m = HashMap::new();
                    m.insert("specialist".to_string(), serde_json::json!("probe_detector"));
                    m.insert("min_confidence".to_string(), serde_json::json!(0.8));
                    m
                },
                enabled: true,
            },
            AutoTriggerConfig {
                trigger_type: "big_momma_decision".to_string(),
                conditions: {
                    let mut m = HashMap::new();
                    m.insert("action".to_string(), serde_json::json!("activate_ids"));
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

/// Create YARA scanner tool
pub fn create_yara_tool(config: YaraConfig) -> DormantTool {
    DormantTool {
        id: "yara_scanner".to_string(),
        name: "YARA Scanner".to_string(),
        category: ToolCategory::ThreatDetection,
        description: "Pattern matching tool for malware identification using YARA rules.".to_string(),
        binary: PathBuf::from("/usr/bin/yara"),
        args_template: config.to_args(),
        env_vars: HashMap::new(),
        work_dir: None,
        budget: ResourceBudget {
            max_memory_mb: 512,
            max_cpu_percent: 75,
            max_disk_mb: 100,
            max_bandwidth_kbps: None,
            max_runtime: Some(Duration::from_secs(3600)),
        },
        dependencies: vec![],
        idle_timeout: Some(Duration::from_secs(300)),
        auto_triggers: vec![],
        state: super::toolkit::ToolState::Dormant,
        pid: None,
        activated_at: None,
        last_activity: None,
    }
}

/// Create ClamAV scanner tool
pub fn create_clamav_tool(config: ClamavConfig) -> DormantTool {
    DormantTool {
        id: "clamav_scanner".to_string(),
        name: "ClamAV Scanner".to_string(),
        category: ToolCategory::ThreatDetection,
        description: "Antivirus scanner for detecting malware and malicious files.".to_string(),
        binary: PathBuf::from("/usr/bin/clamscan"),
        args_template: config.to_args(),
        env_vars: HashMap::new(),
        work_dir: None,
        budget: ResourceBudget {
            max_memory_mb: 1024,
            max_cpu_percent: 50,
            max_disk_mb: 200,
            max_bandwidth_kbps: None,
            max_runtime: Some(Duration::from_secs(7200)),
        },
        dependencies: vec![],
        idle_timeout: Some(Duration::from_secs(600)),
        auto_triggers: vec![],
        state: super::toolkit::ToolState::Dormant,
        pid: None,
        activated_at: None,
        last_activity: None,
    }
}

/// Create Zeek (formerly Bro) network monitor
pub fn create_zeek_tool() -> DormantTool {
    DormantTool {
        id: "zeek_monitor".to_string(),
        name: "Zeek Network Monitor".to_string(),
        category: ToolCategory::ThreatDetection,
        description: "Network analysis framework for deep traffic inspection and threat detection.".to_string(),
        binary: PathBuf::from("/usr/bin/zeek"),
        args_template: vec![
            "-i".to_string(),
            "any".to_string(),
            "-C".to_string(), // Ignore checksum errors
        ],
        env_vars: HashMap::new(),
        work_dir: Some(PathBuf::from("/var/log/zeek")),
        budget: ResourceBudget {
            max_memory_mb: 512,
            max_cpu_percent: 40,
            max_disk_mb: 2048,
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

/// Create fail2ban jail monitor
pub fn create_fail2ban_tool() -> DormantTool {
    DormantTool {
        id: "fail2ban".to_string(),
        name: "Fail2Ban".to_string(),
        category: ToolCategory::ThreatDetection,
        description: "Intrusion prevention system that bans IPs showing malicious activity.".to_string(),
        binary: PathBuf::from("/usr/bin/fail2ban-server"),
        args_template: vec![
            "-f".to_string(),
            "-x".to_string(),
        ],
        env_vars: HashMap::new(),
        work_dir: None,
        budget: ResourceBudget {
            max_memory_mb: 128,
            max_cpu_percent: 10,
            max_disk_mb: 100,
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
                    m.insert("metric".to_string(), serde_json::json!("failed_auth_rate"));
                    m.insert("threshold".to_string(), serde_json::json!(10));
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

/// Create rkhunter (rootkit hunter)
pub fn create_rkhunter_tool() -> DormantTool {
    DormantTool {
        id: "rkhunter".to_string(),
        name: "Rootkit Hunter".to_string(),
        category: ToolCategory::ThreatDetection,
        description: "Scans for rootkits, backdoors, and local exploits.".to_string(),
        binary: PathBuf::from("/usr/bin/rkhunter"),
        args_template: vec![
            "--check".to_string(),
            "--skip-keypress".to_string(),
            "--report-warnings-only".to_string(),
        ],
        env_vars: HashMap::new(),
        work_dir: None,
        budget: ResourceBudget {
            max_memory_mb: 256,
            max_cpu_percent: 30,
            max_disk_mb: 50,
            max_bandwidth_kbps: None,
            max_runtime: Some(Duration::from_secs(1800)),
        },
        dependencies: vec![],
        idle_timeout: Some(Duration::from_secs(300)),
        auto_triggers: vec![],
        state: super::toolkit::ToolState::Dormant,
        pid: None,
        activated_at: None,
        last_activity: None,
    }
}

/// Get all default threat detection tools
pub fn default_threat_detection_tools() -> Vec<DormantTool> {
    vec![
        create_suricata_tool(SuricataConfig::default()),
        create_yara_tool(YaraConfig::default()),
        create_clamav_tool(ClamavConfig::default()),
        create_zeek_tool(),
        create_fail2ban_tool(),
        create_rkhunter_tool(),
    ]
}
