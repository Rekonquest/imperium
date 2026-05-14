//! Counter-Forensics Detection
//!
//! Tools to detect when the system is being analyzed or surveilled:
//! - DPI (Deep Packet Inspection) detection
//! - Traffic analysis detection
//! - Timing attack detection
//! - Honeypot detection
//! - Fingerprinting detection

use super::toolkit::{DormantTool, ResourceBudget, ToolCategory, AutoTriggerConfig};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

/// DPI detection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpiDetectorConfig {
    /// Interface to monitor
    pub interface: String,
    /// Detection sensitivity (0.0 - 1.0)
    pub sensitivity: f32,
    /// Alert threshold for DPI indicators
    pub alert_threshold: u32,
    /// Enable timing analysis
    pub timing_analysis: bool,
    /// Enable packet size analysis
    pub size_analysis: bool,
    /// Enable protocol fingerprinting detection
    pub fingerprint_detection: bool,
    /// Log file path
    pub log_file: PathBuf,
}

impl Default for DpiDetectorConfig {
    fn default() -> Self {
        Self {
            interface: "any".to_string(),
            sensitivity: 0.7,
            alert_threshold: 5,
            timing_analysis: true,
            size_analysis: true,
            fingerprint_detection: true,
            log_file: PathBuf::from("/var/log/cloakwise/dpi_detection.log"),
        }
    }
}

/// Traffic analysis detection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficAnalysisConfig {
    /// Window size for pattern detection (seconds)
    pub window_size: u32,
    /// Minimum correlation coefficient for detection
    pub correlation_threshold: f32,
    /// Enable inter-packet delay analysis
    pub ipd_analysis: bool,
    /// Enable flow correlation detection
    pub flow_correlation: bool,
    /// Enable volume analysis
    pub volume_analysis: bool,
}

impl Default for TrafficAnalysisConfig {
    fn default() -> Self {
        Self {
            window_size: 60,
            correlation_threshold: 0.8,
            ipd_analysis: true,
            flow_correlation: true,
            volume_analysis: true,
        }
    }
}

/// Honeypot/decoy detection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoneypotDetectorConfig {
    /// Target ranges to probe
    pub target_ranges: Vec<String>,
    /// Ports to check for honeypots
    pub check_ports: Vec<u16>,
    /// Detection methods to use
    pub methods: Vec<String>,
    /// Timeout per probe in milliseconds
    pub timeout_ms: u32,
}

impl Default for HoneypotDetectorConfig {
    fn default() -> Self {
        Self {
            target_ranges: vec![],
            check_ports: vec![22, 23, 80, 443, 445, 3389],
            methods: vec![
                "banner_analysis".to_string(),
                "latency_check".to_string(),
                "service_verification".to_string(),
            ],
            timeout_ms: 5000,
        }
    }
}

/// Create DPI detector tool
pub fn create_dpi_detector_tool(config: DpiDetectorConfig) -> DormantTool {
    // Build environment variables for the detector script
    let mut env_vars = HashMap::new();
    env_vars.insert("DPI_INTERFACE".to_string(), config.interface.clone());
    env_vars.insert("DPI_SENSITIVITY".to_string(), config.sensitivity.to_string());
    env_vars.insert("DPI_THRESHOLD".to_string(), config.alert_threshold.to_string());
    env_vars.insert("DPI_TIMING".to_string(), config.timing_analysis.to_string());
    env_vars.insert("DPI_SIZE".to_string(), config.size_analysis.to_string());
    env_vars.insert("DPI_FINGERPRINT".to_string(), config.fingerprint_detection.to_string());
    env_vars.insert("DPI_LOG".to_string(), config.log_file.to_string_lossy().to_string());

    DormantTool {
        id: "dpi_detector".to_string(),
        name: "DPI Detector".to_string(),
        category: ToolCategory::CounterForensics,
        description: "Detects deep packet inspection attempts by analyzing traffic patterns, timing, and protocol fingerprints.".to_string(),
        binary: PathBuf::from("/usr/local/bin/cloakwise-dpi-detect"),
        args_template: vec![
            "--interface".to_string(),
            config.interface,
            "--sensitivity".to_string(),
            config.sensitivity.to_string(),
        ],
        env_vars,
        work_dir: None,
        budget: ResourceBudget {
            max_memory_mb: 256,
            max_cpu_percent: 20,
            max_disk_mb: 512,
            max_bandwidth_kbps: None,
            max_runtime: None,
        },
        dependencies: vec![],
        idle_timeout: None, // Run continuously when active
        auto_triggers: vec![
            AutoTriggerConfig {
                trigger_type: "specialist_escalation".to_string(),
                conditions: {
                    let mut m = HashMap::new();
                    m.insert("specialist".to_string(), serde_json::json!("probe_detector"));
                    m.insert("min_confidence".to_string(), serde_json::json!(0.6));
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

/// Create traffic analysis detector tool
pub fn create_traffic_analysis_detector_tool(config: TrafficAnalysisConfig) -> DormantTool {
    let mut env_vars = HashMap::new();
    env_vars.insert("TA_WINDOW".to_string(), config.window_size.to_string());
    env_vars.insert("TA_CORRELATION".to_string(), config.correlation_threshold.to_string());
    env_vars.insert("TA_IPD".to_string(), config.ipd_analysis.to_string());
    env_vars.insert("TA_FLOW_CORR".to_string(), config.flow_correlation.to_string());
    env_vars.insert("TA_VOLUME".to_string(), config.volume_analysis.to_string());

    DormantTool {
        id: "traffic_analysis_detector".to_string(),
        name: "Traffic Analysis Detector".to_string(),
        category: ToolCategory::CounterForensics,
        description: "Detects statistical traffic analysis attacks by monitoring for correlation patterns.".to_string(),
        binary: PathBuf::from("/usr/local/bin/cloakwise-ta-detect"),
        args_template: vec![
            "--window".to_string(),
            config.window_size.to_string(),
            "--threshold".to_string(),
            config.correlation_threshold.to_string(),
        ],
        env_vars,
        work_dir: None,
        budget: ResourceBudget {
            max_memory_mb: 512,
            max_cpu_percent: 25,
            max_disk_mb: 256,
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

/// Create timing attack detector
pub fn create_timing_detector_tool() -> DormantTool {
    DormantTool {
        id: "timing_detector".to_string(),
        name: "Timing Attack Detector".to_string(),
        category: ToolCategory::CounterForensics,
        description: "Monitors for timing-based side-channel attacks and traffic correlation.".to_string(),
        binary: PathBuf::from("/usr/local/bin/cloakwise-timing-detect"),
        args_template: vec![
            "--precision".to_string(),
            "microsecond".to_string(),
            "--buffer".to_string(),
            "10000".to_string(),
        ],
        env_vars: HashMap::new(),
        work_dir: None,
        budget: ResourceBudget {
            max_memory_mb: 128,
            max_cpu_percent: 15,
            max_disk_mb: 100,
            max_bandwidth_kbps: None,
            max_runtime: None,
        },
        dependencies: vec![],
        idle_timeout: Some(Duration::from_secs(3600)),
        auto_triggers: vec![],
        state: super::toolkit::ToolState::Dormant,
        pid: None,
        activated_at: None,
        last_activity: None,
    }
}

/// Create fingerprint detector (JA3, JA3S, JARM, etc.)
pub fn create_fingerprint_detector_tool() -> DormantTool {
    DormantTool {
        id: "fingerprint_detector".to_string(),
        name: "TLS Fingerprint Detector".to_string(),
        category: ToolCategory::CounterForensics,
        description: "Detects TLS fingerprinting attempts (JA3, JA3S, JARM) and alerts on known malicious signatures.".to_string(),
        binary: PathBuf::from("/usr/local/bin/cloakwise-fingerprint-detect"),
        args_template: vec![
            "--ja3".to_string(),
            "--ja3s".to_string(),
            "--jarm".to_string(),
            "--database".to_string(),
            "/var/lib/cloakwise/fingerprints.db".to_string(),
        ],
        env_vars: HashMap::new(),
        work_dir: None,
        budget: ResourceBudget {
            max_memory_mb: 256,
            max_cpu_percent: 20,
            max_disk_mb: 200,
            max_bandwidth_kbps: None,
            max_runtime: None,
        },
        dependencies: vec!["pcap_capture".to_string()],
        idle_timeout: None,
        auto_triggers: vec![],
        state: super::toolkit::ToolState::Dormant,
        pid: None,
        activated_at: None,
        last_activity: None,
    }
}

/// Create decoy/honeypot deployer
pub fn create_decoy_deployer_tool() -> DormantTool {
    DormantTool {
        id: "decoy_deployer".to_string(),
        name: "Decoy Deployer".to_string(),
        category: ToolCategory::CounterForensics,
        description: "Deploys decoy services and honeypots to detect and misdirect attackers.".to_string(),
        binary: PathBuf::from("/usr/local/bin/cloakwise-decoy"),
        args_template: vec![
            "--config".to_string(),
            "/etc/cloakwise/decoys.yaml".to_string(),
        ],
        env_vars: HashMap::new(),
        work_dir: None,
        budget: ResourceBudget {
            max_memory_mb: 512,
            max_cpu_percent: 10,
            max_disk_mb: 100,
            max_bandwidth_kbps: Some(1000),
            max_runtime: None,
        },
        dependencies: vec![],
        idle_timeout: None,
        auto_triggers: vec![
            AutoTriggerConfig {
                trigger_type: "specialist_escalation".to_string(),
                conditions: {
                    let mut m = HashMap::new();
                    m.insert("specialist".to_string(), serde_json::json!("probe_detector"));
                    m.insert("min_confidence".to_string(), serde_json::json!(0.9));
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

/// Create active probing detector
pub fn create_probe_detector_tool() -> DormantTool {
    DormantTool {
        id: "active_probe_detector".to_string(),
        name: "Active Probe Detector".to_string(),
        category: ToolCategory::CounterForensics,
        description: "Detects active probing attempts like those used by the Great Firewall and similar systems.".to_string(),
        binary: PathBuf::from("/usr/local/bin/cloakwise-probe-detect"),
        args_template: vec![
            "--mode".to_string(),
            "passive".to_string(),
            "--log-probes".to_string(),
        ],
        env_vars: HashMap::new(),
        work_dir: None,
        budget: ResourceBudget {
            max_memory_mb: 128,
            max_cpu_percent: 10,
            max_disk_mb: 256,
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
                    m.insert("metric".to_string(), serde_json::json!("unusual_connection_pattern"));
                    m.insert("threshold".to_string(), serde_json::json!(3));
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

/// Get all default counter-forensics tools
pub fn default_counter_forensics_tools() -> Vec<DormantTool> {
    vec![
        create_dpi_detector_tool(DpiDetectorConfig::default()),
        create_traffic_analysis_detector_tool(TrafficAnalysisConfig::default()),
        create_timing_detector_tool(),
        create_fingerprint_detector_tool(),
        create_decoy_deployer_tool(),
        create_probe_detector_tool(),
    ]
}
