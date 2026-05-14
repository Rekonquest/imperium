//! Network Forensics Tools
//!
//! Dormant tools for network traffic capture and analysis:
//! - Packet capture (tcpdump, tshark)
//! - Flow analysis (nfdump, softflowd)
//! - Traffic replay (tcpreplay)
//! - Protocol analysis
//! - Bandwidth monitoring

use super::toolkit::{DormantTool, ResourceBudget, ToolCategory, AutoTriggerConfig};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

/// Packet capture configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketCaptureConfig {
    /// Network interface to capture on
    pub interface: String,
    /// Capture filter (BPF syntax)
    pub filter: Option<String>,
    /// Output file path
    pub output_file: PathBuf,
    /// Maximum file size in MB before rotation
    pub max_file_size_mb: u32,
    /// Maximum number of rotated files
    pub max_files: u32,
    /// Capture duration limit
    pub duration: Option<Duration>,
    /// Snap length (bytes to capture per packet)
    pub snaplen: u32,
    /// Enable promiscuous mode
    pub promiscuous: bool,
}

impl Default for PacketCaptureConfig {
    fn default() -> Self {
        Self {
            interface: "any".to_string(),
            filter: None,
            output_file: PathBuf::from("/var/lib/cloakwise/evidence/capture.pcap"),
            max_file_size_mb: 100,
            max_files: 10,
            duration: Some(Duration::from_secs(3600)),
            snaplen: 65535,
            promiscuous: true,
        }
    }
}

impl PacketCaptureConfig {
    /// Build tcpdump arguments
    pub fn to_tcpdump_args(&self) -> Vec<String> {
        let mut args = vec![
            "-i".to_string(),
            self.interface.clone(),
            "-s".to_string(),
            self.snaplen.to_string(),
            "-w".to_string(),
            self.output_file.to_string_lossy().to_string(),
            "-C".to_string(),
            self.max_file_size_mb.to_string(),
            "-W".to_string(),
            self.max_files.to_string(),
        ];

        if self.promiscuous {
            args.push("-p".to_string());
        }

        if let Some(ref filter) = self.filter {
            args.push(filter.clone());
        }

        args
    }

    /// Build tshark arguments
    pub fn to_tshark_args(&self) -> Vec<String> {
        let mut args = vec![
            "-i".to_string(),
            self.interface.clone(),
            "-w".to_string(),
            self.output_file.to_string_lossy().to_string(),
            "-b".to_string(),
            format!("filesize:{}", self.max_file_size_mb * 1024),
            "-b".to_string(),
            format!("files:{}", self.max_files),
        ];

        if let Some(dur) = self.duration {
            args.push("-a".to_string());
            args.push(format!("duration:{}", dur.as_secs()));
        }

        if let Some(ref filter) = self.filter {
            args.push("-f".to_string());
            args.push(filter.clone());
        }

        args
    }
}

/// Flow analysis configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowAnalysisConfig {
    /// NetFlow/IPFIX collector port
    pub collector_port: u16,
    /// Flow export interval in seconds
    pub export_interval: u32,
    /// Active timeout in seconds
    pub active_timeout: u32,
    /// Inactive timeout in seconds
    pub inactive_timeout: u32,
    /// Output directory for flow data
    pub output_dir: PathBuf,
}

impl Default for FlowAnalysisConfig {
    fn default() -> Self {
        Self {
            collector_port: 2055,
            export_interval: 60,
            active_timeout: 1800,
            inactive_timeout: 15,
            output_dir: PathBuf::from("/var/lib/cloakwise/flows"),
        }
    }
}

/// Bandwidth monitor configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BandwidthMonitorConfig {
    /// Interface to monitor
    pub interface: String,
    /// Sample interval in seconds
    pub interval: u32,
    /// Alert threshold in Mbps
    pub alert_threshold_mbps: Option<u32>,
    /// Output format (json, csv, human)
    pub output_format: String,
}

impl Default for BandwidthMonitorConfig {
    fn default() -> Self {
        Self {
            interface: "eth0".to_string(),
            interval: 1,
            alert_threshold_mbps: None,
            output_format: "json".to_string(),
        }
    }
}

/// Create packet capture tool
pub fn create_packet_capture_tool(config: PacketCaptureConfig) -> DormantTool {
    let output_dir = config.output_file.parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("/var/lib/cloakwise/evidence"));

    DormantTool {
        id: "pcap_capture".to_string(),
        name: "Packet Capture".to_string(),
        category: ToolCategory::NetworkForensics,
        description: "Captures network packets for forensic analysis. Supports rotation and filtering.".to_string(),
        binary: PathBuf::from("/usr/sbin/tcpdump"),
        args_template: config.to_tcpdump_args(),
        env_vars: HashMap::new(),
        work_dir: Some(output_dir),
        budget: ResourceBudget {
            max_memory_mb: 128,
            max_cpu_percent: 15,
            max_disk_mb: config.max_file_size_mb * config.max_files,
            max_bandwidth_kbps: None,
            max_runtime: config.duration,
        },
        dependencies: vec![],
        idle_timeout: Some(Duration::from_secs(300)), // 5 min idle timeout
        auto_triggers: vec![
            AutoTriggerConfig {
                trigger_type: "specialist_escalation".to_string(),
                conditions: {
                    let mut m = HashMap::new();
                    m.insert("specialist".to_string(), serde_json::json!("probe_detector"));
                    m.insert("min_confidence".to_string(), serde_json::json!(0.7));
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

/// Create deep packet capture with tshark (more detailed analysis)
pub fn create_deep_capture_tool(config: PacketCaptureConfig) -> DormantTool {
    let output_dir = config.output_file.parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("/var/lib/cloakwise/evidence"));

    DormantTool {
        id: "deep_capture".to_string(),
        name: "Deep Packet Analysis".to_string(),
        category: ToolCategory::NetworkForensics,
        description: "Deep packet inspection and protocol analysis with Wireshark/tshark.".to_string(),
        binary: PathBuf::from("/usr/bin/tshark"),
        args_template: config.to_tshark_args(),
        env_vars: HashMap::new(),
        work_dir: Some(output_dir),
        budget: ResourceBudget {
            max_memory_mb: 512,
            max_cpu_percent: 30,
            max_disk_mb: config.max_file_size_mb * config.max_files * 2,
            max_bandwidth_kbps: None,
            max_runtime: config.duration,
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

/// Create NetFlow collector tool
pub fn create_flow_collector_tool(config: FlowAnalysisConfig) -> DormantTool {
    DormantTool {
        id: "flow_collector".to_string(),
        name: "NetFlow Collector".to_string(),
        category: ToolCategory::NetworkForensics,
        description: "Collects and analyzes network flow data (NetFlow/IPFIX).".to_string(),
        binary: PathBuf::from("/usr/bin/nfcapd"),
        args_template: vec![
            "-w".to_string(),
            "-D".to_string(),
            "-l".to_string(),
            config.output_dir.to_string_lossy().to_string(),
            "-p".to_string(),
            config.collector_port.to_string(),
            "-T".to_string(),
            "all".to_string(),
        ],
        env_vars: HashMap::new(),
        work_dir: Some(config.output_dir.clone()),
        budget: ResourceBudget {
            max_memory_mb: 256,
            max_cpu_percent: 10,
            max_disk_mb: 2048,
            max_bandwidth_kbps: None,
            max_runtime: None, // Run indefinitely
        },
        dependencies: vec![],
        idle_timeout: None, // Don't timeout flow collector
        auto_triggers: vec![],
        state: super::toolkit::ToolState::Dormant,
        pid: None,
        activated_at: None,
        last_activity: None,
    }
}

/// Create bandwidth monitor tool
pub fn create_bandwidth_monitor_tool(config: BandwidthMonitorConfig) -> DormantTool {
    DormantTool {
        id: "bandwidth_monitor".to_string(),
        name: "Bandwidth Monitor".to_string(),
        category: ToolCategory::NetworkForensics,
        description: "Real-time bandwidth monitoring and alerting.".to_string(),
        binary: PathBuf::from("/usr/bin/vnstat"),
        args_template: vec![
            "-l".to_string(),
            "-i".to_string(),
            config.interface.clone(),
            "--json".to_string(),
        ],
        env_vars: HashMap::new(),
        work_dir: None,
        budget: ResourceBudget {
            max_memory_mb: 32,
            max_cpu_percent: 5,
            max_disk_mb: 100,
            max_bandwidth_kbps: None,
            max_runtime: None,
        },
        dependencies: vec![],
        idle_timeout: Some(Duration::from_secs(1800)),
        auto_triggers: vec![],
        state: super::toolkit::ToolState::Dormant,
        pid: None,
        activated_at: None,
        last_activity: None,
    }
}

/// Create connection tracker tool
pub fn create_connection_tracker_tool() -> DormantTool {
    DormantTool {
        id: "conn_tracker".to_string(),
        name: "Connection Tracker".to_string(),
        category: ToolCategory::NetworkForensics,
        description: "Tracks and logs all network connections with metadata.".to_string(),
        binary: PathBuf::from("/usr/sbin/conntrack"),
        args_template: vec![
            "-E".to_string(),
            "-o".to_string(),
            "timestamp,extended".to_string(),
        ],
        env_vars: HashMap::new(),
        work_dir: None,
        budget: ResourceBudget {
            max_memory_mb: 64,
            max_cpu_percent: 10,
            max_disk_mb: 512,
            max_bandwidth_kbps: None,
            max_runtime: None,
        },
        dependencies: vec![],
        idle_timeout: Some(Duration::from_secs(3600)),
        auto_triggers: vec![
            AutoTriggerConfig {
                trigger_type: "threshold_breach".to_string(),
                conditions: {
                    let mut m = HashMap::new();
                    m.insert("metric".to_string(), serde_json::json!("connection_rate"));
                    m.insert("threshold".to_string(), serde_json::json!(1000));
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

/// Get all default forensics tools
pub fn default_forensics_tools() -> Vec<DormantTool> {
    vec![
        create_packet_capture_tool(PacketCaptureConfig::default()),
        create_deep_capture_tool(PacketCaptureConfig {
            output_file: PathBuf::from("/var/lib/cloakwise/evidence/deep_capture.pcap"),
            ..Default::default()
        }),
        create_flow_collector_tool(FlowAnalysisConfig::default()),
        create_bandwidth_monitor_tool(BandwidthMonitorConfig::default()),
        create_connection_tracker_tool(),
    ]
}
