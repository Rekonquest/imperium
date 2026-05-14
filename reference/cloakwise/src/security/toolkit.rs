//! Security Toolkit Manager
//!
//! Manages dormant security tools with zero-overhead until activation.
//! Tools are defined as configurations only - no processes, no memory
//! allocation beyond the config struct itself.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use parking_lot::RwLock;

/// Tool state in the lifecycle
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolState {
    /// Tool is defined but not running (zero resource usage)
    Dormant,
    /// Tool is starting up
    Activating,
    /// Tool is running and consuming resources
    Active,
    /// Tool is shutting down
    Deactivating,
    /// Tool encountered an error
    Error,
}

impl Default for ToolState {
    fn default() -> Self {
        Self::Dormant
    }
}

/// Tool category for organization and batch operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolCategory {
    /// Network traffic analysis and capture
    NetworkForensics,
    /// Threat detection and IDS
    ThreatDetection,
    /// Incident response and evidence
    IncidentResponse,
    /// Detect surveillance attempts
    CounterForensics,
    /// Active defense measures
    DefenseHardening,
    /// Open source intelligence
    Osint,
    /// Software defined radio
    RadioBridge,
}

/// Resource budget for a tool
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceBudget {
    /// Maximum memory usage in MB
    pub max_memory_mb: u32,
    /// Maximum CPU percentage (0-100)
    pub max_cpu_percent: u8,
    /// Maximum disk usage in MB
    pub max_disk_mb: u32,
    /// Maximum network bandwidth in Kbps
    pub max_bandwidth_kbps: Option<u32>,
    /// Maximum runtime before auto-deactivation
    pub max_runtime: Option<Duration>,
}

impl Default for ResourceBudget {
    fn default() -> Self {
        Self {
            max_memory_mb: 256,
            max_cpu_percent: 25,
            max_disk_mb: 1024,
            max_bandwidth_kbps: None,
            max_runtime: Some(Duration::from_secs(3600)), // 1 hour default
        }
    }
}

/// Activation trigger types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivationTrigger {
    /// Manual activation via API or CLI
    Manual { user: String },
    /// Specialist detected a threat
    SpecialistEscalation { specialist: String, confidence: f32 },
    /// Threshold breach (e.g., anomaly score)
    ThresholdBreach { metric: String, value: f64, threshold: f64 },
    /// Big Momma decision
    BigMommaDecision { reason: String },
    /// Scheduled activation
    Scheduled { schedule: String },
    /// Another tool requested activation
    ToolChain { source_tool: String },
    /// SDR fallback triggered
    RadioFallback { reason: String },
}

/// Dormant tool definition - just config, no runtime overhead
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DormantTool {
    /// Unique tool identifier
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Tool category
    pub category: ToolCategory,
    /// Description of what the tool does
    pub description: String,
    /// Binary or command to execute
    pub binary: PathBuf,
    /// Command line arguments template
    pub args_template: Vec<String>,
    /// Environment variables
    pub env_vars: HashMap<String, String>,
    /// Working directory
    pub work_dir: Option<PathBuf>,
    /// Resource budget when active
    pub budget: ResourceBudget,
    /// Dependencies (other tool IDs that must be active first)
    pub dependencies: Vec<String>,
    /// Auto-deactivate after this duration of inactivity
    pub idle_timeout: Option<Duration>,
    /// Activation triggers that can auto-start this tool
    pub auto_triggers: Vec<AutoTriggerConfig>,
    /// Current state
    #[serde(skip)]
    pub state: ToolState,
    /// Process ID when active
    #[serde(skip)]
    pub pid: Option<u32>,
    /// Activation timestamp
    #[serde(skip)]
    pub activated_at: Option<Instant>,
    /// Last activity timestamp
    #[serde(skip)]
    pub last_activity: Option<Instant>,
}

/// Auto-trigger configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoTriggerConfig {
    /// Trigger type
    pub trigger_type: String,
    /// Conditions as key-value pairs
    pub conditions: HashMap<String, serde_json::Value>,
    /// Whether this trigger is enabled
    pub enabled: bool,
}

impl DormantTool {
    /// Create a new dormant tool definition
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        category: ToolCategory,
        binary: impl Into<PathBuf>,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            category,
            description: String::new(),
            binary: binary.into(),
            args_template: vec![],
            env_vars: HashMap::new(),
            work_dir: None,
            budget: ResourceBudget::default(),
            dependencies: vec![],
            idle_timeout: Some(Duration::from_secs(1800)), // 30 min default
            auto_triggers: vec![],
            state: ToolState::Dormant,
            pid: None,
            activated_at: None,
            last_activity: None,
        }
    }

    /// Set description
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    /// Set arguments template
    pub fn with_args(mut self, args: Vec<String>) -> Self {
        self.args_template = args;
        self
    }

    /// Set resource budget
    pub fn with_budget(mut self, budget: ResourceBudget) -> Self {
        self.budget = budget;
        self
    }

    /// Add dependency
    pub fn with_dependency(mut self, dep: impl Into<String>) -> Self {
        self.dependencies.push(dep.into());
        self
    }

    /// Check if tool is dormant (zero resource usage)
    pub fn is_dormant(&self) -> bool {
        self.state == ToolState::Dormant
    }

    /// Check if tool is active
    pub fn is_active(&self) -> bool {
        self.state == ToolState::Active
    }

    /// Get runtime duration if active
    pub fn runtime(&self) -> Option<Duration> {
        self.activated_at.map(|t| t.elapsed())
    }

    /// Check if tool should auto-deactivate due to timeout
    pub fn should_timeout(&self) -> bool {
        if let (Some(timeout), Some(last)) = (self.idle_timeout, self.last_activity) {
            last.elapsed() > timeout
        } else if let (Some(max_runtime), Some(activated)) =
            (self.budget.max_runtime, self.activated_at)
        {
            activated.elapsed() > max_runtime
        } else {
            false
        }
    }
}

/// Event sent to toolkit manager
#[derive(Debug, Clone)]
pub enum ToolkitEvent {
    /// Activate a tool
    Activate { tool_id: String, trigger: ActivationTrigger },
    /// Deactivate a tool
    Deactivate { tool_id: String, reason: String },
    /// Activate all tools in a category
    ActivateCategory { category: ToolCategory, trigger: ActivationTrigger },
    /// Deactivate all tools in a category
    DeactivateCategory { category: ToolCategory },
    /// Record activity (prevents idle timeout)
    RecordActivity { tool_id: String },
    /// Check for timed-out tools
    CheckTimeouts,
    /// Emergency deactivate all
    EmergencyShutdown,
}

/// Toolkit status for monitoring
#[derive(Debug, Clone, Serialize)]
pub struct ToolkitStatus {
    pub total_tools: usize,
    pub dormant_count: usize,
    pub active_count: usize,
    pub error_count: usize,
    pub active_tools: Vec<ActiveToolInfo>,
    pub total_memory_mb: u32,
    pub total_cpu_percent: u8,
}

/// Information about an active tool
#[derive(Debug, Clone, Serialize)]
pub struct ActiveToolInfo {
    pub id: String,
    pub name: String,
    pub category: ToolCategory,
    pub runtime_secs: u64,
    pub pid: Option<u32>,
}

/// Security Toolkit Manager
///
/// Manages all security tools with dormant-first architecture.
/// Tools consume zero resources until explicitly activated.
pub struct SecurityToolkit {
    /// All registered tools (dormant and active)
    tools: RwLock<HashMap<String, DormantTool>>,
    /// Event sender for async operations
    event_tx: Option<mpsc::Sender<ToolkitEvent>>,
    /// Data directory for tool outputs
    data_dir: PathBuf,
    /// Evidence storage directory
    evidence_dir: PathBuf,
}

impl SecurityToolkit {
    /// Create a new security toolkit
    pub fn new(data_dir: PathBuf) -> Self {
        let evidence_dir = data_dir.join("evidence");
        Self {
            tools: RwLock::new(HashMap::new()),
            event_tx: None,
            data_dir,
            evidence_dir,
        }
    }

    /// Register a dormant tool
    pub fn register(&self, tool: DormantTool) {
        let mut tools = self.tools.write();
        tracing::info!("Registering dormant tool: {} ({})", tool.name, tool.id);
        tools.insert(tool.id.clone(), tool);
    }

    /// Register multiple tools
    pub fn register_all(&self, tools: Vec<DormantTool>) {
        for tool in tools {
            self.register(tool);
        }
    }

    /// Get toolkit status
    pub fn status(&self) -> ToolkitStatus {
        let tools = self.tools.read();

        let mut dormant_count = 0;
        let mut active_count = 0;
        let mut error_count = 0;
        let mut active_tools = Vec::new();
        let mut total_memory = 0u32;
        let mut total_cpu = 0u8;

        for tool in tools.values() {
            match tool.state {
                ToolState::Dormant => dormant_count += 1,
                ToolState::Active => {
                    active_count += 1;
                    total_memory += tool.budget.max_memory_mb;
                    total_cpu = total_cpu.saturating_add(tool.budget.max_cpu_percent);
                    active_tools.push(ActiveToolInfo {
                        id: tool.id.clone(),
                        name: tool.name.clone(),
                        category: tool.category,
                        runtime_secs: tool.runtime().map(|d| d.as_secs()).unwrap_or(0),
                        pid: tool.pid,
                    });
                }
                ToolState::Error => error_count += 1,
                _ => {}
            }
        }

        ToolkitStatus {
            total_tools: tools.len(),
            dormant_count,
            active_count,
            error_count,
            active_tools,
            total_memory_mb: total_memory,
            total_cpu_percent: total_cpu.min(100),
        }
    }

    /// Get a tool by ID
    pub fn get_tool(&self, id: &str) -> Option<DormantTool> {
        self.tools.read().get(id).cloned()
    }

    /// List all tools
    pub fn list_tools(&self) -> Vec<DormantTool> {
        self.tools.read().values().cloned().collect()
    }

    /// List tools by category
    pub fn list_by_category(&self, category: ToolCategory) -> Vec<DormantTool> {
        self.tools
            .read()
            .values()
            .filter(|t| t.category == category)
            .cloned()
            .collect()
    }

    /// Activate a tool
    pub async fn activate(&self, tool_id: &str, trigger: ActivationTrigger) -> Result<()> {
        // Check dependencies first
        let deps = {
            let tools = self.tools.read();
            let tool = tools.get(tool_id)
                .context(format!("Tool not found: {}", tool_id))?;

            if tool.state == ToolState::Active {
                tracing::debug!("Tool {} is already active", tool_id);
                return Ok(());
            }

            tool.dependencies.clone()
        };

        // Activate dependencies recursively
        for dep_id in &deps {
            Box::pin(self.activate(dep_id, trigger.clone())).await?;
        }

        // Now activate the tool
        let (binary, args, env_vars, work_dir) = {
            let mut tools = self.tools.write();
            let tool = tools.get_mut(tool_id)
                .context(format!("Tool not found: {}", tool_id))?;

            tool.state = ToolState::Activating;

            (
                tool.binary.clone(),
                tool.args_template.clone(),
                tool.env_vars.clone(),
                tool.work_dir.clone(),
            )
        };

        tracing::info!("Activating security tool: {} (trigger: {:?})", tool_id, trigger);

        // Create data directory
        tokio::fs::create_dir_all(&self.data_dir).await?;
        tokio::fs::create_dir_all(&self.evidence_dir).await?;

        // Build and spawn the process
        let mut cmd = tokio::process::Command::new(&binary);
        cmd.args(&args);

        for (key, value) in &env_vars {
            cmd.env(key, value);
        }

        if let Some(ref dir) = work_dir {
            cmd.current_dir(dir);
        }

        cmd.stdin(std::process::Stdio::null());
        cmd.stdout(std::process::Stdio::null());
        cmd.stderr(std::process::Stdio::null());

        match cmd.spawn() {
            Ok(child) => {
                let pid = child.id();
                let mut tools = self.tools.write();
                if let Some(tool) = tools.get_mut(tool_id) {
                    tool.state = ToolState::Active;
                    tool.pid = pid;
                    tool.activated_at = Some(Instant::now());
                    tool.last_activity = Some(Instant::now());
                }
                tracing::info!("Tool {} activated with PID {:?}", tool_id, pid);
                Ok(())
            }
            Err(e) => {
                let mut tools = self.tools.write();
                if let Some(tool) = tools.get_mut(tool_id) {
                    tool.state = ToolState::Error;
                }
                tracing::error!("Failed to activate tool {}: {}", tool_id, e);
                Err(e.into())
            }
        }
    }

    /// Deactivate a tool
    pub async fn deactivate(&self, tool_id: &str, reason: &str) -> Result<()> {
        let pid = {
            let mut tools = self.tools.write();
            let tool = tools.get_mut(tool_id)
                .context(format!("Tool not found: {}", tool_id))?;

            if tool.state == ToolState::Dormant {
                return Ok(());
            }

            tool.state = ToolState::Deactivating;
            tool.pid
        };

        tracing::info!("Deactivating tool {}: {}", tool_id, reason);

        // Kill the process if running
        if let Some(pid) = pid {
            let _ = tokio::process::Command::new("kill")
                .args(["-15", &pid.to_string()])
                .output()
                .await;

            tokio::time::sleep(Duration::from_secs(2)).await;

            // Force kill if still running
            let _ = tokio::process::Command::new("kill")
                .args(["-9", &pid.to_string()])
                .output()
                .await;
        }

        // Update state
        {
            let mut tools = self.tools.write();
            if let Some(tool) = tools.get_mut(tool_id) {
                tool.state = ToolState::Dormant;
                tool.pid = None;
                tool.activated_at = None;
                tool.last_activity = None;
            }
        }

        tracing::info!("Tool {} deactivated and dormant", tool_id);
        Ok(())
    }

    /// Activate all tools in a category
    pub async fn activate_category(&self, category: ToolCategory, trigger: ActivationTrigger) -> Result<()> {
        let tool_ids: Vec<String> = self.tools
            .read()
            .values()
            .filter(|t| t.category == category && t.state == ToolState::Dormant)
            .map(|t| t.id.clone())
            .collect();

        for tool_id in tool_ids {
            if let Err(e) = self.activate(&tool_id, trigger.clone()).await {
                tracing::warn!("Failed to activate {}: {}", tool_id, e);
            }
        }

        Ok(())
    }

    /// Deactivate all tools in a category
    pub async fn deactivate_category(&self, category: ToolCategory) -> Result<()> {
        let tool_ids: Vec<String> = self.tools
            .read()
            .values()
            .filter(|t| t.category == category && t.state == ToolState::Active)
            .map(|t| t.id.clone())
            .collect();

        for tool_id in tool_ids {
            if let Err(e) = self.deactivate(&tool_id, "category deactivation").await {
                tracing::warn!("Failed to deactivate {}: {}", tool_id, e);
            }
        }

        Ok(())
    }

    /// Emergency shutdown - deactivate everything
    pub async fn emergency_shutdown(&self) -> Result<()> {
        tracing::warn!("Emergency shutdown of all security tools");

        let tool_ids: Vec<String> = self.tools
            .read()
            .values()
            .filter(|t| t.state == ToolState::Active)
            .map(|t| t.id.clone())
            .collect();

        for tool_id in tool_ids {
            let _ = self.deactivate(&tool_id, "emergency shutdown").await;
        }

        Ok(())
    }

    /// Check and deactivate timed-out tools
    pub async fn check_timeouts(&self) -> Result<()> {
        let timed_out: Vec<String> = self.tools
            .read()
            .values()
            .filter(|t| t.state == ToolState::Active && t.should_timeout())
            .map(|t| t.id.clone())
            .collect();

        for tool_id in timed_out {
            tracing::info!("Tool {} timed out, deactivating", tool_id);
            let _ = self.deactivate(&tool_id, "idle timeout").await;
        }

        Ok(())
    }

    /// Record activity for a tool (prevents idle timeout)
    pub fn record_activity(&self, tool_id: &str) {
        let mut tools = self.tools.write();
        if let Some(tool) = tools.get_mut(tool_id) {
            tool.last_activity = Some(Instant::now());
        }
    }

    /// Get evidence directory path
    pub fn evidence_dir(&self) -> &PathBuf {
        &self.evidence_dir
    }
}

/// Create default security toolkit with common tools
pub fn create_default_toolkit(data_dir: PathBuf) -> SecurityToolkit {
    let toolkit = SecurityToolkit::new(data_dir.clone());

    // Register default dormant tools
    toolkit.register_all(vec![
        // Network Forensics
        DormantTool::new("pcap_capture", "Packet Capture", ToolCategory::NetworkForensics, "/usr/sbin/tcpdump")
            .with_description("Captures network packets for analysis")
            .with_args(vec!["-i".into(), "any".into(), "-w".into(), format!("{}/capture.pcap", data_dir.display())]),

        DormantTool::new("flow_analyzer", "Flow Analyzer", ToolCategory::NetworkForensics, "/usr/bin/nfdump")
            .with_description("Analyzes network flow data"),

        // Threat Detection
        DormantTool::new("suricata", "Suricata IDS", ToolCategory::ThreatDetection, "/usr/bin/suricata")
            .with_description("Network intrusion detection system")
            .with_budget(ResourceBudget {
                max_memory_mb: 512,
                max_cpu_percent: 50,
                ..Default::default()
            }),

        DormantTool::new("yara_scanner", "YARA Scanner", ToolCategory::ThreatDetection, "/usr/bin/yara")
            .with_description("Pattern matching for malware detection"),

        // Incident Response
        DormantTool::new("evidence_collector", "Evidence Collector", ToolCategory::IncidentResponse, "/usr/local/bin/evidence-collect")
            .with_description("Collects forensic evidence"),

        // Counter-Forensics
        DormantTool::new("traffic_analyzer", "DPI Detector", ToolCategory::CounterForensics, "/usr/local/bin/dpi-detect")
            .with_description("Detects deep packet inspection attempts"),

        // Defense Hardening
        DormantTool::new("rate_limiter", "Rate Limiter", ToolCategory::DefenseHardening, "/usr/sbin/iptables")
            .with_description("Applies rate limiting rules"),

        DormantTool::new("fail2ban", "Fail2Ban", ToolCategory::DefenseHardening, "/usr/bin/fail2ban-client")
            .with_description("Bans IPs with suspicious activity"),
    ]);

    toolkit
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dormant_tool_creation() {
        let tool = DormantTool::new("test", "Test Tool", ToolCategory::NetworkForensics, "/usr/bin/test")
            .with_description("A test tool")
            .with_budget(ResourceBudget {
                max_memory_mb: 128,
                ..Default::default()
            });

        assert!(tool.is_dormant());
        assert_eq!(tool.budget.max_memory_mb, 128);
    }

    #[test]
    fn test_toolkit_status() {
        let toolkit = SecurityToolkit::new(PathBuf::from("/tmp/test"));
        toolkit.register(DormantTool::new("test", "Test", ToolCategory::NetworkForensics, "/bin/true"));

        let status = toolkit.status();
        assert_eq!(status.total_tools, 1);
        assert_eq!(status.dormant_count, 1);
        assert_eq!(status.active_count, 0);
    }
}
