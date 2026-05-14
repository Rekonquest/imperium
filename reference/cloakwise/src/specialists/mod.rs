//! Specialist swarm module
//!
//! Contains AI specialists that analyze telemetry and provide recommendations.

pub mod loader;
pub mod probe_detector;
pub mod traffic_analyzer;
pub mod timing_anomaly;
pub mod health_monitor;
pub mod profile_advisor;
pub mod protocol_detector;

pub use loader::*;
pub use probe_detector::ProbeDetector;
pub use traffic_analyzer::TrafficAnalyzer;
pub use timing_anomaly::TimingAnomalyDetector;
pub use health_monitor::HealthMonitor;
pub use profile_advisor::ProfileAdvisor;
pub use protocol_detector::ProtocolDetector;

use crate::telemetry::TelemetryEvent;
use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Types of specialists in the swarm
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpecialistType {
    ProbeDetector,
    TrafficAnalyzer,
    TimingAnomaly,
    HealthMonitor,
    ProfileAdvisor,
    ProtocolDetector,
}

impl std::fmt::Display for SpecialistType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpecialistType::ProbeDetector => write!(f, "probe_detector"),
            SpecialistType::TrafficAnalyzer => write!(f, "traffic_analyzer"),
            SpecialistType::TimingAnomaly => write!(f, "timing_anomaly"),
            SpecialistType::HealthMonitor => write!(f, "health_monitor"),
            SpecialistType::ProfileAdvisor => write!(f, "profile_advisor"),
            SpecialistType::ProtocolDetector => write!(f, "protocol_detector"),
        }
    }
}

/// Assessment result from a specialist
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Assessment {
    /// Everything looks normal
    Normal,
    /// Something suspicious detected
    Suspicious { reason: String },
    /// Active threat detected
    Threat { threat_type: ThreatType },
    /// Service degradation detected
    Degraded { severity: u8 },
    /// Unable to assess (insufficient data)
    Inconclusive { reason: String },
}

/// Types of threats that can be detected
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatType {
    /// Active probe from DPI system
    ActiveProbe,
    /// Traffic fingerprinting attempt
    Fingerprinting,
    /// Replay attack
    ReplayAttack,
    /// Connection blocking
    Blocking,
    /// Bandwidth throttling
    Throttling,
    /// Protocol-specific attack
    ProtocolAttack { protocol: String },
    /// Unknown threat
    Unknown,
}

/// Recommended action from a specialist
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Switch to a different traffic profile
    SwitchProfile { target: String },
    /// Rotate to next profile in sequence
    RotateProfile,
    /// Activate decoy responses
    ActivateDecoy,
    /// Throttle connection rate
    ThrottleConnections { max: u32 },
    /// Add timing jitter to packets
    AddJitter { min_ms: u32, max_ms: u32 },
    /// Alert administrator
    AlertAdmin { message: String },
    /// Enter safe mode
    EnterSafeMode,
    /// No action needed
    None,
}

/// Vote from a specialist
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpecialistVote {
    /// Which specialist produced this vote
    pub specialist: SpecialistType,
    /// Assessment of the situation
    pub assessment: Assessment,
    /// Confidence level (0.0 - 1.0)
    pub confidence: f32,
    /// Recommended action (if any)
    pub recommended_action: Option<Action>,
    /// Additional context/reasoning
    pub reasoning: Option<String>,
    /// Timestamp of the vote
    pub timestamp: u64,
}

impl SpecialistVote {
    pub fn new(specialist: SpecialistType, assessment: Assessment, confidence: f32) -> Self {
        Self {
            specialist,
            assessment,
            confidence: confidence.clamp(0.0, 1.0),
            recommended_action: None,
            reasoning: None,
            timestamp: crate::telemetry::current_timestamp(),
        }
    }

    pub fn with_action(mut self, action: Action) -> Self {
        self.recommended_action = Some(action);
        self
    }

    pub fn with_reasoning(mut self, reasoning: impl Into<String>) -> Self {
        self.reasoning = Some(reasoning.into());
        self
    }
}

/// Trait for specialist implementations
#[async_trait]
pub trait Specialist: Send + Sync {
    /// Get the specialist type
    fn specialist_type(&self) -> SpecialistType;

    /// Analyze telemetry events and produce a vote
    async fn analyze(&self, events: &[TelemetryEvent]) -> Result<SpecialistVote>;

    /// Check if this specialist can handle a specific event type
    fn can_handle(&self, event: &TelemetryEvent) -> bool;

    /// Get the specialist's readiness status
    async fn is_ready(&self) -> bool;
}

/// Context for specialist analysis
#[derive(Debug, Clone)]
pub struct AnalysisContext {
    /// Recent events to analyze
    pub events: Vec<TelemetryEvent>,
    /// Current profile ID
    pub current_profile: Option<String>,
    /// Time window for analysis (ms)
    pub window_ms: u64,
    /// Previous votes from this session
    pub previous_votes: Vec<SpecialistVote>,
}

impl AnalysisContext {
    pub fn new(events: Vec<TelemetryEvent>) -> Self {
        Self {
            events,
            current_profile: None,
            window_ms: 60_000, // 1 minute default
            previous_votes: Vec::new(),
        }
    }

    pub fn with_profile(mut self, profile: impl Into<String>) -> Self {
        self.current_profile = Some(profile.into());
        self
    }

    pub fn with_window(mut self, window_ms: u64) -> Self {
        self.window_ms = window_ms;
        self
    }
}

/// Factory for creating specialists
pub struct SpecialistFactory;

impl SpecialistFactory {
    /// Create all specialists
    pub fn create_all() -> Vec<Box<dyn Specialist>> {
        vec![
            Box::new(ProbeDetector::new()),
            Box::new(TrafficAnalyzer::new()),
            Box::new(TimingAnomalyDetector::new()),
            Box::new(HealthMonitor::new()),
            Box::new(ProfileAdvisor::new()),
            Box::new(ProtocolDetector::new()),
        ]
    }

    /// Create a specific specialist
    pub fn create(specialist_type: SpecialistType) -> Box<dyn Specialist> {
        match specialist_type {
            SpecialistType::ProbeDetector => Box::new(ProbeDetector::new()),
            SpecialistType::TrafficAnalyzer => Box::new(TrafficAnalyzer::new()),
            SpecialistType::TimingAnomaly => Box::new(TimingAnomalyDetector::new()),
            SpecialistType::HealthMonitor => Box::new(HealthMonitor::new()),
            SpecialistType::ProfileAdvisor => Box::new(ProfileAdvisor::new()),
            SpecialistType::ProtocolDetector => Box::new(ProtocolDetector::new()),
        }
    }
}
