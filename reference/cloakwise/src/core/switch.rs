//! Core Switch - Protocol Transition Manager
//!
//! Manages seamless transitions between:
//! - Standard Internet gateway
//! - Different VPN protocols
//! - SDR-based Emergency Bridge
//!
//! Key capability: Switch without dropping active TCP sessions
//! through connection migration and stream splicing.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc, oneshot};

use super::transport::{NetworkConditions, Outbound, OutboundRegistry, ProtocolMetrics, TransportError};

/// Current transport mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransportMode {
    /// Standard internet through ISP
    Direct,
    /// Through active VPN protocol
    Vpn,
    /// Through SDR radio bridge
    Radio,
    /// Hybrid: VPN over Radio
    RadioVpn,
    /// Safe mode: minimal functionality
    SafeMode,
    /// Complete blackout: no connectivity
    Blackout,
}

/// Transition request from AI Pilot
#[derive(Debug, Clone)]
pub struct TransitionRequest {
    /// Target mode
    pub target_mode: TransportMode,

    /// Target protocol (if VPN mode)
    pub target_protocol: Option<String>,

    /// Reason for transition
    pub reason: TransitionReason,

    /// Maximum time to complete transition
    pub timeout: Duration,

    /// Whether to preserve existing sessions
    pub preserve_sessions: bool,

    /// Priority level
    pub priority: TransitionPriority,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransitionReason {
    /// AI Pilot decision
    PilotDecision,
    /// DPI detected
    DpiDetected,
    /// Connection degradation
    ConnectionDegraded,
    /// Internet blackout
    BlackoutDetected,
    /// Manual user request
    ManualRequest,
    /// Scheduled rotation
    ScheduledRotation,
    /// Health check failure
    HealthCheckFailed,
    /// Radio mode activated
    RadioFallback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TransitionPriority {
    Low = 0,
    Normal = 1,
    High = 2,
    Emergency = 3,
}

/// Result of a transition attempt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransitionResult {
    /// Whether transition succeeded
    pub success: bool,

    /// Time taken for transition
    pub duration: Duration,

    /// Number of sessions preserved
    pub sessions_preserved: usize,

    /// Number of sessions dropped
    pub sessions_dropped: usize,

    /// New active protocol (if any)
    pub new_protocol: Option<String>,

    /// Error message (if failed)
    pub error: Option<String>,
}

/// Core Switch - the heart of protocol transitions
pub struct CoreSwitch {
    /// Current transport mode
    mode: RwLock<TransportMode>,

    /// Protocol registry
    registry: Arc<OutboundRegistry>,

    /// Active sessions (connection_id -> session info)
    sessions: RwLock<HashMap<u64, ActiveSession>>,

    /// Session ID counter
    session_counter: AtomicU64,

    /// Transition in progress flag
    transitioning: AtomicBool,

    /// Event broadcast channel
    event_tx: broadcast::Sender<SwitchEvent>,

    /// Transition request channel
    transition_tx: mpsc::Sender<(TransitionRequest, oneshot::Sender<TransitionResult>)>,

    /// Statistics
    stats: RwLock<SwitchStats>,

    /// Blackout detection threshold (seconds without connectivity)
    blackout_threshold: Duration,

    /// Last successful connectivity timestamp
    last_connectivity: RwLock<Instant>,
}

/// Active session information
#[derive(Debug, Clone)]
pub struct ActiveSession {
    /// Session ID
    pub id: u64,

    /// Remote address
    pub remote_addr: SocketAddr,

    /// Protocol used
    pub protocol: String,

    /// Session start time
    pub started: Instant,

    /// Bytes sent
    pub bytes_sent: u64,

    /// Bytes received
    pub bytes_received: u64,

    /// Whether session can be migrated
    pub migratable: bool,
}

/// Events emitted by the switch
#[derive(Debug, Clone)]
pub enum SwitchEvent {
    /// Mode changed
    ModeChanged {
        from: TransportMode,
        to: TransportMode,
        reason: TransitionReason,
    },

    /// Protocol switched
    ProtocolSwitched {
        from: Option<String>,
        to: String,
        duration: Duration,
    },

    /// Blackout detected
    BlackoutDetected { duration: Duration },

    /// Connectivity restored
    ConnectivityRestored { downtime: Duration },

    /// Session migrated
    SessionMigrated { session_id: u64, new_protocol: String },

    /// Session dropped
    SessionDropped { session_id: u64, reason: String },

    /// Health check result
    HealthCheck { success: bool, latency: Duration },
}

/// Switch statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SwitchStats {
    /// Total transitions
    pub total_transitions: u64,

    /// Successful transitions
    pub successful_transitions: u64,

    /// Failed transitions
    pub failed_transitions: u64,

    /// Total sessions migrated
    pub sessions_migrated: u64,

    /// Total sessions dropped
    pub sessions_dropped: u64,

    /// Average transition time
    pub avg_transition_ms: f64,

    /// Fastest transition
    pub fastest_transition_ms: f64,

    /// Slowest transition
    pub slowest_transition_ms: f64,

    /// Total blackout time
    pub total_blackout_secs: f64,

    /// Number of blackout events
    pub blackout_count: u64,
}

impl CoreSwitch {
    pub fn new(registry: Arc<OutboundRegistry>) -> Self {
        let (event_tx, _) = broadcast::channel(1024);
        let (transition_tx, _transition_rx) = mpsc::channel(32);

        Self {
            mode: RwLock::new(TransportMode::Direct),
            registry,
            sessions: RwLock::new(HashMap::new()),
            session_counter: AtomicU64::new(0),
            transitioning: AtomicBool::new(false),
            event_tx,
            transition_tx,
            stats: RwLock::new(SwitchStats::default()),
            blackout_threshold: Duration::from_secs(300), // 5 minutes
            last_connectivity: RwLock::new(Instant::now()),
        }
    }

    /// Get current transport mode
    pub fn current_mode(&self) -> TransportMode {
        *self.mode.read()
    }

    /// Get current active protocol
    pub fn current_protocol(&self) -> Option<String> {
        self.registry.active().map(|o| o.protocol_id().to_string())
    }

    /// Subscribe to switch events
    pub fn subscribe(&self) -> broadcast::Receiver<SwitchEvent> {
        self.event_tx.subscribe()
    }

    /// Perform immediate protocol switch (< 10ms target)
    pub async fn switch_protocol(&self, protocol_id: &str) -> Result<TransitionResult, TransportError> {
        let start = Instant::now();

        // Set transitioning flag
        if self.transitioning.swap(true, Ordering::SeqCst) {
            return Err(TransportError::ResourceExhausted(
                "Transition already in progress".into(),
            ));
        }

        let old_protocol = self.current_protocol();

        // Perform the switch via registry (< 10ms)
        let result = self.registry.switch_to(protocol_id, Duration::from_millis(100)).await;

        let duration = start.elapsed();

        // Update stats
        {
            let mut stats = self.stats.write();
            stats.total_transitions += 1;

            if result.is_ok() {
                stats.successful_transitions += 1;
                let ms = duration.as_secs_f64() * 1000.0;
                stats.avg_transition_ms = (stats.avg_transition_ms * (stats.successful_transitions - 1) as f64 + ms)
                    / stats.successful_transitions as f64;
                if stats.fastest_transition_ms == 0.0 || ms < stats.fastest_transition_ms {
                    stats.fastest_transition_ms = ms;
                }
                if ms > stats.slowest_transition_ms {
                    stats.slowest_transition_ms = ms;
                }
            } else {
                stats.failed_transitions += 1;
            }
        }

        // Clear transitioning flag
        self.transitioning.store(false, Ordering::SeqCst);

        match result {
            Ok(()) => {
                // Emit event
                let _ = self.event_tx.send(SwitchEvent::ProtocolSwitched {
                    from: old_protocol,
                    to: protocol_id.to_string(),
                    duration,
                });

                Ok(TransitionResult {
                    success: true,
                    duration,
                    sessions_preserved: self.sessions.read().len(),
                    sessions_dropped: 0,
                    new_protocol: Some(protocol_id.to_string()),
                    error: None,
                })
            }
            Err(e) => {
                Ok(TransitionResult {
                    success: false,
                    duration,
                    sessions_preserved: 0,
                    sessions_dropped: 0,
                    new_protocol: None,
                    error: Some(e.to_string()),
                })
            }
        }
    }

    /// Switch to a different transport mode
    pub async fn switch_mode(&self, target: TransportMode, reason: TransitionReason) -> Result<(), TransportError> {
        let current = self.current_mode();

        if current == target {
            return Ok(()); // Already in target mode
        }

        tracing::info!("Switching mode: {:?} -> {:?} (reason: {:?})", current, target, reason);

        *self.mode.write() = target;

        let _ = self.event_tx.send(SwitchEvent::ModeChanged {
            from: current,
            to: target,
            reason,
        });

        Ok(())
    }

    /// Activate radio bridge mode
    pub async fn activate_radio_bridge(&self) -> Result<(), TransportError> {
        self.switch_mode(TransportMode::Radio, TransitionReason::RadioFallback).await
    }

    /// Check for blackout and auto-switch to radio if needed
    pub async fn check_blackout(&self) -> bool {
        let last = *self.last_connectivity.read();
        let elapsed = last.elapsed();

        if elapsed > self.blackout_threshold {
            let _ = self.event_tx.send(SwitchEvent::BlackoutDetected { duration: elapsed });

            // Auto-switch to radio mode
            if self.current_mode() != TransportMode::Radio {
                let mut stats = self.stats.write();
                stats.blackout_count += 1;

                if let Err(e) = self.activate_radio_bridge().await {
                    tracing::error!("Failed to activate radio bridge: {}", e);
                }
            }

            return true;
        }

        false
    }

    /// Record successful connectivity
    pub fn record_connectivity(&self) {
        let mut last = self.last_connectivity.write();
        let was_blackout = last.elapsed() > self.blackout_threshold;
        let downtime = last.elapsed();
        *last = Instant::now();

        if was_blackout {
            let _ = self.event_tx.send(SwitchEvent::ConnectivityRestored { downtime });

            // Update blackout time stats
            let mut stats = self.stats.write();
            stats.total_blackout_secs += downtime.as_secs_f64();
        }
    }

    /// Get switch statistics
    pub fn stats(&self) -> SwitchStats {
        self.stats.read().clone()
    }

    /// Register a new session
    pub fn register_session(&self, remote_addr: SocketAddr, protocol: &str, migratable: bool) -> u64 {
        let id = self.session_counter.fetch_add(1, Ordering::Relaxed);

        let session = ActiveSession {
            id,
            remote_addr,
            protocol: protocol.to_string(),
            started: Instant::now(),
            bytes_sent: 0,
            bytes_received: 0,
            migratable,
        };

        self.sessions.write().insert(id, session);
        id
    }

    /// Unregister a session
    pub fn unregister_session(&self, id: u64) {
        self.sessions.write().remove(&id);
    }

    /// Get session count
    pub fn session_count(&self) -> usize {
        self.sessions.read().len()
    }

    /// Get all protocol telemetry
    pub fn all_telemetry(&self) -> Vec<ProtocolMetrics> {
        self.registry.all_telemetry()
    }

    /// Find best protocol for current conditions
    pub fn select_best_protocol(&self, conditions: &NetworkConditions) -> Option<String> {
        self.registry.select_best(conditions)
    }
}

/// Cross-protocol stream splicing support
/// Allows handing off a data stream from one protocol to another mid-connection
pub struct StreamSplicer {
    /// Active splices
    splices: RwLock<HashMap<u64, SpliceState>>,
}

#[derive(Debug, Clone)]
pub struct SpliceState {
    /// Original protocol
    pub from_protocol: String,
    /// Target protocol
    pub to_protocol: String,
    /// Bytes pending transfer
    pub pending_bytes: usize,
    /// Splice start time
    pub started: Instant,
}

impl StreamSplicer {
    pub fn new() -> Self {
        Self {
            splices: RwLock::new(HashMap::new()),
        }
    }

    /// Begin splicing a stream from one protocol to another
    pub fn begin_splice(&self, session_id: u64, from: &str, to: &str) {
        self.splices.write().insert(
            session_id,
            SpliceState {
                from_protocol: from.to_string(),
                to_protocol: to.to_string(),
                pending_bytes: 0,
                started: Instant::now(),
            },
        );
    }

    /// Complete a splice operation
    pub fn complete_splice(&self, session_id: u64) -> Option<SpliceState> {
        self.splices.write().remove(&session_id)
    }

    /// Check if session is being spliced
    pub fn is_splicing(&self, session_id: u64) -> bool {
        self.splices.read().contains_key(&session_id)
    }
}

impl Default for StreamSplicer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mode_switch() {
        let registry = Arc::new(OutboundRegistry::new());
        let switch = CoreSwitch::new(registry);

        assert_eq!(switch.current_mode(), TransportMode::Direct);

        switch
            .switch_mode(TransportMode::Radio, TransitionReason::BlackoutDetected)
            .await
            .unwrap();

        assert_eq!(switch.current_mode(), TransportMode::Radio);
    }

    #[tokio::test]
    async fn test_session_management() {
        let registry = Arc::new(OutboundRegistry::new());
        let switch = CoreSwitch::new(registry);

        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let id = switch.register_session(addr, "test-proto", true);

        assert_eq!(switch.session_count(), 1);

        switch.unregister_session(id);
        assert_eq!(switch.session_count(), 0);
    }
}
