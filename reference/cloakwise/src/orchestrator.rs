//! Orchestrator - Main coordination loop
//!
//! Ties together all components: telemetry, specialists, confidence bus,
//! Big Momma, fallback, and enforcers.

use crate::bigmomma::BigMomma;
use crate::confidence::{ConfidenceBus, ConsensusResult};
use crate::config::Config;
use crate::enforcers::{
    ClientNotifier, ConnectionThrottler, DecoyActivator, EnforcerCoordinator, ProfileSwitcher,
};
use crate::fallback::{FallbackController, FallbackDecision};
use crate::specialists::{Action, Specialist, SpecialistFactory, SpecialistVote};
use crate::telemetry::{TelemetryEvent, TelemetryReceiver};
use crate::vpn::{ProfileTemplates, TrafficProfile, VpnControllerFactory, VpnManager};
use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, watch};
use tracing::{debug, error, info, warn};

/// Bridges orchestrator metrics and live telemetry into the web dashboard.
pub trait DashboardSink: Send + Sync {
    fn push_telemetry_event(&self, event: TelemetryEvent);
    fn sync_from_orchestrator(
        &self,
        state: OrchestratorState,
        stats: OrchestratorStats,
        active_vpn_profile: Option<TrafficProfile>,
    );
}

/// Orchestrator state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrchestratorState {
    Starting,
    Running,
    SafeMode,
    ShuttingDown,
}

/// The main orchestrator
pub struct Orchestrator {
    config: Config,
    state: parking_lot::RwLock<OrchestratorState>,

    // Core components
    vpn_manager: Arc<VpnManager>,
    specialists: Vec<Box<dyn Specialist>>,
    confidence_bus: ConfidenceBus,
    big_momma: BigMomma,
    fallback: parking_lot::RwLock<FallbackController>,
    enforcers: EnforcerCoordinator,

    /// Shared profile directory (UI + ProfileSwitcher + orchestrator).
    profiles_store: Arc<parking_lot::RwLock<HashMap<String, TrafficProfile>>>,

    // Channels
    shutdown_tx: watch::Sender<bool>,
    shutdown_rx: watch::Receiver<bool>,

    /// API / dashboard-initiated actions (optional until `link_ui` runs).
    api_actions: tokio::sync::Mutex<Option<mpsc::UnboundedReceiver<Action>>>,

    /// Live dashboard updates (optional).
    dashboard: parking_lot::Mutex<Option<Arc<dyn DashboardSink>>>,

    // Statistics
    stats: parking_lot::RwLock<OrchestratorStats>,
}

/// Orchestrator statistics
#[derive(Debug, Clone, Default)]
pub struct OrchestratorStats {
    pub events_processed: u64,
    pub decisions_made: u64,
    pub profile_switches: u64,
    pub escalations_to_bigmomma: u64,
    pub fallback_activations: u64,
    pub safe_mode_entries: u64,
    pub uptime_secs: u64,
    pub specialist_count: usize,
    pub ai_model_available: bool,
}

impl Orchestrator {
    /// Create a new orchestrator from configuration.
    ///
    /// `profiles_store` must be pre-populated (same `Arc` as the UI uses).
    pub fn new(
        config: Config,
        profiles_store: Arc<parking_lot::RwLock<HashMap<String, TrafficProfile>>>,
    ) -> Result<Self> {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let mut protocols: HashSet<crate::config::Protocol> = config
            .profiles
            .values()
            .map(|p| p.protocol)
            .collect();
        for t in ProfileTemplates::all() {
            protocols.insert(t.protocol);
        }

        let mut vpn_manager = VpnManager::new();
        let iface = config.vpn.interface.as_str();
        let dir = &config.vpn.config_dir;
        for proto in protocols {
            vpn_manager.register(VpnControllerFactory::create(proto, iface, dir));
        }
        let vpn_manager = Arc::new(vpn_manager);

        // Initialize specialists
        let specialists = SpecialistFactory::create_all();

        // Initialize confidence bus
        let confidence_bus = ConfidenceBus::new(config.confidence.clone());

        // Initialize Big Momma
        let mut big_momma = BigMomma::new(
            config.models.inference.clone(),
            config.confidence.escalation_timeout_ms,
        );

        // Configure API endpoint if present
        if let Some(ref endpoint) = config.models.api_endpoint {
            big_momma.set_api_endpoint(
                endpoint.clone(),
                config.models.api_model.clone(),
            );
        }

        // Initialize fallback
        let fallback = FallbackController::new(config.fallback.clone());

        // Initialize enforcers
        let mut enforcers = EnforcerCoordinator::new();
        enforcers.register(Box::new(ProfileSwitcher::new(
            vpn_manager.clone(),
            profiles_store.clone(),
        )));
        enforcers.register(Box::new(ConnectionThrottler::new()));
        enforcers.register(Box::new(DecoyActivator::new()));
        enforcers.register(Box::new(ClientNotifier::new()));

        Ok(Self {
            config,
            state: parking_lot::RwLock::new(OrchestratorState::Starting),
            vpn_manager,
            specialists,
            confidence_bus,
            big_momma,
            fallback: parking_lot::RwLock::new(fallback),
            enforcers,
            profiles_store,
            shutdown_tx,
            shutdown_rx,
            api_actions: tokio::sync::Mutex::new(None),
            dashboard: parking_lot::Mutex::new(None),
            stats: parking_lot::RwLock::new(OrchestratorStats::default()),
        })
    }

    /// Connect dashboard metrics and API-driven profile switches.
    pub async fn link_ui(
        &self,
        dashboard: Arc<dyn DashboardSink>,
        api_actions: mpsc::UnboundedReceiver<Action>,
    ) {
        *self.dashboard.lock() = Some(dashboard);
        *self.api_actions.lock().await = Some(api_actions);
    }

    /// Clone the shutdown sender for signal handlers.
    pub fn shutdown_sender(&self) -> watch::Sender<bool> {
        self.shutdown_tx.clone()
    }

    /// Get a shutdown receiver for spawning tasks
    pub fn shutdown_receiver(&self) -> watch::Receiver<bool> {
        self.shutdown_rx.clone()
    }

    /// Run the orchestrator
    pub async fn run(mut self, mut telemetry_rx: TelemetryReceiver) -> Result<()> {
        info!("Orchestrator starting...");
        *self.state.write() = OrchestratorState::Running;

        let mut shutdown_rx = self.shutdown_rx.clone();

        // Initialize Big Momma
        self.big_momma.initialize().await?;

        // Set initial profile
        let initial_profile = {
            let store = self.profiles_store.read();
            self.config
                .fallback
                .profile_rotation_order
                .first()
                .and_then(|id| store.get(id).cloned())
                .unwrap_or_else(ProfileTemplates::https_clone)
        };

        info!("Setting initial profile: {}", initial_profile.name);
        if let Err(e) = self.vpn_manager.switch_profile(&initial_profile).await {
            warn!("Failed to set initial profile: {}", e);
        }
        self.sync_dashboard();

        // Main event loop
        let mut event_buffer: Vec<TelemetryEvent> = Vec::new();
        let mut process_interval = tokio::time::interval(Duration::from_secs(1));
        let mut rotation_check_interval = tokio::time::interval(Duration::from_secs(60));

        let start_time = std::time::Instant::now();

        loop {
            tokio::select! {
                // Receive telemetry events
                Some(event) = telemetry_rx.recv() => {
                    event_buffer.push(event);
                    self.stats.write().events_processed += 1;

                    // Process immediately if buffer is large
                    if event_buffer.len() >= 10 {
                        self.process_events(&event_buffer).await;
                        event_buffer.clear();
                    }
                }

                // API / dashboard actions
                Some(action) = self.recv_api_action() => {
                    if let Err(e) = self.execute_action(&action).await {
                        error!("Failed to execute API action: {}", e);
                    }
                    self.sync_dashboard();
                }

                // Periodic processing of buffered events
                _ = process_interval.tick() => {
                    if !event_buffer.is_empty() {
                        self.process_events(&event_buffer).await;
                        event_buffer.clear();
                    }

                    // Update uptime
                    self.stats.write().uptime_secs = start_time.elapsed().as_secs();
                    self.sync_dashboard();
                }

                // Periodic rotation check
                _ = rotation_check_interval.tick() => {
                    self.check_timed_rotation().await;
                    self.sync_dashboard();
                }

                // Shutdown signal
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        info!("Orchestrator received shutdown signal");
                        break;
                    }
                }
            }
        }

        *self.state.write() = OrchestratorState::ShuttingDown;
        info!("Orchestrator shutting down...");

        Ok(())
    }

    async fn recv_api_action(&self) -> Option<Action> {
        let mut guard = self.api_actions.lock().await;
        match guard.as_mut() {
            Some(rx) => rx.recv().await,
            None => std::future::pending().await,
        }
    }

    fn sync_dashboard(&self) {
        let dash = self.dashboard.lock().clone();
        let Some(d) = dash else {
            return;
        };
        let mut stats = self.stats.read().clone();
        stats.specialist_count = self.specialists.len();
        stats.ai_model_available = self.big_momma.is_model_available();
        d.sync_from_orchestrator(
            *self.state.read(),
            stats,
            self.vpn_manager.active_profile(),
        );
    }

    /// Process a batch of telemetry events
    async fn process_events(&self, events: &[TelemetryEvent]) {
        debug!("Processing {} events", events.len());

        {
            let dash = self.dashboard.lock().clone();
            if let Some(ref d) = dash {
                for ev in events {
                    d.push_telemetry_event(ev.clone());
                }
            }
        }

        // First, run through fallback controller
        for event in events {
            let fallback_decision = self.fallback.write().process_event(event);
            if let Some(action) = self.handle_fallback_decision(fallback_decision).await {
                if let Err(e) = self.execute_action(&action).await {
                    error!("Failed to execute fallback action: {}", e);
                }
            }
        }

        // If not in safe mode, run AI analysis
        if *self.state.read() != OrchestratorState::SafeMode {
            self.run_ai_analysis(events).await;
        }
    }

    /// Run AI specialist analysis on events
    async fn run_ai_analysis(&self, events: &[TelemetryEvent]) {
        // Collect votes from all specialists
        let mut votes = Vec::new();

        for specialist in &self.specialists {
            if specialist.is_ready().await {
                // Check if specialist can handle any of these events
                let can_handle = events.iter().any(|e| specialist.can_handle(e));
                if can_handle {
                    match specialist.analyze(events).await {
                        Ok(vote) => {
                            debug!(
                                "Specialist {:?} vote: {:?} (confidence: {:.2})",
                                vote.specialist, vote.assessment, vote.confidence
                            );
                            votes.push(vote);
                        }
                        Err(e) => {
                            warn!("Specialist {:?} failed: {}", specialist.specialist_type(), e);
                        }
                    }
                }
            }
        }

        if votes.is_empty() {
            return;
        }

        // Evaluate consensus
        let result = self.confidence_bus.evaluate(&votes);
        self.stats.write().decisions_made += 1;

        match result {
            ConsensusResult::Consensus {
                action,
                confidence,
                contributing_specialists,
            } => {
                info!(
                    "Consensus reached (confidence: {:.2}): {:?} from {:?}",
                    confidence, action, contributing_specialists
                );
                if let Err(e) = self.execute_action(&action).await {
                    error!("Failed to execute consensus action: {}", e);
                }
            }
            ConsensusResult::Escalate { reason, votes } => {
                info!("Escalating to Big Momma: {}", reason);
                self.stats.write().escalations_to_bigmomma += 1;

                let timeout = Duration::from_millis(self.config.confidence.escalation_timeout_ms);
                match crate::bigmomma::decide_with_timeout(&self.big_momma, &votes, events, &reason, timeout).await {
                    Ok(Some(decision)) => {
                        info!("Big Momma decision: {:?} (confidence: {:.2})", decision.action, decision.confidence);
                        if let Err(e) = self.execute_action(&decision.action).await {
                            error!("Failed to execute Big Momma action: {}", e);
                        }
                    }
                    Ok(None) => {
                        warn!("Big Momma timed out, falling back to deterministic rotation");
                        self.stats.write().fallback_activations += 1;
                        let action = Action::RotateProfile;
                        if let Err(e) = self.execute_action(&action).await {
                            error!("Failed to execute fallback action: {}", e);
                        }
                    }
                    Err(e) => {
                        error!("Big Momma error: {}, falling back", e);
                        self.stats.write().fallback_activations += 1;
                    }
                }
            }
            ConsensusResult::NoAction { confidence } => {
                debug!("No action needed (confidence: {:.2})", confidence);
            }
            ConsensusResult::Conflict { conflicting_assessments } => {
                warn!("Specialist conflict detected: {:?}", conflicting_assessments);
                // Escalate conflicts to Big Momma
                self.stats.write().escalations_to_bigmomma += 1;

                let conflict_reason = format!(
                    "Conflicting assessments: {:?}",
                    conflicting_assessments
                        .iter()
                        .map(|(s, a)| format!("{:?}: {:?}", s, a))
                        .collect::<Vec<_>>()
                        .join(", ")
                );

                let timeout = Duration::from_millis(self.config.confidence.escalation_timeout_ms);
                if let Ok(Some(decision)) = crate::bigmomma::decide_with_timeout(
                    &self.big_momma,
                    &votes,
                    events,
                    &conflict_reason,
                    timeout,
                ).await {
                    if let Err(e) = self.execute_action(&decision.action).await {
                        error!("Failed to execute conflict resolution action: {}", e);
                    }
                }
            }
        }
    }

    /// Handle fallback controller decision
    async fn handle_fallback_decision(&self, decision: FallbackDecision) -> Option<Action> {
        match decision {
            FallbackDecision::NoAction => None,
            FallbackDecision::RotateProfile { target, reason } => {
                info!("Fallback rotation: {} ({})", target, reason);
                self.stats.write().profile_switches += 1;
                Some(Action::SwitchProfile { target })
            }
            FallbackDecision::EnterSafeMode { reason } => {
                warn!("Entering safe mode: {}", reason);
                *self.state.write() = OrchestratorState::SafeMode;
                self.stats.write().safe_mode_entries += 1;
                Some(Action::EnterSafeMode)
            }
            FallbackDecision::AlertAdmin { message } => {
                Some(Action::AlertAdmin { message })
            }
        }
    }

    /// Check for timed rotation
    async fn check_timed_rotation(&self) {
        let decision = self.fallback.write().check_timed_rotation();
        if let Some(action) = self.handle_fallback_decision(decision).await {
            if let Err(e) = self.execute_action(&action).await {
                error!("Failed to execute timed rotation: {}", e);
            }
        }
    }

    /// Execute an action through enforcers
    fn execute_action<'a>(&'a self, action: &'a Action) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            debug!("Executing action: {:?}", action);

            let result = self.enforcers.execute(action).await?;

            if result.success {
                info!("Action executed: {}", result.description);

                // Handle follow-up actions
                if let Some(follow_up) = result.follow_up {
                    debug!("Executing follow-up action: {:?}", follow_up);
                    self.execute_action(&follow_up).await?;
                }

                // Track profile switches
                if matches!(action, Action::SwitchProfile { .. } | Action::RotateProfile) {
                    self.stats.write().profile_switches += 1;
                }
            } else {
                warn!("Action failed: {}", result.description);
            }

            Ok(())
        })
    }

    /// Trigger shutdown
    pub fn shutdown(&self) {
        info!("Triggering orchestrator shutdown");
        let _ = self.shutdown_tx.send(true);
    }

    /// Get current state
    pub fn state(&self) -> OrchestratorState {
        *self.state.read()
    }

    /// Get statistics
    pub fn stats(&self) -> OrchestratorStats {
        self.stats.read().clone()
    }

    /// Snapshot of registered profiles
    pub fn profiles(&self) -> HashMap<String, TrafficProfile> {
        self.profiles_store.read().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vpn::ProfileTemplates;

    fn test_profiles_store() -> Arc<parking_lot::RwLock<HashMap<String, TrafficProfile>>> {
        let config = Config::default_test();
        let mut map = HashMap::new();
        for (id, pc) in &config.profiles {
            map.insert(id.clone(), TrafficProfile::from_config(id, pc));
        }
        for t in ProfileTemplates::all() {
            map.entry(t.id.clone()).or_insert(t);
        }
        Arc::new(parking_lot::RwLock::new(map))
    }

    #[test]
    fn test_orchestrator_creation() {
        let config = Config::default_test();
        let orchestrator = Orchestrator::new(config, test_profiles_store());
        assert!(orchestrator.is_ok());
    }

    #[test]
    fn test_initial_state() {
        let config = Config::default_test();
        let orchestrator = Orchestrator::new(config, test_profiles_store()).unwrap();
        assert_eq!(orchestrator.state(), OrchestratorState::Starting);
    }
}
