//! Shared application state for the UI server.

use crate::config::{DeployConfig, ModelsConfig};
use crate::mesh::MeshHub;
use crate::enforcers::client_notifier::Alert;
use crate::orchestrator::{DashboardSink, OrchestratorState, OrchestratorStats};
use crate::specialists::Action;
use crate::telemetry::TelemetryEvent;
use crate::ui::profile_generator::ProfileGenerator;
use crate::vpn::profiles::TrafficProfile;
use parking_lot::RwLock;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::mpsc;

/// Shared state accessible from API handlers
pub struct AppState {
    /// Node identifier
    pub node_id: String,

    /// Orchestrator lifecycle state
    pub orchestrator_state: RwLock<OrchestratorState>,

    /// Orchestrator statistics snapshot
    pub stats: RwLock<OrchestratorStats>,

    /// All registered profiles (static + dynamic), shared with orchestrator / ProfileSwitcher
    pub profiles: Arc<RwLock<HashMap<String, TrafficProfile>>>,

    /// Currently active profile
    pub active_profile: RwLock<Option<TrafficProfile>>,

    /// Dynamic profile generator engine
    pub profile_generator: RwLock<ProfileGenerator>,

    /// Channel to send actions to the orchestrator
    pub action_tx: RwLock<Option<mpsc::UnboundedSender<Action>>>,

    /// Recent telemetry events (ring buffer)
    pub recent_events: RwLock<VecDeque<TelemetryEvent>>,

    /// Recent alerts
    pub alerts: RwLock<Vec<Alert>>,

    /// Autonomous deploy agent settings (mutable for hot tweaks)
    pub deploy: RwLock<DeployConfig>,

    /// Copy of models config for deploy LLM client
    pub models: ModelsConfig,

    /// P2P mesh hub (if mesh.enabled in config)
    pub mesh: Option<Arc<MeshHub>>,
}

impl AppState {
    pub fn new(
        node_id: String,
        profiles: Arc<RwLock<HashMap<String, TrafficProfile>>>,
        deploy: DeployConfig,
        models: ModelsConfig,
        mesh: Option<Arc<MeshHub>>,
    ) -> Self {
        Self {
            node_id,
            orchestrator_state: RwLock::new(OrchestratorState::Starting),
            stats: RwLock::new(OrchestratorStats::default()),
            profiles,
            active_profile: RwLock::new(None),
            profile_generator: RwLock::new(ProfileGenerator::new()),
            action_tx: RwLock::new(None),
            recent_events: RwLock::new(VecDeque::with_capacity(200)),
            alerts: RwLock::new(Vec::new()),
            deploy: RwLock::new(deploy),
            models,
            mesh,
        }
    }

    /// Push a telemetry event into the recent buffer
    pub fn push_event(&self, event: TelemetryEvent) {
        let mut events = self.recent_events.write();
        if events.len() >= 200 {
            events.pop_front();
        }
        events.push_back(event);
    }

    /// Push an alert
    pub fn push_alert(&self, alert: Alert) {
        self.alerts.write().push(alert);
    }

    /// Update stats snapshot
    pub fn update_stats(&self, stats: OrchestratorStats) {
        *self.stats.write() = stats;
    }

    /// Update orchestrator state
    pub fn set_state(&self, state: OrchestratorState) {
        *self.orchestrator_state.write() = state;
    }
}

impl DashboardSink for AppState {
    fn push_telemetry_event(&self, event: TelemetryEvent) {
        self.push_event(event);
    }

    fn sync_from_orchestrator(
        &self,
        state: OrchestratorState,
        stats: OrchestratorStats,
        active_vpn_profile: Option<TrafficProfile>,
    ) {
        self.set_state(state);
        self.update_stats(stats);
        *self.active_profile.write() = active_vpn_profile;
    }
}
