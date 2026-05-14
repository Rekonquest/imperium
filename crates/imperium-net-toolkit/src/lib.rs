use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use imperium_bus::Bus;
use imperium_protocol::{Message, ToolActivationRequest, ToolBudget, ToolState, ToolStateChange};
use parking_lot::RwLock;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ToolkitError {
    #[error("tool not found: {0}")]
    NotFound(String),
    #[error("tool not in required state: expected {expected:?}, got {actual:?}")]
    InvalidState {
        expected: ToolState,
        actual: ToolState,
    },
    #[error("activation budget exhausted for: {0}")]
    BudgetExhausted(String),
    #[error("tool in cooldown until {0}")]
    InCooldown(DateTime<Utc>),
    #[error("bus error: {0}")]
    Bus(#[from] imperium_bus::BusError),
}

#[derive(Clone, Debug)]
pub struct TriggerCondition {
    pub event_topic: String,
    pub min_confidence: f64,
}

#[derive(Clone, Debug)]
pub struct ToolManifest {
    pub name: String,
    pub description: String,
    pub trigger_conditions: Vec<TriggerCondition>,
    pub idle_timeout: Duration,
    pub cooldown_duration: Duration,
    pub max_activations_per_hour: u32,
}

struct ManagedTool {
    manifest: ToolManifest,
    state: ToolState,
    activation_count: u32,
    hour_window_start: DateTime<Utc>,
    last_activity: Option<DateTime<Utc>>,
    cooldown_until: Option<DateTime<Utc>>,
}

impl ManagedTool {
    fn new(manifest: ToolManifest) -> Self {
        Self {
            manifest,
            state: ToolState::Dormant,
            activation_count: 0,
            hour_window_start: Utc::now(),
            last_activity: None,
            cooldown_until: None,
        }
    }

    fn reset_hour_window_if_needed(&mut self) {
        let elapsed = Utc::now() - self.hour_window_start;
        if elapsed.num_seconds() >= 3600 {
            self.hour_window_start = Utc::now();
            self.activation_count = 0;
        }
    }

    fn budget_remaining(&mut self) -> u32 {
        self.reset_hour_window_if_needed();
        self.manifest
            .max_activations_per_hour
            .saturating_sub(self.activation_count)
    }

    fn is_in_cooldown(&self) -> bool {
        if let Some(until) = self.cooldown_until {
            Utc::now() < until
        } else {
            false
        }
    }
}

pub struct ToolManager {
    tools: Arc<RwLock<HashMap<String, ManagedTool>>>,
    bus: Arc<Bus>,
}

impl ToolManager {
    pub fn new(bus: Arc<Bus>) -> Self {
        Self {
            tools: Arc::new(RwLock::new(HashMap::new())),
            bus,
        }
    }

    pub fn register(&self, manifest: ToolManifest) {
        let name = manifest.name.clone();
        self.tools
            .write()
            .insert(name, ManagedTool::new(manifest));
    }

    pub fn arm(&self, tool_name: &str) -> Result<(), ToolkitError> {
        let mut tools = self.tools.write();
        let tool = tools
            .get_mut(tool_name)
            .ok_or_else(|| ToolkitError::NotFound(tool_name.to_string()))?;

        if tool.state != ToolState::Dormant {
            return Err(ToolkitError::InvalidState {
                expected: ToolState::Dormant,
                actual: tool.state.clone(),
            });
        }

        let from = tool.state.clone();
        tool.state = ToolState::Armed;

        self.emit_state_change(tool_name, from, ToolState::Armed, "armed by operator");
        Ok(())
    }

    pub fn activate(&self, request: &ToolActivationRequest) -> Result<(), ToolkitError> {
        let mut tools = self.tools.write();
        let tool = tools
            .get_mut(&request.tool_name)
            .ok_or_else(|| ToolkitError::NotFound(request.tool_name.clone()))?;

        if tool.state != ToolState::Armed {
            return Err(ToolkitError::InvalidState {
                expected: ToolState::Armed,
                actual: tool.state.clone(),
            });
        }

        if tool.is_in_cooldown() {
            return Err(ToolkitError::InCooldown(tool.cooldown_until.unwrap()));
        }

        tool.reset_hour_window_if_needed();
        if tool.activation_count >= tool.manifest.max_activations_per_hour {
            return Err(ToolkitError::BudgetExhausted(request.tool_name.clone()));
        }

        let from = tool.state.clone();
        tool.state = ToolState::Active;
        tool.activation_count += 1;
        tool.last_activity = Some(Utc::now());

        drop(tools);

        self.emit_state_change(
            &request.tool_name,
            from,
            ToolState::Active,
            &format!("triggered by: {}", request.trigger),
        );

        let _ = self.bus.publish(
            "net.toolkit.activation",
            Message::ToolActivationReq(request.clone()),
        );

        Ok(())
    }

    pub fn deactivate(&self, tool_name: &str) -> Result<(), ToolkitError> {
        let mut tools = self.tools.write();
        let tool = tools
            .get_mut(tool_name)
            .ok_or_else(|| ToolkitError::NotFound(tool_name.to_string()))?;

        if tool.state != ToolState::Active {
            return Err(ToolkitError::InvalidState {
                expected: ToolState::Active,
                actual: tool.state.clone(),
            });
        }

        let from = tool.state.clone();
        tool.state = ToolState::Cooldown;
        tool.cooldown_until =
            Some(Utc::now() + chrono::Duration::from_std(tool.manifest.cooldown_duration).unwrap());

        drop(tools);

        self.emit_state_change(tool_name, from, ToolState::Cooldown, "deactivated, entering cooldown");
        Ok(())
    }

    pub fn complete_cooldown(&self, tool_name: &str) -> Result<(), ToolkitError> {
        let mut tools = self.tools.write();
        let tool = tools
            .get_mut(tool_name)
            .ok_or_else(|| ToolkitError::NotFound(tool_name.to_string()))?;

        if tool.state != ToolState::Cooldown {
            return Err(ToolkitError::InvalidState {
                expected: ToolState::Cooldown,
                actual: tool.state.clone(),
            });
        }

        let from = tool.state.clone();
        tool.state = ToolState::Dormant;
        tool.cooldown_until = None;

        drop(tools);

        self.emit_state_change(tool_name, from, ToolState::Dormant, "cooldown complete");
        Ok(())
    }

    pub fn disarm(&self, tool_name: &str) -> Result<(), ToolkitError> {
        let mut tools = self.tools.write();
        let tool = tools
            .get_mut(tool_name)
            .ok_or_else(|| ToolkitError::NotFound(tool_name.to_string()))?;

        if tool.state != ToolState::Armed {
            return Err(ToolkitError::InvalidState {
                expected: ToolState::Armed,
                actual: tool.state.clone(),
            });
        }

        let from = tool.state.clone();
        tool.state = ToolState::Dormant;

        drop(tools);

        self.emit_state_change(tool_name, from, ToolState::Dormant, "disarmed by operator");
        Ok(())
    }

    pub fn get_state(&self, tool_name: &str) -> Option<ToolState> {
        self.tools.read().get(tool_name).map(|t| t.state.clone())
    }

    pub fn get_budget(&self, tool_name: &str) -> Option<ToolBudget> {
        let mut tools = self.tools.write();
        let tool = tools.get_mut(tool_name)?;
        tool.reset_hour_window_if_needed();

        Some(ToolBudget {
            tool_name: tool_name.to_string(),
            max_activations_per_hour: tool.manifest.max_activations_per_hour,
            cooldown_seconds: tool.manifest.cooldown_duration.as_secs(),
            remaining_activations: tool.budget_remaining(),
        })
    }

    pub fn list_tools(&self) -> Vec<(String, ToolState)> {
        self.tools
            .read()
            .iter()
            .map(|(name, tool)| (name.clone(), tool.state.clone()))
            .collect()
    }

    pub fn check_trigger(
        &self,
        event_topic: &str,
        confidence: f64,
    ) -> Vec<String> {
        self.tools
            .read()
            .iter()
            .filter(|(_, tool)| {
                tool.state == ToolState::Armed
                    && tool.trigger_conditions_match(event_topic, confidence)
            })
            .map(|(name, _)| name.clone())
            .collect()
    }

    fn emit_state_change(&self, tool_name: &str, from: ToolState, to: ToolState, reason: &str) {
        let change = ToolStateChange {
            tool_name: tool_name.to_string(),
            from,
            to,
            reason: reason.to_string(),
            timestamp: Utc::now(),
        };
        let _ = self.bus.publish(
            "net.toolkit.state",
            Message::ToolStateChange(change),
        );
    }
}

impl ManagedTool {
    fn trigger_conditions_match(&self, event_topic: &str, confidence: f64) -> bool {
        self.manifest.trigger_conditions.iter().any(|cond| {
            event_topic.starts_with(&cond.event_topic) && confidence >= cond.min_confidence
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use imperium_protocol::ToolActivationRequest;

    fn test_manifest(name: &str) -> ToolManifest {
        ToolManifest {
            name: name.to_string(),
            description: format!("{} tool", name),
            trigger_conditions: vec![TriggerCondition {
                event_topic: "net.sensors.threat".to_string(),
                min_confidence: 0.8,
            }],
            idle_timeout: Duration::from_secs(300),
            cooldown_duration: Duration::from_secs(60),
            max_activations_per_hour: 5,
        }
    }

    fn test_activation(name: &str) -> ToolActivationRequest {
        ToolActivationRequest {
            tool_name: name.to_string(),
            trigger: "high threat detected".to_string(),
            context: HashMap::new(),
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn full_lifecycle() {
        let bus = Arc::new(Bus::new());
        let mgr = ToolManager::new(bus);

        mgr.register(test_manifest("probe"));

        assert_eq!(mgr.get_state("probe"), Some(ToolState::Dormant));

        mgr.arm("probe").unwrap();
        assert_eq!(mgr.get_state("probe"), Some(ToolState::Armed));

        mgr.activate(&test_activation("probe")).unwrap();
        assert_eq!(mgr.get_state("probe"), Some(ToolState::Active));

        mgr.deactivate("probe").unwrap();
        assert_eq!(mgr.get_state("probe"), Some(ToolState::Cooldown));

        mgr.complete_cooldown("probe").unwrap();
        assert_eq!(mgr.get_state("probe"), Some(ToolState::Dormant));
    }

    #[test]
    fn cannot_activate_dormant() {
        let bus = Arc::new(Bus::new());
        let mgr = ToolManager::new(bus);
        mgr.register(test_manifest("probe"));

        assert!(mgr.activate(&test_activation("probe")).is_err());
    }

    #[test]
    fn budget_tracking() {
        let bus = Arc::new(Bus::new());
        let mgr = ToolManager::new(bus);

        let mut manifest = test_manifest("scanner");
        manifest.max_activations_per_hour = 2;
        manifest.cooldown_duration = Duration::from_secs(0);
        mgr.register(manifest);

        let budget = mgr.get_budget("scanner").unwrap();
        assert_eq!(budget.remaining_activations, 2);

        mgr.arm("scanner").unwrap();
        mgr.activate(&test_activation("scanner")).unwrap();
        mgr.deactivate("scanner").unwrap();
        mgr.complete_cooldown("scanner").unwrap();

        let budget = mgr.get_budget("scanner").unwrap();
        assert_eq!(budget.remaining_activations, 1);
    }

    #[test]
    fn trigger_matching() {
        let bus = Arc::new(Bus::new());
        let mgr = ToolManager::new(bus);

        mgr.register(test_manifest("probe"));
        mgr.arm("probe").unwrap();

        let matches = mgr.check_trigger("net.sensors.threat.high", 0.9);
        assert_eq!(matches.len(), 1);

        let no_match = mgr.check_trigger("net.sensors.threat.high", 0.5);
        assert!(no_match.is_empty());

        let wrong_topic = mgr.check_trigger("net.mesh.peer", 0.9);
        assert!(wrong_topic.is_empty());
    }

    #[test]
    fn disarm_returns_to_dormant() {
        let bus = Arc::new(Bus::new());
        let mgr = ToolManager::new(bus);
        mgr.register(test_manifest("probe"));

        mgr.arm("probe").unwrap();
        mgr.disarm("probe").unwrap();
        assert_eq!(mgr.get_state("probe"), Some(ToolState::Dormant));
    }
}
