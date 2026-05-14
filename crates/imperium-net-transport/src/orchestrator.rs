use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use imperium_bus::Bus;
use imperium_protocol::{
    EmergencyShutdown, Message, OrchestratorDecision, OrchestratorState,
    ProtocolCommand, ProtocolCommandKind, ProtocolEvent, ProtocolEventKind,
    ProtocolRole, ProtocolStatus, ThreatAssessment,
};
use parking_lot::RwLock;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum OrchestratorError {
    #[error("bus error: {0}")]
    Bus(#[from] imperium_bus::BusError),
    #[error("invalid state transition: {from:?} -> {to:?}")]
    InvalidTransition {
        from: OrchestratorState,
        to: OrchestratorState,
    },
    #[error("no active protocol")]
    NoActiveProtocol,
}

#[derive(Clone, Debug)]
pub struct OrchestratorPolicy {
    pub health_check_interval: Duration,
    pub health_failure_threshold: u32,
    pub burn_threshold: f64,
    pub double_degraded_policy: DoubleDegradedPolicy,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DoubleDegradedPolicy {
    EmergencyShutdown,
    SafeModeLock,
}

impl Default for OrchestratorPolicy {
    fn default() -> Self {
        Self {
            health_check_interval: Duration::from_secs(5),
            health_failure_threshold: 3,
            burn_threshold: 0.8,
            double_degraded_policy: DoubleDegradedPolicy::EmergencyShutdown,
        }
    }
}

#[derive(Clone, Debug)]
pub struct OrchestratorConfig {
    pub active_protocol: String,
    pub standby_protocol: String,
    pub policy: OrchestratorPolicy,
}

struct ProtocolState {
    name: String,
    role: ProtocolRole,
    status: ProtocolStatus,
    healing_in_progress: bool,
}

pub struct Orchestrator {
    config: OrchestratorConfig,
    state: Arc<RwLock<OrchestratorState>>,
    active: Arc<RwLock<ProtocolState>>,
    standby: Arc<RwLock<ProtocolState>>,
    bus: Arc<Bus>,
}

impl Orchestrator {
    pub fn new(config: OrchestratorConfig, bus: Arc<Bus>) -> Self {
        let active = ProtocolState {
            name: config.active_protocol.clone(),
            role: ProtocolRole::Active,
            status: ProtocolStatus::Running,

            healing_in_progress: false,
        };

        let standby = ProtocolState {
            name: config.standby_protocol.clone(),
            role: ProtocolRole::Standby,
            status: ProtocolStatus::Running,

            healing_in_progress: false,
        };

        Self {
            config,
            state: Arc::new(RwLock::new(OrchestratorState::Steady)),
            active: Arc::new(RwLock::new(active)),
            standby: Arc::new(RwLock::new(standby)),
            bus,
        }
    }

    pub fn state(&self) -> OrchestratorState {
        self.state.read().clone()
    }

    pub fn active_protocol(&self) -> String {
        self.active.read().name.clone()
    }

    pub fn standby_protocol(&self) -> String {
        self.standby.read().name.clone()
    }

    pub fn handle_protocol_event(
        &self,
        event: &ProtocolEvent,
    ) -> Result<Option<OrchestratorDecision>, OrchestratorError> {
        match &event.event {
            ProtocolEventKind::Crashed { reason } => {
                self.handle_crash(&event.protocol_name, reason)
            }
            ProtocolEventKind::Fingerprinted { details } => {
                self.handle_fingerprinted(&event.protocol_name, details)
            }
            ProtocolEventKind::HealingSucceeded => {
                self.handle_healing_success(&event.protocol_name)
            }
            ProtocolEventKind::HealingFailed { reason } => {
                self.handle_healing_failure(&event.protocol_name, reason)
            }
            ProtocolEventKind::SelfTestPassed => {
                self.handle_self_test_passed(&event.protocol_name)
            }
            ProtocolEventKind::SelfTestFailed { reason } => {
                self.handle_self_test_failed(&event.protocol_name, reason)
            }
            _ => Ok(None),
        }
    }

    fn handle_crash(
        &self,
        protocol_name: &str,
        reason: &str,
    ) -> Result<Option<OrchestratorDecision>, OrchestratorError> {
        let current_state = self.state();

        let is_active = self.active.read().name == protocol_name;

        match current_state {
            OrchestratorState::Steady if is_active => {
                *self.state.write() = OrchestratorState::Failover;

                let standby_name = self.standby.read().name.clone();
                let active_name = self.active.read().name.clone();

                {
                    let mut active = self.active.write();
                    let mut standby = self.standby.write();
                    std::mem::swap(&mut active.name, &mut standby.name);
                    active.role = ProtocolRole::Active;
                    active.status = ProtocolStatus::Running;
                    standby.role = ProtocolRole::Quarantined;
                    standby.status = ProtocolStatus::Failed;
                    standby.healing_in_progress = false;
                }

                self.emit_command(&standby_name, ProtocolCommandKind::PromoteToActive)?;
                self.emit_command(&active_name, ProtocolCommandKind::Quarantine)?;

                *self.state.write() = OrchestratorState::Healing;

                let decision = OrchestratorDecision::PromoteStandby {
                    protocol_name: standby_name,
                };
                self.emit_decision(&decision)?;

                let quarantine_decision = OrchestratorDecision::QuarantineActive {
                    protocol_name: active_name.clone(),
                    reason: reason.to_string(),
                };
                self.emit_decision(&quarantine_decision)?;

                let heal_decision = OrchestratorDecision::BeginHealing {
                    protocol_name: active_name,
                };
                self.emit_decision(&heal_decision)?;

                Ok(Some(decision))
            }

            OrchestratorState::Healing if is_active => {
                self.trigger_emergency_shutdown(
                    &format!("active protocol {} crashed during healing", protocol_name),
                )
            }

            OrchestratorState::Healing if !is_active => {
                Ok(None)
            }

            _ => Ok(None),
        }
    }

    fn handle_fingerprinted(
        &self,
        protocol_name: &str,
        details: &str,
    ) -> Result<Option<OrchestratorDecision>, OrchestratorError> {
        let is_active = self.active.read().name == protocol_name;
        if !is_active {
            return Ok(None);
        }

        self.handle_crash(protocol_name, &format!("fingerprinted: {}", details))
    }

    fn handle_healing_success(
        &self,
        protocol_name: &str,
    ) -> Result<Option<OrchestratorDecision>, OrchestratorError> {
        let is_standby = self.standby.read().name == protocol_name;
        if !is_standby || self.state() != OrchestratorState::Healing {
            return Ok(None);
        }

        {
            let mut standby = self.standby.write();
            standby.status = ProtocolStatus::Running;
            standby.role = ProtocolRole::Standby;
            standby.healing_in_progress = false;
        }

        self.emit_command(protocol_name, ProtocolCommandKind::DemoteToStandby)?;

        *self.state.write() = OrchestratorState::Steady;

        let decision = OrchestratorDecision::RestoreFromHealing {
            protocol_name: protocol_name.to_string(),
        };
        self.emit_decision(&decision)?;

        Ok(Some(decision))
    }

    fn handle_healing_failure(
        &self,
        protocol_name: &str,
        reason: &str,
    ) -> Result<Option<OrchestratorDecision>, OrchestratorError> {
        let is_standby = self.standby.read().name == protocol_name;
        if !is_standby {
            return Ok(None);
        }

        match self.config.policy.double_degraded_policy {
            DoubleDegradedPolicy::EmergencyShutdown => {
                self.trigger_emergency_shutdown(
                    &format!("healing failed for {}: {}", protocol_name, reason),
                )
            }
            DoubleDegradedPolicy::SafeModeLock => {
                tracing::warn!("safe mode lock: healing failed for {}", protocol_name);
                Ok(None)
            }
        }
    }

    fn handle_self_test_passed(
        &self,
        protocol_name: &str,
    ) -> Result<Option<OrchestratorDecision>, OrchestratorError> {
        self.handle_healing_success(protocol_name)
    }

    fn handle_self_test_failed(
        &self,
        protocol_name: &str,
        reason: &str,
    ) -> Result<Option<OrchestratorDecision>, OrchestratorError> {
        self.handle_healing_failure(protocol_name, reason)
    }

    pub fn handle_threat_assessment(
        &self,
        assessment: &ThreatAssessment,
    ) -> Result<Option<OrchestratorDecision>, OrchestratorError> {
        if assessment.confidence >= self.config.policy.burn_threshold {
            let active_name = self.active.read().name.clone();
            tracing::warn!(
                "high-confidence threat ({:.2}) against active protocol {}",
                assessment.confidence,
                active_name
            );

            return self.handle_crash(
                &active_name,
                &format!("burned: threat confidence {:.2}", assessment.confidence),
            );
        }

        Ok(None)
    }

    fn trigger_emergency_shutdown(
        &self,
        reason: &str,
    ) -> Result<Option<OrchestratorDecision>, OrchestratorError> {
        *self.state.write() = OrchestratorState::Emergency;

        let shutdown = EmergencyShutdown {
            reason: reason.to_string(),
            triggered_at: Utc::now(),
            active_protocol: Some(self.active.read().name.clone()),
            standby_protocol: Some(self.standby.read().name.clone()),
        };

        self.bus.publish(
            "emergency.transport.double_degraded",
            Message::EmergencyShutdown(shutdown),
        )?;

        let decision = OrchestratorDecision::EmergencyShutdown {
            reason: reason.to_string(),
        };
        self.emit_decision(&decision)?;

        tracing::error!("EMERGENCY SHUTDOWN: {}", reason);
        Ok(Some(decision))
    }

    fn emit_command(
        &self,
        protocol_name: &str,
        command: ProtocolCommandKind,
    ) -> Result<(), OrchestratorError> {
        let cmd = ProtocolCommand {
            protocol_name: protocol_name.to_string(),
            command,
            issued_at: Utc::now(),
        };

        self.bus.publish(
            "net.transport.command",
            Message::ProtocolCmd(cmd),
        )?;

        Ok(())
    }

    fn emit_decision(
        &self,
        decision: &OrchestratorDecision,
    ) -> Result<(), OrchestratorError> {
        self.bus.publish(
            "net.transport.decision",
            Message::OrchestratorDecision(decision.clone()),
        )?;
        Ok(())
    }

    pub fn subscribe_threat_assessments(
        self: &Arc<Self>,
    ) -> tokio::task::JoinHandle<()> {
        let mut sub = self.bus.subscribe("net.sensors.");
        let orch = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                match sub.recv().await {
                    Ok(event) => {
                        if let Message::ThreatAssessment(ref assessment) = event.message {
                            if let Err(e) = orch.handle_threat_assessment(assessment) {
                                tracing::error!(error = %e, "failed to handle threat assessment");
                            }
                        }
                    }
                    Err(imperium_bus::BusError::Closed) => break,
                    Err(_) => continue,
                }
            }
        })
    }

    pub fn subscribe_watchtower_observations(
        self: &Arc<Self>,
    ) -> tokio::task::JoinHandle<()> {
        let mut sub = self.bus.subscribe("net.watchtower.");
        let orch = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                match sub.recv().await {
                    Ok(event) => {
                        if let Message::WatchtowerObservation(ref obs) = event.message {
                            let assessment = ThreatAssessment {
                                source: imperium_protocol::ThreatSource::Watchtower,
                                confidence: obs.confidence,
                                description: obs.description.clone(),
                                remote_addr: None,
                                timestamp: obs.timestamp,
                                suggested_action: obs.suggested_action.clone(),
                            };
                            if let Err(e) = orch.handle_threat_assessment(&assessment) {
                                tracing::error!(error = %e, "failed to handle watchtower observation");
                            }
                        }
                    }
                    Err(imperium_bus::BusError::Closed) => break,
                    Err(_) => continue,
                }
            }
        })
    }

    pub fn subscribe_protocol_events(
        self: &Arc<Self>,
    ) -> tokio::task::JoinHandle<()> {
        let mut sub = self.bus.subscribe("net.transport.event");
        let orch = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                match sub.recv().await {
                    Ok(event) => {
                        if let Message::ProtocolEvt(ref pe) = event.message {
                            if let Err(e) = orch.handle_protocol_event(pe) {
                                tracing::error!(error = %e, "failed to handle protocol event");
                            }
                        }
                    }
                    Err(imperium_bus::BusError::Closed) => break,
                    Err(_) => continue,
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use imperium_protocol::{SuggestedAction, ThreatSource};

    fn test_orchestrator() -> Orchestrator {
        let bus = Arc::new(Bus::new());
        let config = OrchestratorConfig {
            active_protocol: "xray".into(),
            standby_protocol: "amneziawg".into(),
            policy: OrchestratorPolicy::default(),
        };
        Orchestrator::new(config, bus)
    }

    #[test]
    fn starts_in_steady_state() {
        let orch = test_orchestrator();
        assert_eq!(orch.state(), OrchestratorState::Steady);
        assert_eq!(orch.active_protocol(), "xray");
        assert_eq!(orch.standby_protocol(), "amneziawg");
    }

    #[test]
    fn active_crash_triggers_failover() {
        let orch = test_orchestrator();

        let event = ProtocolEvent {
            protocol_name: "xray".into(),
            role: ProtocolRole::Active,
            status: ProtocolStatus::Failed,
            event: ProtocolEventKind::Crashed {
                reason: "segfault".into(),
            },
            timestamp: Utc::now(),
        };

        let decision = orch.handle_protocol_event(&event).unwrap();
        assert!(decision.is_some());

        assert_eq!(orch.state(), OrchestratorState::Healing);
        assert_eq!(orch.active_protocol(), "amneziawg");
    }

    #[test]
    fn healing_success_returns_to_steady() {
        let orch = test_orchestrator();

        let crash_event = ProtocolEvent {
            protocol_name: "xray".into(),
            role: ProtocolRole::Active,
            status: ProtocolStatus::Failed,
            event: ProtocolEventKind::Crashed {
                reason: "crash".into(),
            },
            timestamp: Utc::now(),
        };
        orch.handle_protocol_event(&crash_event).unwrap();
        assert_eq!(orch.state(), OrchestratorState::Healing);

        let heal_event = ProtocolEvent {
            protocol_name: "xray".into(),
            role: ProtocolRole::Quarantined,
            status: ProtocolStatus::Running,
            event: ProtocolEventKind::HealingSucceeded,
            timestamp: Utc::now(),
        };
        let decision = orch.handle_protocol_event(&heal_event).unwrap();
        assert!(decision.is_some());
        assert_eq!(orch.state(), OrchestratorState::Steady);
    }

    #[test]
    fn double_crash_triggers_emergency() {
        let orch = test_orchestrator();

        let crash1 = ProtocolEvent {
            protocol_name: "xray".into(),
            role: ProtocolRole::Active,
            status: ProtocolStatus::Failed,
            event: ProtocolEventKind::Crashed {
                reason: "crash 1".into(),
            },
            timestamp: Utc::now(),
        };
        orch.handle_protocol_event(&crash1).unwrap();
        assert_eq!(orch.state(), OrchestratorState::Healing);

        let crash2 = ProtocolEvent {
            protocol_name: "amneziawg".into(),
            role: ProtocolRole::Active,
            status: ProtocolStatus::Failed,
            event: ProtocolEventKind::Crashed {
                reason: "crash 2".into(),
            },
            timestamp: Utc::now(),
        };
        let decision = orch.handle_protocol_event(&crash2).unwrap();
        assert!(decision.is_some());
        assert_eq!(orch.state(), OrchestratorState::Emergency);
    }

    fn arc_orchestrator() -> Arc<Orchestrator> {
        let bus = Arc::new(Bus::new());
        let config = OrchestratorConfig {
            active_protocol: "xray".into(),
            standby_protocol: "amneziawg".into(),
            policy: OrchestratorPolicy::default(),
        };
        Arc::new(Orchestrator::new(config, bus))
    }

    #[tokio::test]
    async fn subscribe_threat_assessment_triggers_failover() {
        let orch = arc_orchestrator();
        let _handle = orch.subscribe_threat_assessments();

        let assessment = ThreatAssessment {
            source: ThreatSource::SignatureEngine,
            confidence: 0.95,
            description: "test threat".into(),
            remote_addr: None,
            timestamp: Utc::now(),
            suggested_action: SuggestedAction::TriggerFailover,
        };

        orch.bus.publish(
            "net.sensors.signature_match",
            Message::ThreatAssessment(assessment),
        ).unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(orch.state(), OrchestratorState::Healing);
    }

    #[tokio::test]
    async fn subscribe_watchtower_observation_triggers_failover() {
        let orch = arc_orchestrator();
        let _handle = orch.subscribe_watchtower_observations();

        let obs = imperium_protocol::WatchtowerObservation {
            pattern_id: "test_pattern".into(),
            description: "suspicious pattern detected".into(),
            confidence: 0.95,
            evidence: vec!["evidence1".into()],
            timestamp: Utc::now(),
            suggested_action: SuggestedAction::TriggerFailover,
        };

        orch.bus.publish(
            "net.watchtower.observation",
            Message::WatchtowerObservation(obs),
        ).unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(orch.state(), OrchestratorState::Healing);
    }

    #[tokio::test]
    async fn subscribe_protocol_events_processes_crash() {
        let orch = arc_orchestrator();
        let _handle = orch.subscribe_protocol_events();

        let event = ProtocolEvent {
            protocol_name: "xray".into(),
            role: ProtocolRole::Active,
            status: ProtocolStatus::Failed,
            event: ProtocolEventKind::Crashed { reason: "bus crash".into() },
            timestamp: Utc::now(),
        };

        orch.bus.publish(
            "net.transport.event",
            Message::ProtocolEvt(event),
        ).unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(orch.state(), OrchestratorState::Healing);
    }

    #[test]
    fn standby_crash_does_not_trigger_failover() {
        let orch = test_orchestrator();

        let event = ProtocolEvent {
            protocol_name: "amneziawg".into(),
            role: ProtocolRole::Standby,
            status: ProtocolStatus::Failed,
            event: ProtocolEventKind::Crashed {
                reason: "standby crash".into(),
            },
            timestamp: Utc::now(),
        };

        let decision = orch.handle_protocol_event(&event).unwrap();
        assert!(decision.is_none());
        assert_eq!(orch.state(), OrchestratorState::Steady);
    }
}
