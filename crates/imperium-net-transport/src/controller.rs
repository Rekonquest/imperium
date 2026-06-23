use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use imperium_bus::Bus;
use imperium_managed_process::{ManagedProcess, ProcessConfig, ResourceBudget, RestartPolicy};
use imperium_protocol::{
    Message, PaddingDistribution, ProtocolCommand, ProtocolCommandKind, ProtocolEvent,
    ProtocolEventKind, ProtocolHardeningProfile, ProtocolRole, ProtocolStatus,
};
use parking_lot::RwLock;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ControllerError {
    #[error("process error: {0}")]
    Process(#[from] imperium_managed_process::ProcessError),
    #[error("bus error: {0}")]
    Bus(#[from] imperium_bus::BusError),
    #[error("protocol not configured")]
    NotConfigured,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProtocolKind {
    Xray,
    AmneziaWg,
}

impl ProtocolKind {
    pub fn name(&self) -> &str {
        match self {
            ProtocolKind::Xray => "xray",
            ProtocolKind::AmneziaWg => "amneziawg",
        }
    }
}

#[derive(Clone, Debug)]
pub struct ProtocolControllerConfig {
    pub kind: ProtocolKind,
    pub binary_path: PathBuf,
    pub config_template: String,
    pub health_check_interval: Duration,
    pub graceful_stop_timeout: Duration,
}

pub struct ProtocolController {
    config: ProtocolControllerConfig,
    role: Arc<RwLock<ProtocolRole>>,
    status: Arc<RwLock<ProtocolStatus>>,
    hardening_profile: Arc<RwLock<Option<ProtocolHardeningProfile>>>,
    process: Option<ManagedProcess>,
    bus: Arc<Bus>,
}

impl ProtocolController {
    pub fn new(config: ProtocolControllerConfig, bus: Arc<Bus>) -> Self {
        Self {
            config,
            role: Arc::new(RwLock::new(ProtocolRole::Standby)),
            status: Arc::new(RwLock::new(ProtocolStatus::Stopped)),
            hardening_profile: Arc::new(RwLock::new(None)),
            process: None,
            bus,
        }
    }

    pub fn protocol_name(&self) -> String {
        self.config.kind.name().to_string()
    }

    pub fn role(&self) -> ProtocolRole {
        self.role.read().clone()
    }

    pub fn status(&self) -> ProtocolStatus {
        self.status.read().clone()
    }

    pub fn set_role(&self, role: ProtocolRole) {
        *self.role.write() = role;
    }

    pub fn apply_hardening_profile(&self, profile: ProtocolHardeningProfile) {
        *self.hardening_profile.write() = Some(profile);
    }

    pub fn subscribe_hardening_profiles(
        self: &Arc<Self>,
        bus: &Arc<Bus>,
    ) -> tokio::task::JoinHandle<()> {
        let mut sub = bus.subscribe("net.transport.hardening.apply");
        let controller = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                match sub.recv().await {
                    Ok(event) => {
                        if let Message::ProtocolHardeningProfile(profile) = event.message {
                            let applies_to_this_controller = match profile.protocol_name.as_deref()
                            {
                                None => true,
                                Some(name) => name == controller.protocol_name(),
                            };
                            if applies_to_this_controller {
                                controller.apply_hardening_profile(profile);
                            }
                        }
                    }
                    Err(imperium_bus::BusError::Closed) => break,
                    Err(_) => continue,
                }
            }
        })
    }

    pub async fn start(&mut self) -> Result<(), ControllerError> {
        let proc_config = ProcessConfig {
            binary: self.config.binary_path.clone(),
            args: vec![],
            env: HashMap::new(),
            health_check_interval: self.config.health_check_interval,
            restart_policy: RestartPolicy::Never,
            budget: ResourceBudget::default(),
            graceful_stop_timeout: self.config.graceful_stop_timeout,
        };

        let mut managed = ManagedProcess::new(proc_config);
        managed.start().await?;
        self.process = Some(managed);

        *self.status.write() = ProtocolStatus::Running;
        self.emit_event(ProtocolEventKind::Started)?;
        Ok(())
    }

    pub async fn stop(&mut self) -> Result<(), ControllerError> {
        if let Some(ref mut proc) = self.process {
            proc.stop().await?;
        }
        self.process = None;
        *self.status.write() = ProtocolStatus::Stopped;
        self.emit_event(ProtocolEventKind::Stopped)?;
        Ok(())
    }

    pub async fn check_health(&mut self) -> bool {
        if let Some(ref mut proc) = self.process {
            let healthy = proc.check_health().await;
            if !healthy {
                *self.status.write() = ProtocolStatus::Failed;
                let _ = self.emit_event(ProtocolEventKind::Crashed {
                    reason: "process exited unexpectedly".into(),
                });
            }
            healthy
        } else {
            false
        }
    }

    pub fn handle_command(&mut self, cmd: &ProtocolCommand) {
        if cmd.protocol_name != self.protocol_name() {
            return;
        }

        match cmd.command {
            ProtocolCommandKind::PromoteToActive => {
                self.set_role(ProtocolRole::Active);
            }
            ProtocolCommandKind::DemoteToStandby => {
                self.set_role(ProtocolRole::Standby);
            }
            ProtocolCommandKind::Quarantine => {
                self.set_role(ProtocolRole::Quarantined);
            }
            _ => {}
        }
    }

    pub fn render_config(&self, params: &HashMap<String, String>) -> String {
        let mut rendered = self.config.config_template.clone();
        let mut merged = params.clone();

        if let Some(profile) = self.hardening_profile.read().clone() {
            merged.extend(hardening_template_params(&profile));
        }

        for (key, value) in merged {
            rendered = rendered.replace(&format!("{{{{{}}}}}", key), &value);
        }

        rendered
    }

    pub fn parse_status(&self, _output: &str) -> ProtocolStatus {
        self.status()
    }

    fn emit_event(&self, event: ProtocolEventKind) -> Result<(), ControllerError> {
        let protocol_event = ProtocolEvent {
            protocol_name: self.protocol_name(),
            role: self.role(),
            status: self.status(),
            event,
            timestamp: Utc::now(),
        };

        self.bus.publish(
            format!("net.transport.event.{}", self.config.kind.name()),
            Message::ProtocolEvt(protocol_event),
        )?;

        Ok(())
    }

    pub fn is_running(&self) -> bool {
        self.status() == ProtocolStatus::Running
    }
}

fn hardening_template_params(profile: &ProtocolHardeningProfile) -> HashMap<String, String> {
    let mut params = HashMap::new();
    params.insert(
        "hardening.profile_id".to_string(),
        profile.profile_id.clone(),
    );
    params.insert(
        "hardening.protocol_name".to_string(),
        profile.protocol_name.clone().unwrap_or_default(),
    );
    params.insert(
        "hardening.padding.mode".to_string(),
        match &profile.traffic_morph.padding {
            PaddingDistribution::None => "none".to_string(),
            PaddingDistribution::Fixed { .. } => "fixed".to_string(),
            PaddingDistribution::Bucketed { .. } => "bucketed".to_string(),
            PaddingDistribution::Envelope { .. } => "envelope".to_string(),
        },
    );
    params.insert(
        "hardening.padding.max_overhead_ppm".to_string(),
        profile.traffic_morph.max_padding_overhead_ppm.to_string(),
    );
    params.insert(
        "hardening.jitter.floor_ms".to_string(),
        profile.traffic_morph.jitter_floor_ms.to_string(),
    );
    params.insert(
        "hardening.jitter.ceiling_ms".to_string(),
        profile.traffic_morph.jitter_ceiling_ms.to_string(),
    );
    params.insert(
        "hardening.cover_traffic_ppm".to_string(),
        profile.traffic_morph.cover_traffic_ppm.to_string(),
    );
    params.insert(
        "hardening.rekey.max_age_seconds".to_string(),
        profile.rekey.max_key_age_seconds.to_string(),
    );
    params.insert(
        "hardening.rekey.max_key_bytes".to_string(),
        profile.rekey.max_key_bytes.to_string(),
    );
    params.insert(
        "hardening.probe.auth_first_packet".to_string(),
        profile
            .probe_resistance
            .authenticated_first_packet_required
            .to_string(),
    );
    params.insert(
        "hardening.deception.enabled".to_string(),
        profile.probe_deception.enabled.to_string(),
    );
    params.insert(
        "hardening.deception.mode".to_string(),
        format!("{:?}", profile.probe_deception.mode),
    );
    params.insert(
        "hardening.deception.min_confidence".to_string(),
        format!("{:.3}", profile.probe_deception.min_confidence),
    );
    params.insert(
        "hardening.deception.max_transcript_bytes".to_string(),
        profile.probe_deception.max_transcript_bytes.to_string(),
    );
    params.insert(
        "hardening.path_hopping.enabled".to_string(),
        profile.path_hopping.enabled.to_string(),
    );
    params.insert(
        "hardening.fec.enabled".to_string(),
        profile.fec.enabled.to_string(),
    );
    params.insert(
        "hardening.fec.data_shards".to_string(),
        profile.fec.data_shards.to_string(),
    );
    params.insert(
        "hardening.fec.parity_shards".to_string(),
        profile.fec.parity_shards.to_string(),
    );

    params
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config(kind: ProtocolKind) -> ProtocolControllerConfig {
        ProtocolControllerConfig {
            kind,
            binary_path: PathBuf::from("echo"),
            config_template: String::new(),
            health_check_interval: Duration::from_secs(5),
            graceful_stop_timeout: Duration::from_secs(5),
        }
    }

    #[test]
    fn controller_role_management() {
        let bus = Arc::new(Bus::new());
        let ctrl = ProtocolController::new(test_config(ProtocolKind::Xray), bus);

        assert_eq!(ctrl.role(), ProtocolRole::Standby);
        ctrl.set_role(ProtocolRole::Active);
        assert_eq!(ctrl.role(), ProtocolRole::Active);
    }

    #[test]
    fn protocol_names() {
        let bus = Arc::new(Bus::new());
        let xray = ProtocolController::new(test_config(ProtocolKind::Xray), bus.clone());
        let awg = ProtocolController::new(test_config(ProtocolKind::AmneziaWg), bus);

        assert_eq!(xray.protocol_name(), "xray");
        assert_eq!(awg.protocol_name(), "amneziawg");
    }

    #[test]
    fn render_config_includes_hardening_params() {
        let bus = Arc::new(Bus::new());
        let config = ProtocolControllerConfig {
            kind: ProtocolKind::Xray,
            binary_path: PathBuf::from("echo"),
            config_template: concat!(
                "profile={{hardening.profile_id}}\n",
                "padding={{hardening.padding.mode}}\n",
                "jitter={{hardening.jitter.floor_ms}}-{{hardening.jitter.ceiling_ms}}\n",
                "deception={{hardening.deception.mode}}\n",
                "fec={{hardening.fec.data_shards}}/{{hardening.fec.parity_shards}}\n",
                "custom={{operator.value}}\n"
            )
            .to_string(),
            health_check_interval: Duration::from_secs(5),
            graceful_stop_timeout: Duration::from_secs(5),
        };
        let ctrl = ProtocolController::new(config, bus);
        ctrl.apply_hardening_profile(crate::HardeningController::resilience_profile(Some(
            "xray".to_string(),
        )));

        let mut params = HashMap::new();
        params.insert("operator.value".to_string(), "enabled".to_string());
        let rendered = ctrl.render_config(&params);

        assert!(rendered.contains("profile=resilience-rf-inspired"));
        assert!(rendered.contains("padding=envelope"));
        assert!(rendered.contains("jitter=5-50"));
        assert!(rendered.contains("deception=ShadowEndpoint"));
        assert!(rendered.contains("fec=10/4"));
        assert!(rendered.contains("custom=enabled"));
    }

    #[tokio::test]
    async fn hardening_subscription_updates_config_rendering() {
        let bus = Arc::new(Bus::new());
        let config = ProtocolControllerConfig {
            kind: ProtocolKind::Xray,
            binary_path: PathBuf::from("echo"),
            config_template: "profile={{hardening.profile_id}}".to_string(),
            health_check_interval: Duration::from_secs(5),
            graceful_stop_timeout: Duration::from_secs(5),
        };
        let ctrl = Arc::new(ProtocolController::new(config, Arc::clone(&bus)));
        let _sub = ctrl.subscribe_hardening_profiles(&bus);

        assert_eq!(
            ctrl.render_config(&HashMap::new()),
            "profile={{hardening.profile_id}}"
        );

        bus.publish(
            "net.transport.hardening.apply",
            Message::ProtocolHardeningProfile(crate::HardeningController::resilience_profile(
                Some("xray".to_string()),
            )),
        )
        .unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;

        assert_eq!(
            ctrl.render_config(&HashMap::new()),
            "profile=resilience-rf-inspired"
        );
    }
}
