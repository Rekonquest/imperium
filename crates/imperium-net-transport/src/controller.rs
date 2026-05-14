use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use imperium_bus::Bus;
use imperium_managed_process::{ManagedProcess, ProcessConfig, ResourceBudget, RestartPolicy};
use imperium_protocol::{
    Message, ProtocolCommand, ProtocolCommandKind, ProtocolEvent, ProtocolEventKind,
    ProtocolRole, ProtocolStatus,
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
    process: Option<ManagedProcess>,
    bus: Arc<Bus>,
}

impl ProtocolController {
    pub fn new(config: ProtocolControllerConfig, bus: Arc<Bus>) -> Self {
        Self {
            config,
            role: Arc::new(RwLock::new(ProtocolRole::Standby)),
            status: Arc::new(RwLock::new(ProtocolStatus::Stopped)),
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

    pub fn render_config(&self, _params: &HashMap<String, String>) -> String {
        self.config.config_template.clone()
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
}
