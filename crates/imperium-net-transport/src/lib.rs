mod controller;
mod hardening;
mod leak_guard;
mod masque;
mod orchestrator;

pub use controller::{ProtocolController, ProtocolControllerConfig, ProtocolKind};
pub use hardening::{HardeningController, HardeningError, ProbeDeceptionEngine};
pub use leak_guard::LeakGuard;
pub use masque::MasqueController;
pub use orchestrator::{Orchestrator, OrchestratorConfig, OrchestratorPolicy};

use std::sync::Arc;

use imperium_bus::Bus;
use imperium_protocol::{KillSwitchState, LeakGuardStatus, Message};

pub async fn init(bus: Arc<Bus>) -> Result<(), imperium_bus::BusError> {
    let _sub = bus.subscribe("net.transport.");
    bus.publish(
        "net.transport.ready",
        Message::SubsystemReady {
            name: "imperium-net-transport".into(),
        },
    )?;

    bus.publish(
        "net.transport.leak_guard.status",
        Message::LeakGuardStatus(LeakGuardStatus {
            dns_guard_enabled: true,
            route_guard_enabled: true,
            kill_switch: KillSwitchState::Armed,
            last_violation: None,
            timestamp: chrono::Utc::now(),
        }),
    )?;

    let hardening_profile = HardeningController::balanced_profile(None);
    bus.publish(
        "net.transport.hardening.apply",
        Message::ProtocolHardeningProfile(hardening_profile.clone()),
    )?;
    if let Err(e) = HardeningController::new(Arc::clone(&bus)).apply(hardening_profile) {
        tracing::warn!(error = %e, "default hardening profile rejected");
    }

    tracing::info!("imperium-net-transport initialized");
    Ok(())
}
