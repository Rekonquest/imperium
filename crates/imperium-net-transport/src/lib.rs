mod controller;
mod orchestrator;

pub use controller::{ProtocolController, ProtocolControllerConfig, ProtocolKind};
pub use orchestrator::{Orchestrator, OrchestratorConfig, OrchestratorPolicy};

use std::sync::Arc;

use imperium_bus::Bus;
use imperium_protocol::Message;

pub async fn init(bus: Arc<Bus>) -> Result<(), imperium_bus::BusError> {
    let _sub = bus.subscribe("net.transport.");
    bus.publish(
        "net.transport.ready",
        Message::SubsystemReady {
            name: "imperium-net-transport".into(),
        },
    )?;
    tracing::info!("imperium-net-transport initialized");
    Ok(())
}
