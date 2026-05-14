mod observer;
mod projection;

pub use observer::{Watchtower, WatchtowerConfig, WatchtowerState};
pub use projection::{ProjectionTask, ProjectionResult};

use std::sync::Arc;

use imperium_bus::Bus;
use imperium_protocol::Message;

pub async fn init(bus: Arc<Bus>) -> Result<(), imperium_bus::BusError> {
    let _sub = bus.subscribe("net.watchtower.");
    bus.publish(
        "net.watchtower.ready",
        Message::SubsystemReady {
            name: "imperium-net-watchtower".into(),
        },
    )?;
    tracing::info!("imperium-net-watchtower initialized");
    Ok(())
}
