mod classifier;
mod fusion;
mod signature_engine;

pub use classifier::{ClassifierConfig, ClassifierSensor};
pub use fusion::{FusionPolicy, SensorFusion};
pub use signature_engine::SignatureEngineSensor;

use std::sync::Arc;

use imperium_bus::Bus;
use imperium_protocol::Message;

pub async fn init(bus: Arc<Bus>) -> Result<(), imperium_bus::BusError> {
    let _sub = bus.subscribe("net.sensors.");
    bus.publish(
        "net.sensors.ready",
        Message::SubsystemReady {
            name: "imperium-net-sensors".into(),
        },
    )?;
    tracing::info!("imperium-net-sensors initialized");
    Ok(())
}
