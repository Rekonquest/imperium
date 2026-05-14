mod database;
mod extractor;
mod staging;

pub use database::{SignatureDatabase, SignatureEntry};
pub use extractor::{ExtractionLoop, SignatureExtractor};
pub use staging::{StagingArea, ApprovalFlow};

use std::sync::Arc;

use imperium_bus::Bus;
use imperium_protocol::Message;

pub async fn init(bus: Arc<Bus>) -> Result<(), imperium_bus::BusError> {
    let _sub = bus.subscribe("net.signatures.");
    bus.publish(
        "net.signatures.ready",
        Message::SubsystemReady {
            name: "imperium-net-signatures".into(),
        },
    )?;
    tracing::info!("imperium-net-signatures initialized");
    Ok(())
}
