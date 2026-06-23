mod access;
mod config;
mod membership;
mod token;

pub use access::AccessPolicy;
pub use config::{ClusterConfig, ConfigManager};
pub use membership::{MembershipManager, MembershipState};
pub use token::TokenManager;

use std::sync::Arc;

use imperium_bus::Bus;
use imperium_protocol::Message;

pub async fn init(bus: Arc<Bus>) -> Result<(), imperium_bus::BusError> {
    let _sub = bus.subscribe("net.cluster.");
    bus.publish(
        "net.cluster.ready",
        Message::SubsystemReady {
            name: "imperium-net-cluster".into(),
        },
    )?;
    tracing::info!("imperium-net-cluster initialized");
    Ok(())
}
