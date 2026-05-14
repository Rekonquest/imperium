mod peer;
mod session;
mod stun;
mod transport;

pub use peer::{PeerManager, PeerState};
pub use session::{PeerSession, SessionManager};
pub use stun::StunClient;
pub use transport::MeshTransport;

use std::sync::Arc;

use imperium_bus::Bus;
use imperium_protocol::Message;

pub async fn init(bus: Arc<Bus>) -> Result<(), imperium_bus::BusError> {
    let _sub = bus.subscribe("net.mesh.");
    bus.publish(
        "net.mesh.ready",
        Message::SubsystemReady {
            name: "imperium-net-mesh".into(),
        },
    )?;
    tracing::info!("imperium-net-mesh initialized");
    Ok(())
}
