mod hardening;
mod path;
mod peer;
mod session;
mod stun;
mod transport;
mod traversal;

pub use hardening::{HardenedPacketFrame, HardenedPayload, MeshHardener};
pub use path::{PathManager, PathScoreWeights};
pub use peer::{PeerManager, PeerState};
pub use session::{PeerSession, SessionManager};
pub use stun::StunClient;
pub use transport::MeshTransport;
pub use traversal::NatTraversalPlanner;

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

    bus.publish(
        "net.mesh.nat.policy",
        Message::NatTraversalPolicy(NatTraversalPlanner::default_policy()),
    )?;

    tracing::info!("imperium-net-mesh initialized");
    Ok(())
}
