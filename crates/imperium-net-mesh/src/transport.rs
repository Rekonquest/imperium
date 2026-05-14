use std::net::SocketAddr;
use std::sync::Arc;

use imperium_bus::Bus;
use imperium_protocol::{Message, MeshPing, MeshPong, PeerId};
use thiserror::Error;
use tokio::net::UdpSocket;

use crate::peer::PeerManager;
use crate::session::SessionManager;

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("bus error: {0}")]
    Bus(#[from] imperium_bus::BusError),
    #[error("no session for peer")]
    NoSession,
    #[error("serialization error: {0}")]
    Serialization(String),
}

pub struct MeshTransport {
    bus: Arc<Bus>,
    peer_manager: Arc<PeerManager>,
    session_manager: Arc<SessionManager>,
    local_peer_id: PeerId,
}

impl MeshTransport {
    pub fn new(
        bus: Arc<Bus>,
        peer_manager: Arc<PeerManager>,
        session_manager: Arc<SessionManager>,
        local_peer_id: PeerId,
    ) -> Self {
        Self {
            bus,
            peer_manager,
            session_manager,
            local_peer_id,
        }
    }

    pub fn local_peer_id(&self) -> &PeerId {
        &self.local_peer_id
    }

    pub async fn send_ping(
        &self,
        socket: &UdpSocket,
        peer_id: &PeerId,
    ) -> Result<(), TransportError> {
        let session_id = self
            .session_manager
            .get_session_for_peer(peer_id)
            .ok_or(TransportError::NoSession)?;

        let endpoints = self
            .peer_manager
            .get_endpoints(peer_id)
            .ok_or(TransportError::NoSession)?;

        let ping = MeshPing {
            peer_id: self.local_peer_id.clone(),
            session_id: session_id.clone(),
            seq: 0,
            sent_at: chrono::Utc::now(),
        };

        let payload = serde_json::to_vec(&ping)
            .map_err(|e| TransportError::Serialization(e.to_string()))?;

        if let Some(addr) = endpoints.first() {
            socket.send_to(&payload, addr).await?;
        }

        self.bus.publish(
            "net.mesh.ping.sent",
            Message::MeshPing(ping),
        )?;

        Ok(())
    }

    pub async fn send_pong(
        &self,
        socket: &UdpSocket,
        target: SocketAddr,
        ping: &MeshPing,
    ) -> Result<(), TransportError> {
        let pong = MeshPong {
            peer_id: self.local_peer_id.clone(),
            session_id: ping.session_id.clone(),
            seq: ping.seq,
            received_at: chrono::Utc::now(),
        };

        let payload = serde_json::to_vec(&pong)
            .map_err(|e| TransportError::Serialization(e.to_string()))?;

        socket.send_to(&payload, target).await?;

        self.bus.publish(
            "net.mesh.pong.sent",
            Message::MeshPong(pong),
        )?;

        Ok(())
    }

    pub fn handle_pong(&self, pong: &MeshPong) {
        let now = chrono::Utc::now();
        let rtt_ms = (now - pong.received_at).num_milliseconds().unsigned_abs();
        self.session_manager.record_pong(&pong.session_id, rtt_ms);
        self.session_manager.touch_session(&pong.session_id);
    }

    pub fn peer_manager(&self) -> &PeerManager {
        &self.peer_manager
    }

    pub fn session_manager(&self) -> &SessionManager {
        &self.session_manager
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_construction() {
        let bus = Arc::new(Bus::new());
        let pm = Arc::new(PeerManager::new());
        let sm = Arc::new(SessionManager::new());
        let peer_id = PeerId::new();

        let transport = MeshTransport::new(bus, pm, sm, peer_id.clone());
        assert_eq!(transport.local_peer_id(), &peer_id);
    }
}
