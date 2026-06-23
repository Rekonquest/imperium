use std::net::SocketAddr;
use std::sync::Arc;

use imperium_bus::Bus;
use imperium_protocol::{MeshPing, MeshPong, Message, PeerId, ProtocolHardeningProfile};
use parking_lot::RwLock;
use thiserror::Error;
use tokio::net::UdpSocket;

use crate::hardening::{HardenedPayload, MeshHardener};
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
    hardener: Arc<RwLock<Option<MeshHardener>>>,
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
            hardener: Arc::new(RwLock::new(None)),
        }
    }

    pub fn local_peer_id(&self) -> &PeerId {
        &self.local_peer_id
    }

    pub fn apply_hardening_profile(&self, profile: ProtocolHardeningProfile) {
        *self.hardener.write() = Some(MeshHardener::new(profile));
    }

    pub fn clear_hardening_profile(&self) {
        *self.hardener.write() = None;
    }

    pub fn harden_payload_for_send(&self, payload: Vec<u8>) -> HardenedPayload {
        if let Some(ref mut hardener) = *self.hardener.write() {
            hardener.harden_payload(payload, false)
        } else {
            HardenedPayload {
                bytes: payload,
                delay: std::time::Duration::ZERO,
                rekey_epoch: 0,
                cover: false,
            }
        }
    }

    pub fn subscribe_hardening_profiles(
        self: &Arc<Self>,
        bus: &Arc<Bus>,
    ) -> tokio::task::JoinHandle<()> {
        let mut sub = bus.subscribe("net.transport.hardening.apply");
        let transport = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                match sub.recv().await {
                    Ok(event) => {
                        if let Message::ProtocolHardeningProfile(profile) = event.message {
                            transport.apply_hardening_profile(profile);
                        }
                    }
                    Err(imperium_bus::BusError::Closed) => break,
                    Err(_) => continue,
                }
            }
        })
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

        let payload =
            serde_json::to_vec(&ping).map_err(|e| TransportError::Serialization(e.to_string()))?;

        if let Some(addr) = endpoints.first() {
            let hardened = self.harden_payload_for_send(payload);
            if !hardened.delay.is_zero() {
                tokio::time::sleep(hardened.delay).await;
            }
            socket.send_to(&hardened.bytes, addr).await?;
        }

        self.bus
            .publish("net.mesh.ping.sent", Message::MeshPing(ping))?;

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

        let payload =
            serde_json::to_vec(&pong).map_err(|e| TransportError::Serialization(e.to_string()))?;

        let hardened = self.harden_payload_for_send(payload);
        if !hardened.delay.is_zero() {
            tokio::time::sleep(hardened.delay).await;
        }
        socket.send_to(&hardened.bytes, target).await?;

        self.bus
            .publish("net.mesh.pong.sent", Message::MeshPong(pong))?;

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
    use chrono::Utc;
    use imperium_protocol::{
        FecPolicy, PaddingDistribution, PathHoppingPolicy, ProbeDeceptionMode,
        ProbeDeceptionPolicy, ProbeFailureMode, ProbeResistancePolicy, RekeyPolicy,
        TrafficMorphProfile,
    };

    #[test]
    fn transport_construction() {
        let bus = Arc::new(Bus::new());
        let pm = Arc::new(PeerManager::new());
        let sm = Arc::new(SessionManager::new());
        let peer_id = PeerId::new();

        let transport = MeshTransport::new(bus, pm, sm, peer_id.clone());
        assert_eq!(transport.local_peer_id(), &peer_id);
    }

    fn test_profile() -> ProtocolHardeningProfile {
        ProtocolHardeningProfile {
            profile_id: "mesh-live-test".to_string(),
            protocol_name: Some("mesh".to_string()),
            traffic_morph: TrafficMorphProfile {
                profile_id: "mesh-live-test-morph".to_string(),
                padding: PaddingDistribution::Bucketed {
                    buckets: vec![64, 256],
                },
                max_padding_overhead_ppm: 500_000,
                jitter_floor_ms: 0,
                jitter_ceiling_ms: 0,
                cover_traffic_ppm: 0,
                packet_batching_window_ms: 0,
            },
            rekey: RekeyPolicy {
                max_key_age_seconds: 600,
                max_key_bytes: 1_048_576,
                threat_triggered: true,
                stagger_window_ms: 0,
            },
            probe_resistance: ProbeResistancePolicy {
                authenticated_first_packet_required: true,
                unauthenticated_failure_mode: ProbeFailureMode::ConstantShapeReject,
                min_response_delay_ms: 0,
                max_response_delay_ms: 0,
                decoy_response_budget_per_hour: 0,
            },
            probe_deception: ProbeDeceptionPolicy {
                enabled: false,
                mode: ProbeDeceptionMode::Disabled,
                min_confidence: 1.0,
                response_budget_per_source_per_hour: 0,
                min_delay_ms: 0,
                max_delay_ms: 0,
                max_transcript_bytes: 0,
                persona_rotation_seconds: 3_600,
                log_transcripts: false,
            },
            path_hopping: PathHoppingPolicy {
                enabled: true,
                min_dwell_seconds: 60,
                max_dwell_seconds: 300,
                burn_score_threshold: 0.8,
                packet_loss_threshold_ppm: 50_000,
                jitter_threshold_ms: 80,
            },
            fec: FecPolicy {
                enabled: true,
                data_shards: 8,
                parity_shards: 2,
                loss_threshold_ppm: 20_000,
                max_overhead_ppm: 250_000,
            },
            applied_at: Utc::now(),
            reason: "test profile".to_string(),
        }
    }

    #[test]
    fn hardening_profile_wraps_payload_for_send() {
        let bus = Arc::new(Bus::new());
        let pm = Arc::new(PeerManager::new());
        let sm = Arc::new(SessionManager::new());
        let peer_id = PeerId::new();
        let transport = MeshTransport::new(bus, pm, sm, peer_id);

        transport.apply_hardening_profile(test_profile());

        let original = br#"{"mesh":"ping"}"#.to_vec();
        let hardened = transport.harden_payload_for_send(original.clone());

        assert!(hardened.bytes.len() > original.len());
        assert_eq!(MeshHardener::recover_payload(&hardened.bytes), original);
    }

    #[tokio::test]
    async fn hardening_subscription_updates_send_path() {
        let bus = Arc::new(Bus::new());
        let pm = Arc::new(PeerManager::new());
        let sm = Arc::new(SessionManager::new());
        let peer_id = PeerId::new();
        let transport = Arc::new(MeshTransport::new(Arc::clone(&bus), pm, sm, peer_id));
        let _sub = transport.subscribe_hardening_profiles(&bus);

        let original = br#"{"mesh":"ping"}"#.to_vec();
        assert_eq!(
            transport.harden_payload_for_send(original.clone()).bytes,
            original
        );

        bus.publish(
            "net.transport.hardening.apply",
            Message::ProtocolHardeningProfile(test_profile()),
        )
        .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let hardened = transport.harden_payload_for_send(original.clone());
        assert!(hardened.bytes.len() > original.len());
        assert_eq!(MeshHardener::recover_payload(&hardened.bytes), original);
    }
}
