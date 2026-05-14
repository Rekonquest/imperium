use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use imperium_net_crypto::HybridSessionKey;
use imperium_protocol::{PeerId, SessionId};
use parking_lot::RwLock;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("session not found: {0:?}")]
    NotFound(SessionId),
    #[error("session expired: {0:?}")]
    Expired(SessionId),
    #[error("key exchange failed: {0}")]
    KexFailed(String),
    #[error("peer already has an active session")]
    DuplicateSession,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionState {
    Handshaking,
    Established,
    Expired,
}

pub struct PeerSession {
    pub session_id: SessionId,
    pub peer_id: PeerId,
    pub remote_addr: SocketAddr,
    pub state: SessionState,
    pub session_key: Option<Arc<HybridSessionKey>>,
    pub established_at: Option<DateTime<Utc>>,
    pub last_activity: DateTime<Utc>,
    pub ping_seq: u64,
    pub rtt_ms: Option<u64>,
}

impl PeerSession {
    fn new(session_id: SessionId, peer_id: PeerId, remote_addr: SocketAddr) -> Self {
        Self {
            session_id,
            peer_id,
            remote_addr,
            state: SessionState::Handshaking,
            session_key: None,
            established_at: None,
            last_activity: Utc::now(),
            ping_seq: 0,
            rtt_ms: None,
        }
    }

    pub fn establish(&mut self, key: HybridSessionKey) {
        self.state = SessionState::Established;
        self.session_key = Some(Arc::new(key));
        self.established_at = Some(Utc::now());
        self.last_activity = Utc::now();
    }

    pub fn touch(&mut self) {
        self.last_activity = Utc::now();
    }

    pub fn is_established(&self) -> bool {
        self.state == SessionState::Established
    }

    pub fn next_ping_seq(&mut self) -> u64 {
        self.ping_seq += 1;
        self.ping_seq
    }

    pub fn record_rtt(&mut self, rtt_ms: u64) {
        self.rtt_ms = Some(rtt_ms);
        self.touch();
    }
}

pub struct SessionManager {
    sessions: Arc<RwLock<HashMap<SessionId, PeerSession>>>,
    peer_sessions: Arc<RwLock<HashMap<PeerId, SessionId>>>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            peer_sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn create_session(
        &self,
        peer_id: PeerId,
        remote_addr: SocketAddr,
    ) -> Result<SessionId, SessionError> {
        let peer_map = self.peer_sessions.read();
        if peer_map.contains_key(&peer_id) {
            return Err(SessionError::DuplicateSession);
        }
        drop(peer_map);

        let session_id = SessionId::new();
        let session = PeerSession::new(session_id.clone(), peer_id.clone(), remote_addr);

        self.sessions.write().insert(session_id.clone(), session);
        self.peer_sessions
            .write()
            .insert(peer_id, session_id.clone());

        Ok(session_id)
    }

    pub fn establish_session(
        &self,
        session_id: &SessionId,
        key: HybridSessionKey,
    ) -> Result<(), SessionError> {
        let mut sessions = self.sessions.write();
        let session = sessions
            .get_mut(session_id)
            .ok_or_else(|| SessionError::NotFound(session_id.clone()))?;
        session.establish(key);
        Ok(())
    }

    pub fn get_session_state(&self, session_id: &SessionId) -> Option<SessionState> {
        self.sessions.read().get(session_id).map(|s| s.state.clone())
    }

    pub fn get_session_for_peer(&self, peer_id: &PeerId) -> Option<SessionId> {
        self.peer_sessions.read().get(peer_id).cloned()
    }

    pub fn touch_session(&self, session_id: &SessionId) {
        if let Some(session) = self.sessions.write().get_mut(session_id) {
            session.touch();
        }
    }

    pub fn record_pong(&self, session_id: &SessionId, rtt_ms: u64) {
        if let Some(session) = self.sessions.write().get_mut(session_id) {
            session.record_rtt(rtt_ms);
        }
    }

    pub fn remove_session(&self, session_id: &SessionId) {
        if let Some(session) = self.sessions.write().remove(session_id) {
            self.peer_sessions.write().remove(&session.peer_id);
        }
    }

    pub fn active_session_count(&self) -> usize {
        self.sessions
            .read()
            .values()
            .filter(|s| s.is_established())
            .count()
    }

    pub fn all_session_ids(&self) -> Vec<SessionId> {
        self.sessions.read().keys().cloned().collect()
    }

    pub fn expire_stale_sessions(&self, max_idle_secs: i64) -> Vec<SessionId> {
        let now = Utc::now();
        let mut expired = Vec::new();

        let mut sessions = self.sessions.write();
        let session_ids: Vec<SessionId> = sessions.keys().cloned().collect();

        for sid in session_ids {
            if let Some(session) = sessions.get(&sid) {
                let idle = (now - session.last_activity).num_seconds();
                if idle > max_idle_secs {
                    expired.push(sid.clone());
                }
            }
        }

        for sid in &expired {
            if let Some(session) = sessions.remove(sid) {
                self.peer_sessions.write().remove(&session.peer_id);
            }
        }

        expired
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use imperium_net_crypto::HybridX25519Mlkem;
    use rand::rngs::OsRng;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn test_addr() -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9000))
    }

    #[test]
    fn create_and_establish_session() {
        let mgr = SessionManager::new();
        let peer = PeerId::new();
        let sid = mgr.create_session(peer.clone(), test_addr()).unwrap();

        assert_eq!(mgr.get_session_state(&sid), Some(SessionState::Handshaking));

        let mut rng = OsRng;
        let (_secret, public) = HybridX25519Mlkem::generate_keypair(&mut rng);
        let (_encap, key) = HybridX25519Mlkem::encapsulate(&mut rng, &public);

        mgr.establish_session(&sid, key).unwrap();
        assert_eq!(mgr.get_session_state(&sid), Some(SessionState::Established));
        assert_eq!(mgr.active_session_count(), 1);
    }

    #[test]
    fn duplicate_session_rejected() {
        let mgr = SessionManager::new();
        let peer = PeerId::new();
        mgr.create_session(peer.clone(), test_addr()).unwrap();
        assert!(mgr.create_session(peer, test_addr()).is_err());
    }

    #[test]
    fn remove_session_clears_peer_mapping() {
        let mgr = SessionManager::new();
        let peer = PeerId::new();
        let sid = mgr.create_session(peer.clone(), test_addr()).unwrap();
        mgr.remove_session(&sid);
        assert!(mgr.get_session_for_peer(&peer).is_none());
        assert_eq!(mgr.active_session_count(), 0);
    }
}
