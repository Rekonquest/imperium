//! Shared mesh status for the HTTP API.

use crate::config::{MeshConfig, MeshOverlay};
use crate::mesh::types::MeshSnapshot;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

pub struct MeshHub {
    snap: RwLock<MeshSnapshot>,
}

impl MeshHub {
    pub fn new(peer_id: String, cfg: &MeshConfig) -> Arc<Self> {
        let overlay = match &cfg.overlay {
            MeshOverlay::None => "none".to_string(),
            MeshOverlay::HeadscaleCli { login_server, .. } => {
                format!("headscale_cli:{}", login_server.trim())
            }
        };
        Arc::new(Self {
            snap: RwLock::new(MeshSnapshot {
                enabled: true,
                local_peer_id: peer_id,
                listen_addr: None,
                mapped_addr: None,
                stun_servers: cfg.stun_servers.clone(),
                signaling_url: cfg.signaling_base_url.clone(),
                encrypted: cfg.psk.as_ref().map(|s| !s.is_empty()).unwrap_or(false),
                peers_seen: HashMap::new(),
                packets_sent: 0,
                packets_recv: 0,
                last_error: None,
                overlay,
            }),
        })
    }

    pub fn snapshot(&self) -> MeshSnapshot {
        self.snap.read().clone()
    }

    pub fn set_listen(&self, addr: String) {
        self.snap.write().listen_addr = Some(addr);
    }

    pub fn set_mapped(&self, addr: Option<String>) {
        self.snap.write().mapped_addr = addr;
    }

    pub fn set_error(&self, err: Option<String>) {
        self.snap.write().last_error = err;
    }

    pub fn inc_tx(&self) {
        self.snap.write().packets_sent += 1;
    }

    pub fn inc_rx(&self) {
        self.snap.write().packets_recv += 1;
    }

    pub fn note_peer(&self, peer_id: &str, endpoint: String) {
        let mut g = self.snap.write();
        g.peers_seen
            .entry(peer_id.to_string())
            .or_default()
            .push(endpoint);
        let v = g.peers_seen.get_mut(peer_id).unwrap();
        v.sort();
        v.dedup();
        if v.len() > 32 {
            v.drain(0..v.len() - 32);
        }
    }
}
