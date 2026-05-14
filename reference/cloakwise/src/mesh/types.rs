//! Mesh wire messages and API snapshots.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

const WIRE_MAGIC: [u8; 4] = *b"CWME";
pub const WIRE_VERSION: u16 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum MeshPayload {
    Hello {
        peer_id: String,
        #[serde(default)]
        mapped_addr: Option<String>,
    },
    Ping {
        seq: u64,
    },
    Pong {
        seq: u64,
    },
    PeerAnn {
        /// Announced peer id
        peer_id: String,
        /// Best-effort reachable UDP endpoints
        endpoints: Vec<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MeshSnapshot {
    pub enabled: bool,
    pub local_peer_id: String,
    pub listen_addr: Option<String>,
    pub mapped_addr: Option<String>,
    pub stun_servers: Vec<String>,
    pub signaling_url: Option<String>,
    pub encrypted: bool,
    pub peers_seen: HashMap<String, Vec<String>>,
    pub packets_sent: u64,
    pub packets_recv: u64,
    pub last_error: Option<String>,
    /// `none` or `headscale_cli:<login_server>`
    #[serde(default)]
    pub overlay: String,
}

impl MeshSnapshot {
    pub fn disabled(local_peer_id: String) -> Self {
        Self {
            enabled: false,
            local_peer_id,
            listen_addr: None,
            mapped_addr: None,
            stun_servers: vec![],
            signaling_url: None,
            encrypted: false,
            peers_seen: HashMap::new(),
            packets_sent: 0,
            packets_recv: 0,
            last_error: None,
            overlay: "none".to_string(),
        }
    }
}

pub fn encode_wire(version: u16, body: &[u8]) -> Vec<u8> {
    let len: u32 = body.len().try_into().unwrap_or(u32::MAX);
    let mut out = Vec::with_capacity(10 + body.len());
    out.extend_from_slice(&WIRE_MAGIC);
    out.extend_from_slice(&version.to_be_bytes());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(body);
    out
}

pub fn decode_wire(buf: &[u8]) -> Option<(u16, &[u8])> {
    if buf.len() < 10 || buf[0..4] != WIRE_MAGIC {
        return None;
    }
    let ver = u16::from_be_bytes([buf[4], buf[5]]);
    let len = u32::from_be_bytes([buf[6], buf[7], buf[8], buf[9]]) as usize;
    let end = 10 + len;
    if buf.len() < end {
        return None;
    }
    Some((ver, &buf[10..end]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_roundtrip() {
        let body = b"{\"t\":\"ping\",\"seq\":1}";
        let w = encode_wire(WIRE_VERSION, body);
        let (v, inner) = decode_wire(&w).unwrap();
        assert_eq!(v, WIRE_VERSION);
        assert_eq!(inner, body);
    }
}
