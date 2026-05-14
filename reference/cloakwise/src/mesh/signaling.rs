//! Optional HTTP cloud rendezvous (register local mapping, fetch other peers).

use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tracing::debug;

#[derive(Debug, Serialize)]
pub struct RegisterPayload {
    pub peer_id: String,
    pub listen_port: u16,
    pub mapped_ip: String,
    pub mapped_port: u16,
}

#[derive(Debug, Deserialize)]
pub struct PeersEnvelope {
    pub peers: Vec<RemotePeerRecord>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RemotePeerRecord {
    pub peer_id: String,
    pub endpoints: Vec<RemoteEndpoint>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RemoteEndpoint {
    pub ip: String,
    pub port: u16,
}

pub async fn cloud_register(
    client: &reqwest::Client,
    base: &str,
    token: Option<&str>,
    mapped: SocketAddr,
    peer_id: &str,
    listen_port: u16,
) -> anyhow::Result<()> {
    let url = format!("{}/register", base.trim_end_matches('/'));
    let (mapped_ip, mapped_port) = match mapped {
        SocketAddr::V4(v) => (v.ip().to_string(), v.port()),
        SocketAddr::V6(v) => (v.ip().to_string(), v.port()),
    };
    let body = RegisterPayload {
        peer_id: peer_id.to_string(),
        listen_port,
        mapped_ip,
        mapped_port,
    };
    let mut req = client.post(&url).json(&body);
    if let Some(t) = token.filter(|s| !s.is_empty()) {
        let mut h = HeaderMap::new();
        let val = HeaderValue::from_str(&format!("Bearer {}", t))
            .unwrap_or_else(|_| HeaderValue::from_static("invalid"));
        h.insert(AUTHORIZATION, val);
        req = req.headers(h);
    }
    let r = req.send().await?;
    if !r.status().is_success() {
        anyhow::bail!("signaling register {}", r.status());
    }
    debug!("Cloud signaling register ok");
    Ok(())
}

pub async fn cloud_fetch_peers(
    client: &reqwest::Client,
    base: &str,
    token: Option<&str>,
) -> anyhow::Result<Vec<RemotePeerRecord>> {
    let url = format!("{}/peers", base.trim_end_matches('/'));
    let mut req = client.get(&url);
    if let Some(t) = token.filter(|s| !s.is_empty()) {
        let mut h = HeaderMap::new();
        let val = HeaderValue::from_str(&format!("Bearer {}", t))
            .unwrap_or_else(|_| HeaderValue::from_static("invalid"));
        h.insert(AUTHORIZATION, val);
        req = req.headers(h);
    }
    let r = req.send().await?;
    if !r.status().is_success() {
        anyhow::bail!("signaling peers {}", r.status());
    }
    let env: PeersEnvelope = r.json().await?;
    Ok(env.peers)
}
