//! UDP mesh loop: STUN refresh, cloud signaling, encrypted payloads.

use crate::config::MeshConfig;
use crate::mesh::crypto::{maybe_decrypt, maybe_encrypt};
use crate::mesh::signaling::{cloud_fetch_peers, cloud_register};
use crate::mesh::state::MeshHub;
use crate::mesh::stun::stun_binding;
use crate::mesh::types::{decode_wire, encode_wire, MeshPayload, WIRE_VERSION};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tracing::{debug, info, warn};

async fn resolve_addr(spec: &str) -> Option<SocketAddr> {
    let s = spec.trim();
    if s.is_empty() {
        return None;
    }
    tokio::net::lookup_host(s).await.ok()?.next()
}

async fn send_mesh(
    sock: &UdpSocket,
    psk: Option<&str>,
    to: SocketAddr,
    msg: &MeshPayload,
    hub: &MeshHub,
) {
    let json = match serde_json::to_vec(msg) {
        Ok(j) => j,
        Err(e) => {
            warn!("mesh serialize: {}", e);
            return;
        }
    };
    let body = match maybe_encrypt(psk, &json) {
        Ok(b) => b,
        Err(e) => {
            warn!("mesh encrypt: {}", e);
            return;
        }
    };
    let wire = encode_wire(WIRE_VERSION, &body);
    if sock.send_to(&wire, to).await.is_ok() {
        hub.inc_tx();
    }
}

async fn handle_incoming(
    buf: &[u8],
    from: SocketAddr,
    psk: Option<&str>,
    local_id: &str,
    sock: &UdpSocket,
    hub: &MeshHub,
) {
    let (_ver, body) = match decode_wire(buf) {
        Some(x) => x,
        None => return,
    };
    let plain = match maybe_decrypt(psk, body) {
        Ok(p) => p,
        Err(_) => return,
    };
    let payload: MeshPayload = match serde_json::from_slice(&plain) {
        Ok(p) => p,
        Err(_) => return,
    };
    hub.inc_rx();
    let ep = from.to_string();
    let mapped = hub.snapshot().mapped_addr.clone();

    match &payload {
        MeshPayload::Ping { seq } => {
            let pong = MeshPayload::Pong { seq: *seq };
            send_mesh(sock, psk, from, &pong, hub).await;
        }
        MeshPayload::Pong { .. } => {
            debug!("mesh pong from {}", from);
        }
        MeshPayload::Hello { peer_id, .. } => {
            hub.note_peer(peer_id, ep);
            let hello = MeshPayload::Hello {
                peer_id: local_id.to_string(),
                mapped_addr: mapped,
            };
            send_mesh(sock, psk, from, &hello, hub).await;
        }
        MeshPayload::PeerAnn { peer_id, .. } => {
            hub.note_peer(peer_id, ep);
            let hello = MeshPayload::Hello {
                peer_id: local_id.to_string(),
                mapped_addr: mapped,
            };
            send_mesh(sock, psk, from, &hello, hub).await;
        }
    }
}

pub async fn run_mesh(
    cfg: MeshConfig,
    local_peer_id: String,
    hub: std::sync::Arc<MeshHub>,
    mut shutdown: watch::Receiver<bool>,
) {
    let psk = cfg.psk.clone().filter(|s| !s.is_empty());
    let listen = format!("0.0.0.0:{}", cfg.listen_port);
    let sock = match UdpSocket::bind(&listen).await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            hub.set_error(Some(format!("bind {}: {}", listen, e)));
            warn!("mesh bind failed: {}", e);
            return;
        }
    };
    hub.set_listen(listen.clone());
    hub.set_error(None);
    info!("Mesh UDP listening on {}", listen);

    for server in &cfg.stun_servers {
        match stun_binding(sock.as_ref(), server).await {
            Ok(m) => {
                hub.set_mapped(Some(m.to_string()));
                info!("Initial STUN {} -> {}", server, m);
                break;
            }
            Err(e) => debug!("Initial STUN {} failed: {}", server, e),
        }
    }

    let http = match reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            hub.set_error(Some(format!("http client: {}", e)));
            return;
        }
    };

    let mut stun_tick =
        tokio::time::interval(Duration::from_secs(cfg.stun_refresh_secs.max(30) as u64));
    let mut signal_tick = tokio::time::interval(Duration::from_secs(
        cfg.signaling_poll_secs.max(15) as u64,
    ));
    let mut ping_tick = tokio::time::interval(Duration::from_secs(30));
    stun_tick.tick().await;
    signal_tick.tick().await;
    ping_tick.tick().await;

    let mut buf = vec![0u8; 65536];

    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    info!("Mesh runtime stopping (shutdown)");
                    break;
                }
            }
            _ = stun_tick.tick() => {
                hub.set_error(None);
                for server in &cfg.stun_servers {
                    match stun_binding(sock.as_ref(), server).await {
                        Ok(m) => {
                            let s = m.to_string();
                            hub.set_mapped(Some(s.clone()));
                            info!("STUN {} -> mapped {}", server, s);
                            break;
                        }
                        Err(e) => {
                            debug!("STUN {} failed: {}", server, e);
                            hub.set_error(Some(e.to_string()));
                        }
                    }
                }
            }
            _ = signal_tick.tick() => {
                if let Some(ref base) = cfg.signaling_base_url {
                    let mapped = hub.snapshot().mapped_addr.and_then(|s| s.parse().ok());
                    if let Some(m) = mapped {
                        let tok = cfg.signaling_token.as_deref();
                        if let Err(e) = cloud_register(
                            &http,
                            base,
                            tok,
                            m,
                            &local_peer_id,
                            cfg.listen_port,
                        ).await {
                            warn!("mesh signaling register: {}", e);
                            hub.set_error(Some(e.to_string()));
                        }
                        match cloud_fetch_peers(&http, base, tok).await {
                            Ok(peers) => {
                                hub.set_error(None);
                                for p in peers {
                                    if p.peer_id == local_peer_id {
                                        continue;
                                    }
                                        for ep in &p.endpoints {
                                        let spec = format!("{}:{}", ep.ip, ep.port);
                                        if let Some(sa) = resolve_addr(&spec).await {
                                            let fallback_ep =
                                                format!("0.0.0.0:{}", cfg.listen_port);
                                            let ann = MeshPayload::PeerAnn {
                                                peer_id: local_peer_id.clone(),
                                                endpoints: vec![hub
                                                    .snapshot()
                                                    .mapped_addr
                                                    .clone()
                                                    .unwrap_or(fallback_ep)],
                                            };
                                            send_mesh(sock.as_ref(), psk.as_deref(), sa, &ann, &hub).await;
                                            let hello = MeshPayload::Hello {
                                                peer_id: local_peer_id.clone(),
                                                mapped_addr: hub.snapshot().mapped_addr.clone(),
                                            };
                                            send_mesh(sock.as_ref(), psk.as_deref(), sa, &hello, &hub).await;
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("mesh signaling peers: {}", e);
                                hub.set_error(Some(e.to_string()));
                            }
                        }
                    }
                }
            }
            _ = ping_tick.tick() => {
                let ping = MeshPayload::Ping { seq: rand::random() };
                for spec in &cfg.bootstrap_peer_addrs {
                    if let Some(sa) = resolve_addr(spec).await {
                        send_mesh(sock.as_ref(), psk.as_deref(), sa, &ping, &hub).await;
                    }
                }
            }
            r = sock.recv_from(&mut buf) => {
                match r {
                    Ok((n, from)) => {
                        handle_incoming(
                            &buf[..n],
                            from,
                            psk.as_deref(),
                            &local_peer_id,
                            sock.as_ref(),
                            &hub,
                        )
                        .await;
                    }
                    Err(e) => {
                        warn!("mesh recv: {}", e);
                        hub.set_error(Some(e.to_string()));
                    }
                }
            }
        }
    }
}
