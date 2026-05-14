//! Minimal RFC 5389 STUN binding client (IPv4 XOR-MAPPED-ADDRESS).

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;
use tokio::net::UdpSocket;

const MAGIC: u32 = 0x2112A442;

fn parse_xor_mapped(data: &[u8]) -> Option<SocketAddrV4> {
    if data.len() < 8 {
        return None;
    }
    if data[1] != 1 {
        return None;
    } // IPv4
    let xport = u16::from_be_bytes([data[2], data[3]]) ^ ((MAGIC >> 16) as u16);
    let xaddr = u32::from_be_bytes([data[4], data[5], data[6], data[7]]) ^ MAGIC;
    Some(SocketAddrV4::new(Ipv4Addr::from(xaddr), xport))
}

fn parse_binding_response(pkt: &[u8]) -> Option<SocketAddr> {
    if pkt.len() < 20 {
        return None;
    }
    let typ = u16::from_be_bytes([pkt[0], pkt[1]]);
    if typ != 0x0101 {
        return None;
    }
    let len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
    if pkt.len() < 20 + len {
        return None;
    }
    let mut i = 20;
    let end = 20 + len;
    while i + 4 <= end {
        let atyp = u16::from_be_bytes([pkt[i], pkt[i + 1]]);
        let alen = u16::from_be_bytes([pkt[i + 2], pkt[i + 3]]) as usize;
        let vstart = i + 4;
        if vstart + alen > pkt.len() {
            break;
        }
        if atyp == 0x0020 {
            if let Some(a) = parse_xor_mapped(&pkt[vstart..vstart + alen]) {
                return Some(SocketAddr::V4(a));
            }
        }
        let padded = (alen + 3) & !3;
        i = vstart + padded;
    }
    None
}

async fn resolve_first(host_port: &str) -> std::io::Result<SocketAddr> {
    let mut it = tokio::net::lookup_host(host_port).await?;
    it.next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "dns"))
}

/// Discover public UDP endpoint via STUN (same socket as mesh traffic).
pub async fn stun_binding(socket: &UdpSocket, server: &str) -> anyhow::Result<SocketAddr> {
    let dest = resolve_first(server).await?;
    let tid: [u8; 12] = rand::random();
    let mut req = Vec::with_capacity(20);
    req.extend_from_slice(&0x0001u16.to_be_bytes());
    req.extend_from_slice(&0u16.to_be_bytes());
    req.extend_from_slice(&MAGIC.to_be_bytes());
    req.extend_from_slice(&tid);
    socket.send_to(&req, dest).await?;
    let mut buf = [0u8; 1024];
    let (n, _) = tokio::time::timeout(Duration::from_secs(4), socket.recv_from(&mut buf))
        .await
        .map_err(|_| anyhow::anyhow!("stun timeout"))??;
    parse_binding_response(&buf[..n]).ok_or_else(|| anyhow::anyhow!("stun: no XOR-MAPPED-ADDRESS"))
}
