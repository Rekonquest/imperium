use std::net::SocketAddr;
use thiserror::Error;
use tokio::net::UdpSocket;

#[derive(Debug, Error)]
pub enum StunError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid STUN response")]
    InvalidResponse,
    #[error("STUN request timed out")]
    Timeout,
}

const STUN_BINDING_REQUEST: u16 = 0x0001;
const STUN_BINDING_RESPONSE: u16 = 0x0101;
const STUN_MAGIC_COOKIE: u32 = 0x2112A442;
const STUN_ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const STUN_ATTR_MAPPED_ADDRESS: u16 = 0x0001;

pub struct StunClient;

impl StunClient {
    pub async fn discover_mapped_address(
        socket: &UdpSocket,
        stun_server: SocketAddr,
    ) -> Result<SocketAddr, StunError> {
        let transaction_id: [u8; 12] = rand::random();
        let request = build_binding_request(&transaction_id);

        socket.send_to(&request, stun_server).await?;

        let mut buf = [0u8; 512];
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            socket.recv_from(&mut buf),
        )
        .await;

        match result {
            Ok(Ok((len, _from))) => parse_binding_response(&buf[..len], &transaction_id),
            Ok(Err(e)) => Err(StunError::Io(e)),
            Err(_) => Err(StunError::Timeout),
        }
    }
}

fn build_binding_request(transaction_id: &[u8; 12]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(20);
    pkt.extend_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes()); // message length
    pkt.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    pkt.extend_from_slice(transaction_id);
    pkt
}

fn parse_binding_response(data: &[u8], expected_tid: &[u8; 12]) -> Result<SocketAddr, StunError> {
    if data.len() < 20 {
        return Err(StunError::InvalidResponse);
    }

    let msg_type = u16::from_be_bytes([data[0], data[1]]);
    if msg_type != STUN_BINDING_RESPONSE {
        return Err(StunError::InvalidResponse);
    }

    let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    let cookie = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    if cookie != STUN_MAGIC_COOKIE {
        return Err(StunError::InvalidResponse);
    }

    let tid = &data[8..20];
    if tid != expected_tid {
        return Err(StunError::InvalidResponse);
    }

    let attrs = &data[20..20 + msg_len.min(data.len() - 20)];
    parse_attributes(attrs)
}

fn parse_attributes(mut attrs: &[u8]) -> Result<SocketAddr, StunError> {
    while attrs.len() >= 4 {
        let attr_type = u16::from_be_bytes([attrs[0], attrs[1]]);
        let attr_len = u16::from_be_bytes([attrs[2], attrs[3]]) as usize;

        if attrs.len() < 4 + attr_len {
            break;
        }

        let attr_data = &attrs[4..4 + attr_len];

        if attr_type == STUN_ATTR_XOR_MAPPED_ADDRESS {
            return parse_xor_mapped_address(attr_data);
        }
        if attr_type == STUN_ATTR_MAPPED_ADDRESS {
            return parse_mapped_address(attr_data);
        }

        let padded = (attr_len + 3) & !3;
        attrs = &attrs[4 + padded.min(attrs.len() - 4)..];
    }

    Err(StunError::InvalidResponse)
}

fn parse_xor_mapped_address(data: &[u8]) -> Result<SocketAddr, StunError> {
    if data.len() < 8 {
        return Err(StunError::InvalidResponse);
    }

    let family = data[1];
    let xored_port = u16::from_be_bytes([data[2], data[3]]);
    let port = xored_port ^ (STUN_MAGIC_COOKIE >> 16) as u16;

    match family {
        0x01 => {
            let xored_ip = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
            let ip = xored_ip ^ STUN_MAGIC_COOKIE;
            let addr = std::net::Ipv4Addr::from(ip);
            Ok(SocketAddr::new(addr.into(), port))
        }
        _ => Err(StunError::InvalidResponse),
    }
}

fn parse_mapped_address(data: &[u8]) -> Result<SocketAddr, StunError> {
    if data.len() < 8 {
        return Err(StunError::InvalidResponse);
    }

    let family = data[1];
    let port = u16::from_be_bytes([data[2], data[3]]);

    match family {
        0x01 => {
            let ip = std::net::Ipv4Addr::new(data[4], data[5], data[6], data[7]);
            Ok(SocketAddr::new(ip.into(), port))
        }
        _ => Err(StunError::InvalidResponse),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_and_parse_stun_request() {
        let tid = [1u8; 12];
        let req = build_binding_request(&tid);
        assert_eq!(req.len(), 20);
        assert_eq!(u16::from_be_bytes([req[0], req[1]]), STUN_BINDING_REQUEST);
    }

    #[test]
    fn parse_xor_mapped_ipv4() {
        let port: u16 = 12345;
        let ip = std::net::Ipv4Addr::new(192, 168, 1, 100);

        let xored_port = port ^ (STUN_MAGIC_COOKIE >> 16) as u16;
        let xored_ip = u32::from(ip) ^ STUN_MAGIC_COOKIE;

        let mut data = vec![0u8, 0x01]; // reserved + family
        data.extend_from_slice(&xored_port.to_be_bytes());
        data.extend_from_slice(&xored_ip.to_be_bytes());

        let addr = parse_xor_mapped_address(&data).unwrap();
        assert_eq!(addr, SocketAddr::new(ip.into(), port));
    }
}
