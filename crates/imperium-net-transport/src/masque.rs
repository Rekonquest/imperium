use chrono::Utc;
use imperium_bus::Bus;
use imperium_protocol::{MasqueTunnelConfig, MasqueTunnelState, MasqueTunnelStatus, Message};
use std::sync::Arc;
use thiserror::Error;

pub const MIN_QUIC_DATAGRAM_MTU: u16 = 1_200;

#[derive(Debug, Error)]
pub enum MasqueError {
    #[error("inner MTU must be between 1200 and 1300 bytes")]
    InvalidMtu,
    #[error("MASQUE proxy authority cannot be empty")]
    EmptyProxyAuthority,
    #[error("MASQUE target authority cannot be empty")]
    EmptyTargetAuthority,
    #[error("bus error: {0}")]
    Bus(#[from] imperium_bus::BusError),
}

pub struct MasqueController {
    bus: Arc<Bus>,
}

impl MasqueController {
    pub fn new(bus: Arc<Bus>) -> Self {
        Self { bus }
    }

    pub fn validate_config(config: &MasqueTunnelConfig) -> Result<(), MasqueError> {
        if config.proxy_authority.trim().is_empty() {
            return Err(MasqueError::EmptyProxyAuthority);
        }
        if config.target_authority.trim().is_empty() {
            return Err(MasqueError::EmptyTargetAuthority);
        }
        if !(MIN_QUIC_DATAGRAM_MTU..=1_300).contains(&config.inner_mtu) {
            return Err(MasqueError::InvalidMtu);
        }
        Ok(())
    }

    pub fn configure(&self, config: MasqueTunnelConfig) -> Result<MasqueTunnelStatus, MasqueError> {
        let status = match Self::validate_config(&config) {
            Ok(()) => MasqueTunnelStatus {
                tunnel_id: config.tunnel_id,
                state: MasqueTunnelState::Configured,
                reason: None,
                timestamp: Utc::now(),
            },
            Err(err) => MasqueTunnelStatus {
                tunnel_id: config.tunnel_id,
                state: MasqueTunnelState::Failed,
                reason: Some(err.to_string()),
                timestamp: Utc::now(),
            },
        };

        self.bus.publish(
            "net.transport.masque.status",
            Message::MasqueTunnelStatus(status.clone()),
        )?;

        Ok(status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use imperium_protocol::MasqueTunnelKind;

    fn config(inner_mtu: u16) -> MasqueTunnelConfig {
        MasqueTunnelConfig {
            tunnel_id: "masque-1".into(),
            proxy_authority: "proxy.example:443".into(),
            target_authority: "target.example:443".into(),
            kind: MasqueTunnelKind::ConnectUdp,
            inner_mtu,
            use_quic_datagrams: true,
        }
    }

    #[test]
    fn accepts_conservative_mtu() {
        MasqueController::validate_config(&config(1_280)).unwrap();
    }

    #[test]
    fn rejects_too_small_mtu() {
        assert!(matches!(
            MasqueController::validate_config(&config(1_100)),
            Err(MasqueError::InvalidMtu)
        ));
    }
}
