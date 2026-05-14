//! Telemetry event definitions
//!
//! Events represent signals from the VPN infrastructure that specialists analyze.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Unique identifier for telemetry events
pub type EventId = uuid::Uuid;

/// Timestamp in milliseconds since Unix epoch
pub type Timestamp = u64;

/// All telemetry event types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TelemetryEvent {
    /// Client connection attempt
    Connection(ConnectionEvent),
    /// Packet pattern observation
    PacketPattern(PacketPatternEvent),
    /// Suspected probe attempt
    ProbeAttempt(ProbeAttemptEvent),
    /// Health check result
    HealthCheck(HealthCheckEvent),
    /// Bandwidth usage sample
    Bandwidth(BandwidthEvent),
    /// Protocol-specific event
    ProtocolEvent(ProtocolSpecificEvent),
    /// Error from VPN infrastructure
    InfraError(InfraErrorEvent),
}

impl TelemetryEvent {
    /// Get the timestamp of this event
    pub fn timestamp(&self) -> Timestamp {
        match self {
            TelemetryEvent::Connection(e) => e.timestamp,
            TelemetryEvent::PacketPattern(e) => e.timestamp,
            TelemetryEvent::ProbeAttempt(e) => e.timestamp,
            TelemetryEvent::HealthCheck(e) => e.timestamp,
            TelemetryEvent::Bandwidth(e) => e.timestamp,
            TelemetryEvent::ProtocolEvent(e) => e.timestamp,
            TelemetryEvent::InfraError(e) => e.timestamp,
        }
    }

    /// Get the event ID
    pub fn id(&self) -> EventId {
        match self {
            TelemetryEvent::Connection(e) => e.id,
            TelemetryEvent::PacketPattern(e) => e.id,
            TelemetryEvent::ProbeAttempt(e) => e.id,
            TelemetryEvent::HealthCheck(e) => e.id,
            TelemetryEvent::Bandwidth(e) => e.id,
            TelemetryEvent::ProtocolEvent(e) => e.id,
            TelemetryEvent::InfraError(e) => e.id,
        }
    }
}

/// Client connection event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionEvent {
    pub id: EventId,
    pub timestamp: Timestamp,
    pub client_id: String,
    pub source_ip: Option<IpAddr>,
    pub success: bool,
    pub latency_ms: Option<u32>,
    pub handshake_duration_ms: Option<u32>,
    pub failure_reason: Option<ConnectionFailure>,
    pub protocol: String,
}

/// Reasons for connection failure
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionFailure {
    Timeout,
    Rejected,
    AuthFailure,
    ProtocolError,
    RateLimited,
    Blocked,
    Unknown(String),
}

/// Packet pattern observation for traffic analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketPatternEvent {
    pub id: EventId,
    pub timestamp: Timestamp,
    pub client_id: Option<String>,
    pub direction: Direction,
    /// Packet sizes in bytes
    pub sizes: Vec<u16>,
    /// Intervals between packets in milliseconds
    pub intervals_ms: Vec<u16>,
    /// Total bytes in this sample
    pub total_bytes: u64,
    /// Sample duration in milliseconds
    pub duration_ms: u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Inbound,
    Outbound,
    Both,
}

/// Suspected probe attempt from DPI/censorship system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeAttemptEvent {
    pub id: EventId,
    pub timestamp: Timestamp,
    pub source_ip: IpAddr,
    pub destination_port: u16,
    pub signature: ProbeSignature,
    pub raw_data: Option<Vec<u8>>,
    pub confidence: f32,
}

/// Known probe signatures
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeSignature {
    /// TSPU-style active probe
    TspuActive,
    /// Generic TLS fingerprinting probe
    TlsFingerprint,
    /// WireGuard protocol probe
    WireguardProbe,
    /// Port scan
    PortScan,
    /// Connection reset injection
    ResetInjection,
    /// Replay attack attempt
    ReplayAttack,
    /// Unknown probe pattern
    Unknown { pattern_hash: String },
}

/// Health check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckEvent {
    pub id: EventId,
    pub timestamp: Timestamp,
    pub endpoint: String,
    pub reachable: bool,
    pub latency_ms: Option<u32>,
    pub status_code: Option<u16>,
    pub check_type: HealthCheckType,
    pub from_region: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthCheckType {
    Http,
    Https,
    Tcp,
    Dns,
    Icmp,
}

/// Bandwidth usage sample
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BandwidthEvent {
    pub id: EventId,
    pub timestamp: Timestamp,
    pub interface: String,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub packets_in: u64,
    pub packets_out: u64,
    pub sample_duration_ms: u32,
}

/// Protocol-specific event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolSpecificEvent {
    pub id: EventId,
    pub timestamp: Timestamp,
    pub protocol: String,
    pub event_type: String,
    pub details: serde_json::Value,
}

/// Infrastructure error event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfraErrorEvent {
    pub id: EventId,
    pub timestamp: Timestamp,
    pub component: String,
    pub error_type: InfraErrorType,
    pub message: String,
    pub recoverable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InfraErrorType {
    ProcessCrash,
    ConfigError,
    ResourceExhausted,
    NetworkError,
    PermissionDenied,
    Unknown,
}

/// Builder for creating connection events
impl ConnectionEvent {
    pub fn new(client_id: impl Into<String>, success: bool) -> Self {
        Self {
            id: uuid::Uuid::new_v4(),
            timestamp: current_timestamp(),
            client_id: client_id.into(),
            source_ip: None,
            success,
            latency_ms: None,
            handshake_duration_ms: None,
            failure_reason: None,
            protocol: String::new(),
        }
    }

    pub fn with_latency(mut self, latency_ms: u32) -> Self {
        self.latency_ms = Some(latency_ms);
        self
    }

    pub fn with_source_ip(mut self, ip: IpAddr) -> Self {
        self.source_ip = Some(ip);
        self
    }

    pub fn with_failure_reason(mut self, reason: ConnectionFailure) -> Self {
        self.failure_reason = Some(reason);
        self
    }

    pub fn with_protocol(mut self, protocol: impl Into<String>) -> Self {
        self.protocol = protocol.into();
        self
    }
}

impl HealthCheckEvent {
    pub fn new(endpoint: impl Into<String>, reachable: bool) -> Self {
        Self {
            id: uuid::Uuid::new_v4(),
            timestamp: current_timestamp(),
            endpoint: endpoint.into(),
            reachable,
            latency_ms: None,
            status_code: None,
            check_type: HealthCheckType::Https,
            from_region: None,
        }
    }

    pub fn with_latency(mut self, latency_ms: u32) -> Self {
        self.latency_ms = Some(latency_ms);
        self
    }

    pub fn with_status_code(mut self, code: u16) -> Self {
        self.status_code = Some(code);
        self
    }
}

impl ProbeAttemptEvent {
    pub fn new(source_ip: IpAddr, destination_port: u16, signature: ProbeSignature) -> Self {
        Self {
            id: uuid::Uuid::new_v4(),
            timestamp: current_timestamp(),
            source_ip,
            destination_port,
            signature,
            raw_data: None,
            confidence: 0.5,
        }
    }

    pub fn with_confidence(mut self, confidence: f32) -> Self {
        self.confidence = confidence.clamp(0.0, 1.0);
        self
    }

    pub fn with_raw_data(mut self, data: Vec<u8>) -> Self {
        self.raw_data = Some(data);
        self
    }
}

/// Get current timestamp in milliseconds
pub fn current_timestamp() -> Timestamp {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as Timestamp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_event_builder() {
        let event = ConnectionEvent::new("client-123", true)
            .with_latency(50)
            .with_protocol("wireguard");

        assert_eq!(event.client_id, "client-123");
        assert!(event.success);
        assert_eq!(event.latency_ms, Some(50));
        assert_eq!(event.protocol, "wireguard");
    }

    #[test]
    fn test_event_serialization() {
        let event = TelemetryEvent::Connection(ConnectionEvent::new("test", true));
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("connection"));
    }
}
