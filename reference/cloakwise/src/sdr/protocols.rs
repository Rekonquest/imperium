//! Radio Protocols for SDR Bridge
//!
//! Supported protocols for over-the-air communication:
//! - LoRa: Long range, low power (ISM bands)
//! - AX.25: Amateur radio packet protocol
//! - JS8Call: Weak signal digital mode
//! - FreeDV: Digital voice with data
//! - APRS: Automatic Packet Reporting System
//! - Meshtastic: LoRa mesh networking
//! - Custom: User-defined protocols

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Supported radio protocols
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RadioProtocol {
    /// LoRa spread spectrum (long range, low power)
    LoRa,
    /// AX.25 packet radio (amateur radio)
    Ax25,
    /// JS8Call (weak signal keyboard-to-keyboard)
    JsEight,
    /// FreeDV digital voice with data
    FreeDv,
    /// APRS (position/telemetry reporting)
    Aprs,
    /// Meshtastic LoRa mesh
    Meshtastic,
    /// POCSAG paging protocol
    Pocsag,
    /// DMR digital mobile radio
    Dmr,
    /// Custom/raw protocol
    Custom,
}

impl Default for RadioProtocol {
    fn default() -> Self {
        Self::LoRa
    }
}

impl RadioProtocol {
    /// Get typical data rate in bps
    pub fn typical_bitrate(&self) -> u32 {
        match self {
            RadioProtocol::LoRa => 300,
            RadioProtocol::Ax25 => 1200,
            RadioProtocol::JsEight => 50,
            RadioProtocol::FreeDv => 700,
            RadioProtocol::Aprs => 1200,
            RadioProtocol::Meshtastic => 250,
            RadioProtocol::Pocsag => 1200,
            RadioProtocol::Dmr => 9600,
            RadioProtocol::Custom => 9600,
        }
    }

    /// Get typical range in km (line of sight)
    pub fn typical_range_km(&self) -> f32 {
        match self {
            RadioProtocol::LoRa => 15.0,
            RadioProtocol::Ax25 => 50.0,
            RadioProtocol::JsEight => 1000.0, // HF propagation
            RadioProtocol::FreeDv => 100.0,
            RadioProtocol::Aprs => 50.0,
            RadioProtocol::Meshtastic => 10.0,
            RadioProtocol::Pocsag => 30.0,
            RadioProtocol::Dmr => 20.0,
            RadioProtocol::Custom => 10.0,
        }
    }

    /// Check if protocol requires amateur license
    pub fn requires_license(&self) -> bool {
        match self {
            RadioProtocol::LoRa => false, // ISM band
            RadioProtocol::Ax25 => true,
            RadioProtocol::JsEight => true,
            RadioProtocol::FreeDv => true,
            RadioProtocol::Aprs => true,
            RadioProtocol::Meshtastic => false, // ISM band
            RadioProtocol::Pocsag => false,
            RadioProtocol::Dmr => true,
            RadioProtocol::Custom => true, // Assume yes for safety
        }
    }

    /// Get default frequency in MHz
    pub fn default_frequency(&self) -> f64 {
        match self {
            RadioProtocol::LoRa => 915.0,
            RadioProtocol::Ax25 => 144.390,
            RadioProtocol::JsEight => 7.078,
            RadioProtocol::FreeDv => 14.236,
            RadioProtocol::Aprs => 144.390,
            RadioProtocol::Meshtastic => 915.0,
            RadioProtocol::Pocsag => 466.075,
            RadioProtocol::Dmr => 446.0,
            RadioProtocol::Custom => 433.0,
        }
    }
}

/// Protocol-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolConfig {
    /// Protocol type
    pub protocol: RadioProtocol,
    /// Frequency in MHz
    pub frequency: f64,
    /// Bandwidth in Hz
    pub bandwidth: u32,
    /// Transmit power in dBm
    pub power_dbm: i32,
    /// Protocol-specific parameters
    pub params: ProtocolParams,
}

/// Protocol-specific parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ProtocolParams {
    /// LoRa parameters
    LoRa(LoRaParams),
    /// AX.25 parameters
    Ax25(Ax25Params),
    /// JS8Call parameters
    JsEight(JsEightParams),
    /// FreeDV parameters
    FreeDv(FreeDvParams),
    /// Meshtastic parameters
    Meshtastic(MeshtasticParams),
    /// Generic parameters
    Generic(GenericParams),
}

/// LoRa protocol parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoRaParams {
    /// Spreading factor (7-12)
    pub spreading_factor: u8,
    /// Coding rate (1-4 for 4/5 to 4/8)
    pub coding_rate: u8,
    /// Preamble length
    pub preamble_length: u16,
    /// Enable CRC
    pub crc: bool,
    /// Enable implicit header mode
    pub implicit_header: bool,
    /// Sync word
    pub sync_word: u8,
}

impl Default for LoRaParams {
    fn default() -> Self {
        Self {
            spreading_factor: 9,
            coding_rate: 1, // 4/5
            preamble_length: 8,
            crc: true,
            implicit_header: false,
            sync_word: 0x12,
        }
    }
}

/// AX.25 protocol parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ax25Params {
    /// Source callsign
    pub src_callsign: String,
    /// Source SSID
    pub src_ssid: u8,
    /// Destination callsign
    pub dst_callsign: String,
    /// Destination SSID
    pub dst_ssid: u8,
    /// Digipeater path
    pub digipeaters: Vec<String>,
    /// Frame type (UI, I, etc.)
    pub frame_type: String,
    /// Baud rate
    pub baud_rate: u32,
}

impl Default for Ax25Params {
    fn default() -> Self {
        Self {
            src_callsign: "N0CALL".to_string(),
            src_ssid: 0,
            dst_callsign: "CQ".to_string(),
            dst_ssid: 0,
            digipeaters: vec!["WIDE1-1".to_string(), "WIDE2-1".to_string()],
            frame_type: "UI".to_string(),
            baud_rate: 1200,
        }
    }
}

/// JS8Call protocol parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsEightParams {
    /// Speed mode (normal, fast, turbo, slow)
    pub speed: String,
    /// Grid square
    pub grid: String,
    /// Enable heartbeat
    pub heartbeat: bool,
    /// Heartbeat interval in minutes
    pub heartbeat_interval: u32,
}

impl Default for JsEightParams {
    fn default() -> Self {
        Self {
            speed: "normal".to_string(),
            grid: "AA00aa".to_string(),
            heartbeat: true,
            heartbeat_interval: 15,
        }
    }
}

/// FreeDV protocol parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FreeDvParams {
    /// Mode (700D, 1600, 2400A, 2400B, 800XA)
    pub mode: String,
    /// Enable voice
    pub voice: bool,
    /// Text message
    pub text: Option<String>,
}

impl Default for FreeDvParams {
    fn default() -> Self {
        Self {
            mode: "700D".to_string(),
            voice: false,
            text: None,
        }
    }
}

/// Meshtastic protocol parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshtasticParams {
    /// Region (US, EU, etc.)
    pub region: String,
    /// Channel index
    pub channel: u8,
    /// Channel name
    pub channel_name: String,
    /// Pre-shared key
    pub psk: Option<String>,
    /// Enable GPS
    pub gps: bool,
}

impl Default for MeshtasticParams {
    fn default() -> Self {
        Self {
            region: "US".to_string(),
            channel: 0,
            channel_name: "Default".to_string(),
            psk: None,
            gps: false,
        }
    }
}

/// Generic protocol parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenericParams {
    /// Modulation type
    pub modulation: String,
    /// Symbol rate
    pub symbol_rate: u32,
    /// Packet format
    pub packet_format: String,
    /// Custom parameters
    pub custom: std::collections::HashMap<String, serde_json::Value>,
}

impl Default for GenericParams {
    fn default() -> Self {
        Self {
            modulation: "GFSK".to_string(),
            symbol_rate: 9600,
            packet_format: "raw".to_string(),
            custom: std::collections::HashMap::new(),
        }
    }
}

impl Default for ProtocolConfig {
    fn default() -> Self {
        Self {
            protocol: RadioProtocol::LoRa,
            frequency: 915.0,
            bandwidth: 125000,
            power_dbm: 20,
            params: ProtocolParams::LoRa(LoRaParams::default()),
        }
    }
}

/// Message for radio transmission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RadioMessage {
    /// Message ID
    pub id: String,
    /// Source identifier
    pub source: String,
    /// Destination identifier
    pub destination: String,
    /// Message type
    pub msg_type: MessageType,
    /// Payload
    pub payload: Vec<u8>,
    /// Timestamp
    pub timestamp: u64,
    /// TTL (hops remaining)
    pub ttl: u8,
    /// Sequence number
    pub sequence: u32,
    /// Flags
    pub flags: u8,
}

/// Message types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageType {
    /// Discovery beacon
    Beacon,
    /// Data packet
    Data,
    /// Acknowledgement
    Ack,
    /// Negative acknowledgement
    Nack,
    /// Route request
    RouteRequest,
    /// Route reply
    RouteReply,
    /// Keepalive
    Keepalive,
    /// Emergency
    Emergency,
}

impl RadioMessage {
    /// Create a new data message
    pub fn data(source: &str, destination: &str, payload: Vec<u8>) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};

        Self {
            id: uuid::Uuid::new_v4().to_string(),
            source: source.to_string(),
            destination: destination.to_string(),
            msg_type: MessageType::Data,
            payload,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            ttl: 5,
            sequence: 0,
            flags: 0,
        }
    }

    /// Create a beacon message
    pub fn beacon(source: &str, capabilities: &[String]) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};

        let payload = serde_json::to_vec(capabilities).unwrap_or_default();

        Self {
            id: uuid::Uuid::new_v4().to_string(),
            source: source.to_string(),
            destination: "BROADCAST".to_string(),
            msg_type: MessageType::Beacon,
            payload,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            ttl: 1,
            sequence: 0,
            flags: 0,
        }
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        // Simple serialization format
        // In a real implementation, use a compact binary format
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        serde_json::from_slice(data).ok()
    }
}
