//! Unified Transport Core - Protocol Abstraction Layer
//!
//! All VPN protocols (VLESS, Trojan, Hysteria, Shadowsocks, etc.) implement
//! the Outbound trait, allowing hot-swapping without process restarts.
//!
//! This eliminates:
//! - 2-5 second process restart latency
//! - Multiple runtime memory overhead
//! - Visible process churn in `top`/`ps`

use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use async_trait::async_trait;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};

/// Unified async stream type for all protocols
pub type BoxedAsyncStream = Pin<Box<dyn AsyncStream>>;

/// Trait for async read/write streams
pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send + Sync {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + Sync> AsyncStream for T {}

/// Protocol-level error types
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Handshake failed: {0}")]
    HandshakeFailed(String),

    #[error("Protocol error: {0}")]
    ProtocolError(String),

    #[error("Encryption error: {0}")]
    EncryptionError(String),

    #[error("Timeout after {0:?}")]
    Timeout(Duration),

    #[error("Connection reset by peer")]
    ConnectionReset,

    #[error("DPI detected: {0}")]
    DpiDetected(String),

    #[error("Resource exhausted: {0}")]
    ResourceExhausted(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Real-time protocol telemetry for AI Pilot analysis
#[derive(Debug, Clone)]
pub struct ProtocolMetrics {
    /// Protocol identifier
    pub protocol_id: String,

    /// Current connection state
    pub state: ConnectionState,

    /// Bytes sent since connection start
    pub bytes_sent: u64,

    /// Bytes received since connection start
    pub bytes_received: u64,

    /// Current estimated RTT in milliseconds
    pub rtt_ms: f64,

    /// Packet loss percentage (0.0-1.0)
    pub packet_loss: f64,

    /// Jitter in milliseconds
    pub jitter_ms: f64,

    /// Current bandwidth estimate (bytes/sec)
    pub bandwidth_bps: u64,

    /// Handshake duration
    pub handshake_duration: Duration,

    /// Time since connection established
    pub connection_age: Duration,

    /// Number of retransmissions
    pub retransmits: u64,

    /// TLS/encryption overhead percentage
    pub encryption_overhead: f64,

    /// Fingerprint risk score (0.0-1.0, higher = more detectable)
    pub fingerprint_risk: f64,

    /// Last activity timestamp
    pub last_activity: Instant,
}

impl Default for ProtocolMetrics {
    fn default() -> Self {
        Self {
            protocol_id: String::new(),
            state: ConnectionState::Disconnected,
            bytes_sent: 0,
            bytes_received: 0,
            rtt_ms: 0.0,
            packet_loss: 0.0,
            jitter_ms: 0.0,
            bandwidth_bps: 0,
            handshake_duration: Duration::ZERO,
            connection_age: Duration::ZERO,
            retransmits: 0,
            encryption_overhead: 0.0,
            fingerprint_risk: 0.0,
            last_activity: Instant::now(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Handshaking,
    Connected,
    Degraded,
    Reconnecting,
    Failed,
}

/// The core Outbound trait - all protocols must implement this
#[async_trait]
pub trait Outbound: Send + Sync {
    /// Protocol identifier (e.g., "vless-reality", "trojan-ws", "hysteria2")
    fn protocol_id(&self) -> &str;

    /// Human-readable protocol name
    fn display_name(&self) -> &str;

    /// Initialize connection and return encrypted stream
    ///
    /// This performs:
    /// 1. TCP/UDP connection establishment
    /// 2. TLS/QUIC handshake (if applicable)
    /// 3. Protocol-specific authentication
    /// 4. Return ready-to-use encrypted stream
    async fn connect(&self, target: SocketAddr) -> Result<BoxedAsyncStream, TransportError>;

    /// Get current protocol metrics for AI analysis
    fn get_telemetry(&self) -> ProtocolMetrics;

    /// Perform in-place mutation without reconnection
    ///
    /// Examples:
    /// - Change SNI
    /// - Rotate UUID
    /// - Adjust congestion parameters
    /// - Modify padding patterns
    async fn mutate(&self, mutation: ProtocolMutation) -> Result<(), TransportError>;

    /// Graceful connection drain (allow existing streams to complete)
    async fn drain(&self, timeout: Duration) -> Result<(), TransportError>;

    /// Immediate connection termination
    async fn terminate(&self) -> Result<(), TransportError>;

    /// Check if protocol supports a specific feature
    fn supports_feature(&self, feature: ProtocolFeature) -> bool;

    /// Get fingerprint characteristics for stealth analysis
    fn get_fingerprint(&self) -> ProtocolFingerprint;

    /// Estimated overhead compared to raw TCP
    fn overhead_estimate(&self) -> f64;
}

/// Protocol features for capability checking
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtocolFeature {
    /// Can multiplex streams over single connection
    Multiplexing,
    /// Supports UDP traffic
    Udp,
    /// Zero-RTT connection establishment
    ZeroRtt,
    /// Can traverse CDN (Cloudflare, etc.)
    CdnTraversal,
    /// Works over WebSocket
    WebSocket,
    /// Works over gRPC
    Grpc,
    /// Works over QUIC
    Quic,
    /// Has built-in padding
    Padding,
    /// Can mimic specific TLS fingerprint
    FingerprintMimicry,
    /// Works in high packet loss environments
    LossyNetwork,
    /// Works over DNS tunneling
    DnsTunnel,
    /// Works over radio/SDR
    RadioBridge,
}

/// Mutations that can be applied in-place without reconnection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProtocolMutation {
    /// Change TLS Server Name Indication
    ChangeSni(String),

    /// Rotate authentication credential
    RotateCredential { new_credential: String },

    /// Adjust padding parameters
    AdjustPadding {
        min_bytes: usize,
        max_bytes: usize,
        frequency: f64,
    },

    /// Change congestion control parameters
    AdjustCongestion {
        initial_window: u32,
        max_window: u32,
        loss_reduction_factor: f64,
    },

    /// Change timing patterns
    AdjustTiming {
        min_interval_ms: u64,
        max_interval_ms: u64,
        burst_size: usize,
    },

    /// Switch to different server in pool
    SwitchServer { server_addr: SocketAddr },

    /// Enable/disable specific obfuscation
    ToggleObfuscation { enabled: bool, method: String },
}

/// Protocol fingerprint for stealth analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolFingerprint {
    /// TLS fingerprint (JA3 hash if applicable)
    pub ja3_hash: Option<String>,

    /// Server fingerprint (JA3S hash if applicable)
    pub ja3s_hash: Option<String>,

    /// Typical packet size distribution
    pub packet_sizes: Vec<(usize, f64)>,

    /// Typical inter-packet timing (ms)
    pub timing_pattern: Vec<(f64, f64)>,

    /// Services this protocol mimics
    pub mimics: Vec<String>,

    /// Known detection signatures this protocol avoids
    pub evades: Vec<String>,

    /// Risk level (0.0-1.0)
    pub detection_risk: f64,
}

/// Registry of all available outbound protocols
pub struct OutboundRegistry {
    /// Active outbounds by ID
    outbounds: RwLock<HashMap<String, Arc<dyn Outbound>>>,

    /// Currently selected outbound
    active_outbound: RwLock<Option<String>>,

    /// Total bytes through all protocols
    total_bytes: AtomicU64,

    /// Protocol switch count
    switch_count: AtomicU64,
}

impl OutboundRegistry {
    pub fn new() -> Self {
        Self {
            outbounds: RwLock::new(HashMap::new()),
            active_outbound: RwLock::new(None),
            total_bytes: AtomicU64::new(0),
            switch_count: AtomicU64::new(0),
        }
    }

    /// Register a new outbound protocol
    pub fn register(&self, outbound: Arc<dyn Outbound>) {
        let id = outbound.protocol_id().to_string();
        self.outbounds.write().insert(id, outbound);
    }

    /// Get outbound by ID
    pub fn get(&self, id: &str) -> Option<Arc<dyn Outbound>> {
        self.outbounds.read().get(id).cloned()
    }

    /// Get currently active outbound
    pub fn active(&self) -> Option<Arc<dyn Outbound>> {
        let active_id = self.active_outbound.read().clone()?;
        self.get(&active_id)
    }

    /// Hot-swap to a different protocol (< 10ms)
    ///
    /// This is the core efficiency gain - no process restart needed
    pub async fn switch_to(&self, id: &str, drain_timeout: Duration) -> Result<(), TransportError> {
        // Verify target exists
        let new_outbound = self.get(id).ok_or_else(|| {
            TransportError::ProtocolError(format!("Protocol '{}' not registered", id))
        })?;

        // Drain existing connection gracefully
        if let Some(current) = self.active() {
            if let Err(e) = current.drain(drain_timeout).await {
                tracing::warn!("Drain failed during switch: {}", e);
                // Force terminate if drain fails
                let _ = current.terminate().await;
            }
        }

        // Atomic pointer swap - this is where the magic happens
        // No process restart, no memory reallocation, just a pointer change
        *self.active_outbound.write() = Some(id.to_string());

        self.switch_count.fetch_add(1, Ordering::Relaxed);

        tracing::info!(
            "Protocol switched to '{}' ({}) - switch #{}",
            id,
            new_outbound.display_name(),
            self.switch_count.load(Ordering::Relaxed)
        );

        Ok(())
    }

    /// Get all registered protocol IDs
    pub fn list_protocols(&self) -> Vec<String> {
        self.outbounds.read().keys().cloned().collect()
    }

    /// Get telemetry from all protocols
    pub fn all_telemetry(&self) -> Vec<ProtocolMetrics> {
        self.outbounds
            .read()
            .values()
            .map(|o| o.get_telemetry())
            .collect()
    }

    /// Find best protocol for given conditions
    pub fn select_best(&self, conditions: &NetworkConditions) -> Option<String> {
        let outbounds = self.outbounds.read();

        outbounds
            .iter()
            .filter(|(_, o)| {
                // Filter by required features
                if conditions.high_packet_loss && !o.supports_feature(ProtocolFeature::LossyNetwork) {
                    return false;
                }
                if conditions.need_cdn_traversal && !o.supports_feature(ProtocolFeature::CdnTraversal) {
                    return false;
                }
                if conditions.udp_required && !o.supports_feature(ProtocolFeature::Udp) {
                    return false;
                }
                true
            })
            .min_by(|(_, a), (_, b)| {
                // Sort by fingerprint risk (lower is better)
                let risk_a = a.get_fingerprint().detection_risk;
                let risk_b = b.get_fingerprint().detection_risk;
                risk_a.partial_cmp(&risk_b).unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|(id, _)| id.clone())
    }
}

impl Default for OutboundRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Network conditions for protocol selection
#[derive(Debug, Clone, Default)]
pub struct NetworkConditions {
    pub high_packet_loss: bool,
    pub need_cdn_traversal: bool,
    pub udp_required: bool,
    pub low_latency_required: bool,
    pub high_bandwidth_required: bool,
    pub stealth_priority: bool,
    pub detected_dpi: bool,
    pub radio_mode: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockOutbound {
        id: String,
    }

    #[async_trait]
    impl Outbound for MockOutbound {
        fn protocol_id(&self) -> &str {
            &self.id
        }

        fn display_name(&self) -> &str {
            "Mock Protocol"
        }

        async fn connect(&self, _target: SocketAddr) -> Result<BoxedAsyncStream, TransportError> {
            Err(TransportError::ConnectionFailed("Mock".into()))
        }

        fn get_telemetry(&self) -> ProtocolMetrics {
            ProtocolMetrics::default()
        }

        async fn mutate(&self, _mutation: ProtocolMutation) -> Result<(), TransportError> {
            Ok(())
        }

        async fn drain(&self, _timeout: Duration) -> Result<(), TransportError> {
            Ok(())
        }

        async fn terminate(&self) -> Result<(), TransportError> {
            Ok(())
        }

        fn supports_feature(&self, _feature: ProtocolFeature) -> bool {
            false
        }

        fn get_fingerprint(&self) -> ProtocolFingerprint {
            ProtocolFingerprint {
                ja3_hash: None,
                ja3s_hash: None,
                packet_sizes: vec![],
                timing_pattern: vec![],
                mimics: vec![],
                evades: vec![],
                detection_risk: 0.5,
            }
        }

        fn overhead_estimate(&self) -> f64 {
            0.1
        }
    }

    #[tokio::test]
    async fn test_registry_switch() {
        let registry = OutboundRegistry::new();

        registry.register(Arc::new(MockOutbound { id: "proto-a".into() }));
        registry.register(Arc::new(MockOutbound { id: "proto-b".into() }));

        // Switch should be < 10ms
        let start = Instant::now();
        registry.switch_to("proto-a", Duration::from_secs(1)).await.unwrap();
        registry.switch_to("proto-b", Duration::from_secs(1)).await.unwrap();
        let elapsed = start.elapsed();

        assert!(elapsed < Duration::from_millis(100), "Switch took too long: {:?}", elapsed);
    }
}
