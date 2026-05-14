//! Unified Sensor Fabric
//!
//! Merges all detection capabilities into a single sensor bus:
//! - Network capture (packets, flows, deep inspection)
//! - Surveillance detection (DPI, timing, fingerprinting)
//! - RF sensing (spectrum, jamming, interference)
//! - Hardware telemetry (TPM, SmartNIC, CPU)
//!
//! This eliminates:
//! - Multiple pcap handles
//! - Redundant packet processing
//! - Separate monitoring threads
//! - Inconsistent timing between sensors

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc};

/// Unified sensor reading from any source
#[derive(Debug, Clone)]
pub struct SensorReading {
    /// Sensor that produced this reading
    pub source: SensorSource,

    /// Reading timestamp
    pub timestamp: Instant,

    /// Reading data
    pub data: SensorData,

    /// Confidence level (0.0-1.0)
    pub confidence: f64,

    /// Whether this requires immediate attention
    pub urgent: bool,
}

/// Source of sensor reading
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SensorSource {
    // Network sensors
    NetworkCapture,
    FlowAnalysis,
    DeepInspection,

    // Surveillance detection
    DpiDetector,
    TimingAnalyzer,
    FingerprintDetector,
    TrafficAnalyzer,
    ProbeDetector,

    // RF sensors
    SpectrumAnalyzer,
    JammingDetector,
    SignalStrength,

    // Hardware sensors
    TpmHealth,
    SmartNicStats,
    CpuTelemetry,
    MemoryPressure,

    // Composite (multiple sensors agree)
    Composite,
}

/// Sensor data variants
#[derive(Debug, Clone)]
pub enum SensorData {
    /// Packet capture data
    Packet(PacketData),

    /// Flow statistics
    Flow(FlowData),

    /// DPI detection event
    DpiEvent(DpiEvent),

    /// Timing anomaly
    TimingAnomaly(TimingAnomaly),

    /// Fingerprint detection
    FingerprintEvent(FingerprintEvent),

    /// Traffic pattern analysis
    TrafficPattern(TrafficPattern),

    /// Active probe detection
    ProbeDetection(ProbeDetection),

    /// RF spectrum data
    SpectrumData(SpectrumData),

    /// Jamming detection
    JammingEvent(JammingEvent),

    /// Hardware health
    HardwareHealth(HardwareHealth),

    /// Composite threat assessment
    ThreatAssessment(ThreatAssessment),
}

//
// Network Sensor Data Types
//

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketData {
    pub size: usize,
    pub protocol: u8,
    pub src_addr: Option<IpAddr>,
    pub dst_addr: Option<IpAddr>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub tcp_flags: Option<u8>,
    pub ttl: Option<u8>,
    pub payload_entropy: f64,
    pub is_encrypted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowData {
    pub flow_id: u64,
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub packets: u64,
    pub bytes: u64,
    pub duration: Duration,
    pub avg_packet_size: f64,
    pub packets_per_second: f64,
    pub bytes_per_second: f64,
    pub bidirectional_ratio: f64,
}

//
// Surveillance Detection Data Types
//

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpiEvent {
    pub method: DpiMethod,
    pub target_protocol: Option<String>,
    pub inspection_depth: usize,
    pub signatures_matched: Vec<String>,
    pub source_ip: Option<IpAddr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DpiMethod {
    /// Checking SNI field
    SniInspection,
    /// Checking TLS fingerprint
    TlsFingerprinting,
    /// Protocol signature matching
    ProtocolSignature,
    /// Payload pattern matching
    PayloadInspection,
    /// Statistical analysis
    StatisticalAnalysis,
    /// Machine learning based
    MlClassification,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingAnomaly {
    pub anomaly_type: TimingAnomalyType,
    pub expected_interval_ms: f64,
    pub actual_interval_ms: f64,
    pub deviation_sigma: f64,
    pub affected_connections: Vec<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimingAnomalyType {
    /// Artificially delayed packets
    ArtificialDelay,
    /// Packets arriving too uniformly
    UniformTiming,
    /// Correlation with external events
    ExternalCorrelation,
    /// Burst pattern detection
    BurstPattern,
    /// Watermarking detection
    WatermarkPattern,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintEvent {
    pub fingerprint_type: FingerprintType,
    pub collected_hash: String,
    pub matching_known: Vec<String>,
    pub uniqueness_score: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FingerprintType {
    Ja3,
    Ja3s,
    Jarm,
    Http2Settings,
    QuicTransport,
    TcpStack,
    DnsResolver,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficPattern {
    pub pattern_type: TrafficPatternType,
    pub confidence: f64,
    pub duration_analyzed: Duration,
    pub matching_profiles: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrafficPatternType {
    /// Normal VPN traffic
    VpnTraffic,
    /// Traffic appears to mimic specific protocol
    ProtocolMimicry,
    /// Traffic is being throttled
    Throttling,
    /// Traffic shape suggests video streaming
    VideoStreaming,
    /// Traffic shape suggests voice call
    VoiceCall,
    /// Traffic shape suggests bulk transfer
    BulkTransfer,
    /// Anomalous pattern
    Anomalous,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeDetection {
    pub probe_type: ProbeType,
    pub source_ips: Vec<IpAddr>,
    pub target_ports: Vec<u16>,
    pub probe_count: u64,
    pub time_window: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProbeType {
    /// GFW-style active probing
    ActiveProbe,
    /// Port scanning
    PortScan,
    /// Protocol replay attack
    ProtocolReplay,
    /// Timing correlation probe
    TimingProbe,
    /// Certificate validation probe
    CertProbe,
}

//
// RF Sensor Data Types
//

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpectrumData {
    pub center_freq_hz: u64,
    pub bandwidth_hz: u64,
    pub power_spectrum_dbm: Vec<f64>,
    pub noise_floor_dbm: f64,
    pub peak_power_dbm: f64,
    pub occupied_bandwidth_hz: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JammingEvent {
    pub jamming_type: JammingType,
    pub affected_freq_hz: u64,
    pub affected_bandwidth_hz: u64,
    pub power_increase_db: f64,
    pub duration: Duration,
    pub estimated_direction: Option<f64>, // degrees
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JammingType {
    /// Continuous wave jamming
    ContinuousWave,
    /// Additive white Gaussian noise
    Awgn,
    /// Swept frequency jamming
    Sweeping,
    /// Pulsed jamming
    Pulsed,
    /// Smart/adaptive jamming
    Adaptive,
    /// Protocol-aware jamming
    ProtocolAware,
}

//
// Hardware Sensor Data Types
//

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareHealth {
    pub component: HardwareComponent,
    pub status: HealthStatus,
    pub metrics: HashMap<String, f64>,
    pub alerts: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HardwareComponent {
    Tpm,
    SmartNic,
    Cpu,
    Memory,
    Storage,
    NetworkInterface,
    SdrDevice,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Warning,
    Critical,
    Tampered,
    Unknown,
}

//
// Composite Assessment
//

#[derive(Debug, Clone)]
pub struct ThreatAssessment {
    /// Overall threat level (0.0-1.0)
    pub threat_level: f64,

    /// Active threats detected
    pub active_threats: Vec<ActiveThreat>,

    /// Recommended actions
    pub recommendations: Vec<RecommendedAction>,

    /// Time until assessment expires
    pub valid_for: Duration,
}

#[derive(Debug, Clone)]
pub struct ActiveThreat {
    pub threat_type: ThreatType,
    pub severity: f64,
    pub source: Option<IpAddr>,
    pub first_seen: Instant,
    pub evidence: Vec<SensorSource>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreatType {
    ActiveDpi,
    PassiveSurveillance,
    ProtocolBlocking,
    RfJamming,
    ManInTheMiddle,
    ActiveProbing,
    HardwareTamper,
    NetworkPartition,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RecommendedAction {
    SwitchProtocol(String),
    ActivateRadioBridge,
    EnablePadding,
    RotateCredentials,
    AdjustTiming,
    Blackhole(IpAddr),
    EmergencyShutdown,
}

//
// Unified Sensor Bus
//

/// The unified sensor bus that collects and correlates all sensor data
pub struct SensorBus {
    /// Whether the bus is running
    running: AtomicBool,

    /// Reading counter
    reading_count: AtomicU64,

    /// Recent readings (ring buffer per source)
    readings: RwLock<HashMap<SensorSource, VecDeque<SensorReading>>>,

    /// Maximum readings to keep per source
    max_readings_per_source: usize,

    /// Output channel for readings
    output_tx: broadcast::Sender<SensorReading>,

    /// High-priority channel for urgent readings
    urgent_tx: mpsc::Sender<SensorReading>,

    /// Registered sensor callbacks
    callbacks: RwLock<Vec<Box<dyn Fn(&SensorReading) + Send + Sync>>>,

    /// Threat assessment cache
    threat_cache: RwLock<Option<ThreatAssessment>>,

    /// Assessment expiry time
    assessment_expiry: RwLock<Instant>,
}

impl SensorBus {
    pub fn new() -> (Self, broadcast::Receiver<SensorReading>, mpsc::Receiver<SensorReading>) {
        let (output_tx, output_rx) = broadcast::channel(4096);
        let (urgent_tx, urgent_rx) = mpsc::channel(256);

        let bus = Self {
            running: AtomicBool::new(true),
            reading_count: AtomicU64::new(0),
            readings: RwLock::new(HashMap::new()),
            max_readings_per_source: 1000,
            output_tx,
            urgent_tx,
            callbacks: RwLock::new(Vec::new()),
            threat_cache: RwLock::new(None),
            assessment_expiry: RwLock::new(Instant::now()),
        };

        (bus, output_rx, urgent_rx)
    }

    /// Submit a reading to the bus
    pub async fn submit(&self, reading: SensorReading) {
        if !self.running.load(Ordering::Relaxed) {
            return;
        }

        self.reading_count.fetch_add(1, Ordering::Relaxed);

        // Store in ring buffer
        {
            let mut readings = self.readings.write();
            let buffer = readings
                .entry(reading.source)
                .or_insert_with(|| VecDeque::with_capacity(self.max_readings_per_source));

            if buffer.len() >= self.max_readings_per_source {
                buffer.pop_front();
            }
            buffer.push_back(reading.clone());
        }

        // Send to urgent channel if needed
        if reading.urgent {
            let _ = self.urgent_tx.send(reading.clone()).await;
        }

        // Broadcast to all subscribers
        let _ = self.output_tx.send(reading.clone());

        // Call registered callbacks
        for callback in self.callbacks.read().iter() {
            callback(&reading);
        }

        // Invalidate threat cache on significant readings
        if reading.confidence > 0.7 {
            *self.assessment_expiry.write() = Instant::now();
        }
    }

    /// Get recent readings from a specific source
    pub fn get_recent(&self, source: SensorSource, count: usize) -> Vec<SensorReading> {
        self.readings
            .read()
            .get(&source)
            .map(|buffer| buffer.iter().rev().take(count).cloned().collect())
            .unwrap_or_default()
    }

    /// Get all recent readings across all sources
    pub fn get_all_recent(&self, count_per_source: usize) -> Vec<SensorReading> {
        let readings = self.readings.read();
        let mut all: Vec<_> = readings
            .values()
            .flat_map(|buffer| buffer.iter().rev().take(count_per_source).cloned())
            .collect();

        all.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        all
    }

    /// Compute threat assessment from recent readings
    pub fn assess_threats(&self) -> ThreatAssessment {
        // Check cache
        {
            let expiry = *self.assessment_expiry.read();
            if expiry.elapsed() < Duration::from_secs(5) {
                if let Some(cached) = self.threat_cache.read().clone() {
                    return cached;
                }
            }
        }

        // Compute new assessment
        let readings = self.readings.read();
        let mut threats = Vec::new();
        let mut threat_level: f64 = 0.0;

        // Check DPI readings
        if let Some(dpi_readings) = readings.get(&SensorSource::DpiDetector) {
            for reading in dpi_readings.iter().rev().take(10) {
                if reading.confidence > 0.6 {
                    threat_level = threat_level.max(reading.confidence * 0.8);
                    threats.push(ActiveThreat {
                        threat_type: ThreatType::ActiveDpi,
                        severity: reading.confidence,
                        source: None,
                        first_seen: reading.timestamp,
                        evidence: vec![SensorSource::DpiDetector],
                    });
                }
            }
        }

        // Check jamming readings
        if let Some(jamming_readings) = readings.get(&SensorSource::JammingDetector) {
            for reading in jamming_readings.iter().rev().take(5) {
                if reading.confidence > 0.7 {
                    threat_level = threat_level.max(reading.confidence * 0.9);
                    threats.push(ActiveThreat {
                        threat_type: ThreatType::RfJamming,
                        severity: reading.confidence,
                        source: None,
                        first_seen: reading.timestamp,
                        evidence: vec![SensorSource::JammingDetector],
                    });
                }
            }
        }

        // Generate recommendations
        let mut recommendations = Vec::new();

        if threat_level > 0.8 {
            recommendations.push(RecommendedAction::EmergencyShutdown);
        } else if threat_level > 0.6 {
            recommendations.push(RecommendedAction::ActivateRadioBridge);
            recommendations.push(RecommendedAction::SwitchProtocol("hysteria2".into()));
        } else if threat_level > 0.3 {
            recommendations.push(RecommendedAction::EnablePadding);
            recommendations.push(RecommendedAction::RotateCredentials);
        }

        let assessment = ThreatAssessment {
            threat_level,
            active_threats: threats,
            recommendations,
            valid_for: Duration::from_secs(30),
        };

        // Cache the assessment
        *self.threat_cache.write() = Some(assessment.clone());
        *self.assessment_expiry.write() = Instant::now();

        assessment
    }

    /// Register a callback for new readings
    pub fn on_reading<F>(&self, callback: F)
    where
        F: Fn(&SensorReading) + Send + Sync + 'static,
    {
        self.callbacks.write().push(Box::new(callback));
    }

    /// Subscribe to all readings
    pub fn subscribe(&self) -> broadcast::Receiver<SensorReading> {
        self.output_tx.subscribe()
    }

    /// Get total reading count
    pub fn total_readings(&self) -> u64 {
        self.reading_count.load(Ordering::Relaxed)
    }

    /// Stop the sensor bus
    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

impl Default for SensorBus {
    fn default() -> Self {
        Self::new().0
    }
}

//
// Unified Capture Engine
//

/// Unified packet capture that feeds multiple analysis pipelines
pub struct UnifiedCapture {
    /// Whether capture is active
    active: AtomicBool,

    /// Packets captured
    packets_captured: AtomicU64,

    /// Bytes captured
    bytes_captured: AtomicU64,

    /// Active flows
    flows: RwLock<HashMap<u64, FlowState>>,

    /// Sensor bus reference
    sensor_bus: Arc<SensorBus>,
}

#[derive(Debug, Clone)]
struct FlowState {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub packets: u64,
    pub bytes: u64,
    pub started: Instant,
    pub last_seen: Instant,
}

impl UnifiedCapture {
    pub fn new(sensor_bus: Arc<SensorBus>) -> Self {
        Self {
            active: AtomicBool::new(false),
            packets_captured: AtomicU64::new(0),
            bytes_captured: AtomicU64::new(0),
            flows: RwLock::new(HashMap::new()),
            sensor_bus,
        }
    }

    /// Start unified capture
    pub fn start(&self) {
        self.active.store(true, Ordering::Relaxed);
        tracing::info!("Unified capture started");
    }

    /// Stop capture
    pub fn stop(&self) {
        self.active.store(false, Ordering::Relaxed);
        tracing::info!("Unified capture stopped");
    }

    /// Process a captured packet (called from pcap callback or eBPF)
    pub async fn process_packet(&self, data: &[u8], timestamp: Instant) {
        if !self.active.load(Ordering::Relaxed) {
            return;
        }

        self.packets_captured.fetch_add(1, Ordering::Relaxed);
        self.bytes_captured.fetch_add(data.len() as u64, Ordering::Relaxed);

        // Parse packet (simplified)
        let packet_data = PacketData {
            size: data.len(),
            protocol: data.get(9).copied().unwrap_or(0),
            src_addr: None, // Would parse from IP header
            dst_addr: None,
            src_port: None, // Would parse from TCP/UDP header
            dst_port: None,
            tcp_flags: None,
            ttl: data.get(8).copied(),
            payload_entropy: calculate_entropy(data),
            is_encrypted: calculate_entropy(data) > 7.5,
        };

        // Submit to sensor bus
        let reading = SensorReading {
            source: SensorSource::NetworkCapture,
            timestamp,
            data: SensorData::Packet(packet_data),
            confidence: 1.0,
            urgent: false,
        };

        self.sensor_bus.submit(reading).await;
    }

    /// Get capture statistics
    pub fn stats(&self) -> (u64, u64) {
        (
            self.packets_captured.load(Ordering::Relaxed),
            self.bytes_captured.load(Ordering::Relaxed),
        )
    }
}

/// Calculate Shannon entropy of data
fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0u64; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_sensor_bus() {
        let (bus, mut rx, _urgent_rx) = SensorBus::new();

        // Submit a reading
        let reading = SensorReading {
            source: SensorSource::DpiDetector,
            timestamp: Instant::now(),
            data: SensorData::DpiEvent(DpiEvent {
                method: DpiMethod::SniInspection,
                target_protocol: Some("tls".into()),
                inspection_depth: 100,
                signatures_matched: vec![],
                source_ip: None,
            }),
            confidence: 0.8,
            urgent: false,
        };

        bus.submit(reading.clone()).await;

        // Should receive on broadcast channel
        let received = rx.recv().await.unwrap();
        assert_eq!(received.source, SensorSource::DpiDetector);
    }

    #[test]
    fn test_entropy() {
        // Random data should have high entropy
        let random: Vec<u8> = (0..256).map(|i| i as u8).collect();
        let entropy = calculate_entropy(&random);
        assert!(entropy > 7.0);

        // Repetitive data should have low entropy
        let repetitive = vec![0u8; 256];
        let entropy = calculate_entropy(&repetitive);
        assert!(entropy < 1.0);
    }
}
