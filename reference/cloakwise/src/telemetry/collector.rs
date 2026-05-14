//! Telemetry collector implementation
//!
//! Collects telemetry data from VPN logs and optionally packet capture.

use super::events::*;
use crate::config::{CaptureMethod, TelemetryConfig};
use anyhow::Result;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Channel for sending telemetry events
pub type TelemetrySender = mpsc::Sender<TelemetryEvent>;
pub type TelemetryReceiver = mpsc::Receiver<TelemetryEvent>;

/// Create a new telemetry channel
pub fn channel(buffer_size: usize) -> (TelemetrySender, TelemetryReceiver) {
    mpsc::channel(buffer_size)
}

/// Telemetry collector that gathers events from various sources
pub struct TelemetryCollector {
    config: TelemetryConfig,
    sender: TelemetrySender,
    shutdown: tokio::sync::watch::Receiver<bool>,
}

impl TelemetryCollector {
    pub fn new(
        config: TelemetryConfig,
        sender: TelemetrySender,
        shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Self {
        Self {
            config,
            sender,
            shutdown,
        }
    }

    /// Start collecting telemetry
    pub async fn run(self) -> Result<()> {
        info!(
            "Starting telemetry collector with method: {:?}",
            self.config.capture_method
        );

        match self.config.capture_method {
            CaptureMethod::VpnLogs => self.collect_from_logs().await,
            CaptureMethod::PacketCapture => self.collect_from_packets().await,
            CaptureMethod::Both => {
                // Run both collectors concurrently
                let log_config = self.config.clone();
                let packet_config = self.config.clone();
                let log_sender = self.sender.clone();
                let packet_sender = self.sender.clone();
                let log_shutdown = self.shutdown.clone();
                let packet_shutdown = self.shutdown;

                let log_collector = TelemetryCollector::new(
                    TelemetryConfig {
                        capture_method: CaptureMethod::VpnLogs,
                        ..log_config
                    },
                    log_sender,
                    log_shutdown,
                );

                let packet_collector = TelemetryCollector::new(
                    TelemetryConfig {
                        capture_method: CaptureMethod::PacketCapture,
                        ..packet_config
                    },
                    packet_sender,
                    packet_shutdown,
                );

                tokio::select! {
                    r = log_collector.collect_from_logs() => r,
                    r = packet_collector.collect_from_packets() => r,
                }
            }
        }
    }

    /// Collect telemetry from VPN log files
    async fn collect_from_logs(mut self) -> Result<()> {
        info!("Starting log-based telemetry collection from {:?}", self.config.log_path);

        // Check if log directory exists
        if !self.config.log_path.exists() {
            warn!(
                "Log path {:?} does not exist, creating directory",
                self.config.log_path
            );
            tokio::fs::create_dir_all(&self.config.log_path).await?;
        }

        let log_path = self.config.log_path.clone();
        let sample_rate = self.config.sample_rate;

        // Use a simple polling approach for log files
        // In production, you'd use inotify/kqueue via notify crate
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(1));
        let mut last_position: u64 = 0;

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if let Err(e) = self.process_log_files(&log_path, &mut last_position, sample_rate).await {
                        error!("Error processing log files: {}", e);
                    }
                }
                _ = self.shutdown.changed() => {
                    if *self.shutdown.borrow() {
                        info!("Telemetry collector received shutdown signal");
                        break;
                    }
                }
            }
        }

        Ok(())
    }

    /// Process log files and extract events
    async fn process_log_files(
        &self,
        log_path: &Path,
        last_position: &mut u64,
        sample_rate: f64,
    ) -> Result<()> {
        // Look for common VPN log files
        let log_patterns = ["wg*.log", "wireguard.log", "cloak.log", "shadowsocks.log"];

        for pattern in &log_patterns {
            let full_pattern = log_path.join(pattern);
            if let Some(pattern_str) = full_pattern.to_str() {
                // Simple glob implementation for log files
                if let Ok(entries) = glob_log_files(pattern_str).await {
                    for entry in entries {
                        if let Ok(content) = tokio::fs::read_to_string(&entry).await {
                            let events = parse_vpn_log(&content, sample_rate);
                            for event in events {
                                if self.sender.send(event).await.is_err() {
                                    warn!("Telemetry channel closed");
                                    return Ok(());
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Collect telemetry from packet capture (stub - would require pcap/pnet)
    async fn collect_from_packets(mut self) -> Result<()> {
        info!("Starting packet capture telemetry collection");

        // This is a stub - real implementation would use pnet or libpcap
        // For now, just wait for shutdown
        loop {
            tokio::select! {
                _ = self.shutdown.changed() => {
                    if *self.shutdown.borrow() {
                        info!("Packet capture collector received shutdown signal");
                        break;
                    }
                }
                _ = tokio::time::sleep(tokio::time::Duration::from_secs(1)) => {
                    // Packet capture would happen here
                    debug!("Packet capture tick (stub)");
                }
            }
        }

        Ok(())
    }
}

/// Simple glob for log files
async fn glob_log_files(pattern: &str) -> Result<Vec<std::path::PathBuf>> {
    // Simple implementation - just check if the exact file exists
    // In production, use the glob crate
    let path = std::path::PathBuf::from(pattern.replace("*", ""));
    if path.exists() {
        Ok(vec![path])
    } else {
        Ok(vec![])
    }
}

/// Parse VPN log content into telemetry events
fn parse_vpn_log(content: &str, sample_rate: f64) -> Vec<TelemetryEvent> {
    let mut events = Vec::new();
    let mut rng = rand::thread_rng();

    for line in content.lines() {
        // Apply sampling
        if sample_rate < 1.0 && rand::Rng::gen::<f64>(&mut rng) > sample_rate {
            continue;
        }

        // Try to parse different log formats
        if let Some(event) = parse_wireguard_log_line(line) {
            events.push(event);
        } else if let Some(event) = parse_cloak_log_line(line) {
            events.push(event);
        } else if let Some(event) = parse_shadowsocks_log_line(line) {
            events.push(event);
        }
    }

    events
}

/// Parse WireGuard log line
fn parse_wireguard_log_line(line: &str) -> Option<TelemetryEvent> {
    // WireGuard log patterns:
    // "peer XYZ... - Handshake completed"
    // "peer XYZ... - Sending keepalive packet"
    // "peer XYZ... - Receiving handshake initiation"

    if line.contains("Handshake") {
        let client_id = extract_peer_id(line).unwrap_or_else(|| "unknown".to_string());
        let success = line.contains("completed");

        let mut event = ConnectionEvent::new(client_id, success).with_protocol("wireguard");

        if !success {
            event = event.with_failure_reason(ConnectionFailure::Timeout);
        }

        return Some(TelemetryEvent::Connection(event));
    }

    if line.contains("error") || line.contains("Error") {
        return Some(TelemetryEvent::InfraError(InfraErrorEvent {
            id: uuid::Uuid::new_v4(),
            timestamp: current_timestamp(),
            component: "wireguard".to_string(),
            error_type: InfraErrorType::Unknown,
            message: line.to_string(),
            recoverable: true,
        }));
    }

    None
}

/// Parse Cloak log line
fn parse_cloak_log_line(line: &str) -> Option<TelemetryEvent> {
    // Cloak log patterns vary by version
    if line.contains("new session") || line.contains("Session") {
        let client_id = extract_session_id(line).unwrap_or_else(|| "unknown".to_string());
        return Some(TelemetryEvent::Connection(
            ConnectionEvent::new(client_id, true).with_protocol("cloak"),
        ));
    }

    if line.contains("closed") || line.contains("terminated") {
        let client_id = extract_session_id(line).unwrap_or_else(|| "unknown".to_string());
        return Some(TelemetryEvent::Connection(
            ConnectionEvent::new(client_id, false)
                .with_protocol("cloak")
                .with_failure_reason(ConnectionFailure::Unknown("session closed".to_string())),
        ));
    }

    None
}

/// Parse Shadowsocks log line
fn parse_shadowsocks_log_line(line: &str) -> Option<TelemetryEvent> {
    // Shadowsocks-rust log patterns
    if line.contains("accepted") || line.contains("connected") {
        return Some(TelemetryEvent::Connection(
            ConnectionEvent::new("ss-client", true).with_protocol("shadowsocks"),
        ));
    }

    if line.contains("error") || line.contains("failed") {
        return Some(TelemetryEvent::InfraError(InfraErrorEvent {
            id: uuid::Uuid::new_v4(),
            timestamp: current_timestamp(),
            component: "shadowsocks".to_string(),
            error_type: InfraErrorType::NetworkError,
            message: line.to_string(),
            recoverable: true,
        }));
    }

    None
}

/// Extract peer ID from WireGuard log line
fn extract_peer_id(line: &str) -> Option<String> {
    // Pattern: "peer <base64>... - message"
    if let Some(start) = line.find("peer ") {
        let rest = &line[start + 5..];
        if let Some(end) = rest.find(" -") {
            return Some(rest[..end].trim().to_string());
        }
        // Take first word after "peer "
        return rest.split_whitespace().next().map(String::from);
    }
    None
}

/// Extract session ID from Cloak log line
fn extract_session_id(line: &str) -> Option<String> {
    // Try various patterns
    if let Some(start) = line.find("session=") {
        let rest = &line[start + 8..];
        return rest.split_whitespace().next().map(String::from);
    }
    if let Some(start) = line.find("Session ") {
        let rest = &line[start + 8..];
        return rest.split_whitespace().next().map(String::from);
    }
    None
}

/// Health checker that performs periodic connectivity checks
pub struct HealthChecker {
    endpoints: Vec<String>,
    sender: TelemetrySender,
    interval_secs: u32,
    shutdown: tokio::sync::watch::Receiver<bool>,
}

impl HealthChecker {
    pub fn new(
        endpoints: Vec<String>,
        sender: TelemetrySender,
        interval_secs: u32,
        shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Self {
        Self {
            endpoints,
            sender,
            interval_secs,
            shutdown,
        }
    }

    pub async fn run(mut self) -> Result<()> {
        info!(
            "Starting health checker with {} endpoints, interval: {}s",
            self.endpoints.len(),
            self.interval_secs
        );

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()?;

        let mut interval =
            tokio::time::interval(tokio::time::Duration::from_secs(self.interval_secs as u64));

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    for endpoint in &self.endpoints {
                        let event = self.check_endpoint(&client, endpoint).await;
                        if self.sender.send(TelemetryEvent::HealthCheck(event)).await.is_err() {
                            warn!("Telemetry channel closed");
                            return Ok(());
                        }
                    }
                }
                _ = self.shutdown.changed() => {
                    if *self.shutdown.borrow() {
                        info!("Health checker received shutdown signal");
                        break;
                    }
                }
            }
        }

        Ok(())
    }

    async fn check_endpoint(&self, client: &reqwest::Client, endpoint: &str) -> HealthCheckEvent {
        let start = std::time::Instant::now();

        match client.get(endpoint).send().await {
            Ok(response) => {
                let latency = start.elapsed().as_millis() as u32;
                let status = response.status().as_u16();
                let reachable = response.status().is_success();

                HealthCheckEvent::new(endpoint, reachable)
                    .with_latency(latency)
                    .with_status_code(status)
            }
            Err(e) => {
                debug!("Health check failed for {}: {}", endpoint, e);
                HealthCheckEvent::new(endpoint, false)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_wireguard_handshake() {
        let line = "2024-01-15 10:00:00 peer abc123... - Handshake completed";
        let event = parse_wireguard_log_line(line);
        assert!(event.is_some());
        if let Some(TelemetryEvent::Connection(conn)) = event {
            assert!(conn.success);
            assert_eq!(conn.protocol, "wireguard");
        }
    }

    #[test]
    fn test_extract_peer_id() {
        let line = "peer abcdef123456 - Handshake completed";
        let peer_id = extract_peer_id(line);
        assert_eq!(peer_id, Some("abcdef123456".to_string()));
    }
}
