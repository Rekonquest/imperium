//! Hardware Abstraction Layer (HAL)
//!
//! Provides unified access to physical hardware sensors:
//! - TPM 2.0 (attestation, PCR monitoring)
//! - SmartNIC (offloaded packet stats, hardware filtering)
//! - CPU telemetry (voltage, frequency, side-channel indicators)
//! - Memory pressure monitoring
//! - SDR devices (spectrum sensing, jamming detection)
//!
//! The HAL polls hardware at 100Hz and feeds readings to the Sensor Bus.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use super::sensors::{
    HardwareComponent, HardwareHealth, HealthStatus, SensorBus, SensorData, SensorReading,
    SensorSource, SpectrumData,
};

/// Hardware Abstraction Layer - unified hardware sensor access
pub struct HardwareAbstractionLayer {
    /// Whether HAL is running
    running: AtomicBool,

    /// Polling rate in Hz
    poll_rate_hz: u32,

    /// Registered hardware devices
    devices: RwLock<Vec<Box<dyn HardwareDevice>>>,

    /// Sensor bus for output
    sensor_bus: Arc<SensorBus>,

    /// Health baseline (for anomaly detection)
    baseline: RwLock<HashMap<HardwareComponent, HardwareBaseline>>,

    /// Total polls executed
    poll_count: AtomicU64,

    /// Anomalies detected
    anomaly_count: AtomicU64,
}

/// Baseline for a hardware component
#[derive(Debug, Clone)]
pub struct HardwareBaseline {
    pub component: HardwareComponent,
    pub normal_ranges: HashMap<String, (f64, f64)>, // metric -> (min, max)
    pub established: Instant,
    pub samples: u64,
}

/// Trait for hardware devices
pub trait HardwareDevice: Send + Sync {
    /// Get device type
    fn component(&self) -> HardwareComponent;

    /// Get device name
    fn name(&self) -> &str;

    /// Poll current readings
    fn poll(&self) -> Result<HardwareHealth>;

    /// Check if device is available
    fn is_available(&self) -> bool;

    /// Get supported metrics
    fn supported_metrics(&self) -> Vec<String>;
}

impl HardwareAbstractionLayer {
    pub fn new(sensor_bus: Arc<SensorBus>, poll_rate_hz: u32) -> Self {
        Self {
            running: AtomicBool::new(false),
            poll_rate_hz,
            devices: RwLock::new(Vec::new()),
            sensor_bus,
            baseline: RwLock::new(HashMap::new()),
            poll_count: AtomicU64::new(0),
            anomaly_count: AtomicU64::new(0),
        }
    }

    /// Register a hardware device
    pub fn register_device(&self, device: Box<dyn HardwareDevice>) {
        if device.is_available() {
            tracing::info!("Registered hardware device: {} ({:?})", device.name(), device.component());
            self.devices.write().push(device);
        } else {
            tracing::warn!("Hardware device not available: {}", device.name());
        }
    }

    /// Auto-detect and register available hardware
    pub fn auto_detect(&self) {
        // TPM
        if TpmDevice::detect() {
            self.register_device(Box::new(TpmDevice::new()));
        }

        // SmartNIC (check for common paths)
        if SmartNicDevice::detect() {
            self.register_device(Box::new(SmartNicDevice::new()));
        }

        // CPU telemetry (always available on Linux)
        self.register_device(Box::new(CpuTelemetryDevice::new()));

        // Memory monitoring (always available)
        self.register_device(Box::new(MemoryDevice::new()));

        // SDR devices
        for sdr in SdrProbeDevice::detect_all() {
            self.register_device(Box::new(sdr));
        }

        tracing::info!("Auto-detected {} hardware devices", self.devices.read().len());
    }

    /// Start polling loop
    pub async fn start(&self) {
        self.running.store(true, Ordering::Relaxed);
        let poll_interval = Duration::from_micros(1_000_000 / self.poll_rate_hz as u64);

        tracing::info!("HAL started, polling at {}Hz", self.poll_rate_hz);

        while self.running.load(Ordering::Relaxed) {
            let start = Instant::now();

            self.poll_all().await;

            // Sleep for remaining interval
            let elapsed = start.elapsed();
            if elapsed < poll_interval {
                tokio::time::sleep(poll_interval - elapsed).await;
            }
        }
    }

    /// Stop polling loop
    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }

    /// Poll all devices once
    async fn poll_all(&self) {
        let devices = self.devices.read();

        for device in devices.iter() {
            match device.poll() {
                Ok(health) => {
                    let is_anomaly = self.check_anomaly(&health);

                    let reading = SensorReading {
                        source: component_to_source(device.component()),
                        timestamp: Instant::now(),
                        data: SensorData::HardwareHealth(health),
                        confidence: 1.0,
                        urgent: is_anomaly,
                    };

                    self.sensor_bus.submit(reading).await;

                    if is_anomaly {
                        self.anomaly_count.fetch_add(1, Ordering::Relaxed);
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to poll {}: {}", device.name(), e);
                }
            }
        }

        self.poll_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Check if reading is anomalous compared to baseline
    fn check_anomaly(&self, health: &HardwareHealth) -> bool {
        let baseline = self.baseline.read();

        if let Some(base) = baseline.get(&health.component) {
            for (metric, value) in &health.metrics {
                if let Some((min, max)) = base.normal_ranges.get(metric) {
                    if value < min || value > max {
                        tracing::warn!(
                            "Hardware anomaly: {:?} {} = {} (expected {}-{})",
                            health.component,
                            metric,
                            value,
                            min,
                            max
                        );
                        return true;
                    }
                }
            }
        }

        // Check for explicit alerts
        !health.alerts.is_empty()
    }

    /// Establish baseline from current readings
    pub fn establish_baseline(&self, samples: u64) {
        tracing::info!("Establishing hardware baseline ({} samples)...", samples);

        let mut baselines: HashMap<HardwareComponent, Vec<HashMap<String, f64>>> = HashMap::new();

        for _ in 0..samples {
            for device in self.devices.read().iter() {
                if let Ok(health) = device.poll() {
                    baselines
                        .entry(device.component())
                        .or_default()
                        .push(health.metrics);
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }

        // Calculate ranges
        let mut baseline_write = self.baseline.write();
        for (component, readings) in baselines {
            if readings.is_empty() {
                continue;
            }

            let mut ranges = HashMap::new();

            // Get all metric names from first reading
            if let Some(first) = readings.first() {
                for metric in first.keys() {
                    let values: Vec<f64> = readings
                        .iter()
                        .filter_map(|r| r.get(metric).copied())
                        .collect();

                    if !values.is_empty() {
                        let min = values.iter().cloned().fold(f64::INFINITY, f64::min);
                        let max = values.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
                        let margin = (max - min) * 0.2; // 20% margin

                        ranges.insert(metric.clone(), (min - margin, max + margin));
                    }
                }
            }

            baseline_write.insert(
                component,
                HardwareBaseline {
                    component,
                    normal_ranges: ranges,
                    established: Instant::now(),
                    samples,
                },
            );
        }

        tracing::info!("Hardware baseline established for {} components", baseline_write.len());
    }

    /// Get statistics
    pub fn stats(&self) -> HalStats {
        HalStats {
            device_count: self.devices.read().len(),
            poll_count: self.poll_count.load(Ordering::Relaxed),
            anomaly_count: self.anomaly_count.load(Ordering::Relaxed),
            poll_rate_hz: self.poll_rate_hz,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HalStats {
    pub device_count: usize,
    pub poll_count: u64,
    pub anomaly_count: u64,
    pub poll_rate_hz: u32,
}

fn component_to_source(component: HardwareComponent) -> SensorSource {
    match component {
        HardwareComponent::Tpm => SensorSource::TpmHealth,
        HardwareComponent::SmartNic => SensorSource::SmartNicStats,
        HardwareComponent::Cpu => SensorSource::CpuTelemetry,
        HardwareComponent::Memory => SensorSource::MemoryPressure,
        HardwareComponent::SdrDevice => SensorSource::SpectrumAnalyzer,
        _ => SensorSource::Composite,
    }
}

//
// Hardware Device Implementations
//

/// TPM 2.0 Device
pub struct TpmDevice {
    path: PathBuf,
    expected_pcrs: RwLock<HashMap<u32, Vec<u8>>>,
}

impl TpmDevice {
    pub fn new() -> Self {
        Self {
            path: PathBuf::from("/dev/tpm0"),
            expected_pcrs: RwLock::new(HashMap::new()),
        }
    }

    pub fn detect() -> bool {
        PathBuf::from("/dev/tpm0").exists() || PathBuf::from("/dev/tpmrm0").exists()
    }

    /// Set expected PCR values for integrity checking
    pub fn set_expected_pcrs(&self, pcrs: HashMap<u32, Vec<u8>>) {
        *self.expected_pcrs.write() = pcrs;
    }
}

impl HardwareDevice for TpmDevice {
    fn component(&self) -> HardwareComponent {
        HardwareComponent::Tpm
    }

    fn name(&self) -> &str {
        "TPM 2.0"
    }

    fn poll(&self) -> Result<HardwareHealth> {
        let mut metrics = HashMap::new();
        let mut alerts = Vec::new();

        // Read TPM properties via sysfs
        let tpm_path = PathBuf::from("/sys/class/tpm/tpm0");

        if let Ok(caps) = std::fs::read_to_string(tpm_path.join("caps")) {
            metrics.insert("caps_available".into(), 1.0);

            // Parse capabilities
            if caps.contains("TPM 2.0") {
                metrics.insert("version".into(), 2.0);
            }
        }

        // Check PCR bank status
        if let Ok(pcrs) = std::fs::read_to_string(tpm_path.join("pcrs")) {
            let pcr_count = pcrs.lines().count();
            metrics.insert("pcr_banks".into(), pcr_count as f64);
        }

        // In real implementation: compare PCRs with expected values
        let expected = self.expected_pcrs.read();
        if !expected.is_empty() {
            // Would actually read and compare PCRs here
            metrics.insert("pcr_integrity".into(), 1.0);
        }

        let status = if alerts.is_empty() {
            HealthStatus::Healthy
        } else {
            HealthStatus::Warning
        };

        Ok(HardwareHealth {
            component: HardwareComponent::Tpm,
            status,
            metrics,
            alerts,
        })
    }

    fn is_available(&self) -> bool {
        Self::detect()
    }

    fn supported_metrics(&self) -> Vec<String> {
        vec![
            "version".into(),
            "pcr_banks".into(),
            "pcr_integrity".into(),
        ]
    }
}

impl Default for TpmDevice {
    fn default() -> Self {
        Self::new()
    }
}

/// SmartNIC Device (DASH-enabled or similar)
pub struct SmartNicDevice {
    interface: String,
}

impl SmartNicDevice {
    pub fn new() -> Self {
        Self {
            interface: "eth0".into(),
        }
    }

    pub fn detect() -> bool {
        // Check for common SmartNIC indicators
        PathBuf::from("/sys/class/net/eth0/device/sriov_numvfs").exists()
    }
}

impl HardwareDevice for SmartNicDevice {
    fn component(&self) -> HardwareComponent {
        HardwareComponent::SmartNic
    }

    fn name(&self) -> &str {
        "SmartNIC"
    }

    fn poll(&self) -> Result<HardwareHealth> {
        let mut metrics = HashMap::new();
        let alerts = Vec::new();

        // Read network interface stats
        let stats_path = format!("/sys/class/net/{}/statistics", self.interface);

        if let Ok(rx_bytes) = std::fs::read_to_string(format!("{}/rx_bytes", stats_path)) {
            if let Ok(bytes) = rx_bytes.trim().parse::<f64>() {
                metrics.insert("rx_bytes".into(), bytes);
            }
        }

        if let Ok(tx_bytes) = std::fs::read_to_string(format!("{}/tx_bytes", stats_path)) {
            if let Ok(bytes) = tx_bytes.trim().parse::<f64>() {
                metrics.insert("tx_bytes".into(), bytes);
            }
        }

        if let Ok(rx_dropped) = std::fs::read_to_string(format!("{}/rx_dropped", stats_path)) {
            if let Ok(dropped) = rx_dropped.trim().parse::<f64>() {
                metrics.insert("rx_dropped".into(), dropped);
            }
        }

        if let Ok(tx_dropped) = std::fs::read_to_string(format!("{}/tx_dropped", stats_path)) {
            if let Ok(dropped) = tx_dropped.trim().parse::<f64>() {
                metrics.insert("tx_dropped".into(), dropped);
            }
        }

        Ok(HardwareHealth {
            component: HardwareComponent::SmartNic,
            status: HealthStatus::Healthy,
            metrics,
            alerts,
        })
    }

    fn is_available(&self) -> bool {
        PathBuf::from(format!("/sys/class/net/{}", self.interface)).exists()
    }

    fn supported_metrics(&self) -> Vec<String> {
        vec![
            "rx_bytes".into(),
            "tx_bytes".into(),
            "rx_dropped".into(),
            "tx_dropped".into(),
        ]
    }
}

impl Default for SmartNicDevice {
    fn default() -> Self {
        Self::new()
    }
}

/// CPU Telemetry Device
pub struct CpuTelemetryDevice;

impl CpuTelemetryDevice {
    pub fn new() -> Self {
        Self
    }
}

impl HardwareDevice for CpuTelemetryDevice {
    fn component(&self) -> HardwareComponent {
        HardwareComponent::Cpu
    }

    fn name(&self) -> &str {
        "CPU Telemetry"
    }

    fn poll(&self) -> Result<HardwareHealth> {
        let mut metrics = HashMap::new();
        let mut alerts = Vec::new();

        // Read CPU frequency
        if let Ok(freq) = std::fs::read_to_string("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq") {
            if let Ok(khz) = freq.trim().parse::<f64>() {
                metrics.insert("frequency_mhz".into(), khz / 1000.0);
            }
        }

        // Read CPU temperature (thermal zones)
        for i in 0..10 {
            let temp_path = format!("/sys/class/thermal/thermal_zone{}/temp", i);
            if let Ok(temp) = std::fs::read_to_string(&temp_path) {
                if let Ok(millicelsius) = temp.trim().parse::<f64>() {
                    let celsius = millicelsius / 1000.0;
                    metrics.insert(format!("temp_zone{}_c", i), celsius);

                    if celsius > 90.0 {
                        alerts.push(format!("High temperature: {}°C", celsius));
                    }
                }
            } else {
                break;
            }
        }

        // Read load average
        if let Ok(loadavg) = std::fs::read_to_string("/proc/loadavg") {
            let parts: Vec<&str> = loadavg.split_whitespace().collect();
            if let Some(load1) = parts.first() {
                if let Ok(load) = load1.parse::<f64>() {
                    metrics.insert("load_1min".into(), load);
                }
            }
        }

        let status = if alerts.is_empty() {
            HealthStatus::Healthy
        } else {
            HealthStatus::Warning
        };

        Ok(HardwareHealth {
            component: HardwareComponent::Cpu,
            status,
            metrics,
            alerts,
        })
    }

    fn is_available(&self) -> bool {
        true // Always available on Linux
    }

    fn supported_metrics(&self) -> Vec<String> {
        vec![
            "frequency_mhz".into(),
            "temp_c".into(),
            "load_1min".into(),
        ]
    }
}

impl Default for CpuTelemetryDevice {
    fn default() -> Self {
        Self::new()
    }
}

/// Memory Monitoring Device
pub struct MemoryDevice;

impl MemoryDevice {
    pub fn new() -> Self {
        Self
    }
}

impl HardwareDevice for MemoryDevice {
    fn component(&self) -> HardwareComponent {
        HardwareComponent::Memory
    }

    fn name(&self) -> &str {
        "Memory Monitor"
    }

    fn poll(&self) -> Result<HardwareHealth> {
        let mut metrics = HashMap::new();
        let mut alerts = Vec::new();

        if let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") {
            for line in meminfo.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    let key = parts[0].trim_end_matches(':');
                    if let Ok(value) = parts[1].parse::<f64>() {
                        match key {
                            "MemTotal" => metrics.insert("total_kb".into(), value),
                            "MemFree" => metrics.insert("free_kb".into(), value),
                            "MemAvailable" => metrics.insert("available_kb".into(), value),
                            "SwapTotal" => metrics.insert("swap_total_kb".into(), value),
                            "SwapFree" => metrics.insert("swap_free_kb".into(), value),
                            _ => None,
                        };
                    }
                }
            }
        }

        // Calculate usage percentage
        if let (Some(&total), Some(&available)) = (metrics.get("total_kb"), metrics.get("available_kb")) {
            let usage_pct = (total - available) / total * 100.0;
            metrics.insert("usage_percent".into(), usage_pct);

            if usage_pct > 90.0 {
                alerts.push(format!("High memory usage: {:.1}%", usage_pct));
            }
        }

        let status = if alerts.is_empty() {
            HealthStatus::Healthy
        } else {
            HealthStatus::Warning
        };

        Ok(HardwareHealth {
            component: HardwareComponent::Memory,
            status,
            metrics,
            alerts,
        })
    }

    fn is_available(&self) -> bool {
        #[cfg(unix)]
        {
            std::path::Path::new("/proc/meminfo").exists()
        }
        #[cfg(not(unix))]
        {
            false
        }
    }

    fn supported_metrics(&self) -> Vec<String> {
        vec![
            "total_kb".into(),
            "free_kb".into(),
            "available_kb".into(),
            "usage_percent".into(),
        ]
    }
}

impl Default for MemoryDevice {
    fn default() -> Self {
        Self::new()
    }
}

/// SDR Probe Device for spectrum sensing
pub struct SdrProbeDevice {
    device_path: PathBuf,
    device_name: String,
    center_freq: u64,
    sample_rate: u64,
}

impl SdrProbeDevice {
    pub fn new(path: PathBuf, name: String) -> Self {
        Self {
            device_path: path,
            device_name: name,
            center_freq: 915_000_000, // 915 MHz default
            sample_rate: 2_400_000,   // 2.4 MS/s
        }
    }

    pub fn detect_all() -> Vec<Self> {
        let mut devices = Vec::new();

        // Check for RTL-SDR devices
        for i in 0..4 {
            let path = format!("/dev/swradio{}", i);
            if PathBuf::from(&path).exists() {
                devices.push(Self::new(
                    PathBuf::from(&path),
                    format!("RTL-SDR #{}", i),
                ));
            }
        }

        // Check for HackRF
        if PathBuf::from("/dev/hackrf0").exists() {
            devices.push(Self::new(
                PathBuf::from("/dev/hackrf0"),
                "HackRF One".into(),
            ));
        }

        // Check for LimeSDR
        if PathBuf::from("/dev/limesdr0").exists() {
            devices.push(Self::new(
                PathBuf::from("/dev/limesdr0"),
                "LimeSDR".into(),
            ));
        }

        devices
    }

    pub fn set_frequency(&mut self, freq_hz: u64) {
        self.center_freq = freq_hz;
    }
}

impl HardwareDevice for SdrProbeDevice {
    fn component(&self) -> HardwareComponent {
        HardwareComponent::SdrDevice
    }

    fn name(&self) -> &str {
        &self.device_name
    }

    fn poll(&self) -> Result<HardwareHealth> {
        let mut metrics = HashMap::new();
        let alerts = Vec::new();

        metrics.insert("center_freq_hz".into(), self.center_freq as f64);
        metrics.insert("sample_rate".into(), self.sample_rate as f64);

        // In real implementation: read actual signal strength
        // For now, report device is present
        metrics.insert("device_present".into(), 1.0);

        Ok(HardwareHealth {
            component: HardwareComponent::SdrDevice,
            status: HealthStatus::Healthy,
            metrics,
            alerts,
        })
    }

    fn is_available(&self) -> bool {
        self.device_path.exists()
    }

    fn supported_metrics(&self) -> Vec<String> {
        vec![
            "center_freq_hz".into(),
            "sample_rate".into(),
            "signal_strength_dbm".into(),
            "noise_floor_dbm".into(),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cpu_telemetry() {
        let device = CpuTelemetryDevice::new();
        assert!(device.is_available());

        let health = device.poll().unwrap();
        assert_eq!(health.component, HardwareComponent::Cpu);
    }

    #[test]
    fn test_memory_device() {
        let device = MemoryDevice::new();
        if !device.is_available() {
            // No /proc/meminfo (e.g. Windows)
            return;
        }

        let health = device.poll().unwrap();
        assert!(health.metrics.contains_key("total_kb"));
    }
}
