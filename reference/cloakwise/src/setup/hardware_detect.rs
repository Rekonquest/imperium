//! Hardware detection for automatic tier selection

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// Detected hardware capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareProfile {
    /// Total RAM in MB
    pub ram_mb: u64,

    /// Number of CPU cores
    pub cpu_cores: usize,

    /// CPU frequency in MHz (if detectable)
    pub cpu_mhz: Option<u64>,

    /// Whether a GPU is available
    pub gpu_available: bool,

    /// Available disk space in MB
    pub disk_mb: u64,

    /// Detected SDR devices
    pub sdr_devices: Vec<SdrDeviceInfo>,

    /// TPM available
    pub tpm_available: bool,

    /// Network interfaces
    pub network_interfaces: Vec<String>,

    /// Recommended tier based on hardware
    pub recommended_tier: HardwareTier,
}

/// SDR device information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdrDeviceInfo {
    pub device_type: String,
    pub device_path: String,
    pub capabilities: Vec<String>,
}

/// Hardware tier classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HardwareTier {
    /// Minimal: <1GB RAM, 1 core - Rule-based only
    Minimal,
    /// Standard: 1-4GB RAM, 2-4 cores - Micro-models
    Standard,
    /// Enhanced: 4-16GB RAM, 4+ cores - Full AI
    Enhanced,
    /// Lab: 16GB+ RAM, GPU - Research/development
    Lab,
}

impl HardwareTier {
    pub fn name(&self) -> &'static str {
        match self {
            HardwareTier::Minimal => "Minimal",
            HardwareTier::Standard => "Standard",
            HardwareTier::Enhanced => "Enhanced",
            HardwareTier::Lab => "Lab/Research",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            HardwareTier::Minimal => "Rule-based fallback only, no AI (~50MB RAM)",
            HardwareTier::Standard => "3x micro-models for fast reflex decisions (~200MB RAM)",
            HardwareTier::Enhanced => "Full AI + optional Big Momma reasoner (~1GB RAM)",
            HardwareTier::Lab => "Full AI + GPU acceleration + SDR processing (~4GB+ RAM)",
        }
    }

    pub fn supports_ai(&self) -> bool {
        !matches!(self, HardwareTier::Minimal)
    }

    pub fn supports_big_momma(&self) -> bool {
        matches!(self, HardwareTier::Enhanced | HardwareTier::Lab)
    }

    pub fn supports_sdr_processing(&self) -> bool {
        matches!(self, HardwareTier::Lab)
    }
}

impl HardwareProfile {
    /// Detect hardware capabilities
    pub fn detect() -> Self {
        let ram_mb = detect_ram_mb();
        let cpu_cores = detect_cpu_cores();
        let cpu_mhz = detect_cpu_mhz();
        let gpu_available = detect_gpu();
        let disk_mb = detect_disk_mb();
        let sdr_devices = detect_sdr_devices();
        let tpm_available = detect_tpm();
        let network_interfaces = detect_network_interfaces();

        let recommended_tier = determine_tier(ram_mb, cpu_cores, gpu_available);

        Self {
            ram_mb,
            cpu_cores,
            cpu_mhz,
            gpu_available,
            disk_mb,
            sdr_devices,
            tpm_available,
            network_interfaces,
            recommended_tier,
        }
    }

    /// Get a human-readable summary
    pub fn summary(&self) -> String {
        format!(
            "RAM: {}MB | CPU: {} cores{} | Disk: {}MB | TPM: {} | SDR: {}",
            self.ram_mb,
            self.cpu_cores,
            self.cpu_mhz.map(|m| format!(" @ {}MHz", m)).unwrap_or_default(),
            self.disk_mb,
            if self.tpm_available { "Yes" } else { "No" },
            if self.sdr_devices.is_empty() {
                "None".to_string()
            } else {
                format!("{} device(s)", self.sdr_devices.len())
            }
        )
    }
}

fn determine_tier(ram_mb: u64, cpu_cores: usize, gpu_available: bool) -> HardwareTier {
    if gpu_available && ram_mb >= 16000 {
        HardwareTier::Lab
    } else if ram_mb >= 4000 && cpu_cores >= 4 {
        HardwareTier::Enhanced
    } else if ram_mb >= 1000 && cpu_cores >= 2 {
        HardwareTier::Standard
    } else {
        HardwareTier::Minimal
    }
}

fn detect_ram_mb() -> u64 {
    // Try to read from /proc/meminfo
    if let Ok(content) = fs::read_to_string("/proc/meminfo") {
        for line in content.lines() {
            if line.starts_with("MemTotal:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    if let Ok(kb) = parts[1].parse::<u64>() {
                        return kb / 1024; // Convert to MB
                    }
                }
            }
        }
    }

    // Fallback: assume minimal
    512
}

fn detect_cpu_cores() -> usize {
    // Try to read from /proc/cpuinfo
    if let Ok(content) = fs::read_to_string("/proc/cpuinfo") {
        let count = content.lines().filter(|l| l.starts_with("processor")).count();
        if count > 0 {
            return count;
        }
    }

    // Fallback to std
    std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(1)
}

fn detect_cpu_mhz() -> Option<u64> {
    // Try to read from /proc/cpuinfo
    if let Ok(content) = fs::read_to_string("/proc/cpuinfo") {
        for line in content.lines() {
            if line.starts_with("cpu MHz") {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 2 {
                    if let Ok(mhz) = parts[1].trim().parse::<f64>() {
                        return Some(mhz as u64);
                    }
                }
            }
        }
    }

    None
}

fn detect_gpu() -> bool {
    // Check for NVIDIA GPU
    if Path::new("/dev/nvidia0").exists() {
        return true;
    }

    // Check for AMD GPU
    if Path::new("/dev/dri/renderD128").exists() {
        // Could be integrated, check for discrete
        if let Ok(content) = fs::read_to_string("/proc/driver/nvidia/version") {
            if content.contains("NVIDIA") {
                return true;
            }
        }
    }

    // Check lspci output indicator
    if Path::new("/sys/bus/pci/devices").exists() {
        if let Ok(entries) = fs::read_dir("/sys/bus/pci/devices") {
            for entry in entries.flatten() {
                let class_path = entry.path().join("class");
                if let Ok(class) = fs::read_to_string(&class_path) {
                    // VGA compatible controller or 3D controller
                    if class.trim().starts_with("0x03") {
                        return true;
                    }
                }
            }
        }
    }

    false
}

fn detect_disk_mb() -> u64 {
    // Use statvfs on current directory
    // For simplicity, read from /proc/mounts or estimate
    if let Ok(content) = fs::read_to_string("/proc/mounts") {
        for line in content.lines() {
            if line.contains(" / ") && !line.starts_with("overlay") {
                // Found root mount, try to get size
                // This is a simplified check
                break;
            }
        }
    }

    // Fallback: assume 10GB available
    10000
}

fn detect_sdr_devices() -> Vec<SdrDeviceInfo> {
    let mut devices = Vec::new();

    // Check for RTL-SDR
    for i in 0..4 {
        let path = format!("/dev/swradio{}", i);
        if Path::new(&path).exists() {
            devices.push(SdrDeviceInfo {
                device_type: "RTL-SDR".to_string(),
                device_path: path,
                capabilities: vec!["RX".to_string()],
            });
        }
    }

    // Check for HackRF
    if Path::new("/dev/hackrf0").exists() {
        devices.push(SdrDeviceInfo {
            device_type: "HackRF One".to_string(),
            device_path: "/dev/hackrf0".to_string(),
            capabilities: vec!["TX".to_string(), "RX".to_string()],
        });
    }

    // Check for LimeSDR (usually via USB)
    if Path::new("/dev/limesdr0").exists() {
        devices.push(SdrDeviceInfo {
            device_type: "LimeSDR".to_string(),
            device_path: "/dev/limesdr0".to_string(),
            capabilities: vec!["TX".to_string(), "RX".to_string(), "Full Duplex".to_string()],
        });
    }

    // Check for LoRa modules (common serial paths)
    for path in &["/dev/ttyUSB0", "/dev/ttyACM0", "/dev/ttyAMA0"] {
        if Path::new(path).exists() {
            // Could be LoRa, but we can't be sure without probing
            // Add as potential device
            devices.push(SdrDeviceInfo {
                device_type: "Serial Device (potential LoRa)".to_string(),
                device_path: path.to_string(),
                capabilities: vec!["Unknown".to_string()],
            });
            break; // Only add one potential LoRa
        }
    }

    devices
}

fn detect_tpm() -> bool {
    Path::new("/dev/tpm0").exists() || Path::new("/dev/tpmrm0").exists()
}

fn detect_network_interfaces() -> Vec<String> {
    let mut interfaces = Vec::new();

    if let Ok(entries) = fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            // Skip loopback and docker interfaces
            if name != "lo" && !name.starts_with("docker") && !name.starts_with("br-") {
                interfaces.push(name);
            }
        }
    }

    interfaces
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tier_determination() {
        assert_eq!(determine_tier(512, 1, false), HardwareTier::Minimal);
        assert_eq!(determine_tier(2000, 2, false), HardwareTier::Standard);
        assert_eq!(determine_tier(8000, 4, false), HardwareTier::Enhanced);
        assert_eq!(determine_tier(32000, 8, true), HardwareTier::Lab);
    }

    #[test]
    fn test_tier_capabilities() {
        assert!(!HardwareTier::Minimal.supports_ai());
        assert!(HardwareTier::Standard.supports_ai());
        assert!(HardwareTier::Enhanced.supports_big_momma());
        assert!(HardwareTier::Lab.supports_sdr_processing());
    }
}
