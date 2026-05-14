//! SDR Hardware Abstraction
//!
//! Supports multiple SDR hardware types:
//! - RTL-SDR (receive only, cheap)
//! - HackRF One (TX/RX, 1MHz-6GHz)
//! - LimeSDR (TX/RX, full duplex)
//! - USRP (professional grade)
//! - PlutoSDR (TX/RX, portable)
//! - LoRa modules (SX1276, RFM95, etc.)

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// SDR device types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceType {
    /// RTL-SDR USB dongle (receive only)
    RtlSdr,
    /// HackRF One
    HackRf,
    /// LimeSDR
    LimeSdr,
    /// USRP (any variant)
    Usrp,
    /// PlutoSDR
    PlutoSdr,
    /// LoRa SX1276/SX1278 module
    LoRaSx127x,
    /// LoRa SX126x module
    LoRaSx126x,
    /// Simulated device (for testing)
    Simulated,
    /// Unknown device
    Unknown,
}

impl Default for DeviceType {
    fn default() -> Self {
        Self::Unknown
    }
}

/// Device capabilities
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceCapability {
    /// Can receive
    Receive,
    /// Can transmit
    Transmit,
    /// Full duplex
    FullDuplex,
    /// Half duplex
    HalfDuplex,
    /// GPIO available
    Gpio,
    /// Has integrated amplifier
    Amplifier,
    /// Has frequency hopping
    FrequencyHopping,
    /// Supports spread spectrum
    SpreadSpectrum,
}

/// Frequency range
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrequencyRange {
    pub min_hz: u64,
    pub max_hz: u64,
}

/// Device specifications
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceSpecs {
    /// Device type
    pub device_type: DeviceType,
    /// Device name
    pub name: String,
    /// Serial number
    pub serial: Option<String>,
    /// Frequency range
    pub freq_range: FrequencyRange,
    /// Maximum sample rate
    pub max_sample_rate: u32,
    /// Maximum bandwidth
    pub max_bandwidth: u32,
    /// Maximum TX power in dBm
    pub max_power_dbm: Option<i32>,
    /// Minimum RX sensitivity in dBm
    pub sensitivity_dbm: Option<i32>,
    /// Capabilities
    pub capabilities: Vec<DeviceCapability>,
}

impl DeviceSpecs {
    /// Create specs for RTL-SDR
    pub fn rtl_sdr() -> Self {
        Self {
            device_type: DeviceType::RtlSdr,
            name: "RTL-SDR".to_string(),
            serial: None,
            freq_range: FrequencyRange {
                min_hz: 24_000_000,   // 24 MHz
                max_hz: 1_766_000_000, // 1766 MHz
            },
            max_sample_rate: 2_400_000,
            max_bandwidth: 2_400_000,
            max_power_dbm: None, // RX only
            sensitivity_dbm: Some(-130),
            capabilities: vec![DeviceCapability::Receive],
        }
    }

    /// Create specs for HackRF One
    pub fn hackrf() -> Self {
        Self {
            device_type: DeviceType::HackRf,
            name: "HackRF One".to_string(),
            serial: None,
            freq_range: FrequencyRange {
                min_hz: 1_000_000,      // 1 MHz
                max_hz: 6_000_000_000,   // 6 GHz
            },
            max_sample_rate: 20_000_000,
            max_bandwidth: 20_000_000,
            max_power_dbm: Some(15),
            sensitivity_dbm: Some(-120),
            capabilities: vec![
                DeviceCapability::Receive,
                DeviceCapability::Transmit,
                DeviceCapability::HalfDuplex,
            ],
        }
    }

    /// Create specs for LimeSDR
    pub fn limesdr() -> Self {
        Self {
            device_type: DeviceType::LimeSdr,
            name: "LimeSDR".to_string(),
            serial: None,
            freq_range: FrequencyRange {
                min_hz: 100_000,        // 100 kHz
                max_hz: 3_800_000_000,   // 3.8 GHz
            },
            max_sample_rate: 61_440_000,
            max_bandwidth: 61_440_000,
            max_power_dbm: Some(10),
            sensitivity_dbm: Some(-125),
            capabilities: vec![
                DeviceCapability::Receive,
                DeviceCapability::Transmit,
                DeviceCapability::FullDuplex,
            ],
        }
    }

    /// Create specs for LoRa SX1276
    pub fn lora_sx1276() -> Self {
        Self {
            device_type: DeviceType::LoRaSx127x,
            name: "LoRa SX1276".to_string(),
            serial: None,
            freq_range: FrequencyRange {
                min_hz: 137_000_000,  // 137 MHz
                max_hz: 1_020_000_000, // 1020 MHz
            },
            max_sample_rate: 500_000,
            max_bandwidth: 500_000,
            max_power_dbm: Some(20),
            sensitivity_dbm: Some(-148),
            capabilities: vec![
                DeviceCapability::Receive,
                DeviceCapability::Transmit,
                DeviceCapability::HalfDuplex,
                DeviceCapability::SpreadSpectrum,
            ],
        }
    }

    /// Create specs for simulated device
    pub fn simulated() -> Self {
        Self {
            device_type: DeviceType::Simulated,
            name: "Simulated SDR".to_string(),
            serial: Some("SIM-0001".to_string()),
            freq_range: FrequencyRange {
                min_hz: 1_000_000,
                max_hz: 6_000_000_000,
            },
            max_sample_rate: 20_000_000,
            max_bandwidth: 20_000_000,
            max_power_dbm: Some(20),
            sensitivity_dbm: Some(-120),
            capabilities: vec![
                DeviceCapability::Receive,
                DeviceCapability::Transmit,
                DeviceCapability::FullDuplex,
            ],
        }
    }

    /// Check if device supports a capability
    pub fn has_capability(&self, cap: DeviceCapability) -> bool {
        self.capabilities.contains(&cap)
    }

    /// Check if device can transmit
    pub fn can_transmit(&self) -> bool {
        self.has_capability(DeviceCapability::Transmit)
    }

    /// Check if frequency is supported
    pub fn supports_frequency(&self, freq_hz: u64) -> bool {
        freq_hz >= self.freq_range.min_hz && freq_hz <= self.freq_range.max_hz
    }
}

/// SDR device trait for hardware abstraction
#[async_trait::async_trait]
pub trait SdrDevice: Send + Sync {
    /// Get device specifications
    fn specs(&self) -> &DeviceSpecs;

    /// Open/initialize the device
    async fn open(&mut self) -> Result<()>;

    /// Close the device
    async fn close(&mut self) -> Result<()>;

    /// Check if device is open
    fn is_open(&self) -> bool;

    /// Set center frequency in Hz
    async fn set_frequency(&mut self, freq_hz: u64) -> Result<()>;

    /// Get current frequency in Hz
    fn get_frequency(&self) -> u64;

    /// Set sample rate
    async fn set_sample_rate(&mut self, rate: u32) -> Result<()>;

    /// Set bandwidth
    async fn set_bandwidth(&mut self, bw_hz: u32) -> Result<()>;

    /// Set transmit power in dBm
    async fn set_tx_power(&mut self, power_dbm: i32) -> Result<()>;

    /// Set gain in dB
    async fn set_gain(&mut self, gain_db: f32) -> Result<()>;

    /// Start receiving
    async fn start_rx(&mut self) -> Result<()>;

    /// Stop receiving
    async fn stop_rx(&mut self) -> Result<()>;

    /// Read received samples
    async fn read_samples(&mut self, buffer: &mut [u8]) -> Result<usize>;

    /// Start transmitting
    async fn start_tx(&mut self) -> Result<()>;

    /// Stop transmitting
    async fn stop_tx(&mut self) -> Result<()>;

    /// Write samples to transmit
    async fn write_samples(&mut self, samples: &[u8]) -> Result<usize>;

    /// Get RSSI (received signal strength)
    fn get_rssi(&self) -> Option<i32>;

    /// Get temperature in Celsius
    fn get_temperature(&self) -> Option<f32>;
}

/// Simulated SDR device for testing
pub struct SimulatedSdr {
    specs: DeviceSpecs,
    is_open: bool,
    frequency: u64,
    sample_rate: u32,
    bandwidth: u32,
    tx_power: i32,
    gain: f32,
    is_receiving: bool,
    is_transmitting: bool,
}

impl SimulatedSdr {
    pub fn new() -> Self {
        Self {
            specs: DeviceSpecs::simulated(),
            is_open: false,
            frequency: 915_000_000,
            sample_rate: 1_000_000,
            bandwidth: 500_000,
            tx_power: 10,
            gain: 20.0,
            is_receiving: false,
            is_transmitting: false,
        }
    }
}

impl Default for SimulatedSdr {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl SdrDevice for SimulatedSdr {
    fn specs(&self) -> &DeviceSpecs {
        &self.specs
    }

    async fn open(&mut self) -> Result<()> {
        self.is_open = true;
        Ok(())
    }

    async fn close(&mut self) -> Result<()> {
        self.is_receiving = false;
        self.is_transmitting = false;
        self.is_open = false;
        Ok(())
    }

    fn is_open(&self) -> bool {
        self.is_open
    }

    async fn set_frequency(&mut self, freq_hz: u64) -> Result<()> {
        if !self.specs.supports_frequency(freq_hz) {
            anyhow::bail!("Frequency {} Hz not supported", freq_hz);
        }
        self.frequency = freq_hz;
        Ok(())
    }

    fn get_frequency(&self) -> u64 {
        self.frequency
    }

    async fn set_sample_rate(&mut self, rate: u32) -> Result<()> {
        if rate > self.specs.max_sample_rate {
            anyhow::bail!("Sample rate {} exceeds maximum", rate);
        }
        self.sample_rate = rate;
        Ok(())
    }

    async fn set_bandwidth(&mut self, bw_hz: u32) -> Result<()> {
        if bw_hz > self.specs.max_bandwidth {
            anyhow::bail!("Bandwidth {} Hz exceeds maximum", bw_hz);
        }
        self.bandwidth = bw_hz;
        Ok(())
    }

    async fn set_tx_power(&mut self, power_dbm: i32) -> Result<()> {
        if let Some(max_power) = self.specs.max_power_dbm {
            if power_dbm > max_power {
                anyhow::bail!("TX power {} dBm exceeds maximum", power_dbm);
            }
        }
        self.tx_power = power_dbm;
        Ok(())
    }

    async fn set_gain(&mut self, gain_db: f32) -> Result<()> {
        self.gain = gain_db;
        Ok(())
    }

    async fn start_rx(&mut self) -> Result<()> {
        if !self.is_open {
            anyhow::bail!("Device not open");
        }
        self.is_receiving = true;
        Ok(())
    }

    async fn stop_rx(&mut self) -> Result<()> {
        self.is_receiving = false;
        Ok(())
    }

    async fn read_samples(&mut self, buffer: &mut [u8]) -> Result<usize> {
        if !self.is_receiving {
            anyhow::bail!("Not receiving");
        }
        // Return simulated noise
        for byte in buffer.iter_mut() {
            *byte = rand::random();
        }
        Ok(buffer.len())
    }

    async fn start_tx(&mut self) -> Result<()> {
        if !self.is_open {
            anyhow::bail!("Device not open");
        }
        if !self.specs.can_transmit() {
            anyhow::bail!("Device cannot transmit");
        }
        self.is_transmitting = true;
        Ok(())
    }

    async fn stop_tx(&mut self) -> Result<()> {
        self.is_transmitting = false;
        Ok(())
    }

    async fn write_samples(&mut self, samples: &[u8]) -> Result<usize> {
        if !self.is_transmitting {
            anyhow::bail!("Not transmitting");
        }
        // Simulated TX - just consume the samples
        Ok(samples.len())
    }

    fn get_rssi(&self) -> Option<i32> {
        if self.is_receiving {
            Some(-70 + (rand::random::<i32>() % 20))
        } else {
            None
        }
    }

    fn get_temperature(&self) -> Option<f32> {
        Some(35.0 + (rand::random::<f32>() * 10.0))
    }
}

/// Detect available SDR devices
pub fn detect_devices() -> Vec<DeviceSpecs> {
    // In a real implementation, this would probe USB devices
    // For now, return a simulated device
    vec![DeviceSpecs::simulated()]
}

/// Create an SDR device instance
pub fn create_device(device_type: DeviceType) -> Box<dyn SdrDevice> {
    match device_type {
        DeviceType::Simulated => Box::new(SimulatedSdr::new()),
        // Other device types would be implemented here
        _ => Box::new(SimulatedSdr::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_simulated_sdr() {
        let mut sdr = SimulatedSdr::new();

        sdr.open().await.unwrap();
        assert!(sdr.is_open());

        sdr.set_frequency(915_000_000).await.unwrap();
        assert_eq!(sdr.get_frequency(), 915_000_000);

        sdr.start_rx().await.unwrap();
        let mut buffer = [0u8; 1024];
        let n = sdr.read_samples(&mut buffer).await.unwrap();
        assert_eq!(n, 1024);

        sdr.stop_rx().await.unwrap();
        sdr.close().await.unwrap();
        assert!(!sdr.is_open());
    }
}
