//! Traffic profile definitions
//!
//! Profiles define how traffic should appear to evade DPI detection.

use crate::config::{ObfuscationType, PaddingType, ProfileConfig, Protocol, TimingPattern};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Unique identifier for a traffic profile
pub type ProfileId = String;

/// Complete traffic profile with all parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficProfile {
    pub id: ProfileId,
    pub name: String,
    pub protocol: Protocol,
    pub port: u16,
    pub obfuscation: ObfuscationType,
    pub timing: TimingProfile,
    pub padding: PaddingProfile,
    pub max_concurrent: u32,
    pub custom_config: HashMap<String, serde_yaml::Value>,
}

/// Timing profile for packet intervals
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingProfile {
    pub pattern: TimingPattern,
    /// Minimum interval between packets (ms)
    pub min_interval_ms: u32,
    /// Maximum interval between packets (ms)
    pub max_interval_ms: u32,
    /// Jitter percentage (0-100)
    pub jitter_percent: u8,
    /// Burst size (packets)
    pub burst_size: u32,
    /// Burst interval (ms)
    pub burst_interval_ms: u32,
}

impl Default for TimingProfile {
    fn default() -> Self {
        Self {
            pattern: TimingPattern::Constant,
            min_interval_ms: 10,
            max_interval_ms: 100,
            jitter_percent: 10,
            burst_size: 1,
            burst_interval_ms: 0,
        }
    }
}

impl TimingProfile {
    /// Create timing profile mimicking WebRTC video call
    pub fn webrtc() -> Self {
        Self {
            pattern: TimingPattern::WebrtcPattern,
            min_interval_ms: 16,  // ~60fps
            max_interval_ms: 33,  // ~30fps
            jitter_percent: 15,
            burst_size: 3,
            burst_interval_ms: 5,
        }
    }

    /// Create timing profile mimicking game traffic
    pub fn game_traffic() -> Self {
        Self {
            pattern: TimingPattern::GameTrafficPattern,
            min_interval_ms: 8,   // 125 tick rate
            max_interval_ms: 16,  // 62.5 tick rate
            jitter_percent: 5,
            burst_size: 1,
            burst_interval_ms: 0,
        }
    }

    /// Create timing profile mimicking video streaming
    pub fn video_stream() -> Self {
        Self {
            pattern: TimingPattern::VideoStream,
            min_interval_ms: 33,  // 30fps
            max_interval_ms: 100,
            jitter_percent: 20,
            burst_size: 10,
            burst_interval_ms: 100,
        }
    }

    /// Create timing profile mimicking web browsing
    pub fn web_browsing() -> Self {
        Self {
            pattern: TimingPattern::WebBrowsing,
            min_interval_ms: 1,
            max_interval_ms: 5000,
            jitter_percent: 50,
            burst_size: 20,
            burst_interval_ms: 10,
        }
    }
}

/// Padding profile for packet sizes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaddingProfile {
    pub padding_type: PaddingType,
    /// Minimum packet size (bytes)
    pub min_size: u16,
    /// Maximum packet size (bytes)
    pub max_size: u16,
    /// Target MTU for fixed padding
    pub target_mtu: u16,
    /// Size distribution for variable padding
    pub size_distribution: Option<SizeDistribution>,
}

impl Default for PaddingProfile {
    fn default() -> Self {
        Self {
            padding_type: PaddingType::None,
            min_size: 0,
            max_size: 1500,
            target_mtu: 1420,
            size_distribution: None,
        }
    }
}

impl PaddingProfile {
    /// Create fixed MTU padding profile
    pub fn fixed_mtu(mtu: u16) -> Self {
        Self {
            padding_type: PaddingType::FixedMtu,
            min_size: mtu,
            max_size: mtu,
            target_mtu: mtu,
            size_distribution: None,
        }
    }

    /// Create variable padding profile
    pub fn variable(min: u16, max: u16) -> Self {
        Self {
            padding_type: PaddingType::Variable,
            min_size: min,
            max_size: max,
            target_mtu: 1420,
            size_distribution: Some(SizeDistribution::Uniform),
        }
    }

    /// Create HTTPS-like size distribution
    pub fn https_like() -> Self {
        Self {
            padding_type: PaddingType::Variable,
            min_size: 64,
            max_size: 1460,
            target_mtu: 1460,
            size_distribution: Some(SizeDistribution::HttpsLike),
        }
    }
}

/// Size distribution for variable padding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SizeDistribution {
    Uniform,
    Normal { mean: f32, std_dev: f32 },
    HttpsLike,
    VideoLike,
    Custom(Vec<(u16, f32)>), // (size, probability) pairs
}

impl TrafficProfile {
    /// Create a profile from config
    pub fn from_config(id: &str, config: &ProfileConfig) -> Self {
        let timing = match config.timing {
            Some(TimingPattern::WebrtcPattern) => TimingProfile::webrtc(),
            Some(TimingPattern::GameTrafficPattern) => TimingProfile::game_traffic(),
            Some(TimingPattern::VideoStream) => TimingProfile::video_stream(),
            Some(TimingPattern::WebBrowsing) => TimingProfile::web_browsing(),
            Some(TimingPattern::Bursty) => TimingProfile {
                pattern: TimingPattern::Bursty,
                min_interval_ms: 1,
                max_interval_ms: 50,
                jitter_percent: 30,
                burst_size: 5,
                burst_interval_ms: 200,
            },
            Some(TimingPattern::Constant) | None => TimingProfile::default(),
        };

        let padding = match config.padding {
            Some(PaddingType::FixedMtu) => PaddingProfile::fixed_mtu(1420),
            Some(PaddingType::Variable) => PaddingProfile::variable(64, 1460),
            Some(PaddingType::Random) => PaddingProfile {
                padding_type: PaddingType::Random,
                min_size: 64,
                max_size: 1500,
                target_mtu: 1420,
                size_distribution: Some(SizeDistribution::Uniform),
            },
            Some(PaddingType::None) | None => PaddingProfile::default(),
        };

        Self {
            id: id.to_string(),
            name: id.to_string(),
            protocol: config.protocol,
            port: config.port,
            obfuscation: config.obfuscation.unwrap_or(ObfuscationType::None),
            timing,
            padding,
            max_concurrent: config.max_concurrent,
            custom_config: config.custom_config.clone(),
        }
    }

    /// Get a human-readable description of this profile
    pub fn description(&self) -> String {
        format!(
            "{} ({:?}) on port {} with {:?} obfuscation",
            self.name, self.protocol, self.port, self.obfuscation
        )
    }
}

/// Predefined profile templates
pub struct ProfileTemplates;

impl ProfileTemplates {
    /// HTTPS clone - looks like normal HTTPS traffic
    pub fn https_clone() -> TrafficProfile {
        TrafficProfile {
            id: "https_clone".to_string(),
            name: "HTTPS Clone".to_string(),
            protocol: Protocol::Cloak,
            port: 443,
            obfuscation: ObfuscationType::Tls1_3,
            timing: TimingProfile::web_browsing(),
            padding: PaddingProfile::https_like(),
            max_concurrent: 100,
            custom_config: HashMap::new(),
        }
    }

    /// Video call profile - mimics WebRTC traffic
    pub fn video_call() -> TrafficProfile {
        TrafficProfile {
            id: "video_call".to_string(),
            name: "Video Call".to_string(),
            protocol: Protocol::Amneziawg,
            port: 443,
            obfuscation: ObfuscationType::None,
            timing: TimingProfile::webrtc(),
            padding: PaddingProfile::variable(100, 1200),
            max_concurrent: 10,
            custom_config: HashMap::new(),
        }
    }

    /// WebSocket profile - looks like WebSocket traffic
    pub fn websocket() -> TrafficProfile {
        TrafficProfile {
            id: "websocket".to_string(),
            name: "WebSocket".to_string(),
            protocol: Protocol::Shadowsocks,
            port: 443,
            obfuscation: ObfuscationType::WebsocketUpgrade,
            timing: TimingProfile::default(),
            padding: PaddingProfile::variable(64, 1400),
            max_concurrent: 50,
            custom_config: HashMap::new(),
        }
    }

    /// Gaming profile - mimics game traffic patterns
    pub fn gaming() -> TrafficProfile {
        TrafficProfile {
            id: "gaming".to_string(),
            name: "Gaming".to_string(),
            protocol: Protocol::Amneziawg,
            port: 443,
            obfuscation: ObfuscationType::None,
            timing: TimingProfile::game_traffic(),
            padding: PaddingProfile::fixed_mtu(1420),
            max_concurrent: 20,
            custom_config: HashMap::new(),
        }
    }

    /// Get all predefined templates
    pub fn all() -> Vec<TrafficProfile> {
        vec![
            Self::https_clone(),
            Self::video_call(),
            Self::websocket(),
            Self::gaming(),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_from_config() {
        let config = ProfileConfig {
            protocol: Protocol::Cloak,
            port: 443,
            obfuscation: Some(ObfuscationType::Tls1_3),
            timing: Some(TimingPattern::WebBrowsing),
            padding: Some(PaddingType::Variable),
            max_concurrent: 100,
            custom_config: HashMap::new(),
        };

        let profile = TrafficProfile::from_config("test", &config);
        assert_eq!(profile.protocol, Protocol::Cloak);
        assert_eq!(profile.port, 443);
    }

    #[test]
    fn test_profile_templates() {
        let templates = ProfileTemplates::all();
        assert_eq!(templates.len(), 4);
        assert!(templates.iter().any(|p| p.id == "https_clone"));
    }
}
