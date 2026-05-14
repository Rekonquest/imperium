//! Dynamic Profile Generator
//!
//! LLM-driven engine that creates and mutates traffic profiles
//! to stay ahead of DPI fingerprinting.

use crate::config::{ObfuscationType, PaddingType, Protocol, TimingPattern};
use crate::vpn::profiles::{
    PaddingProfile, SizeDistribution, TimingProfile, TrafficProfile,
};
use anyhow::Result;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info, warn};

/// A generation request describing the desired profile characteristics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileGenerationRequest {
    /// Human-readable intent (e.g. "mimic YouTube streaming from Russia")
    pub intent: String,
    /// Base protocol to use
    pub protocol: Protocol,
    /// Target service to mimic
    #[serde(default)]
    pub mimic_service: Option<MimicTarget>,
    /// Threat level that triggered this generation (0-10)
    #[serde(default)]
    pub threat_level: u8,
    /// Current profile ID to evolve from (if mutating)
    #[serde(default)]
    pub evolve_from: Option<String>,
    /// Specific constraints
    #[serde(default)]
    pub constraints: ProfileConstraints,
}

/// Known services to mimic
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MimicTarget {
    Youtube,
    Netflix,
    Zoom,
    Teams,
    Discord,
    Steam,
    Telegram,
    Whatsapp,
    GenericHttps,
    GenericWebsocket,
}

/// Constraints on generated profiles
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProfileConstraints {
    /// Maximum port number (some networks block high ports)
    #[serde(default)]
    pub max_port: Option<u16>,
    /// Must use TLS obfuscation
    #[serde(default)]
    pub require_tls: bool,
    /// Maximum MTU
    #[serde(default)]
    pub max_mtu: Option<u16>,
    /// Banned protocols (already detected)
    #[serde(default)]
    pub banned_protocols: Vec<Protocol>,
    /// Banned ports
    #[serde(default)]
    pub banned_ports: Vec<u16>,
    /// Maximum concurrent connections
    #[serde(default)]
    pub max_concurrent: Option<u32>,
}

/// Result of profile generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratedProfile {
    /// The generated traffic profile
    pub profile: TrafficProfile,
    /// Confidence that this will evade detection (0.0-1.0)
    pub evasion_confidence: f32,
    /// Reasoning for the choices made
    pub reasoning: String,
    /// Estimated lifespan before fingerprinting (hours)
    pub estimated_lifespan_hours: u32,
    /// Mutation history (if evolved)
    pub lineage: Vec<String>,
}

/// LLM prompt for profile generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmProfilePrompt {
    pub system: String,
    pub user: String,
}

/// The profile generation engine
pub struct ProfileGenerator {
    /// Known service traffic signatures
    service_signatures: HashMap<String, ServiceSignature>,
    /// History of generated profiles
    generation_history: parking_lot::RwLock<Vec<GeneratedProfile>>,
    /// Profiles that were detected/blocked (avoid repeating)
    burned_patterns: parking_lot::RwLock<Vec<BurnedPattern>>,
}

/// Traffic signature of a known service
#[derive(Debug, Clone)]
struct ServiceSignature {
    typical_packet_sizes: Vec<(u16, u16)>, // (min, max) ranges
    typical_intervals_ms: (u32, u32),
    typical_burst_size: (u32, u32),
    jitter_range: (u8, u8),
    typical_port: u16,
    uses_tls: bool,
    bidirectional_ratio: f32, // upload/download ratio
}

/// A pattern that was detected and should be avoided
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BurnedPattern {
    pub profile_id: String,
    pub timestamp: u64,
    pub reason: String,
    /// Specific characteristics to avoid
    pub fingerprint: PatternFingerprint,
}

/// Fingerprint of a detected pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternFingerprint {
    pub protocol: Protocol,
    pub port: u16,
    pub packet_size_range: (u16, u16),
    pub interval_range_ms: (u32, u32),
    pub obfuscation: ObfuscationType,
}

impl ProfileGenerator {
    pub fn new() -> Self {
        let mut signatures = HashMap::new();

        // YouTube streaming signature
        signatures.insert(
            "youtube".to_string(),
            ServiceSignature {
                typical_packet_sizes: vec![(1200, 1460), (64, 200)], // video chunks + acks
                typical_intervals_ms: (16, 50),  // 20-60fps
                typical_burst_size: (5, 15),
                jitter_range: (10, 25),
                typical_port: 443,
                uses_tls: true,
                bidirectional_ratio: 0.05, // mostly download
            },
        );

        // Zoom/video call signature
        signatures.insert(
            "zoom".to_string(),
            ServiceSignature {
                typical_packet_sizes: vec![(200, 800), (100, 400)],
                typical_intervals_ms: (10, 33),
                typical_burst_size: (2, 5),
                jitter_range: (5, 20),
                typical_port: 443,
                uses_tls: true,
                bidirectional_ratio: 0.7, // roughly symmetrical
            },
        );

        // Discord voice signature
        signatures.insert(
            "discord".to_string(),
            ServiceSignature {
                typical_packet_sizes: vec![(80, 200), (60, 150)],
                typical_intervals_ms: (15, 25),
                typical_burst_size: (1, 3),
                jitter_range: (5, 15),
                typical_port: 443,
                uses_tls: true,
                bidirectional_ratio: 0.8,
            },
        );

        // Steam gaming signature
        signatures.insert(
            "steam".to_string(),
            ServiceSignature {
                typical_packet_sizes: vec![(40, 120), (40, 80)],
                typical_intervals_ms: (8, 20),  // high tick rate
                typical_burst_size: (1, 2),
                jitter_range: (2, 8),
                typical_port: 443,
                uses_tls: true,
                bidirectional_ratio: 0.9,
            },
        );

        // Generic HTTPS browsing
        signatures.insert(
            "generic_https".to_string(),
            ServiceSignature {
                typical_packet_sizes: vec![(64, 1460), (40, 200)],
                typical_intervals_ms: (1, 5000),
                typical_burst_size: (5, 30),
                jitter_range: (20, 60),
                typical_port: 443,
                uses_tls: true,
                bidirectional_ratio: 0.15,
            },
        );

        // Telegram messaging
        signatures.insert(
            "telegram".to_string(),
            ServiceSignature {
                typical_packet_sizes: vec![(100, 600), (64, 200)],
                typical_intervals_ms: (50, 10000),
                typical_burst_size: (2, 8),
                jitter_range: (15, 40),
                typical_port: 443,
                uses_tls: true,
                bidirectional_ratio: 0.4,
            },
        );

        Self {
            service_signatures: signatures,
            generation_history: parking_lot::RwLock::new(Vec::new()),
            burned_patterns: parking_lot::RwLock::new(Vec::new()),
        }
    }

    /// Generate a new traffic profile based on the request
    pub fn generate(&self, request: &ProfileGenerationRequest) -> Result<GeneratedProfile> {
        info!("Generating profile: intent='{}', protocol={:?}", request.intent, request.protocol);

        let mut rng = rand::thread_rng();

        // Determine base signature
        let signature = self.resolve_signature(request);

        // Check burned patterns and adjust
        let burned = self.burned_patterns.read();

        // Generate timing profile with randomization
        let timing = self.generate_timing(&signature, &request.constraints, &mut rng);

        // Generate padding profile
        let padding = self.generate_padding(&signature, &request.constraints, &mut rng);

        // Select obfuscation
        let obfuscation = self.select_obfuscation(request, &burned);

        // Select port
        let port = self.select_port(request, &signature, &burned, &mut rng);

        // Max concurrent based on mimic target
        let max_concurrent = request
            .constraints
            .max_concurrent
            .unwrap_or_else(|| self.default_max_concurrent(&request.mimic_service));

        // Build profile ID
        let id = format!(
            "dyn_{}_{}",
            request.protocol,
            chrono::Utc::now().format("%Y%m%d_%H%M%S")
        );

        let profile = TrafficProfile {
            id: id.clone(),
            name: format!("Dynamic: {}", request.intent),
            protocol: request.protocol,
            port,
            obfuscation,
            timing,
            padding,
            max_concurrent,
            custom_config: HashMap::new(),
        };

        // Calculate evasion confidence
        let evasion_confidence = self.estimate_evasion_confidence(&profile, &burned);

        // Estimate lifespan
        let estimated_lifespan = self.estimate_lifespan(evasion_confidence, request.threat_level);

        let lineage = if let Some(ref parent) = request.evolve_from {
            let mut l = self.get_lineage(parent);
            l.push(parent.clone());
            l
        } else {
            vec![]
        };

        let reasoning = self.build_reasoning(request, &profile, evasion_confidence);

        let generated = GeneratedProfile {
            profile,
            evasion_confidence,
            reasoning,
            estimated_lifespan_hours: estimated_lifespan,
            lineage,
        };

        // Store in history
        self.generation_history.write().push(generated.clone());

        info!(
            "Generated profile '{}': evasion={:.0}%, lifespan={}h",
            id,
            evasion_confidence * 100.0,
            estimated_lifespan
        );

        Ok(generated)
    }

    /// Mutate an existing profile to create a variant
    pub fn mutate(&self, profile: &TrafficProfile, mutation_strength: f32) -> Result<GeneratedProfile> {
        info!(
            "Mutating profile '{}' with strength {:.2}",
            profile.id, mutation_strength
        );

        let mut rng = rand::thread_rng();
        let strength = mutation_strength.clamp(0.0, 1.0);

        // Clone and mutate timing
        let mut timing = profile.timing.clone();
        let jitter_delta = (strength * 20.0) as u8;
        timing.jitter_percent = timing
            .jitter_percent
            .saturating_add(rng.gen_range(0..=jitter_delta))
            .min(80);

        let interval_delta = (strength * 50.0) as u32;
        timing.min_interval_ms = timing
            .min_interval_ms
            .saturating_add(rng.gen_range(0..=interval_delta / 2));
        timing.max_interval_ms = timing
            .max_interval_ms
            .saturating_add(rng.gen_range(0..=interval_delta));
        timing.burst_size = (timing.burst_size as f32 * (1.0 + rng.gen_range(-strength..strength)))
            .max(1.0) as u32;

        // Clone and mutate padding
        let mut padding = profile.padding.clone();
        let size_delta = (strength * 100.0) as u16;
        padding.min_size = padding.min_size.saturating_add(rng.gen_range(0..=size_delta / 2));
        padding.max_size = padding.max_size.saturating_add(rng.gen_range(0..=size_delta));
        padding.target_mtu = padding
            .target_mtu
            .saturating_add(rng.gen_range(0..=size_delta / 4))
            .min(1500);

        let new_id = format!(
            "{}_mut_{}",
            profile.id,
            chrono::Utc::now().format("%H%M%S")
        );

        let new_profile = TrafficProfile {
            id: new_id.clone(),
            name: format!("{} (mutated)", profile.name),
            protocol: profile.protocol,
            port: profile.port,
            obfuscation: profile.obfuscation,
            timing,
            padding,
            max_concurrent: profile.max_concurrent,
            custom_config: profile.custom_config.clone(),
        };

        let burned = self.burned_patterns.read();
        let evasion_confidence = self.estimate_evasion_confidence(&new_profile, &burned);
        let estimated_lifespan = self.estimate_lifespan(evasion_confidence, 5);

        let mut lineage = self.get_lineage(&profile.id);
        lineage.push(profile.id.clone());

        let generated = GeneratedProfile {
            profile: new_profile,
            evasion_confidence,
            reasoning: format!(
                "Mutated from '{}' with strength {:.2}. Adjusted timing jitter, intervals, and padding sizes.",
                profile.id, mutation_strength
            ),
            estimated_lifespan_hours: estimated_lifespan,
            lineage,
        };

        self.generation_history.write().push(generated.clone());

        Ok(generated)
    }

    /// Build the LLM prompt for profile generation
    pub fn build_llm_prompt(&self, request: &ProfileGenerationRequest) -> LlmProfilePrompt {
        let burned = self.burned_patterns.read();
        let burned_summary: Vec<String> = burned
            .iter()
            .map(|b| {
                format!(
                    "- {} ({}): {:?} on port {}, sizes {}-{}, intervals {}-{}ms",
                    b.profile_id,
                    b.reason,
                    b.fingerprint.protocol,
                    b.fingerprint.port,
                    b.fingerprint.packet_size_range.0,
                    b.fingerprint.packet_size_range.1,
                    b.fingerprint.interval_range_ms.0,
                    b.fingerprint.interval_range_ms.1,
                )
            })
            .collect();

        let system = format!(
            r#"You are a network traffic engineer designing VPN traffic profiles that evade Deep Packet Inspection (DPI).

Your goal: create a traffic profile that mimics legitimate service traffic so convincingly that statistical analysis cannot distinguish it from the real service.

Rules:
1. NEVER reuse patterns from burned profiles
2. Add realistic jitter — real services are never perfectly periodic
3. Vary packet sizes to match the target service distribution
4. Choose ports commonly associated with the mimicked service
5. Consider bidirectional traffic ratios

Available protocols: wireguard, amneziawg, cloak, shadowsocks, v2ray, xray
Available obfuscation: none, tls_1_3, websocket_upgrade, http2, quic, grpc, meek
Available timing patterns: constant, webrtc_pattern, game_traffic_pattern, video_stream, web_browsing, bursty
Available padding: none, fixed_mtu, variable, random

Respond with valid JSON matching this schema:
{{
  "profile_id": "string",
  "protocol": "string",
  "port": number,
  "obfuscation": "string",
  "timing": {{
    "pattern": "string",
    "min_interval_ms": number,
    "max_interval_ms": number,
    "jitter_percent": number,
    "burst_size": number,
    "burst_interval_ms": number
  }},
  "padding": {{
    "type": "string",
    "min_size": number,
    "max_size": number,
    "target_mtu": number
  }},
  "max_concurrent": number,
  "reasoning": "string",
  "evasion_confidence": number
}}"#
        );

        let burned_section = if burned_summary.is_empty() {
            "No burned profiles.".to_string()
        } else {
            format!("BURNED profiles (DO NOT replicate):\n{}", burned_summary.join("\n"))
        };

        let constraints_section = format!(
            "Constraints:\n- Banned protocols: {:?}\n- Banned ports: {:?}\n- Require TLS: {}\n- Max MTU: {:?}",
            request.constraints.banned_protocols,
            request.constraints.banned_ports,
            request.constraints.require_tls,
            request.constraints.max_mtu
        );

        let user = format!(
            r#"Generate a traffic profile for the following scenario:

Intent: {}
Base protocol: {:?}
Mimic target: {:?}
Threat level: {}/10
Evolve from: {:?}

{}

{}

Produce the profile JSON."#,
            request.intent,
            request.protocol,
            request.mimic_service,
            request.threat_level,
            request.evolve_from,
            burned_section,
            constraints_section,
        );

        LlmProfilePrompt { system, user }
    }

    /// Mark a profile as burned (detected/blocked)
    pub fn burn_profile(&self, profile: &TrafficProfile, reason: &str) {
        warn!("Burning profile '{}': {}", profile.id, reason);

        let fingerprint = PatternFingerprint {
            protocol: profile.protocol,
            port: profile.port,
            packet_size_range: (profile.padding.min_size, profile.padding.max_size),
            interval_range_ms: (profile.timing.min_interval_ms, profile.timing.max_interval_ms),
            obfuscation: profile.obfuscation,
        };

        self.burned_patterns.write().push(BurnedPattern {
            profile_id: profile.id.clone(),
            timestamp: crate::telemetry::current_timestamp(),
            reason: reason.to_string(),
            fingerprint,
        });
    }

    /// Get generation history
    pub fn history(&self) -> Vec<GeneratedProfile> {
        self.generation_history.read().clone()
    }

    /// Get burned patterns
    pub fn burned(&self) -> Vec<BurnedPattern> {
        self.burned_patterns.read().clone()
    }

    // --- Private helpers ---

    fn resolve_signature(&self, request: &ProfileGenerationRequest) -> ServiceSignature {
        let key = match &request.mimic_service {
            Some(MimicTarget::Youtube) | Some(MimicTarget::Netflix) => "youtube",
            Some(MimicTarget::Zoom) | Some(MimicTarget::Teams) => "zoom",
            Some(MimicTarget::Discord) => "discord",
            Some(MimicTarget::Steam) => "steam",
            Some(MimicTarget::Telegram) | Some(MimicTarget::Whatsapp) => "telegram",
            Some(MimicTarget::GenericWebsocket) => "generic_https",
            _ => "generic_https",
        };

        self.service_signatures
            .get(key)
            .cloned()
            .unwrap_or_else(|| self.service_signatures["generic_https"].clone())
    }

    fn generate_timing(
        &self,
        sig: &ServiceSignature,
        constraints: &ProfileConstraints,
        rng: &mut impl Rng,
    ) -> TimingProfile {
        let jitter = rng.gen_range(sig.jitter_range.0..=sig.jitter_range.1);

        // Add some randomness to intervals
        let min_int = sig.typical_intervals_ms.0.saturating_add(rng.gen_range(0..5));
        let max_int = sig.typical_intervals_ms.1.saturating_add(rng.gen_range(0..20));
        let burst = rng.gen_range(sig.typical_burst_size.0..=sig.typical_burst_size.1);

        let pattern = if max_int - min_int > 1000 {
            TimingPattern::WebBrowsing
        } else if min_int < 20 && burst <= 3 {
            TimingPattern::GameTrafficPattern
        } else if min_int < 40 {
            TimingPattern::WebrtcPattern
        } else {
            TimingPattern::Bursty
        };

        TimingProfile {
            pattern,
            min_interval_ms: min_int,
            max_interval_ms: max_int,
            jitter_percent: jitter,
            burst_size: burst,
            burst_interval_ms: rng.gen_range(5..=200),
        }
    }

    fn generate_padding(
        &self,
        sig: &ServiceSignature,
        constraints: &ProfileConstraints,
        rng: &mut impl Rng,
    ) -> PaddingProfile {
        let (size_min, size_max) = if let Some(&(lo, hi)) = sig.typical_packet_sizes.first() {
            (
                lo.saturating_add(rng.gen_range(0..20)),
                hi.saturating_add(rng.gen_range(0..20)),
            )
        } else {
            (64, 1460)
        };

        let target_mtu = constraints.max_mtu.unwrap_or(1420).min(1500);

        PaddingProfile {
            padding_type: PaddingType::Variable,
            min_size: size_min,
            max_size: size_max.min(target_mtu),
            target_mtu,
            size_distribution: Some(SizeDistribution::HttpsLike),
        }
    }

    fn select_obfuscation(
        &self,
        request: &ProfileGenerationRequest,
        burned: &[BurnedPattern],
    ) -> ObfuscationType {
        if request.constraints.require_tls {
            return ObfuscationType::Tls1_3;
        }

        let obfuscation_options = [
            ObfuscationType::Tls1_3,
            ObfuscationType::WebsocketUpgrade,
            ObfuscationType::Http2,
            ObfuscationType::Quic,
        ];

        // Filter out burned obfuscation types
        let burned_obfs: Vec<_> = burned.iter().map(|b| b.fingerprint.obfuscation).collect();

        for opt in &obfuscation_options {
            if !burned_obfs.contains(opt) {
                return *opt;
            }
        }

        // All burned, cycle back to TLS 1.3 (most common, least suspicious)
        ObfuscationType::Tls1_3
    }

    fn select_port(
        &self,
        request: &ProfileGenerationRequest,
        sig: &ServiceSignature,
        burned: &[BurnedPattern],
        rng: &mut impl Rng,
    ) -> u16 {
        let preferred_ports = [443, 8443, 993, 995, 587, 465, 8080, 80];
        let burned_ports: Vec<u16> = burned.iter().map(|b| b.fingerprint.port).collect();
        let banned = &request.constraints.banned_ports;

        // Try the signature's typical port first
        if !burned_ports.contains(&sig.typical_port) && !banned.contains(&sig.typical_port) {
            return sig.typical_port;
        }

        // Try preferred ports
        for &port in &preferred_ports {
            if !burned_ports.contains(&port)
                && !banned.contains(&port)
                && request
                    .constraints
                    .max_port
                    .map_or(true, |max| port <= max)
            {
                return port;
            }
        }

        // Random high port as last resort
        rng.gen_range(1024..=65535)
    }

    fn default_max_concurrent(&self, mimic: &Option<MimicTarget>) -> u32 {
        match mimic {
            Some(MimicTarget::Zoom) | Some(MimicTarget::Teams) => 10,
            Some(MimicTarget::Discord) => 20,
            Some(MimicTarget::Steam) => 15,
            Some(MimicTarget::Telegram) | Some(MimicTarget::Whatsapp) => 50,
            _ => 100,
        }
    }

    fn estimate_evasion_confidence(&self, profile: &TrafficProfile, burned: &[BurnedPattern]) -> f32 {
        let mut confidence = 0.7; // Base confidence

        // Boost for TLS obfuscation
        if matches!(
            profile.obfuscation,
            ObfuscationType::Tls1_3 | ObfuscationType::Http2
        ) {
            confidence += 0.1;
        }

        // Boost for variable padding
        if matches!(profile.padding.padding_type, PaddingType::Variable) {
            confidence += 0.05;
        }

        // Boost for realistic jitter
        if profile.timing.jitter_percent >= 10 && profile.timing.jitter_percent <= 40 {
            confidence += 0.05;
        }

        // Penalty for using port 443 (heavily monitored)
        if profile.port == 443 {
            confidence -= 0.02;
        }

        // Penalty for similarity to burned profiles
        for burned_pat in burned {
            let fp = &burned_pat.fingerprint;
            let mut similarity = 0.0f32;

            if fp.protocol == profile.protocol {
                similarity += 0.3;
            }
            if fp.port == profile.port {
                similarity += 0.2;
            }
            if fp.obfuscation == profile.obfuscation {
                similarity += 0.2;
            }

            // Packet size overlap
            let size_overlap = self.range_overlap(
                (fp.packet_size_range.0, fp.packet_size_range.1),
                (profile.padding.min_size, profile.padding.max_size),
            );
            similarity += size_overlap * 0.15;

            // Interval overlap
            let interval_overlap = self.range_overlap_u32(
                fp.interval_range_ms,
                (profile.timing.min_interval_ms, profile.timing.max_interval_ms),
            );
            similarity += interval_overlap * 0.15;

            confidence -= similarity * 0.15; // Penalize per burned profile
        }

        confidence.clamp(0.1, 0.99)
    }

    fn range_overlap(&self, a: (u16, u16), b: (u16, u16)) -> f32 {
        let overlap_start = a.0.max(b.0);
        let overlap_end = a.1.min(b.1);
        if overlap_start >= overlap_end {
            return 0.0;
        }
        let overlap = (overlap_end - overlap_start) as f32;
        let total = (a.1 - a.0).max(b.1 - b.0).max(1) as f32;
        (overlap / total).clamp(0.0, 1.0)
    }

    fn range_overlap_u32(&self, a: (u32, u32), b: (u32, u32)) -> f32 {
        let overlap_start = a.0.max(b.0);
        let overlap_end = a.1.min(b.1);
        if overlap_start >= overlap_end {
            return 0.0;
        }
        let overlap = (overlap_end - overlap_start) as f32;
        let total = (a.1 - a.0).max(b.1 - b.0).max(1) as f32;
        (overlap / total).clamp(0.0, 1.0)
    }

    fn estimate_lifespan(&self, evasion_confidence: f32, threat_level: u8) -> u32 {
        let base_hours = (evasion_confidence * 200.0) as u32;
        let threat_factor = 1.0 - (threat_level as f32 / 15.0);
        (base_hours as f32 * threat_factor).max(1.0) as u32
    }

    fn get_lineage(&self, profile_id: &str) -> Vec<String> {
        self.generation_history
            .read()
            .iter()
            .find(|g| g.profile.id == profile_id)
            .map(|g| g.lineage.clone())
            .unwrap_or_default()
    }

    fn build_reasoning(
        &self,
        request: &ProfileGenerationRequest,
        profile: &TrafficProfile,
        confidence: f32,
    ) -> String {
        format!(
            "Generated {:?} profile on port {} with {:?} obfuscation mimicking {:?}. \
             Timing: {}-{}ms intervals, {}% jitter, burst size {}. \
             Padding: {}-{} bytes. \
             Evasion confidence: {:.0}%. \
             Threat level: {}/10.",
            profile.protocol,
            profile.port,
            profile.obfuscation,
            request.mimic_service,
            profile.timing.min_interval_ms,
            profile.timing.max_interval_ms,
            profile.timing.jitter_percent,
            profile.timing.burst_size,
            profile.padding.min_size,
            profile.padding.max_size,
            confidence * 100.0,
            request.threat_level,
        )
    }
}

impl Default for ProfileGenerator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_profile() {
        let gen = ProfileGenerator::new();

        let request = ProfileGenerationRequest {
            intent: "mimic YouTube streaming".to_string(),
            protocol: Protocol::Cloak,
            mimic_service: Some(MimicTarget::Youtube),
            threat_level: 5,
            evolve_from: None,
            constraints: ProfileConstraints::default(),
        };

        let result = gen.generate(&request).unwrap();
        assert!(result.evasion_confidence > 0.5);
        assert!(!result.reasoning.is_empty());
        assert!(result.estimated_lifespan_hours > 0);
    }

    #[test]
    fn test_mutate_profile() {
        let gen = ProfileGenerator::new();

        let request = ProfileGenerationRequest {
            intent: "test".to_string(),
            protocol: Protocol::Amneziawg,
            mimic_service: Some(MimicTarget::Zoom),
            threat_level: 3,
            evolve_from: None,
            constraints: ProfileConstraints::default(),
        };

        let original = gen.generate(&request).unwrap();
        let mutated = gen.mutate(&original.profile, 0.5).unwrap();

        assert_ne!(mutated.profile.id, original.profile.id);
        assert!(mutated.lineage.contains(&original.profile.id));
    }

    #[test]
    fn test_burn_profile_avoidance() {
        let gen = ProfileGenerator::new();

        // Generate first profile
        let request = ProfileGenerationRequest {
            intent: "test".to_string(),
            protocol: Protocol::Cloak,
            mimic_service: Some(MimicTarget::GenericHttps),
            threat_level: 5,
            evolve_from: None,
            constraints: ProfileConstraints::default(),
        };

        let first = gen.generate(&request).unwrap();
        let first_confidence = first.evasion_confidence;

        // Burn it
        gen.burn_profile(&first.profile, "Detected by DPI");

        // Generate another - confidence should be affected
        let second = gen.generate(&request).unwrap();
        // The new profile should still have reasonable confidence
        assert!(second.evasion_confidence > 0.3);
    }

    #[test]
    fn test_llm_prompt_generation() {
        let gen = ProfileGenerator::new();

        let request = ProfileGenerationRequest {
            intent: "evade TSPU detection".to_string(),
            protocol: Protocol::Shadowsocks,
            mimic_service: Some(MimicTarget::Telegram),
            threat_level: 8,
            evolve_from: None,
            constraints: ProfileConstraints {
                require_tls: true,
                banned_ports: vec![80],
                ..Default::default()
            },
        };

        let prompt = gen.build_llm_prompt(&request);
        assert!(prompt.system.contains("DPI"));
        assert!(prompt.user.contains("Telegram"));
        assert!(prompt.user.contains("8/10"));
    }
}
