use std::time::Duration;

use imperium_protocol::{PaddingDistribution, ProtocolHardeningProfile};
use serde::{Deserialize, Serialize};

const HARDENED_FRAME_VERSION: u8 = 1;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HardenedPacketFrame {
    pub version: u8,
    pub profile_id: String,
    pub payload: Vec<u8>,
    pub original_len: u16,
    pub padded_len: u16,
    pub padding_len: u16,
    pub jitter_delay_ms: u16,
    pub rekey_epoch: u64,
    pub fec_group_id: u64,
    pub fec_index: u8,
    pub fec_data_shards: u8,
    pub fec_parity_shards: u8,
    pub cover: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HardenedPayload {
    pub bytes: Vec<u8>,
    pub delay: Duration,
    pub rekey_epoch: u64,
    pub cover: bool,
}

#[derive(Clone, Debug)]
pub struct MeshHardener {
    profile: ProtocolHardeningProfile,
    packet_seq: u64,
    bytes_in_epoch: u64,
    rekey_epoch: u64,
}

impl MeshHardener {
    pub fn new(profile: ProtocolHardeningProfile) -> Self {
        Self {
            profile,
            packet_seq: 0,
            bytes_in_epoch: 0,
            rekey_epoch: 0,
        }
    }

    pub fn profile_id(&self) -> &str {
        &self.profile.profile_id
    }

    pub fn harden_payload(&mut self, payload: Vec<u8>, cover: bool) -> HardenedPayload {
        let original_len = payload.len().min(u16::MAX as usize) as u16;
        self.packet_seq = self.packet_seq.saturating_add(1);
        self.bytes_in_epoch = self.bytes_in_epoch.saturating_add(payload.len() as u64);

        if self.bytes_in_epoch >= self.profile.rekey.max_key_bytes {
            self.rekey_epoch = self.rekey_epoch.saturating_add(1);
            self.bytes_in_epoch = payload.len() as u64;
        }

        let padded_len = padded_len(
            original_len,
            &self.profile.traffic_morph.padding,
            self.profile.traffic_morph.max_padding_overhead_ppm,
            self.packet_seq,
        );
        let padding_len = padded_len.saturating_sub(original_len);

        let mut padded_payload = payload;
        padded_payload.extend(std::iter::repeat(0u8).take(padding_len as usize));

        let jitter_delay_ms = deterministic_jitter(
            self.profile.traffic_morph.jitter_floor_ms,
            self.profile.traffic_morph.jitter_ceiling_ms,
            self.packet_seq,
        );

        let fec_data_shards = if self.profile.fec.enabled {
            self.profile.fec.data_shards
        } else {
            0
        };
        let fec_parity_shards = if self.profile.fec.enabled {
            self.profile.fec.parity_shards
        } else {
            0
        };
        let fec_group_id = if fec_data_shards == 0 {
            0
        } else {
            (self.packet_seq - 1) / u64::from(fec_data_shards)
        };
        let fec_index = if fec_data_shards == 0 {
            0
        } else {
            ((self.packet_seq - 1) % u64::from(fec_data_shards)) as u8
        };

        let frame = HardenedPacketFrame {
            version: HARDENED_FRAME_VERSION,
            profile_id: self.profile.profile_id.clone(),
            payload: padded_payload,
            original_len,
            padded_len,
            padding_len,
            jitter_delay_ms,
            rekey_epoch: self.rekey_epoch,
            fec_group_id,
            fec_index,
            fec_data_shards,
            fec_parity_shards,
            cover,
        };

        HardenedPayload {
            bytes: serde_json::to_vec(&frame).expect("serialize hardened packet frame"),
            delay: Duration::from_millis(u64::from(jitter_delay_ms)),
            rekey_epoch: self.rekey_epoch,
            cover,
        }
    }

    pub fn recover_payload(bytes: &[u8]) -> Vec<u8> {
        if let Ok(frame) = serde_json::from_slice::<HardenedPacketFrame>(bytes) {
            if frame.version == HARDENED_FRAME_VERSION
                && usize::from(frame.original_len) <= frame.payload.len()
            {
                return frame.payload[..usize::from(frame.original_len)].to_vec();
            }
        }

        bytes.to_vec()
    }
}

fn padded_len(
    original_len: u16,
    distribution: &PaddingDistribution,
    max_padding_overhead_ppm: u32,
    packet_seq: u64,
) -> u16 {
    let candidate = match distribution {
        PaddingDistribution::None => original_len,
        PaddingDistribution::Fixed { bytes } => original_len.saturating_add(*bytes),
        PaddingDistribution::Bucketed { buckets } => buckets
            .iter()
            .copied()
            .find(|bucket| *bucket >= original_len)
            .unwrap_or_else(|| buckets.iter().copied().max().unwrap_or(original_len)),
        PaddingDistribution::Envelope {
            min_bytes,
            max_bytes,
        } => {
            let lower = original_len.max(*min_bytes);
            let upper = (*max_bytes).max(lower);
            deterministic_range(lower, upper, packet_seq)
        }
    };

    let max_overhead_bytes =
        (u64::from(original_len) * u64::from(max_padding_overhead_ppm) / 1_000_000) as u16;
    let budget_cap = original_len.saturating_add(max_overhead_bytes);
    candidate.min(budget_cap).max(original_len)
}

fn deterministic_jitter(floor_ms: u16, ceiling_ms: u16, packet_seq: u64) -> u16 {
    deterministic_range(floor_ms, ceiling_ms, packet_seq ^ 0xA5A5)
}

fn deterministic_range(min: u16, max: u16, seed: u64) -> u16 {
    if min >= max {
        return min;
    }

    let value = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
    let span = u64::from(max - min) + 1;
    min + ((value >> 32) % span) as u16
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use imperium_protocol::{
        FecPolicy, PaddingDistribution, PathHoppingPolicy, ProbeDeceptionMode,
        ProbeDeceptionPolicy, ProbeFailureMode, ProbeResistancePolicy, RekeyPolicy,
        TrafficMorphProfile,
    };

    fn test_profile() -> ProtocolHardeningProfile {
        ProtocolHardeningProfile {
            profile_id: "mesh-test".to_string(),
            protocol_name: Some("mesh".to_string()),
            traffic_morph: TrafficMorphProfile {
                profile_id: "mesh-test-morph".to_string(),
                padding: PaddingDistribution::Envelope {
                    min_bytes: 128,
                    max_bytes: 512,
                },
                max_padding_overhead_ppm: 500_000,
                jitter_floor_ms: 1,
                jitter_ceiling_ms: 3,
                cover_traffic_ppm: 0,
                packet_batching_window_ms: 0,
            },
            rekey: RekeyPolicy {
                max_key_age_seconds: 600,
                max_key_bytes: 1_048_576,
                threat_triggered: true,
                stagger_window_ms: 0,
            },
            probe_resistance: ProbeResistancePolicy {
                authenticated_first_packet_required: true,
                unauthenticated_failure_mode: ProbeFailureMode::ConstantShapeReject,
                min_response_delay_ms: 0,
                max_response_delay_ms: 0,
                decoy_response_budget_per_hour: 0,
            },
            probe_deception: ProbeDeceptionPolicy {
                enabled: false,
                mode: ProbeDeceptionMode::Disabled,
                min_confidence: 1.0,
                response_budget_per_source_per_hour: 0,
                min_delay_ms: 0,
                max_delay_ms: 0,
                max_transcript_bytes: 0,
                persona_rotation_seconds: 3_600,
                log_transcripts: false,
            },
            path_hopping: PathHoppingPolicy {
                enabled: true,
                min_dwell_seconds: 60,
                max_dwell_seconds: 300,
                burn_score_threshold: 0.8,
                packet_loss_threshold_ppm: 50_000,
                jitter_threshold_ms: 80,
            },
            fec: FecPolicy {
                enabled: true,
                data_shards: 8,
                parity_shards: 2,
                loss_threshold_ppm: 20_000,
                max_overhead_ppm: 250_000,
            },
            applied_at: Utc::now(),
            reason: "test profile".to_string(),
        }
    }

    #[test]
    fn hardens_and_recovers_payload() {
        let mut hardener = MeshHardener::new(test_profile());
        let original = br#"{"ping":1}"#.to_vec();

        let hardened = hardener.harden_payload(original.clone(), false);
        assert!(hardened.bytes.len() > original.len());
        assert_eq!(MeshHardener::recover_payload(&hardened.bytes), original);
    }

    #[test]
    fn rekey_epoch_advances_on_byte_budget() {
        let mut profile = test_profile();
        profile.rekey.max_key_bytes = 1_048_576;
        let mut hardener = MeshHardener::new(profile);

        let first = hardener.harden_payload(vec![0u8; 800_000], false);
        let second = hardener.harden_payload(vec![0u8; 800_000], false);

        assert_eq!(first.rekey_epoch, 0);
        assert_eq!(second.rekey_epoch, 1);
    }
}
