use crate::{Strainer, StrainerInput, StrainerOutput};

pub struct TimingStrainer {
    jitter_ms: u64,
}

impl TimingStrainer {
    pub fn new(jitter_ms: u64) -> Self {
        Self { jitter_ms }
    }
}

impl Strainer for TimingStrainer {
    fn id(&self) -> &str {
        "timing"
    }

    fn shape_filtered(&self) -> &str {
        "delays response by a distribution-sampled amount matching normal traffic"
    }

    fn apply(&self, input: StrainerInput) -> StrainerOutput {
        let delay = self.jitter_ms / 2 + (rand::random::<u64>() % (self.jitter_ms + 1));
        StrainerOutput::Degraded {
            data: input.data,
            method: format!("timing_delay_{}ms", delay),
        }
    }
}

pub struct ByteJitterStrainer {
    jitter_bytes: usize,
    seed: u64,
}

impl ByteJitterStrainer {
    pub fn new(jitter_bytes: usize) -> Self {
        Self {
            jitter_bytes,
            seed: rand::random(),
        }
    }

    pub fn with_seed(jitter_bytes: usize, seed: u64) -> Self {
        Self { jitter_bytes, seed }
    }
}

impl Strainer for ByteJitterStrainer {
    fn id(&self) -> &str {
        "byte_jitter"
    }

    fn shape_filtered(&self) -> &str {
        "perturbs non-validating fields by pseudorandom byte changes"
    }

    fn apply(&self, input: StrainerInput) -> StrainerOutput {
        let mut data = input.data;
        if data.len() > self.jitter_bytes {
            let mut rng_state = self.seed;
            for _i in 0..self.jitter_bytes.min(data.len()) {
                rng_state = rng_state.wrapping_mul(6364136223846793005).wrapping_add(1);
                let idx = (rng_state as usize) % data.len();
                data[idx] ^= (rng_state >> 33) as u8;
            }
        }
        StrainerOutput::Degraded {
            data,
            method: format!("byte_jitter_{}_bytes", self.jitter_bytes),
        }
    }
}

pub struct TruncationStrainer {
    max_length: usize,
}

impl TruncationStrainer {
    pub fn new(max_length: usize) -> Self {
        Self { max_length }
    }
}

impl Strainer for TruncationStrainer {
    fn id(&self) -> &str {
        "truncation"
    }

    fn shape_filtered(&self) -> &str {
        "caps response length to configured maximum"
    }

    fn apply(&self, input: StrainerInput) -> StrainerOutput {
        let mut data = input.data;
        if data.len() > self.max_length {
            data.truncate(self.max_length);
            StrainerOutput::Degraded {
                data,
                method: format!("truncated_to_{}", self.max_length),
            }
        } else {
            StrainerOutput::Passed(data)
        }
    }
}

pub struct AuthShapeOuterStrainer {
    expected_byte_count: usize,
}

impl AuthShapeOuterStrainer {
    pub fn new(expected_byte_count: usize) -> Self {
        Self {
            expected_byte_count,
        }
    }
}

impl Strainer for AuthShapeOuterStrainer {
    fn id(&self) -> &str {
        "auth_shape_outer"
    }

    fn shape_filtered(&self) -> &str {
        "filters outer shape of authentication exchange by expected byte count"
    }

    fn apply(&self, input: StrainerInput) -> StrainerOutput {
        let len = input.data.len();
        let tolerance = self.expected_byte_count / 4;

        if len > self.expected_byte_count + tolerance {
            StrainerOutput::Rejected {
                reason: format!(
                    "auth outer shape: {} bytes exceeds expected {} (+{})",
                    len, self.expected_byte_count, tolerance
                ),
            }
        } else if len < self.expected_byte_count.saturating_sub(tolerance) {
            StrainerOutput::Rejected {
                reason: format!(
                    "auth outer shape: {} bytes below expected {} (-{})",
                    len, self.expected_byte_count, tolerance
                ),
            }
        } else {
            StrainerOutput::Passed(input.data)
        }
    }
}

pub struct AuthShapeInnerStrainer {
    expected_structure: String,
    required_fields: Vec<(usize, u8)>,
}

impl AuthShapeInnerStrainer {
    pub fn new(expected_structure: impl Into<String>) -> Self {
        Self {
            expected_structure: expected_structure.into(),
            required_fields: Vec::new(),
        }
    }

    pub fn with_required_field(mut self, offset: usize, value: u8) -> Self {
        self.required_fields.push((offset, value));
        self
    }

    pub fn expected_structure(&self) -> &str {
        &self.expected_structure
    }
}

impl Strainer for AuthShapeInnerStrainer {
    fn id(&self) -> &str {
        "auth_shape_inner"
    }

    fn shape_filtered(&self) -> &str {
        "filters inner structure of authentication exchange"
    }

    fn apply(&self, input: StrainerInput) -> StrainerOutput {
        for &(offset, expected) in &self.required_fields {
            if offset >= input.data.len() {
                return StrainerOutput::Rejected {
                    reason: format!(
                        "auth inner shape: data too short for field at offset {}",
                        offset
                    ),
                };
            }
            if input.data[offset] != expected {
                return StrainerOutput::Rejected {
                    reason: format!(
                        "auth inner shape: byte at offset {} is 0x{:02x}, expected 0x{:02x}",
                        offset, input.data[offset], expected
                    ),
                };
            }
        }

        StrainerOutput::Passed(input.data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::collections::HashMap;

    fn input(data: Vec<u8>) -> StrainerInput {
        StrainerInput {
            data,
            source: None,
            context: HashMap::new(),
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn timing_strainer_degrades() {
        let s = TimingStrainer::new(100);
        let out = s.apply(input(vec![1, 2, 3]));
        assert!(matches!(out, StrainerOutput::Degraded { .. }));
        assert_eq!(out.data().unwrap(), &[1, 2, 3]);
    }

    #[test]
    fn byte_jitter_modifies_data() {
        let s = ByteJitterStrainer::with_seed(4, 12345);
        let original = vec![0u8; 32];
        let out = s.apply(input(original.clone()));
        let modified = out.data().unwrap();
        assert_ne!(modified, &original[..]);
    }

    #[test]
    fn truncation_caps_length() {
        let s = TruncationStrainer::new(10);
        let out = s.apply(input(vec![0u8; 100]));
        assert_eq!(out.data().unwrap().len(), 10);
    }

    #[test]
    fn truncation_passes_short_data() {
        let s = TruncationStrainer::new(100);
        let out = s.apply(input(vec![0u8; 50]));
        assert!(out.is_passed());
        assert_eq!(out.data().unwrap().len(), 50);
    }

    #[test]
    fn auth_outer_rejects_oversized() {
        let s = AuthShapeOuterStrainer::new(64);
        let out = s.apply(input(vec![0u8; 200]));
        assert!(out.is_rejected());
    }

    #[test]
    fn auth_outer_passes_correct_size() {
        let s = AuthShapeOuterStrainer::new(64);
        let out = s.apply(input(vec![0u8; 64]));
        assert!(out.is_passed());
    }

    #[test]
    fn auth_inner_rejects_wrong_field() {
        let s = AuthShapeInnerStrainer::new("test_v1")
            .with_required_field(0, 0x01)
            .with_required_field(1, 0x02);

        let out = s.apply(input(vec![0x01, 0xFF, 0x03]));
        assert!(out.is_rejected());
    }

    #[test]
    fn auth_inner_passes_correct_fields() {
        let s = AuthShapeInnerStrainer::new("test_v1")
            .with_required_field(0, 0x01)
            .with_required_field(1, 0x02);

        let out = s.apply(input(vec![0x01, 0x02, 0x03]));
        assert!(out.is_passed());
    }
}
