use imperium_protocol::{NatProbePlan, NatTraversalMode, NatTraversalPolicy, PeerId};

pub struct NatTraversalPlanner;

impl NatTraversalPlanner {
    pub fn default_policy() -> NatTraversalPolicy {
        NatTraversalPolicy {
            allowed_modes: vec![
                NatTraversalMode::DirectUdp,
                NatTraversalMode::StunMappedAddress,
                NatTraversalMode::LimitedCoordinatedProbing,
                NatTraversalMode::RelayThroughPeer,
            ],
            aggressive_probe_opt_in: false,
            max_probe_sockets: 4,
            probes_per_socket: 8,
            probe_window_ms: 1_500,
            relay_fallback_enabled: true,
        }
    }

    pub fn aggressive_policy() -> NatTraversalPolicy {
        NatTraversalPolicy {
            allowed_modes: vec![
                NatTraversalMode::DirectUdp,
                NatTraversalMode::StunMappedAddress,
                NatTraversalMode::LimitedCoordinatedProbing,
                NatTraversalMode::AggressiveBirthdayProbe,
                NatTraversalMode::RelayThroughPeer,
            ],
            aggressive_probe_opt_in: true,
            max_probe_sockets: 256,
            probes_per_socket: 256,
            probe_window_ms: 5_000,
            relay_fallback_enabled: true,
        }
    }

    pub fn build_probe_plan(peer_id: PeerId, policy: &NatTraversalPolicy) -> NatProbePlan {
        let aggressive_allowed = policy.aggressive_probe_opt_in
            && policy
                .allowed_modes
                .iter()
                .any(|mode| matches!(mode, NatTraversalMode::AggressiveBirthdayProbe));

        let socket_count = if aggressive_allowed {
            policy.max_probe_sockets
        } else {
            policy.max_probe_sockets.min(4)
        };

        let probes_per_socket = if aggressive_allowed {
            policy.probes_per_socket
        } else {
            policy.probes_per_socket.min(8)
        };

        let modes = policy
            .allowed_modes
            .iter()
            .filter(|mode| {
                aggressive_allowed || !matches!(mode, NatTraversalMode::AggressiveBirthdayProbe)
            })
            .cloned()
            .collect::<Vec<_>>();

        NatProbePlan {
            peer_id,
            modes,
            socket_count,
            probes_per_socket,
            estimated_probe_count: socket_count as u32 * probes_per_socket as u32,
            relay_fallback_enabled: policy.relay_fallback_enabled,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_excludes_aggressive_probe() {
        let policy = NatTraversalPlanner::default_policy();
        let plan = NatTraversalPlanner::build_probe_plan(PeerId::new(), &policy);

        assert!(!plan
            .modes
            .iter()
            .any(|mode| matches!(mode, NatTraversalMode::AggressiveBirthdayProbe)));
        assert_eq!(plan.estimated_probe_count, 32);
        assert!(plan.relay_fallback_enabled);
    }

    #[test]
    fn aggressive_policy_requires_explicit_opt_in() {
        let policy = NatTraversalPlanner::aggressive_policy();
        let plan = NatTraversalPlanner::build_probe_plan(PeerId::new(), &policy);

        assert!(plan
            .modes
            .iter()
            .any(|mode| matches!(mode, NatTraversalMode::AggressiveBirthdayProbe)));
        assert_eq!(plan.estimated_probe_count, 65_536);
    }
}
