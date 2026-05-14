use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use imperium_bus::Bus;
use imperium_net_crypto::{HybridEd25519Mldsa, HybridSigningKey};
use imperium_protocol::{
    ClusterId, MembershipApprovalRequest, MembershipGossip, MembershipGrant, Message, PeerId,
};
use parking_lot::RwLock;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MembershipError {
    #[error("peer already a member: {0:?}")]
    AlreadyMember(PeerId),
    #[error("pending approval already exists for peer")]
    ApprovalPending,
    #[error("peer not found: {0:?}")]
    PeerNotFound(PeerId),
    #[error("bus error: {0}")]
    Bus(#[from] imperium_bus::BusError),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MembershipState {
    PendingApproval,
    Approved,
    Revoked,
}

struct MemberRecord {
    state: MembershipState,
    granted_at: Option<DateTime<Utc>>,
    granted_by: Option<PeerId>,
}

pub struct MembershipManager {
    cluster_id: ClusterId,
    members: Arc<RwLock<HashMap<PeerId, MemberRecord>>>,
    lamport_clock: Arc<RwLock<u64>>,
    local_peer_id: PeerId,
}

impl MembershipManager {
    pub fn new(cluster_id: ClusterId, local_peer_id: PeerId) -> Self {
        let members = Arc::new(RwLock::new(HashMap::new()));
        let mut initial = members.write();
        initial.insert(
            local_peer_id.clone(),
            MemberRecord {
                state: MembershipState::Approved,
                granted_at: Some(Utc::now()),
                granted_by: None,
            },
        );
        drop(initial);

        Self {
            cluster_id,
            members,
            lamport_clock: Arc::new(RwLock::new(0)),
            local_peer_id,
        }
    }

    pub fn request_membership(
        &self,
        peer_id: PeerId,
        bus: &Bus,
    ) -> Result<(), MembershipError> {
        let mut members = self.members.write();
        if members.contains_key(&peer_id) {
            let record = &members[&peer_id];
            if record.state == MembershipState::Approved {
                return Err(MembershipError::AlreadyMember(peer_id));
            }
            if record.state == MembershipState::PendingApproval {
                return Err(MembershipError::ApprovalPending);
            }
        }

        members.insert(
            peer_id.clone(),
            MemberRecord {
                state: MembershipState::PendingApproval,
                granted_at: None,
                granted_by: None,
            },
        );
        drop(members);

        let request = MembershipApprovalRequest {
            cluster_id: self.cluster_id.clone(),
            requesting_peer: peer_id,
            bootstrap_token: imperium_protocol::BootstrapTokenPayload {
                cluster_id: self.cluster_id.clone(),
                issued_by: self.local_peer_id.clone(),
                issued_at: Utc::now(),
                expires_at: Utc::now(),
                signature: Vec::new(),
            },
        };

        bus.publish(
            "net.cluster.membership.request",
            Message::MembershipApprovalReq(request),
        )?;

        Ok(())
    }

    pub fn approve_membership(
        &self,
        peer_id: &PeerId,
        approver: &PeerId,
        signing_key: &HybridSigningKey,
        bus: &Bus,
    ) -> Result<MembershipGrant, MembershipError> {
        let mut members = self.members.write();
        let record = members
            .get_mut(peer_id)
            .ok_or_else(|| MembershipError::PeerNotFound(peer_id.clone()))?;

        let now = Utc::now();
        record.state = MembershipState::Approved;
        record.granted_at = Some(now);
        record.granted_by = Some(approver.clone());
        drop(members);

        let mut payload = Vec::new();
        payload.extend_from_slice(self.cluster_id.0.as_bytes());
        payload.extend_from_slice(peer_id.0.as_bytes());
        payload.extend_from_slice(approver.0.as_bytes());
        payload.extend_from_slice(&now.timestamp().to_le_bytes());

        let sig = HybridEd25519Mldsa::sign(signing_key, &payload);

        let grant = MembershipGrant {
            cluster_id: self.cluster_id.clone(),
            peer_id: peer_id.clone(),
            granted_by: approver.clone(),
            granted_at: now,
            signature: sig.to_bytes(),
        };

        let _ = bus.publish(
            "net.cluster.membership.granted",
            Message::MembershipGrant(grant.clone()),
        );

        self.tick_clock();
        self.gossip_membership(bus);

        Ok(grant)
    }

    pub fn apply_grant(&self, grant: &MembershipGrant) {
        let mut members = self.members.write();
        members
            .entry(grant.peer_id.clone())
            .and_modify(|r| {
                r.state = MembershipState::Approved;
                r.granted_at = Some(grant.granted_at);
                r.granted_by = Some(grant.granted_by.clone());
            })
            .or_insert_with(|| MemberRecord {
                state: MembershipState::Approved,
                granted_at: Some(grant.granted_at),
                granted_by: Some(grant.granted_by.clone()),
            });
    }

    pub fn is_member(&self, peer_id: &PeerId) -> bool {
        self.members
            .read()
            .get(peer_id)
            .map(|r| r.state == MembershipState::Approved)
            .unwrap_or(false)
    }

    pub fn member_count(&self) -> usize {
        self.members
            .read()
            .values()
            .filter(|r| r.state == MembershipState::Approved)
            .count()
    }

    pub fn approved_members(&self) -> Vec<PeerId> {
        self.members
            .read()
            .iter()
            .filter(|(_, r)| r.state == MembershipState::Approved)
            .map(|(id, _)| id.clone())
            .collect()
    }

    pub fn pending_approvals(&self) -> Vec<PeerId> {
        self.members
            .read()
            .iter()
            .filter(|(_, r)| r.state == MembershipState::PendingApproval)
            .map(|(id, _)| id.clone())
            .collect()
    }

    fn tick_clock(&self) {
        let mut clock = self.lamport_clock.write();
        *clock += 1;
    }

    pub fn merge_clock(&self, remote_clock: u64) {
        let mut clock = self.lamport_clock.write();
        *clock = (*clock).max(remote_clock) + 1;
    }

    pub fn current_clock(&self) -> u64 {
        *self.lamport_clock.read()
    }

    fn gossip_membership(&self, bus: &Bus) {
        let members = self.approved_members();
        let clock = self.current_clock();

        let gossip = MembershipGossip {
            cluster_id: self.cluster_id.clone(),
            members,
            lamport_clock: clock,
            from_peer: self.local_peer_id.clone(),
        };

        let _ = bus.publish(
            "net.cluster.membership.gossip",
            Message::MembershipGossip(gossip),
        );
    }

    pub fn subscribe_membership_grants(
        self: &Arc<Self>,
        bus: &Bus,
    ) -> tokio::task::JoinHandle<()> {
        let mut sub = bus.subscribe("net.cluster.membership.granted");
        let mgr = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                match sub.recv().await {
                    Ok(event) => {
                        if let Message::MembershipGrant(ref grant) = event.message {
                            tracing::info!(peer = ?grant.peer_id, "applying membership grant from bus");
                            mgr.apply_grant(grant);
                        }
                    }
                    Err(imperium_bus::BusError::Closed) => break,
                    Err(_) => continue,
                }
            }
        })
    }

    pub fn apply_gossip(&self, gossip: &MembershipGossip) {
        if gossip.lamport_clock <= self.current_clock() {
            return;
        }

        self.merge_clock(gossip.lamport_clock);

        for peer_id in &gossip.members {
            if !self.is_member(peer_id) {
                let mut members = self.members.write();
                members.entry(peer_id.clone()).or_insert_with(|| MemberRecord {
                    state: MembershipState::Approved,
                    granted_at: Some(Utc::now()),
                    granted_by: Some(gossip.from_peer.clone()),
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn new_cluster_has_local_member() {
        let cluster_id = ClusterId::new();
        let local_peer = PeerId::new();
        let mgr = MembershipManager::new(cluster_id, local_peer.clone());

        assert!(mgr.is_member(&local_peer));
        assert_eq!(mgr.member_count(), 1);
    }

    #[test]
    fn approve_membership_flow() {
        let cluster_id = ClusterId::new();
        let operator = PeerId::new();
        let bus = Bus::new();
        let mgr = MembershipManager::new(cluster_id, operator.clone());

        let new_peer = PeerId::new();
        mgr.request_membership(new_peer.clone(), &bus).unwrap();

        assert!(!mgr.is_member(&new_peer));
        assert_eq!(mgr.pending_approvals().len(), 1);

        let mut rng = OsRng;
        let (sk, _vk) = HybridEd25519Mldsa::generate_keypair(&mut rng);

        mgr.approve_membership(&new_peer, &operator, &sk, &bus)
            .unwrap();

        assert!(mgr.is_member(&new_peer));
        assert_eq!(mgr.member_count(), 2);
    }

    #[tokio::test]
    async fn subscribe_membership_grant_applies() {
        let cluster_id = ClusterId::new();
        let local = PeerId::new();
        let mgr = Arc::new(MembershipManager::new(cluster_id.clone(), local.clone()));
        let bus = Arc::new(Bus::new());

        let _handle = mgr.subscribe_membership_grants(&bus);

        let new_peer = PeerId::new();
        let grant = MembershipGrant {
            cluster_id: cluster_id.clone(),
            peer_id: new_peer.clone(),
            granted_by: local.clone(),
            granted_at: Utc::now(),
            signature: vec![1, 2, 3],
        };

        bus.publish(
            "net.cluster.membership.granted",
            Message::MembershipGrant(grant),
        ).unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(mgr.is_member(&new_peer));
        assert_eq!(mgr.member_count(), 2);
    }

    #[test]
    fn gossip_merges_new_members() {
        let cluster_id = ClusterId::new();
        let local = PeerId::new();
        let mgr = MembershipManager::new(cluster_id.clone(), local.clone());

        let remote_peer = PeerId::new();
        let new_peer = PeerId::new();

        let gossip = MembershipGossip {
            cluster_id: cluster_id.clone(),
            members: vec![remote_peer.clone(), new_peer.clone()],
            lamport_clock: 5,
            from_peer: remote_peer.clone(),
        };

        mgr.apply_gossip(&gossip);
        assert!(mgr.is_member(&remote_peer));
        assert!(mgr.is_member(&new_peer));
        assert_eq!(mgr.current_clock(), 6);
    }
}
