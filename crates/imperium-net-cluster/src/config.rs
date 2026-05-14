use std::sync::Arc;

use chrono::{DateTime, Utc};
use imperium_bus::Bus;
use imperium_net_crypto::{HybridEd25519Mldsa, HybridSigningKey};
use imperium_protocol::{
    ClusterId, ConfigurationFetchRequest, ConfigurationFetchResponse, ConfigurationVersion,
    Message, PeerId,
};
use parking_lot::RwLock;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("version conflict: local {local} vs remote {remote}")]
    VersionConflict { local: u64, remote: u64 },
    #[error("stale configuration (version {0})")]
    StaleVersion(u64),
    #[error("bus error: {0}")]
    Bus(#[from] imperium_bus::BusError),
}

#[derive(Clone, Debug)]
pub struct ClusterConfig {
    pub cluster_id: ClusterId,
    pub version: u64,
    pub lamport_clock: u64,
    pub data: Vec<u8>,
    pub config_hash: Vec<u8>,
    pub updated_by: PeerId,
    pub updated_at: DateTime<Utc>,
}

pub struct ConfigManager {
    cluster_id: ClusterId,
    local_peer_id: PeerId,
    current: Arc<RwLock<Option<ClusterConfig>>>,
    lamport_clock: Arc<RwLock<u64>>,
}

impl ConfigManager {
    pub fn new(cluster_id: ClusterId, local_peer_id: PeerId) -> Self {
        Self {
            cluster_id,
            local_peer_id,
            current: Arc::new(RwLock::new(None)),
            lamport_clock: Arc::new(RwLock::new(0)),
        }
    }

    pub fn update_config(
        &self,
        data: Vec<u8>,
        _signing_key: &HybridSigningKey,
        bus: &Bus,
    ) -> Result<u64, ConfigError> {
        let mut clock = self.lamport_clock.write();
        *clock += 1;
        let new_clock = *clock;
        drop(clock);

        let mut current = self.current.write();
        let new_version = current.as_ref().map(|c| c.version + 1).unwrap_or(1);

        let config_hash = sha2_hash(&data);

        let config = ClusterConfig {
            cluster_id: self.cluster_id.clone(),
            version: new_version,
            lamport_clock: new_clock,
            data: data.clone(),
            config_hash: config_hash.clone(),
            updated_by: self.local_peer_id.clone(),
            updated_at: Utc::now(),
        };

        *current = Some(config);
        drop(current);

        let version_msg = ConfigurationVersion {
            cluster_id: self.cluster_id.clone(),
            version: new_version,
            lamport_clock: new_clock,
            config_hash,
            updated_by: self.local_peer_id.clone(),
            updated_at: Utc::now(),
        };

        bus.publish(
            "net.cluster.config.updated",
            Message::ConfigVersion(version_msg),
        )?;

        Ok(new_version)
    }

    pub fn current_version(&self) -> u64 {
        self.current.read().as_ref().map(|c| c.version).unwrap_or(0)
    }

    pub fn current_config(&self) -> Option<ClusterConfig> {
        self.current.read().clone()
    }

    pub fn handle_version_announcement(&self, version: &ConfigurationVersion) -> bool {
        let current_version = self.current_version();
        version.version > current_version
    }

    pub fn request_config(&self, bus: &Bus) -> Result<(), ConfigError> {
        let req = ConfigurationFetchRequest {
            cluster_id: self.cluster_id.clone(),
            from_peer: self.local_peer_id.clone(),
            known_version: self.current_version(),
        };

        bus.publish(
            "net.cluster.config.fetch_request",
            Message::ConfigFetchReq(req),
        )?;

        Ok(())
    }

    pub fn handle_fetch_request(
        &self,
        req: &ConfigurationFetchRequest,
        signing_key: &HybridSigningKey,
        bus: &Bus,
    ) -> Result<(), ConfigError> {
        if req.known_version >= self.current_version() {
            return Ok(());
        }

        let config = match self.current_config() {
            Some(c) => c,
            None => return Ok(()),
        };

        let mut payload = Vec::new();
        payload.extend_from_slice(&config.data);
        payload.extend_from_slice(&config.version.to_le_bytes());
        let sig = HybridEd25519Mldsa::sign(signing_key, &payload);

        let resp = ConfigurationFetchResponse {
            cluster_id: self.cluster_id.clone(),
            version: config.version,
            config_data: config.data,
            signature: sig.to_bytes(),
        };

        bus.publish(
            "net.cluster.config.fetch_response",
            Message::ConfigFetchResp(resp),
        )?;

        Ok(())
    }

    pub fn subscribe_config_responses(
        self: &Arc<Self>,
        bus: &Bus,
    ) -> tokio::task::JoinHandle<()> {
        let mut sub = bus.subscribe("net.cluster.config.fetch_response");
        let mgr = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                match sub.recv().await {
                    Ok(event) => {
                        if let Message::ConfigFetchResp(ref resp) = event.message {
                            match mgr.apply_fetched_config(resp) {
                                Ok(()) => {
                                    tracing::info!(version = resp.version, "applied fetched config");
                                }
                                Err(e) => {
                                    tracing::debug!(error = %e, "config fetch response rejected");
                                }
                            }
                        }
                    }
                    Err(imperium_bus::BusError::Closed) => break,
                    Err(_) => continue,
                }
            }
        })
    }

    pub fn apply_fetched_config(&self, resp: &ConfigurationFetchResponse) -> Result<(), ConfigError> {
        if resp.version <= self.current_version() {
            return Err(ConfigError::StaleVersion(resp.version));
        }

        let config_hash = sha2_hash(&resp.config_data);

        let config = ClusterConfig {
            cluster_id: resp.cluster_id.clone(),
            version: resp.version,
            lamport_clock: {
                let mut clock = self.lamport_clock.write();
                *clock += 1;
                *clock
            },
            data: resp.config_data.clone(),
            config_hash,
            updated_by: self.local_peer_id.clone(),
            updated_at: Utc::now(),
        };

        *self.current.write() = Some(config);
        Ok(())
    }
}

fn sha2_hash(data: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn config_versioning() {
        let cluster_id = ClusterId::new();
        let local = PeerId::new();
        let bus = Bus::new();
        let mgr = ConfigManager::new(cluster_id, local);

        let mut rng = OsRng;
        let (sk, _vk) = HybridEd25519Mldsa::generate_keypair(&mut rng);

        assert_eq!(mgr.current_version(), 0);

        let v1 = mgr.update_config(b"config-v1".to_vec(), &sk, &bus).unwrap();
        assert_eq!(v1, 1);
        assert_eq!(mgr.current_version(), 1);

        let v2 = mgr.update_config(b"config-v2".to_vec(), &sk, &bus).unwrap();
        assert_eq!(v2, 2);
    }

    #[tokio::test]
    async fn subscribe_config_response_applies() {
        let cluster_id = ClusterId::new();
        let local = PeerId::new();
        let bus = Arc::new(Bus::new());
        let mgr = Arc::new(ConfigManager::new(cluster_id.clone(), local));

        let _handle = mgr.subscribe_config_responses(&bus);

        let resp = ConfigurationFetchResponse {
            cluster_id: cluster_id.clone(),
            version: 1,
            config_data: b"new-config".to_vec(),
            signature: vec![1, 2, 3],
        };

        bus.publish(
            "net.cluster.config.fetch_response",
            Message::ConfigFetchResp(resp),
        ).unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(mgr.current_version(), 1);
    }

    #[test]
    fn stale_config_rejected() {
        let cluster_id = ClusterId::new();
        let local = PeerId::new();
        let bus = Bus::new();
        let mgr = ConfigManager::new(cluster_id.clone(), local);

        let mut rng = OsRng;
        let (sk, _vk) = HybridEd25519Mldsa::generate_keypair(&mut rng);

        mgr.update_config(b"config-v1".to_vec(), &sk, &bus).unwrap();

        let stale_resp = ConfigurationFetchResponse {
            cluster_id,
            version: 0,
            config_data: b"old".to_vec(),
            signature: vec![1, 2, 3],
        };

        assert!(mgr.apply_fetched_config(&stale_resp).is_err());
    }
}
