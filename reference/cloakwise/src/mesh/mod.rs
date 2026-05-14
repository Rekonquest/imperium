//! P2P UDP mesh with STUN (NAT), optional HTTP signaling, ChaCha PSK payloads.
//!
//! ## Cloud signaling contract (optional)
//! - `POST {base}/register` JSON: `{ peer_id, listen_port, mapped_ip, mapped_port }`
//! - `GET {base}/peers` JSON: `{ peers: [{ peer_id, endpoints: [{ ip, port }] }] }`
//! - Optional header `Authorization: Bearer <signaling_token>`.

mod crypto;
mod overlay;
mod runtime;
mod signaling;
mod state;
mod stun;
mod types;

pub use overlay::apply_overlay;
pub use runtime::run_mesh;
pub use state::MeshHub;
pub use types::{MeshPayload, MeshSnapshot};
