mod stack;
mod strainers;

pub use stack::{StrainerStack, StrainerRegistry};
pub use strainers::{
    AuthShapeInnerStrainer, AuthShapeOuterStrainer, ByteJitterStrainer,
    TimingStrainer, TruncationStrainer,
};

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use imperium_bus::Bus;
use imperium_protocol::Message;

#[derive(Clone, Debug)]
pub struct StrainerInput {
    pub data: Vec<u8>,
    pub source: Option<SocketAddr>,
    pub context: HashMap<String, String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub enum StrainerOutput {
    Passed(Vec<u8>),
    Rejected { reason: String },
    Degraded { data: Vec<u8>, method: String },
}

impl StrainerOutput {
    pub fn is_passed(&self) -> bool {
        matches!(self, StrainerOutput::Passed(_))
    }

    pub fn is_rejected(&self) -> bool {
        matches!(self, StrainerOutput::Rejected { .. })
    }

    pub fn data(&self) -> Option<&[u8]> {
        match self {
            StrainerOutput::Passed(d) | StrainerOutput::Degraded { data: d, .. } => Some(d),
            StrainerOutput::Rejected { .. } => None,
        }
    }
}

pub trait Strainer: Send + Sync {
    fn id(&self) -> &str;
    fn shape_filtered(&self) -> &str;
    fn apply(&self, input: StrainerInput) -> StrainerOutput;
}

pub async fn init(bus: Arc<Bus>) -> Result<(), imperium_bus::BusError> {
    let _sub = bus.subscribe("net.strainer.");
    bus.publish(
        "net.strainer.ready",
        Message::SubsystemReady {
            name: "imperium-net-strainer".into(),
        },
    )?;
    tracing::info!("imperium-net-strainer initialized");
    Ok(())
}
