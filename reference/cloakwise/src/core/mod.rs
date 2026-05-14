//! Cloakwise Unified Transport Core
//!
//! A single-binary, trait-based architecture that eliminates process-switching
//! latency by treating all protocols as hot-swappable "Outbounds."
//!
//! Key efficiency gains:
//! - Single Rust binary (no external process spawning)
//! - Shared encryption engine (RustCrypto)
//! - Zero-copy buffer pool
//! - <10ms protocol switching (pointer swap vs process restart)
//! - Single process footprint (stealth)

pub mod transport;
pub mod crypto;
pub mod buffer;
pub mod switch;
pub mod sensors;
pub mod hardware;

pub use transport::*;
pub use crypto::*;
pub use buffer::*;
pub use switch::*;
pub use sensors::*;
pub use hardware::*;
