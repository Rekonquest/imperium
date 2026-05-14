//! Software Defined Radio Bridge
//!
//! Provides communication capabilities when traditional internet is unavailable:
//! - Amateur radio packet networks (AX.25)
//! - LoRa long-range communication
//! - Satellite uplinks (Iridium, Starlink)
//! - Mesh radio networks
//! - HF radio for intercontinental communication
//!
//! This module remains dormant until activated by:
//! - Complete internet blackout detection
//! - Manual activation for emergency communication
//! - Big Momma escalation to "radio fallback" mode
//!
//! Requires SDR hardware (RTL-SDR, HackRF, USRP, etc.)

pub mod bridge;
pub mod protocols;
pub mod hardware;

pub use bridge::*;
pub use protocols::*;
pub use hardware::*;
