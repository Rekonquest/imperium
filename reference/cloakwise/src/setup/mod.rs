//! Cloakwise Interactive Setup Wizard
//!
//! A user-friendly CLI that guides users through configuring Cloakwise
//! based on their hardware capabilities and security needs.

pub mod wizard;
pub mod hardware_detect;
pub mod config_builder;
pub mod prompts;

pub use wizard::*;
pub use hardware_detect::*;
pub use config_builder::*;
pub use prompts::*;
