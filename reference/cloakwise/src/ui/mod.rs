//! Unified UI platform for Cloakwise
//!
//! Provides a web dashboard and REST API for:
//! - System monitoring and status
//! - Dynamic profile generation and management
//! - LLM prompt building for profile creation
//! - Telemetry event viewing
//! - Profile activation, mutation, and burning

pub mod api;
pub mod dashboard;
pub mod profile_generator;
pub mod server;
pub mod state;

pub use profile_generator::ProfileGenerator;
pub use server::start_server;
pub use state::AppState;
