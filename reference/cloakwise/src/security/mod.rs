//! Dormant Security Toolkit
//!
//! Security and forensic tools that remain dormant (zero resource usage)
//! until activated by triggers such as:
//! - Manual API/CLI activation
//! - Specialist escalation (threat detected)
//! - Threshold breach (anomaly levels)
//! - Big Momma decision
//! - Scheduled scans
//!
//! Tool Categories:
//! - Network Forensics: Packet capture, flow analysis, traffic replay
//! - Threat Detection: IDS rules, YARA scanning, signature matching
//! - Incident Response: Evidence collection, memory analysis
//! - Counter-Forensics: Detect surveillance, honeypots, decoys
//! - Defense Hardening: Firewall rules, rate limiting, IP blocking
//! - OSINT/Intel: IP reputation, threat feeds

pub mod toolkit;
pub mod forensics;
pub mod threat_detection;
pub mod counter_forensics;
pub mod hardening;

pub use toolkit::*;
pub use forensics::*;
pub use threat_detection::*;
pub use counter_forensics::*;
pub use hardening::*;
