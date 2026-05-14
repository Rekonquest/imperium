# Cloakwise - Adaptive VPN Cluster Defense System

Welcome to the Cloakwise wiki! Cloakwise is an intelligent VPN defense system that uses AI-driven traffic profile switching to evade state-level censorship and maintain connectivity even during internet blackouts.

## Quick Links

- [Installation Guide](Installation)
- [Quick Start](Quick-Start)
- [Configuration Reference](Configuration)
- [Setup Wizard](Setup-Wizard)
- [Supported Protocols](Protocols)
- [AI System](AI-System)
- [Security Tools](Security-Tools)
- [SDR Radio Bridge](SDR-Radio-Bridge)
- [Architecture Overview](Architecture)
- [API Reference](API-Reference)
- [Troubleshooting](Troubleshooting)

## What is Cloakwise?

Cloakwise is designed for environments where VPN traffic is actively detected and blocked. It provides:

- **Adaptive Traffic Profiles**: Automatically switches between VPN protocols to mimic legitimate traffic patterns
- **AI-Powered Decisions**: Micro-models detect threats and select optimal responses in <100ms
- **Protocol Hot-Swapping**: Seamlessly switch between 10+ VPN protocols without dropping connections
- **SDR Radio Bridge**: Maintain communication during complete internet blackouts using radio
- **Hardware Flexibility**: Runs on everything from Raspberry Pi to lab-grade equipment

## System Requirements

### Minimum (Minimal Tier)
- 512MB RAM
- 1 CPU core
- 100MB disk space
- Linux (kernel 4.x+)

### Recommended (Standard Tier)
- 2GB RAM
- 2 CPU cores
- 500MB disk space
- Linux with WireGuard support

### Enhanced Tier
- 4GB+ RAM
- 4+ CPU cores
- GPU (optional, for faster AI)
- SDR hardware (RTL-SDR, HackRF)

## License

Cloakwise is available under the Business Source License 1.1 (BUSL-1.1).

- **Free for**: Personal use, research, education, non-commercial organizations
- **Requires license for**: Commercial use, corporate deployment
- **Converts to**: Apache 2.0 after 4 years

See [LICENSE](../LICENSE) for full details.

## Getting Help

- [GitHub Issues](https://github.com/Rekonquest/Dynamic-VPN/issues) - Bug reports and feature requests
- [Discussions](https://github.com/Rekonquest/Dynamic-VPN/discussions) - Questions and community help
- [Troubleshooting Guide](Troubleshooting) - Common issues and solutions

## Contributing

Contributions are welcome! Please read our [Contributing Guide](Contributing) before submitting pull requests.
