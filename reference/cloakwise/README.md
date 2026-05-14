# Cloakwise — Adaptive VPN Cluster Defense System

An AI-driven VPN defense system designed to evade state-level Deep Packet Inspection (DPI) by dynamically switching traffic profiles. Built to extend VPN cluster operational lifespan from ~3 months to 1+ year by making fingerprinting a moving target.

## Overview

Cloakwise uses lightweight micro-models (~0.5B parameters each, <3B total) that act as fast reflex agents rather than deep reasoners. These models monitor traffic patterns, detect DPI fingerprinting attempts, and trigger immediate protocol switches. The system supports multiple VPN protocols including modern censorship-resistant options like VLESS+Reality, Trojan-Go, and Xray.

### Key Features

- **Multi-Protocol Support**: WireGuard, AmneziaWG, Cloak, Shadowsocks, V2Ray, Xray, Trojan-Go, Hysteria 2, NaïveProxy, Snowflake, Iodine, and Briar
- **Fast Reflex AI**: Three micro-models (~0.5B each) that detect and act in <100ms
- **Dynamic Profile Mutation**: Automatic traffic profile adjustments based on threat detection
- **Traffic Mimicry**: Mimic legitimate services (YouTube, Zoom, Discord, Steam, Telegram)
- **Burned Profile Tracking**: Automatically avoid detected fingerprints
- **Dormant Security Toolkit**: Network forensics, threat detection, and counter-forensics tools that use zero resources until activated
- **SDR Radio Bridge**: Software Defined Radio fallback for complete internet blackouts (LoRa, AX.25, mesh networking)
- **Real-time Dashboard**: Web-based monitoring and management UI
- **Single Binary Deployment**: All components compiled into one executable

## Architecture

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                            Cloakwise Node                                     │
├──────────────────────────────────────────────────────────────────────────────┤
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │              Micro-Model Reflex Layer (<3B total params)               │  │
│  │                                                                        │  │
│  │  ┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐       │  │
│  │  │  Threat Detector │ │ Pattern Matcher  │ │  Action Selector │       │  │
│  │  │     (~0.5B)      │ │     (~0.5B)      │ │     (~0.5B)      │       │  │
│  │  │                  │ │                  │ │                  │       │  │
│  │  │ • DPI detection  │ │ • Traffic shape  │ │ • Protocol pick  │       │  │
│  │  │ • Probe alerts   │ │ • Timing anomaly │ │ • Mutation level │       │  │
│  │  │ • Block signals  │ │ • Fingerprint    │ │ • Fallback mode  │       │  │
│  │  └────────┬─────────┘ └────────┬─────────┘ └────────┬─────────┘       │  │
│  │           └───────────────┬────┴────────────────────┘                 │  │
│  │                           │                                            │  │
│  │                    ┌──────▼──────┐                                    │  │
│  │                    │ Action Bus  │  (< 100ms decision loop)           │  │
│  │                    └──────┬──────┘                                    │  │
│  └───────────────────────────│────────────────────────────────────────────┘  │
│                              │                                                │
│  ┌───────────────────────────▼────────────────────────────────────────────┐  │
│  │                    Deterministic Fallback                               │  │
│  │      (Timed rotation, health checks, safe mode, radio fallback)        │  │
│  └───────────────────────────┬─────────────────────────────────────────────┘  │
│                              │                                                │
│  ┌───────────────────────────▼────────────────────────────────────────────┐  │
│  │                         Enforcer Layer                                  │  │
│  │    Profile Switcher │ Throttler │ Decoy │ Notifier │ Tool Activator    │  │
│  └───────────────────────────┬─────────────────────────────────────────────┘  │
│                              │                                                │
│  ┌───────────────────────────▼────────────────────────────────────────────┐  │
│  │                       VPN Protocol Layer                                │  │
│  │   WireGuard │ Cloak │ SS │ V2Ray │ Xray │ Trojan │ Hysteria │ Naive   │  │
│  │   AmneziaWG │ Snowflake │ Iodine │ Briar (mesh)                        │  │
│  └───────────────────────────┬─────────────────────────────────────────────┘  │
│                              │                                                │
│  ┌───────────────────────────┴─────────────────────────────────────────────┐  │
│  │             Dormant Modules (Zero Resources Until Activated)             │  │
│  │  ┌──────────────────────────┐  ┌──────────────────────────────────────┐ │  │
│  │  │    Security Toolkit      │  │       SDR Radio Bridge               │ │  │
│  │  │  ┌────────┐ ┌─────────┐  │  │  ┌──────┐ ┌───────┐ ┌────────┐      │ │  │
│  │  │  │Forensic│ │ Threat  │  │  │  │ LoRa │ │ AX.25 │ │JS8Call │      │ │  │
│  │  │  │ Tools  │ │Detection│  │  │  └──────┘ └───────┘ └────────┘      │ │  │
│  │  │  └────────┘ └─────────┘  │  │  ┌────────────────────────────┐     │ │  │
│  │  │  ┌────────┐ ┌─────────┐  │  │  │    Mesh Network Relay      │     │ │  │
│  │  │  │Counter │ │ Defense │  │  │  │   (Internet Blackout)      │     │ │  │
│  │  │  │Forensic│ │Hardening│  │  │  └────────────────────────────┘     │ │  │
│  │  │  └────────┘ └─────────┘  │  │  Hardware: RTL-SDR, HackRF,        │ │  │
│  │  └──────────────────────────┘  │  LimeSDR, USRP, LoRa modules       │ │  │
│  │                                 └──────────────────────────────────────┘ │  │
│  └──────────────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────────────┘
```

## Micro-Model Design Philosophy

Cloakwise uses **action-oriented micro-models** rather than large reasoning models:

| Model | Size | Purpose | Latency |
|-------|------|---------|---------|
| **Threat Detector** | ~0.5B | Classify sensor inputs as threat/safe | <30ms |
| **Pattern Matcher** | ~0.5B | Match traffic to known DPI signatures | <30ms |
| **Action Selector** | ~0.5B | Pick protocol/mutation from threat context | <30ms |

**Total: ~1.5B parameters** (expandable to 3B with optional reasoner)

### Why Small Models?

1. **Speed over depth**: In censorship evasion, fast reflexes beat deep analysis
2. **Resource efficiency**: Runs on edge hardware (Raspberry Pi, small VPS)
3. **Deterministic fallback**: If AI fails, rule-based logic takes over
4. **Future expansion**: "Big Momma" reasoner can be added later for complex scenarios

### Model Responsibilities

**Threat Detector** (classify-only, no reasoning):
- Input: Sensor readings (packet stats, timing, fingerprints)
- Output: `{threat_type, confidence, urgency}`
- Triggers: Protocol switch, tool activation, alerts

**Pattern Matcher** (pattern recognition):
- Input: Traffic shape, timing histograms, TLS fingerprints
- Output: `{matches: [known_signatures], novelty_score}`
- Triggers: Profile mutation, fingerprint rotation

**Action Selector** (decision tree + learned weights):
- Input: Threat + Pattern outputs, current state
- Output: `{action, protocol, mutation_params}`
- Actions: switch_protocol, mutate_profile, activate_tool, safe_mode

## Supported Protocols

### WireGuard
- Modern, high-performance VPN protocol
- Simple configuration, fast connection establishment
- Uses ChaCha20 for symmetric encryption

### AmneziaWG
- Modified WireGuard with DPI evasion features
- Junk packet injection for handshake obfuscation
- Header manipulation to avoid fingerprinting

### Cloak
- TLS 1.3 camouflage for existing protocols
- Makes traffic appear as regular HTTPS
- Domain fronting support

### Shadowsocks
- AEAD encryption (aes-256-gcm, chacha20-ietf-poly1305)
- Plugin support for additional obfuscation
- Compatible with Outline clients

### V2Ray (VMess/VLESS)
- **VMess**: Original V2Ray protocol with UUID authentication
- **VLESS**: Lightweight alternative without built-in encryption
- Multiple transports: TCP, WebSocket, HTTP/2, gRPC, QUIC, mKCP

### Xray (VLESS + Reality)
- **VLESS**: Zero-knowledge encryption protocol
- **Reality**: Advanced TLS camouflage without real certificates
  - Uses real TLS from legitimate sites as fingerprint
  - Server sends client's traffic through a real TLS server
  - Much harder to detect than traditional TLS proxies
- **XTLS**: Optimized TLS handling with reduced overhead

### Trojan-Go
- Enhanced Trojan protocol with unique features:
  - **Multiplexing (smux)**: Connection reuse for better performance
  - **WebSocket transport**: CDN bypass capability (Cloudflare compatible)
  - **XTLS support**: Reduced TLS handshake overhead
  - **Router**: Built-in traffic routing decisions
  - **API**: Native remote management interface
  - **Shadowsocks plugin**: Additional encryption layer
  - **TLS fingerprint mimicry**: Chrome, Firefox, Safari, iOS, Android

### Hysteria 2
- QUIC-based proxy with exceptional performance:
  - **Brutal congestion control**: Maintains high speed on lossy networks
  - **QUIC transport**: UDP-based, encrypted by default
  - **Salamander obfuscation**: Makes traffic unrecognizable
  - **Bandwidth control**: Configurable upload/download limits
  - **Fast handshake**: Low latency connection establishment

### NaïveProxy
- Uses Chrome's network stack for perfect browser camouflage:
  - **Identical TLS fingerprint**: Matches real Chrome exactly
  - **HTTP/2 multiplexing**: Same behavior as Chrome browser
  - **Padding and timing**: Patterns match real browsing
  - **QUIC support**: Can use QUIC transport like Chrome
  - Server requires Caddy with forwardproxy plugin

### Snowflake (Tor)
- Tor pluggable transport using WebRTC:
  - **WebRTC disguise**: Appears as video/voice calls
  - **Ephemeral proxies**: Volunteer browsers as relays
  - **Domain fronting**: Uses CDN fronting to reach broker
  - **AMP cache**: Alternative fronting via Google AMP
  - Extremely difficult to block due to distributed nature

### Iodine (IP-over-DNS)
- Tunnels IP traffic through DNS queries:
  - **DNS tunneling**: Works when only port 53 is open
  - **Multiple record types**: NULL, TXT, CNAME, MX, A
  - **Automatic encoding**: Base32, Base64, Base128, Raw
  - **MTU probing**: Automatic optimization
  - Bypasses captive portals and restrictive firewalls

### Briar
- P2P encrypted messaging for extreme scenarios:
  - **Multiple transports**: Tor, Wi-Fi Direct, Bluetooth
  - **No central servers**: Fully decentralized
  - **Mesh networking**: Works in complete blackouts
  - **Forward secrecy**: Perfect message encryption
  - Designed for activists and journalists

## Installation

### Prerequisites

- Rust 1.70+ with Cargo
- Linux system (Ubuntu 20.04+ / Debian 11+ recommended)
- Root access for VPN interface management
- VPN binaries (install as needed):
  - `wireguard-tools` - WireGuard/AmneziaWG
  - `trojan-go` - Trojan-Go protocol
  - `xray` / `v2ray` - V2Ray/Xray protocols
  - `hysteria` - Hysteria 2 protocol
  - `naive` - NaïveProxy (build from source or download)
  - `snowflake-client` / `snowflake-proxy` - Tor Snowflake
  - `iodine` / `iodined` - DNS tunneling
  - `briar-headless` - Briar P2P messaging (optional)

### Building from Source

```bash
# Clone the repository
git clone https://github.com/your-org/cloakwise.git
cd cloakwise

# Build release binary
cargo build --release

# Binary will be at target/release/cloakwise
```

### Installation

```bash
# Install binary
sudo cp target/release/cloakwise /usr/local/bin/

# Create configuration directory
sudo mkdir -p /etc/cloakwise
sudo cp configs/default.yaml /etc/cloakwise/config.yaml

# Create VPN config directory
sudo mkdir -p /etc/cloakwise/vpn

# Create log directory
sudo mkdir -p /var/log/cloakwise
```

## Configuration

### Main Configuration (config.yaml)

```yaml
node:
  id: "node-01"
  admin_contact: "admin@example.com"
  cluster_peers: []

models:
  micro_models_dir: "./models/micro/"
  # Three ~0.5B action-oriented models (<3B total)
  threat_detector: "./models/micro/threat_detector.gguf"
  pattern_matcher: "./models/micro/pattern_matcher.gguf"
  action_selector: "./models/micro/action_selector.gguf"
  inference:
    threads: 2
    context_size: 512   # Small context for fast inference
    temperature: 0.0    # Deterministic outputs

decision:
  action_timeout_ms: 100       # Max time for AI decision
  confidence_threshold: 0.7    # Below this, use rule-based fallback
  enable_ai: true              # Can disable AI entirely for pure rule-based

fallback:
  timed_rotation_hours: 4
  failure_threshold: 50
  failure_window_minutes: 10
  health_check_interval_secs: 60
  health_check_endpoints:
    - "https://www.google.com"
    - "https://www.cloudflare.com"
  profile_rotation_order:
    - "xray_reality"
    - "trojan_ws"
    - "https_clone"
  safe_mode_profile: "https_clone"
  safe_mode_lock_minutes: 30

profiles:
  xray_reality:
    protocol: xray
    port: 443
    obfuscation: tls1_3
    timing: web_browsing
    custom_config:
      vless_uuid: "your-uuid-here"
      reality_dest: "www.microsoft.com:443"
      reality_server_names:
        - "www.microsoft.com"
      reality_private_key: "your-key"
      reality_short_ids:
        - "abcd1234"

  trojan_ws:
    protocol: trojan_go
    port: 443
    obfuscation: websocket_upgrade
    timing: web_browsing
    custom_config:
      passwords:
        - "your-trojan-password"
      sni: "cdn.example.com"
      ws_path: "/trojan"
      ws_host: "cdn.example.com"
      mux_concurrency: 8
      fingerprint: "chrome"

  https_clone:
    protocol: cloak
    port: 443
    obfuscation: tls1_3
    timing: web_browsing
    padding: variable

vpn:
  interface: "wg0"
  config_dir: "/etc/cloakwise/vpn/"
  reload_command: "systemctl reload cloakwise-vpn"

clients:
  config_api_port: 8080
  push_notifications: true

telemetry:
  capture_method: vpn_logs
  log_path: "/var/log/wireguard/"
  sample_rate: 1.0

logging:
  level: "info"
  file: "/var/log/cloakwise/cloakwise.log"
  json_format: false
  max_size_mb: 100
  max_files: 5
```

## API Reference

### System Status

```bash
GET /api/status
```

Returns system health, active profile, and statistics.

### Profile Management

```bash
# List all profiles
GET /api/profiles

# Get specific profile
GET /api/profiles/:id

# Activate a profile
POST /api/profiles/:id/activate

# Mutate an existing profile
POST /api/profiles/:id/mutate
{
  "strength": 0.3
}

# Mark profile as burned (detected)
POST /api/profiles/:id/burn
{
  "reason": "Detected by DPI"
}
```

### Dynamic Profile Generation

```bash
POST /api/profiles/generate
{
  "intent": "Mimic YouTube streaming from Moscow ISP",
  "protocol": "xray",
  "mimic_service": "youtube",
  "threat_level": 7,
  "require_tls": true,
  "evolve_from": "previous_profile_id"
}
```

### LLM Prompt Builder

```bash
POST /api/llm/prompt
{
  "intent": "Create evasion profile for high-threat environment",
  "protocol": "trojan-go",
  "threat_level": 8
}
```

Returns structured prompts for external LLM integration.

### History & Analytics

```bash
# Generation history
GET /api/profiles/history

# Burned profiles
GET /api/profiles/burned

# Recent events
GET /api/events/recent

# Active alerts
GET /api/alerts
```

## Traffic Mimicry Profiles

Cloakwise can generate profiles that mimic traffic patterns of legitimate services:

| Service | Timing Pattern | Typical Obfuscation |
|---------|---------------|---------------------|
| YouTube | Video streaming (burst, variable) | WebSocket, HTTP/2 |
| Netflix | Adaptive bitrate streaming | TLS 1.3, QUIC |
| Zoom | WebRTC-like (consistent intervals) | UDP-over-TCP |
| Discord | WebSocket with voice patterns | WebSocket |
| Steam | Game traffic (low latency, small packets) | Custom |
| Telegram | MTProto patterns | TLS 1.3, WebSocket |

## Usage Examples

### Starting the Service

```bash
# With default config
cloakwise --config /etc/cloakwise/config.yaml

# With debug logging
RUST_LOG=debug cloakwise --config /etc/cloakwise/config.yaml

# Systemd service
sudo systemctl start cloakwise
```

### Generating a Profile via CLI

```bash
# Using curl
curl -X POST http://localhost:8080/api/profiles/generate \
  -H "Content-Type: application/json" \
  -d '{
    "intent": "Evade Russian TSPU while mimicking Discord voice",
    "protocol": "xray",
    "mimic_service": "discord",
    "threat_level": 8
  }'
```

### Using the Web Dashboard

Open `http://localhost:8080/` in your browser to access:

- **Dashboard**: System metrics and active profile status
- **Profiles**: Manage registered profiles (activate, mutate, burn)
- **Generate**: Create new dynamic profiles with LLM assistance
- **Events**: View recent telemetry and detection events

## Protocol-Specific Configuration

### Xray with VLESS + Reality

```yaml
profiles:
  xray_reality:
    protocol: xray
    port: 443
    obfuscation: tls1_3
    custom_config:
      inbound_protocol: vless
      vless_uuid: "your-uuid"
      vless_flow: "xtls-rprx-vision"
      reality_enabled: true
      reality_dest: "www.microsoft.com:443"
      reality_server_names:
        - "www.microsoft.com"
        - "microsoft.com"
      reality_private_key: "server-private-key"
      reality_short_ids:
        - "abc123"
        - "def456"
```

### Trojan-Go with WebSocket + CDN

```yaml
profiles:
  trojan_cdn:
    protocol: trojan_go
    port: 443
    obfuscation: websocket_upgrade
    custom_config:
      passwords:
        - "secure-password-here"
      sni: "your-cdn-domain.com"
      ws_path: "/secure-path"
      ws_host: "your-cdn-domain.com"
      mux_concurrency: 8
      fingerprint: "chrome"
      xtls: true
      shadowsocks_enabled: true
      shadowsocks_method: "aes-128-gcm"
      shadowsocks_password: "ss-password"
```

### V2Ray with gRPC

```yaml
profiles:
  v2ray_grpc:
    protocol: v2ray
    port: 443
    obfuscation: grpc
    custom_config:
      inbound_protocol: vless
      vless_uuid: "your-uuid"
      transport: grpc
      grpc_service_name: "GunService"
      tls_enabled: true
      tls_server_name: "your-domain.com"
```

### Hysteria 2 with Obfuscation

```yaml
profiles:
  hysteria_fast:
    protocol: hysteria2
    port: 443
    obfuscation: quic
    custom_config:
      server: "server.example.com:443"
      password: "your-password"
      obfs_password: "obfuscation-key"
      bandwidth_up: "100 mbps"
      bandwidth_down: "500 mbps"
      congestion: "brutal"
      sni: "www.bing.com"
```

### NaïveProxy with Chrome Camouflage

```yaml
profiles:
  naive_chrome:
    protocol: naiveproxy
    port: 1080
    obfuscation: tls1_3
    custom_config:
      proxy: "https://user:pass@proxy.example.com"
      padding: true
      protocol: "https"  # or "quic"
      concurrency: 16
      extra_headers:
        - "X-Padding:1500"
```

### Snowflake (Tor) with AMP Fronting

```yaml
profiles:
  snowflake_amp:
    protocol: snowflake
    port: 9050
    obfuscation: webrtc
    custom_config:
      mode: "client"
      broker: "https://snowflake-broker.torproject.net/"
      front: "cdn.sstatic.net"
      amp_cache: "https://cdn.ampproject.org/"
      stun: "stun:stun.l.google.com:19302"
```

### Iodine DNS Tunnel

```yaml
profiles:
  dns_tunnel:
    protocol: iodine
    port: 53
    obfuscation: dns_tunnel
    custom_config:
      domain: "t.example.com"
      nameserver: "8.8.8.8"
      password: "tunnel-password"
      record_type: "txt"  # null, private, txt, cname, mx, a
      encoding: "base64"  # base32, base64, base128, raw
      mtu: 1130
```

### Briar P2P Mesh

```yaml
profiles:
  briar_mesh:
    protocol: briar
    port: 7000
    custom_config:
      transport: "all"  # tor, lan, bluetooth, all
      embedded_tor: true
      data_dir: "/var/lib/briar"
```

## Obfuscation Techniques

### TLS Record Fragmentation

TLS Record Fragmentation splits TLS handshake records into smaller fragments to evade DPI that looks for specific patterns:

```yaml
profiles:
  fragmented_tls:
    protocol: xray
    port: 443
    obfuscation: tls_fragmentation
    custom_config:
      fragment_length: 50-100
      fragment_interval: 10-20
      # Fragments TLS ClientHello to bypass fingerprinting
```

This technique is particularly effective against:
- SNI-based blocking
- JA3 fingerprinting
- TLS version detection

## Dormant Security Toolkit

Cloakwise includes a comprehensive security toolkit that remains **dormant** (zero resource usage) until activated. Tools are triggered by:

- Manual API/CLI activation
- Threat Detector alert (high confidence threat)
- Threshold breach (anomaly levels)
- Scheduled scans
- Radio fallback (internet blackout)

### Tool Categories

#### Network Forensics
| Tool | Description | Resource Budget |
|------|-------------|-----------------|
| `packet_capture` | tcpdump-based live packet capture | 256MB RAM, 25% CPU |
| `deep_capture` | tshark deep packet inspection | 512MB RAM, 40% CPU |
| `flow_collector` | NetFlow/IPFIX collection | 256MB RAM, 15% CPU |
| `bandwidth_monitor` | vnstat bandwidth monitoring | 64MB RAM, 5% CPU |
| `connection_tracker` | conntrack connection logging | 128MB RAM, 10% CPU |

#### Threat Detection
| Tool | Description | Auto-Trigger |
|------|-------------|--------------|
| `suricata` | Network IDS/IPS with ET rules | High traffic anomaly |
| `yara_scanner` | Pattern matching for malware | Detection event |
| `clamav_scanner` | Antivirus scanning | File transfer detected |
| `zeek` | Network analysis framework | Sustained threat detection |
| `fail2ban` | Intrusion prevention | SSH/auth anomaly |
| `rkhunter` | Rootkit scanner | System integrity check |

#### Counter-Forensics Detection
Detect when **you** are being analyzed:

| Tool | Description |
|------|-------------|
| `dpi_detector` | Detect Deep Packet Inspection attempts |
| `traffic_analysis_detector` | Statistical traffic analysis detection |
| `timing_detector` | Timing correlation attack detection |
| `fingerprint_detector` | JA3/JA3S/JARM fingerprint detection |
| `decoy_deployer` | Deploy honeypot services |
| `probe_detector` | Active probing detection (GFW-style) |

#### Defense Hardening
| Tool | Description | Max Runtime |
|------|-------------|-------------|
| `rate_limiter` | nftables rate limiting | Indefinite |
| `ip_blocker` | Threat intel IP blocking | Indefinite |
| `port_knocker` | knockd port knocking daemon | Indefinite |
| `firewall_hardener` | Strict iptables rules | 1 hour |
| `geo_blocker` | Geographic IP blocking | Indefinite |
| `connection_drainer` | Graceful connection drain | 5 minutes |

### Security Toolkit API

```bash
# List all dormant tools
GET /api/security/tools

# Get tool status
GET /api/security/tools/:id

# Activate a tool
POST /api/security/tools/:id/activate
{
  "reason": "Manual investigation",
  "timeout_minutes": 30
}

# Deactivate a tool
POST /api/security/tools/:id/deactivate

# Get active tools
GET /api/security/active
```

### Example: Activating Threat Detection

```bash
curl -X POST http://localhost:8080/api/security/tools/suricata/activate \
  -H "Content-Type: application/json" \
  -d '{"reason": "Suspected DPI activity"}'
```

## SDR Radio Bridge (Blackout Mode)

For **absolute digital isolation** scenarios where traditional internet is unavailable, Cloakwise can bridge traffic over Software Defined Radio (SDR). This module remains completely dormant until activated.

### Supported SDR Hardware

| Device | Capabilities | Frequency Range |
|--------|-------------|-----------------|
| RTL-SDR | RX only | 24 MHz - 1.7 GHz |
| HackRF One | TX/RX half-duplex | 1 MHz - 6 GHz |
| LimeSDR | TX/RX full-duplex | 100 kHz - 3.8 GHz |
| PlutoSDR | TX/RX portable | 325 MHz - 3.8 GHz |
| USRP | Professional grade | Varies by model |
| LoRa SX127x | TX/RX spread spectrum | 137 MHz - 1020 MHz |

### Radio Protocols

| Protocol | Use Case | Data Rate | Range |
|----------|----------|-----------|-------|
| **LoRa** | Long range, low power | 0.3-50 kbps | 10+ km |
| **AX.25** | Amateur packet radio | 1200-9600 bps | Line of sight |
| **JS8Call** | Weak signal text | 25-100 bps | Worldwide (HF) |
| **FreeDV** | Digital voice + data | 1.6 kbps | Regional (HF/VHF) |
| **APRS** | Position/telemetry | 1200 bps | Regional |
| **Meshtastic** | LoRa mesh networking | 5-20 kbps | Multi-hop mesh |

### Radio Bridge Configuration

```yaml
# /etc/cloakwise/radio.yaml
radio_bridge:
  primary_protocol: lora
  fallback_protocols:
    - ax25
    - js8call
    - freedv

  device_path: /dev/ttyUSB0  # or auto-detect
  callsign: "N0CALL"  # Required for amateur bands

  max_power_dbm: 20  # Transmit power limit

  allowed_bands:
    - [433.0, 434.8]   # 70cm ISM/amateur
    - [868.0, 870.0]   # EU ISM
    - [902.0, 928.0]   # US ISM
    - [144.0, 148.0]   # 2m amateur

  mesh_enabled: true
  max_hops: 5
  beacon_interval: 60  # seconds

  known_peers:
    - "PEER1-CALL"
    - "PEER2-CALL"

  encryption_key: "base64-encoded-key"  # OTA encryption
```

### Activation Triggers

The radio bridge activates automatically when:

1. **Internet blackout detected** for >5 minutes
2. **Action Selector** outputs `radio_fallback` action
3. **Manual activation** via API or CLI

```bash
# Manual activation
POST /api/sdr/activate
{
  "reason": "Internet blackout detected",
  "protocol": "lora"
}

# Check bridge status
GET /api/sdr/status

# List discovered peers
GET /api/sdr/peers

# Send data to peer
POST /api/sdr/send
{
  "peer": "PEER1-CALL",
  "data": "base64-encoded-data"
}
```

### Emergency Mesh Mode

In complete infrastructure failure, enable full mesh mode:

```bash
curl -X POST http://localhost:8080/api/sdr/mesh/enable \
  -H "Content-Type: application/json" \
  -d '{
    "protocols": ["lora", "ax25"],
    "relay_enabled": true,
    "max_hops": 5
  }'
```

This creates a decentralized mesh network with other Cloakwise nodes, relaying traffic until internet connectivity is restored.

## Unified Transport Core (High-Efficiency Architecture)

Cloakwise uses a **Unified Transport Core** that merges all VPN protocols and detection systems into a single Rust binary. This eliminates process-switching latency and reduces attack surface.

### Key Efficiency Gains

| Metric | Separate Tools | Unified Core |
|--------|---------------|--------------|
| RAM Usage | 500MB+ (multiple runtimes) | <100MB (single binary) |
| Protocol Switch | 2-5 seconds (process restart) | **<10ms** (pointer swap) |
| Maintenance | Update 10+ tools | One binary, one update |
| Stealth | Multiple process names | Single process name |

### Outbound Trait Architecture

All protocols implement a common `Outbound` trait, enabling hot-swapping:

```rust
#[async_trait]
pub trait Outbound: Send + Sync {
    /// Protocol identifier
    fn protocol_id(&self) -> &str;

    /// Connect and return encrypted stream
    async fn connect(&self, target: SocketAddr) -> Result<BoxedAsyncStream>;

    /// Get telemetry for AI analysis
    fn get_telemetry(&self) -> ProtocolMetrics;

    /// In-place mutation (change SNI, rotate credentials)
    async fn mutate(&self, mutation: ProtocolMutation) -> Result<()>;
}
```

### Shared Subsystems

- **Crypto Engine**: Single RustCrypto backend (AES-GCM, ChaCha20-Poly1305, X25519)
- **Buffer Pool**: Zero-copy memory management across all protocols
- **Sensor Bus**: Unified telemetry from network, RF, and hardware sensors
- **Core Switch**: Manages seamless transitions between Internet/VPN/Radio modes

### Unified Sensor Fabric

All detection capabilities merged into a single sensor bus:

| Category | Merged Sensors | Purpose |
|----------|---------------|---------|
| **Network** | packet_capture + deep_capture + flow_collector | Single pcap handle for all capture |
| **Surveillance** | dpi_detector + timing_analyzer + fingerprint_detector + probe_detector | Unified threat detection |
| **RF** | spectrum_analyzer + jamming_detector | SDR-based sensing |
| **Hardware** | tpm_health + smartnic_stats + cpu_telemetry | Physical sensor polling at 100Hz |

### Cross-Protocol Stream Splicing

The unified architecture enables **stream splicing**—handing off a data stream from one protocol to another mid-connection:

```rust
// Start connection on Trojan-Go
let stream = trojan.connect(target).await?;

// Detect 2G downgrade via sensor bus
if sensor_bus.assess_threats().threat_level > 0.7 {
    // Hot-swap to Hysteria 2 without dropping TCP session
    core_switch.switch_protocol("hysteria2").await?;
}
```

### Hardware Abstraction Layer (HAL)

Physical sensors integrated via unified HAL:

| Device | Capability | Integration |
|--------|-----------|-------------|
| TPM 2.0 | PCR monitoring, attestation | Firmware tamper detection |
| SmartNIC | Hardware packet filtering | Offloaded DPI blocking |
| CPU Sensors | Voltage, frequency, temperature | Side-channel detection |
| SDR | Spectrum sensing | Jamming early warning |

## Security Considerations

- **Key Management**: Store private keys securely, never commit to version control
- **API Authentication**: Enable `api_auth_token` in production
- **TLS Certificates**: Use valid certificates for client-facing services
- **Burned Profiles**: Regularly review and clear burned profile patterns
- **Monitoring**: Set up alerts for safe mode entries and high escalation rates
- **Radio Compliance**: Ensure amateur radio license compliance when using licensed bands
- **Encryption**: SDR bridge supports AES-256 over-the-air encryption

## Troubleshooting

### Common Issues

**Profile switch failures:**
```bash
# Check VPN controller logs
journalctl -u cloakwise -f

# Verify VPN binary availability
which trojan-go xray v2ray wg
```

**High escalation rate:**
- Review specialist threshold settings
- Check for network instability
- Analyze recent events for patterns

**Dashboard not loading:**
- Verify `config_api_port` is not blocked
- Check if binding address allows external connections

## License

MIT License - See LICENSE file for details.

## Contributing

Contributions welcome! Please read CONTRIBUTING.md for guidelines.

## Acknowledgments

- [WireGuard](https://www.wireguard.com/) - Jason A. Donenfeld
- [Xray-core](https://github.com/XTLS/Xray-core) - XTLS Project
- [Trojan-Go](https://github.com/p4gefau1t/trojan-go) - p4gefau1t
- [V2Ray](https://www.v2fly.org/) - V2Fly Community
- [Cloak](https://github.com/cbeuw/Cloak) - cbeuw
- [Hysteria](https://hysteria.network/) - Hysteria Project
- [NaïveProxy](https://github.com/klzgrad/naiveproxy) - klzgrad
- [Snowflake](https://snowflake.torproject.org/) - Tor Project
- [Iodine](https://github.com/yarrick/iodine) - yarrick
- [Briar](https://briarproject.org/) - Briar Project
- [GNU Radio](https://www.gnuradio.org/) - GNU Radio Foundation
- [Suricata](https://suricata.io/) - OISF
- [YARA](https://virustotal.github.io/yara/) - VirusTotal
