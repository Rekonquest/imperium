# Configuration Reference

Complete reference for Cloakwise configuration options.

## Configuration File Location

Default: `/etc/cloakwise/config.yaml`

Specify custom location:
```bash
cloakwise -c /path/to/config.yaml
```

## Full Configuration Example

```yaml
# Node identification
node:
  id: "node-alpha-01"
  admin_contact: "admin@example.com"
  cluster_peers:
    - "node-beta.example.com:9443"
    - "node-gamma.example.com:9443"

# AI Models Configuration
models:
  # Directory containing micro-models
  specialists_dir: "/opt/cloakwise/models/specialists/"

  # Individual model paths (optional - uses defaults if not specified)
  threat_detector: "/opt/cloakwise/models/threat-detector-0.5b.gguf"
  pattern_matcher: "/opt/cloakwise/models/pattern-matcher-0.5b.gguf"
  action_selector: "/opt/cloakwise/models/action-selector-0.5b.gguf"

  # Inference settings
  inference:
    threads: 4              # CPU threads for inference
    context_size: 2048      # Context window size
    batch_size: 512         # Batch size for inference
    temperature: 0.1        # Lower = more deterministic
    max_tokens: 256         # Max response length
    timeout_ms: 100         # Decision timeout

# Confidence thresholds for AI decisions
confidence:
  specialist_threshold: 0.85     # Min confidence to trust AI decision
  escalation_timeout_ms: 5000    # Time before escalating uncertain decisions
  min_specialists_for_consensus: 2  # Models that must agree

# Fallback behavior (when AI is disabled or uncertain)
fallback:
  timed_rotation_hours: 4           # Auto-rotate profile every N hours
  failure_threshold: 50             # Failures before switching profile
  failure_window_minutes: 10        # Window for counting failures
  health_check_interval_secs: 60    # How often to check connectivity
  health_check_endpoints:
    - "https://www.google.com"
    - "https://cloudflare.com/cdn-cgi/trace"
    - "https://www.apple.com"
  profile_rotation_order:
    - "https_clone"
    - "video_call"
    - "websocket"
    - "gaming"
  safe_mode_profile: "https_clone"  # Profile to use in emergencies
  safe_mode_lock_minutes: 30        # How long to stay in safe mode

# Traffic profiles (VPN protocols)
profiles:
  https_clone:
    protocol: cloak
    port: 443
    obfuscation: tls1_3
    timing: web_browsing
    padding: variable
    max_concurrent: 100
    custom_config:
      domain: "www.microsoft.com"

  video_call:
    protocol: amneziawg
    port: 443
    timing: webrtc_pattern
    padding: variable
    max_concurrent: 10

  websocket:
    protocol: xray
    port: 443
    obfuscation: websocket
    timing: interactive
    max_concurrent: 50
    custom_config:
      path: "/ws"
      host: "cdn.example.com"

  gaming:
    protocol: hysteria2
    port: 443
    timing: gaming
    padding: minimal
    max_concurrent: 20

# VPN interface settings
vpn:
  interface: "wg0"
  config_dir: "/etc/wireguard/"
  reload_command: "wg syncconf wg0 <(wg-quick strip wg0)"
  pre_switch_hook: "/opt/cloakwise/hooks/pre-switch.sh"
  post_switch_hook: "/opt/cloakwise/hooks/post-switch.sh"

# Client management
clients:
  config_api_port: 8080
  api_bind_address: "127.0.0.1"  # Use 0.0.0.0 for remote access
  push_notifications: true
  api_auth_token: "your-secret-token"  # Optional API authentication

# Telemetry collection
telemetry:
  capture_method: vpn_logs    # vpn_logs, packet_capture, or both
  log_path: "/var/log/wireguard/"
  sample_rate: 1.0            # 1.0 = 100% of traffic
  packet_capture_interface: "wg0"

# Logging configuration
logging:
  level: "info"               # trace, debug, info, warn, error
  file: "/var/log/cloakwise/cloakwise.log"
  json_format: false          # Set true for structured logging
  max_size_mb: 100
  max_files: 5

# SDR Radio Bridge (optional)
sdr:
  enabled: false
  primary_protocol: "lora"    # lora, ax25, js8, aprs
  callsign: "NOCALL"          # Your amateur radio callsign
  auto_activate_on_blackout: true
  mesh_enabled: true
  devices:
    - type: "rtlsdr"
      path: "/dev/bus/usb/001/002"
    - type: "hackrf"
      path: "/dev/bus/usb/001/003"

# Security tools
security:
  dpi_detector:
    enabled: true
    sensitivity: "medium"     # low, medium, high

  probe_detector:
    enabled: true
    honeypot_ports: [22, 23, 3389]

  rate_limiter:
    enabled: true
    requests_per_minute: 1000
    burst_size: 100

  suricata:
    enabled: false
    rules_path: "/etc/suricata/rules/"
```

## Section Reference

### node

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `id` | string | auto-generated | Unique node identifier |
| `admin_contact` | string | required | Admin email for alerts |
| `cluster_peers` | list | [] | Other Cloakwise nodes for coordination |

### models

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `specialists_dir` | path | ./models/specialists/ | Directory containing AI models |
| `threat_detector` | path | auto | Threat detection model path |
| `pattern_matcher` | path | auto | Traffic pattern model path |
| `action_selector` | path | auto | Response selection model path |

### models.inference

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `threads` | int | 4 | CPU threads for AI inference |
| `context_size` | int | 2048 | Model context window |
| `batch_size` | int | 512 | Inference batch size |
| `temperature` | float | 0.1 | Randomness (lower = deterministic) |
| `max_tokens` | int | 256 | Max response length |
| `timeout_ms` | int | 100 | Decision timeout in milliseconds |

### profiles.<name>

| Field | Type | Options | Description |
|-------|------|---------|-------------|
| `protocol` | enum | See [Protocols](Protocols) | VPN protocol to use |
| `port` | int | 1-65535 | Listen port |
| `obfuscation` | enum | tls1_3, websocket, none | Traffic obfuscation method |
| `timing` | enum | web_browsing, webrtc_pattern, interactive, gaming | Timing pattern to mimic |
| `padding` | enum | variable, fixed, minimal, none | Packet padding strategy |
| `max_concurrent` | int | any | Max concurrent connections |
| `custom_config` | map | varies | Protocol-specific options |

### security

| Tool | Key Fields | Description |
|------|------------|-------------|
| `dpi_detector` | enabled, sensitivity | Detect deep packet inspection |
| `probe_detector` | enabled, honeypot_ports | Detect active probing attacks |
| `rate_limiter` | enabled, requests_per_minute | Prevent abuse |
| `suricata` | enabled, rules_path | IDS/IPS integration |

### sdr

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | false | Enable SDR radio bridge |
| `primary_protocol` | enum | lora | Radio protocol (lora, ax25, js8, aprs) |
| `callsign` | string | NOCALL | Amateur radio callsign |
| `auto_activate_on_blackout` | bool | true | Auto-switch to radio on internet loss |
| `mesh_enabled` | bool | true | Enable mesh networking |

## Environment Variables

Configuration can be overridden with environment variables:

```bash
# Override node ID
export CLOAKWISE_NODE_ID="custom-node-id"

# Override API port
export CLOAKWISE_API_PORT=9090

# Override log level
export CLOAKWISE_LOG_LEVEL=debug

# Enable verbose mode
export CLOAKWISE_VERBOSE=1
```

## Hardware Tier Presets

The setup wizard provides presets based on hardware:

| Tier | RAM | AI | Protocols | Use Case |
|------|-----|-----|-----------|----------|
| Minimal | <1GB | Disabled | 2-3 | Raspberry Pi, embedded |
| Standard | 1-4GB | Basic | 5-6 | VPS, small servers |
| Enhanced | 4-8GB | Full | All | Dedicated servers |
| Lab | 8GB+ | Full + GPU | All + SDR | Research, testing |

## Validation

Validate your configuration:

```bash
cloakwise config validate -c /etc/cloakwise/config.yaml
```

## Next Steps

- [Protocols](Protocols) - Detailed protocol configuration
- [AI System](AI-System) - Configure AI models
- [Security Tools](Security-Tools) - Enable threat detection
