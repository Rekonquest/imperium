# Security Tools

Cloakwise includes a comprehensive security toolkit for threat detection, traffic analysis, and active defense.

## Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    UNIFIED SENSOR BUS                       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  DETECTION LAYER                                            │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐       │
│  │   DPI    │ │  Probe   │ │ Suricata │ │   YARA   │       │
│  │ Detector │ │ Detector │ │   IDS    │ │ Scanner  │       │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘       │
│       │            │            │            │              │
│       └────────────┴────────────┴────────────┘              │
│                         │                                   │
│  COLLECTION LAYER       │                                   │
│  ┌──────────┐ ┌─────────┴───┐ ┌──────────┐                 │
│  │  Packet  │ │    Flow     │ │   Deep   │                 │
│  │ Capture  │ │  Collector  │ │ Capture  │                 │
│  └────┬─────┘ └──────┬──────┘ └────┬─────┘                 │
│       │              │              │                       │
│       └──────────────┴──────────────┘                       │
│                      │                                      │
│  RESPONSE LAYER      │                                      │
│  ┌──────────┐ ┌──────┴─────┐ ┌──────────┐                  │
│  │   Rate   │ │    IP      │ │   Geo    │                  │
│  │ Limiter  │ │  Blocker   │ │ Blocker  │                  │
│  └──────────┘ └────────────┘ └──────────┘                  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Detection Tools

### DPI Detector

Detects deep packet inspection attempts by analyzing traffic patterns.

```yaml
security:
  dpi_detector:
    enabled: true
    sensitivity: medium    # low, medium, high
    patterns:
      - "gfw_reset"        # China GFW patterns
      - "iran_throttle"    # Iranian throttling
      - "generic_dpi"      # Generic DPI signatures
```

**Detection Methods:**
- TCP RST injection detection
- TLS fingerprint analysis
- Timing correlation detection
- Traffic shape analysis

**Signals Detected:**
| Signal | Description | Confidence |
|--------|-------------|------------|
| RST_INJECTION | TCP RST from third party | High |
| TLS_MISMATCH | Server hello doesn't match request | High |
| TIMING_CORRELATION | Traffic timing analysis detected | Medium |
| BANDWIDTH_SHAPING | Selective throttling detected | Medium |

---

### Probe Detector

Detects active probing attacks targeting your VPN server.

```yaml
security:
  probe_detector:
    enabled: true
    honeypot_ports:
      - 22     # SSH
      - 23     # Telnet
      - 3389   # RDP
    alert_threshold: 5
    block_after: 10
```

**Probe Types Detected:**
| Probe Type | Description | Response |
|------------|-------------|----------|
| PORT_SCAN | Sequential port probing | Rate limit |
| REPLAY | Replayed VPN handshake | Drop + alert |
| BANNER_GRAB | Service identification | Serve fake banner |
| ACTIVE_PROBE | Direct VPN protocol probing | Serve decoy |

**Honeypot Response:**
When probes hit honeypot ports, Cloakwise can:
- Log the probe attempt
- Serve fake service banners
- Slow-drip response to waste attacker time
- Auto-block after threshold

---

### Suricata Integration

Full IDS/IPS integration with Suricata for comprehensive threat detection.

```yaml
security:
  suricata:
    enabled: true
    mode: ids            # ids (detect only) or ips (block)
    rules_path: "/etc/suricata/rules/"
    custom_rules: "/etc/cloakwise/suricata-custom.rules"
    update_interval_hours: 24
    eve_log: "/var/log/suricata/eve.json"
```

**Setup:**
```bash
# Install Suricata
sudo apt install suricata

# Update rules
sudo suricata-update

# Enable in Cloakwise
# Edit /etc/cloakwise/config.yaml
```

**Custom Rules Example:**
```
# Detect GFW probe pattern
alert tcp any any -> $HOME_NET 443 (msg:"GFW Probe Detected"; \
  content:"|16 03 01|"; offset:0; depth:3; \
  content:"|00 00 00 00 00|"; distance:5; within:10; \
  sid:1000001; rev:1;)
```

---

### YARA Scanner

Pattern matching for detecting malicious traffic or known attack signatures.

```yaml
security:
  yara_scanner:
    enabled: true
    rules_dir: "/etc/cloakwise/yara/"
    scan_uploads: true
    scan_connections: true
    max_scan_size_mb: 10
```

**Example YARA Rules:**
```yara
rule VPN_Probe_China {
    meta:
        description = "China GFW VPN probe"
        author = "Cloakwise"
    strings:
        $magic = { 16 03 01 02 00 01 00 }
        $probe = "GET / HTTP/1.1" nocase
    condition:
        $magic at 0 and $probe
}
```

---

## Collection Tools

### Packet Capture

Raw packet capture for analysis.

```yaml
security:
  packet_capture:
    enabled: true
    interface: "wg0"
    filter: "tcp port 443"
    snaplen: 96            # Capture first 96 bytes
    buffer_mb: 64
    output_dir: "/var/log/cloakwise/pcap/"
    rotate_size_mb: 100
    max_files: 10
```

**Use Cases:**
- Post-incident analysis
- AI model training
- Debugging connectivity issues

---

### Deep Capture

Full packet capture including payload (high storage requirements).

```yaml
security:
  deep_capture:
    enabled: false         # Disabled by default (high storage)
    interface: "wg0"
    snaplen: 65535         # Full packet
    buffer_mb: 256
    output_dir: "/var/log/cloakwise/deep/"
    rotate_size_mb: 1000
    max_files: 5
    encryption_key: "base64-key-here"  # Encrypt captures
```

**Warning:** Deep capture consumes significant storage. Only enable for specific investigations.

---

### Flow Collector

Network flow statistics without full packet capture.

```yaml
security:
  flow_collector:
    enabled: true
    protocols:
      - tcp
      - udp
    export_interval_secs: 60
    output_format: json    # json, csv, netflow
    output_path: "/var/log/cloakwise/flows/"
```

**Collected Metrics:**
- Source/destination IP and port
- Protocol
- Bytes transferred
- Packet count
- Connection duration
- TCP flags seen

---

## Response Tools

### Rate Limiter

Prevent abuse and slow down attacks.

```yaml
security:
  rate_limiter:
    enabled: true

    # Global limits
    global:
      requests_per_second: 1000
      burst_size: 2000

    # Per-IP limits
    per_ip:
      requests_per_minute: 100
      burst_size: 20
      block_duration_secs: 300

    # Per-connection limits
    per_connection:
      bytes_per_second: 10485760  # 10 MB/s
      packets_per_second: 10000

    # Whitelist
    whitelist:
      - "10.0.0.0/8"
      - "192.168.0.0/16"
```

**Rate Limit Actions:**
| Trigger | Action |
|---------|--------|
| Soft limit exceeded | Delay responses |
| Hard limit exceeded | Drop packets |
| Sustained abuse | Temporary block |

---

### IP Blocker

Block malicious IP addresses.

```yaml
security:
  ip_blocker:
    enabled: true

    # Block lists
    blocklists:
      - url: "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
        update_hours: 24
      - file: "/etc/cloakwise/custom-blocklist.txt"

    # Auto-block triggers
    auto_block:
      probe_attempts: 10
      auth_failures: 5
      rate_limit_violations: 3

    # Block duration
    block_duration_hours: 24

    # Whitelist (never block)
    whitelist:
      - "10.0.0.0/8"
```

---

### Geo Blocker

Block connections by geographic region.

```yaml
security:
  geo_blocker:
    enabled: true
    database_path: "/var/lib/cloakwise/GeoLite2-Country.mmdb"

    # Block mode: allowlist or blocklist
    mode: blocklist

    # Countries to block (ISO 3166-1 alpha-2)
    blocked_countries:
      - "CN"    # China
      - "RU"    # Russia
      - "IR"    # Iran

    # Or use allowlist mode
    # allowed_countries:
    #   - "US"
    #   - "DE"
    #   - "NL"

    # Exceptions
    exceptions:
      - "1.2.3.4/32"  # Specific IPs to allow
```

**Setup GeoIP Database:**
```bash
# Download GeoLite2 (requires free account)
# https://dev.maxmind.com/geoip/geoip2/geolite2/

mkdir -p /var/lib/cloakwise
wget -O /var/lib/cloakwise/GeoLite2-Country.mmdb \
  "https://download.maxmind.com/app/geoip_download?..."
```

---

## Unified Sensor Bus

All security tools feed into the Unified Sensor Bus, which:

1. **Normalizes** data from different sources
2. **Correlates** events across tools
3. **Prioritizes** based on threat level
4. **Feeds** the AI decision system

```rust
// Example sensor reading
SensorReading {
    source: DpiDetector,
    timestamp: Instant::now(),
    data: SensorData::Threat {
        threat_type: "DPI_PROBE",
        source_ip: "1.2.3.4",
        confidence: 0.87,
    },
    urgent: true,
}
```

### Sensor Priorities

| Source | Priority | Latency |
|--------|----------|---------|
| DPI Detector | Critical | <10ms |
| Probe Detector | Critical | <10ms |
| Suricata | High | ~50ms |
| Rate Limiter | Medium | <5ms |
| Flow Collector | Low | ~1s |

---

## API Endpoints

```bash
# Get security status
curl http://localhost:8080/api/security/status

# Get active blocks
curl http://localhost:8080/api/security/blocks

# Manually block IP
curl -X POST http://localhost:8080/api/security/block \
  -H "Content-Type: application/json" \
  -d '{"ip": "1.2.3.4", "duration_hours": 24, "reason": "manual"}'

# Unblock IP
curl -X DELETE http://localhost:8080/api/security/block/1.2.3.4

# Get threat history
curl http://localhost:8080/api/security/threats?hours=24
```

---

## Recommended Configurations

### Minimal (Low Resource)

```yaml
security:
  dpi_detector:
    enabled: true
    sensitivity: low
  probe_detector:
    enabled: true
  rate_limiter:
    enabled: true
```

### Standard

```yaml
security:
  dpi_detector:
    enabled: true
    sensitivity: medium
  probe_detector:
    enabled: true
    honeypot_ports: [22, 23]
  rate_limiter:
    enabled: true
  ip_blocker:
    enabled: true
  flow_collector:
    enabled: true
```

### Enhanced

```yaml
security:
  dpi_detector:
    enabled: true
    sensitivity: high
  probe_detector:
    enabled: true
    honeypot_ports: [22, 23, 3389, 5900]
  suricata:
    enabled: true
    mode: ips
  yara_scanner:
    enabled: true
  packet_capture:
    enabled: true
  rate_limiter:
    enabled: true
  ip_blocker:
    enabled: true
  geo_blocker:
    enabled: true
```

---

## Next Steps

- [AI System](AI-System) - How AI uses security data
- [Configuration](Configuration) - Full configuration reference
- [SDR Radio Bridge](SDR-Radio-Bridge) - Backup communication
