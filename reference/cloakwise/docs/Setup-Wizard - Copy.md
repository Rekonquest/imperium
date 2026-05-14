# Setup Wizard Guide

The interactive setup wizard guides you through configuring Cloakwise with sensible defaults based on your hardware.

## Running the Wizard

```bash
sudo cloakwise setup
```

## Wizard Steps

### Step 1: Hardware Detection

The wizard automatically scans your system for:

- **RAM**: Available memory determines AI capabilities
- **CPU**: Core count affects concurrent connections
- **GPU**: Enables faster AI inference (optional)
- **TPM**: Hardware security module for key storage
- **SDR Devices**: RTL-SDR, HackRF, etc. for radio bridge
- **Network Interfaces**: Available for VPN tunneling

Example output:
```
═══════════════════════════════════════════════════════════════
  HARDWARE DETECTION
═══════════════════════════════════════════════════════════════

Scanning system capabilities...

  Detected Components:
    RAM:        7842 MB
    CPU Cores:  4
    CPU Speed:  3200 MHz
    GPU:        Yes
    TPM:        No
    Disk:       45230 MB available

  SDR Devices Found:
    - RTL-SDR at /dev/bus/usb/001/004
      Capabilities: receive, 24-1766MHz

  Network Interfaces:
    - eth0
    - wlan0

✓ Recommended tier: Enhanced - Full AI + all protocols + SDR support
```

### Step 2: Basic Configuration

Enter your node details:

```
═══════════════════════════════════════════════════════════════
  BASIC CONFIGURATION
═══════════════════════════════════════════════════════════════

Node ID: [myserver-a1b2c3d4] █
Admin contact email: [admin@localhost] █

✓ Node ID: myserver-a1b2c3d4
✓ Admin: admin@example.com
```

### Step 3: Hardware Tier Selection

Choose the configuration tier:

```
═══════════════════════════════════════════════════════════════
  HARDWARE TIER SELECTION
═══════════════════════════════════════════════════════════════

ℹ Select the configuration tier for your hardware:
ℹ Based on your system, we recommend: Enhanced

Select hardware tier:
  [1] Minimal    - Rule-based only, 2-3 protocols (for <1GB RAM)
  [2] Standard   - Basic AI, 5-6 protocols (1-4GB RAM)
> [3] Enhanced   - Full AI + all protocols + SDR support (4-8GB RAM)
  [4] Lab        - Everything + experimental features (8GB+ RAM)

Enter selection [3]: █
```

**Tier Capabilities:**

| Tier | AI | Protocols | SDR | Memory |
|------|-----|-----------|-----|--------|
| Minimal | No | 3 | No | <500MB |
| Standard | Basic | 6 | No | ~1GB |
| Enhanced | Full | All | Yes | ~2GB |
| Lab | Full+GPU | All | Yes | ~4GB |

### Step 4: Protocol Selection

Choose which VPN protocols to enable:

```
═══════════════════════════════════════════════════════════════
  PROTOCOL SELECTION
═══════════════════════════════════════════════════════════════

ℹ Select which VPN protocols to enable:
ℹ Protocols with higher stealth are recommended for censored regions.

Enable protocols:
  [x] Xray/VLESS     - Modern, highly configurable (stealth: 9/10)
  [x] Cloak          - Mimics HTTPS traffic perfectly (stealth: 9/10)
  [x] Trojan-Go      - Looks like normal HTTPS (stealth: 8/10)
  [x] AmneziaWG      - Obfuscated WireGuard (stealth: 7/10)
  [ ] Hysteria2      - QUIC-based, very fast (stealth: 6/10)
  [ ] Shadowsocks    - Classic, widely supported (stealth: 5/10)
  [x] NaiveProxy     - Chrome's network stack (stealth: 8/10)
  [ ] Snowflake      - Tor's pluggable transport (stealth: 7/10)
  [ ] Iodine         - DNS tunneling (stealth: 6/10)
  [ ] Briar          - P2P mesh messaging (stealth: 8/10)

Space to toggle, Enter to confirm: █

✓ 5 protocol(s) enabled:
  - Xray/VLESS on port 443 (stealth: 9/10)
  - Cloak on port 443 (stealth: 9/10)
  - Trojan-Go on port 443 (stealth: 8/10)
  - AmneziaWG on port 51820 (stealth: 7/10)
  - NaiveProxy on port 443 (stealth: 8/10)

Customize protocol ports? [y/N]: █
```

### Step 5: AI Configuration

Configure the AI decision system:

```
═══════════════════════════════════════════════════════════════
  AI CONFIGURATION
═══════════════════════════════════════════════════════════════

ℹ AI-powered decision making provides faster threat response.
ℹ Micro-models run locally and don't require internet.

Enable AI decision making? [Y/n]: █

Select AI configuration:
> [1] Micro-Models Only - 3x ~0.5B models for fast reflex decisions (~200MB)
  [2] Full AI           - Micro-models + optional strategic reasoning (~1GB)

Enter selection [1]: █

Micro-model configuration:
  Enable Threat Detector? (identifies attack patterns) [Y/n]: █
  Enable Pattern Matcher? (classifies traffic) [Y/n]: █
  Enable Action Selector? (chooses responses) [Y/n]: █

Decision timeout (ms): [100] █
Confidence threshold (0.0-1.0): [0.8] █

✓ AI configuration complete:
  Threat Detector: Enabled
  Pattern Matcher: Enabled
  Action Selector: Enabled
  Timeout: 100ms
  Confidence: 80%
```

### Step 6: Security Tools

Select security monitoring tools:

```
═══════════════════════════════════════════════════════════════
  SECURITY TOOLS
═══════════════════════════════════════════════════════════════

ℹ Select security tools to enable:
ℹ These tools help detect and respond to threats.

Enable security tools:
  [ ] PacketCapture   - Raw packet capture for analysis
  [ ] DeepCapture     - Full packet contents (high storage)
  [ ] FlowCollector   - Network flow statistics
  [ ] Suricata        - Full IDS/IPS engine
  [ ] YaraScanner     - Malware pattern matching
  [x] DpiDetector     - Detect deep packet inspection
  [x] ProbeDetector   - Detect active probing attacks
  [x] RateLimiter     - Prevent connection flooding
  [ ] IpBlocker       - Block malicious IPs
  [ ] GeoBlocker      - Block by country/region

Space to toggle, Enter to confirm: █

✓ 3 security tool(s) enabled
```

### Step 7: SDR Configuration (if detected)

Configure radio bridge:

```
═══════════════════════════════════════════════════════════════
  SDR RADIO BRIDGE CONFIGURATION
═══════════════════════════════════════════════════════════════

ℹ Detected 1 SDR device(s). Radio bridge enables communication during
  internet blackouts.

Enable SDR radio bridge? [Y/n]: █

Primary radio protocol:
> [1] LoRa  - Long range, low power (recommended for most cases)
  [2] AX.25 - Amateur radio packet protocol
  [3] JS8   - Weak signal keyboard-to-keyboard
  [4] APRS  - Automatic Packet Reporting System

Enter selection [1]: █

Callsign (if licensed, or 'NOCALL'): [NOCALL] █
Auto-activate on internet blackout? [Y/n]: █
Enable mesh networking with nearby nodes? [Y/n]: █

✓ SDR configuration complete
```

### Step 8: Network Configuration

Configure network settings:

```
═══════════════════════════════════════════════════════════════
  NETWORK CONFIGURATION
═══════════════════════════════════════════════════════════════

Customize network settings? [y/N]: █

(Using defaults)
✓ Network configuration:
  API: 127.0.0.1:8080
  Dashboard: Enabled
  VPN Interface: wg0
```

### Step 9: Logging Configuration

Configure logging:

```
═══════════════════════════════════════════════════════════════
  LOGGING CONFIGURATION
═══════════════════════════════════════════════════════════════

Customize logging settings? [y/N]: █

(Using defaults)
✓ Logging configuration:
  Level: info
  Format: Plain text
  File: /var/log/cloakwise/cloakwise.log
```

### Step 10: Review and Save

Review your configuration:

```
═══════════════════════════════════════════════════════════════
  CONFIGURATION REVIEW
═══════════════════════════════════════════════════════════════

Configuration Summary:

  Node: myserver-a1b2c3d4 (admin@example.com)
  Tier: Enhanced
  Protocols: 5
    - Xray/VLESS on port 443
    - Cloak on port 443
    - Trojan-Go on port 443
    - AmneziaWG on port 51820
    - NaiveProxy on port 443
  AI: Enabled
    Timeout: 100ms
  Security Tools: 3
  SDR: Enabled (lora)
  API: 127.0.0.1:8080

Save this configuration? [Y/n]: █

✓ Configuration saved to /etc/cloakwise/config.yaml

Show generated configuration? [y/N]: █

═══════════════════════════════════════════════════════════════
  SETUP COMPLETE!
═══════════════════════════════════════════════════════════════

✓ Cloakwise has been configured successfully.

ℹ Next steps:
  1. Review the configuration file
  2. Download/train AI models (if enabled):
     cloakwise models download
  3. Start the service:
     sudo systemctl start cloakwise
  4. Check status:
     cloakwise status
```

## Command Line Options

```bash
# Run wizard with specific config output
cloakwise setup --output /path/to/config.yaml

# Skip hardware detection (use manual tier)
cloakwise setup --skip-detect --tier standard

# Non-interactive mode with defaults
cloakwise setup --non-interactive --tier enhanced

# Import existing config and modify
cloakwise setup --import /etc/cloakwise/old-config.yaml
```

## Troubleshooting

### Permission Denied

The wizard needs root to:
- Detect hardware
- Write to /etc/cloakwise/
- Configure network interfaces

Run with `sudo`:
```bash
sudo cloakwise setup
```

### Hardware Not Detected

If SDR or other hardware isn't detected:

1. Check device is connected
2. Install required drivers
3. Add udev rules for non-root access
4. Re-run the wizard

### Config Not Saved

If config can't be saved to /etc/cloakwise/:

1. Wizard saves to ./cloakwise-config.yaml instead
2. Move manually when ready:
   ```bash
   sudo mkdir -p /etc/cloakwise
   sudo mv cloakwise-config.yaml /etc/cloakwise/config.yaml
   ```

## Next Steps

After setup:

- [Start the service](Installation#4-create-systemd-service)
- [Download AI models](AI-System#downloading-models)
- [Configure clients](API-Reference#client-management)
