# SDR Radio Bridge

The SDR (Software Defined Radio) Radio Bridge enables Cloakwise to maintain communication during complete internet blackouts using radio frequencies.

## Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     NORMAL OPERATION                        │
│                                                             │
│    Client ──── Internet ──── Cloakwise Server               │
│                                                             │
└─────────────────────────────────────────────────────────────┘

                    ↓ Internet Blackout Detected ↓

┌─────────────────────────────────────────────────────────────┐
│                     BLACKOUT MODE                           │
│                                                             │
│    Client ════ Radio ════ Relay Node ════ Internet          │
│              (LoRa/AX.25)    (outside                       │
│                              blackout zone)                 │
│                                                             │
│    ┌───────────────────────────────────────────────┐        │
│    │              MESH NETWORK                      │        │
│    │   Node A ──── Node B ──── Node C ──── Exit    │        │
│    │      │           │           │                │        │
│    │   Node D ──── Node E ──── Node F              │        │
│    └───────────────────────────────────────────────┘        │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Supported Hardware

### RTL-SDR (Receive Only)
- **Cost**: ~$25
- **Use**: Monitoring, receiving mesh broadcasts
- **Frequency**: 24-1766 MHz

### HackRF One
- **Cost**: ~$300
- **Use**: Full TX/RX capability
- **Frequency**: 1 MHz - 6 GHz
- **Bandwidth**: 20 MHz

### LimeSDR
- **Cost**: ~$300
- **Use**: Full TX/RX, high bandwidth
- **Frequency**: 100 kHz - 3.8 GHz
- **Bandwidth**: 61.44 MHz

### USRP (Ettus Research)
- **Cost**: $1000+
- **Use**: Research-grade, high performance
- **Frequency**: Varies by model

### LoRa Modules (SX1276/SX1262)
- **Cost**: ~$15
- **Use**: Long-range, low-power mesh
- **Range**: Up to 15km line-of-sight

## Radio Protocols

### LoRa (Recommended)

Long Range, low power protocol ideal for mesh networking.

```yaml
sdr:
  enabled: true
  primary_protocol: lora

  lora:
    frequency_mhz: 915.0    # US: 915, EU: 868, AS: 433
    bandwidth_khz: 125
    spreading_factor: 9     # 7-12 (higher = longer range, slower)
    coding_rate: "4/5"
    tx_power_dbm: 14        # Max legal power
    sync_word: 0x12
```

**LoRa Characteristics:**
| Setting | Range | Speed | Battery |
|---------|-------|-------|---------|
| SF7 | 2km | 5.5 kbps | Best |
| SF9 | 8km | 1.7 kbps | Good |
| SF12 | 15km | 0.3 kbps | Worst |

---

### AX.25

Amateur radio packet protocol, well-established and reliable.

```yaml
sdr:
  enabled: true
  primary_protocol: ax25

  ax25:
    callsign: "W1ABC"       # Your amateur radio callsign (required)
    ssid: 1
    frequency_mhz: 144.390  # 2m APRS frequency
    baud_rate: 1200         # 1200 or 9600
    modulation: afsk        # afsk or gfsk
```

**Requirements:**
- Amateur radio license (Technician or higher in US)
- Proper callsign identification

---

### JS8

Weak signal keyboard-to-keyboard mode, extremely robust.

```yaml
sdr:
  enabled: true
  primary_protocol: js8

  js8:
    callsign: "W1ABC"
    frequency_mhz: 7.078    # 40m JS8 frequency
    speed: normal           # slow, normal, fast, turbo
    heartbeat: true         # Send periodic beacons
```

**JS8 Speeds:**
| Mode | Speed | Sensitivity |
|------|-------|-------------|
| Slow | 8 WPM | -28 dB |
| Normal | 16 WPM | -24 dB |
| Fast | 24 WPM | -20 dB |
| Turbo | 40 WPM | -18 dB |

---

### APRS

Automatic Packet Reporting System for location and status.

```yaml
sdr:
  enabled: true
  primary_protocol: aprs

  aprs:
    callsign: "W1ABC-9"
    frequency_mhz: 144.390
    symbol: "/-"            # House symbol
    comment: "Cloakwise Node"
    beacon_interval_secs: 600
```

## Configuration

### Basic Setup

```yaml
sdr:
  enabled: true
  primary_protocol: lora
  callsign: "NOCALL"        # Use your callsign if licensed
  auto_activate_on_blackout: true
  mesh_enabled: true

  devices:
    - type: hackrf
      path: "/dev/hackrf0"
      serial: "0000000000000000"
```

### Advanced Setup

```yaml
sdr:
  enabled: true
  primary_protocol: lora
  fallback_protocol: ax25   # If LoRa fails
  callsign: "W1ABC"

  auto_activate_on_blackout: true
  blackout_detection:
    method: health_check    # health_check, dns, or both
    threshold_failures: 3
    check_interval_secs: 30

  mesh_enabled: true
  mesh:
    max_hops: 5
    ttl_minutes: 60
    relay_enabled: true     # Relay others' messages
    discovery_interval_secs: 300

  encryption:
    enabled: true
    algorithm: aes256gcm
    key_exchange: x25519
    perfect_forward_secrecy: true

  devices:
    - type: hackrf
      path: "/dev/hackrf0"
      tx_enabled: true
      rx_enabled: true
      gain_db: 40

    - type: rtlsdr
      path: "/dev/rtl0"
      rx_enabled: true      # RTL-SDR is receive-only
      gain_db: 30

  lora:
    frequency_mhz: 915.0
    bandwidth_khz: 125
    spreading_factor: 9
    tx_power_dbm: 14
```

## Hardware Setup

### RTL-SDR

```bash
# Install drivers
sudo apt install rtl-sdr librtlsdr-dev

# Blacklist kernel driver
echo "blacklist dvb_usb_rtl28xxu" | sudo tee /etc/modprobe.d/rtl-sdr.conf
sudo modprobe -r dvb_usb_rtl28xxu

# Add udev rules
sudo tee /etc/udev/rules.d/rtl-sdr.rules << 'EOF'
SUBSYSTEM=="usb", ATTRS{idVendor}=="0bda", ATTRS{idProduct}=="2838", GROUP="plugdev", MODE="0666"
EOF

sudo udevadm control --reload-rules
sudo udevadm trigger

# Test
rtl_test -t
```

### HackRF

```bash
# Install drivers
sudo apt install hackrf libhackrf-dev

# Add udev rules
sudo tee /etc/udev/rules.d/hackrf.rules << 'EOF'
SUBSYSTEM=="usb", ATTRS{idVendor}=="1d50", ATTRS{idProduct}=="6089", GROUP="plugdev", MODE="0666"
EOF

sudo udevadm control --reload-rules
sudo udevadm trigger

# Test
hackrf_info
```

### LoRa Module (SPI)

For Raspberry Pi with LoRa HAT:

```bash
# Enable SPI
sudo raspi-config
# Interface Options -> SPI -> Enable

# Verify
ls /dev/spidev*
# Should show /dev/spidev0.0
```

## Mesh Networking

### How It Works

1. **Discovery**: Nodes broadcast presence periodically
2. **Routing**: Messages hop through mesh to reach destination
3. **Deduplication**: Each message has unique ID, duplicates dropped
4. **TTL**: Messages expire after configured time

### Message Flow

```
┌─────────┐          ┌─────────┐          ┌─────────┐
│ Node A  │ ──────── │ Node B  │ ──────── │ Node C  │
│(blocked)│  Radio   │ (relay) │  Radio   │ (exit)  │
└─────────┘          └─────────┘          └─────────┘
     │                    │                    │
     │  "Send to Node C"  │                    │
     ├───────────────────►│                    │
     │                    │  "Relay to C"      │
     │                    ├───────────────────►│
     │                    │                    │
     │                    │                    │──── Internet
     │                    │                    │
     │  "Response from C" │                    │
     │◄───────────────────┤◄───────────────────┤
     │                    │                    │
```

### Mesh Configuration

```yaml
sdr:
  mesh:
    # Routing
    max_hops: 5              # Max relays before dropping
    ttl_minutes: 60          # Message expiration

    # Relaying
    relay_enabled: true      # Relay others' messages
    relay_priority: 0.5      # 0-1, higher = relay more

    # Discovery
    discovery_enabled: true
    discovery_interval_secs: 300
    announce_capabilities: true

    # Bandwidth management
    fair_queuing: true       # Prevent single node from hogging
    max_pending_messages: 100
```

## Blackout Detection

Cloakwise automatically detects internet blackouts:

```yaml
sdr:
  blackout_detection:
    method: health_check     # health_check, dns, or both

    # Health check method
    health_endpoints:
      - "https://www.google.com"
      - "https://cloudflare.com"
    health_check_interval_secs: 30
    threshold_failures: 3

    # DNS method
    dns_servers:
      - "8.8.8.8"
      - "1.1.1.1"
    dns_test_domain: "google.com"

    # Activation delay (prevent false positives)
    activation_delay_secs: 60
```

### Detection Flow

```
Normal → 3 health checks fail → Wait 60s → Still failing → Activate SDR
                                                               ↓
SDR Active → Health check succeeds → Wait 60s → Stable → Deactivate SDR
```

## Security

### Encryption

All radio traffic is encrypted by default:

```yaml
sdr:
  encryption:
    enabled: true
    algorithm: aes256gcm
    key_exchange: x25519
    perfect_forward_secrecy: true

    # Pre-shared key (for mesh without internet)
    psk: "base64-encoded-key"

    # Or use certificate-based
    # cert_path: "/etc/cloakwise/sdr-cert.pem"
    # key_path: "/etc/cloakwise/sdr-key.pem"
```

### Legal Considerations

**Important:** Radio transmission is regulated. Know your local laws.

| Region | License Required | Frequencies |
|--------|-----------------|-------------|
| USA | Depends on power/frequency | ISM: 915 MHz, Amateur: Various |
| EU | Depends on power/frequency | ISM: 868 MHz, Amateur: Various |
| China | Yes for most | Limited |

**ISM Bands** (license-free in most countries):
- 433 MHz (EU)
- 868 MHz (EU)
- 915 MHz (Americas)
- 2.4 GHz (Global)

**Amateur Bands** (license required):
- Higher power allowed
- More frequencies available
- Must identify with callsign

## API Endpoints

```bash
# Get SDR status
curl http://localhost:8080/api/sdr/status

# Response
{
  "enabled": true,
  "active": false,          # true when in blackout mode
  "protocol": "lora",
  "devices": [
    {"type": "hackrf", "status": "ready"}
  ],
  "mesh": {
    "known_nodes": 5,
    "messages_relayed": 123
  }
}

# Force activate SDR (testing)
curl -X POST http://localhost:8080/api/sdr/activate

# Deactivate SDR
curl -X POST http://localhost:8080/api/sdr/deactivate

# Send mesh message
curl -X POST http://localhost:8080/api/sdr/send \
  -H "Content-Type: application/json" \
  -d '{"dest": "NODE-ID", "message": "Hello"}'

# List mesh nodes
curl http://localhost:8080/api/sdr/mesh/nodes
```

## Troubleshooting

### Device Not Detected

```bash
# Check USB devices
lsusb | grep -i "rtl\|hackrf"

# Check permissions
ls -la /dev/hackrf0

# Check dmesg for errors
dmesg | tail -50
```

### Poor Range

1. **Antenna**: Use proper antenna for frequency
2. **Location**: Higher = better, avoid obstructions
3. **Settings**: Increase spreading factor (LoRa) for more range
4. **Power**: Use maximum legal power

### Interference

1. Check for nearby transmitters on same frequency
2. Try different frequency within allowed band
3. Use directional antenna
4. Increase spreading factor

## Next Steps

- [Configuration](Configuration) - Full config reference
- [Architecture](Architecture) - System overview
- [Troubleshooting](Troubleshooting) - Common issues
