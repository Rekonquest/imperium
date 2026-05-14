# Troubleshooting

Common issues and solutions for Cloakwise.

## Quick Diagnostics

```bash
# Check service status
sudo systemctl status cloakwise

# View recent logs
journalctl -u cloakwise -n 100 --no-pager

# Check API health
curl http://localhost:8080/api/health

# Verbose mode for debugging
sudo cloakwise -c /etc/cloakwise/config.yaml -v
```

---

## Installation Issues

### Build fails with missing dependencies

**Error:**
```
error: linker `cc` not found
```

**Solution:**
```bash
# Ubuntu/Debian
sudo apt install build-essential pkg-config libssl-dev

# Fedora
sudo dnf install gcc pkg-config openssl-devel

# Arch
sudo pacman -S base-devel openssl
```

---

### Cargo build fails with "could not find native static library"

**Error:**
```
error: could not find native static library `ssl`
```

**Solution:**
```bash
# Ubuntu/Debian
sudo apt install libssl-dev

# Fedora
sudo dnf install openssl-devel
```

---

### Permission denied when starting

**Error:**
```
Error: Permission denied (os error 13)
```

**Solution:**
```bash
# Create directories with proper permissions
sudo mkdir -p /etc/cloakwise
sudo mkdir -p /var/log/cloakwise
sudo chmod 755 /etc/cloakwise /var/log/cloakwise

# Or run as root
sudo cloakwise -c /etc/cloakwise/config.yaml
```

---

## Configuration Issues

### Config file not found

**Error:**
```
Config file "/etc/cloakwise/config.yaml" not found
```

**Solution:**
```bash
# Run setup wizard
sudo cloakwise setup

# Or copy example config
sudo cp examples/config.yaml /etc/cloakwise/config.yaml
```

---

### Invalid YAML syntax

**Error:**
```
Error: YAML parse error at line 42
```

**Solution:**
```bash
# Validate YAML syntax
python3 -c "import yaml; yaml.safe_load(open('/etc/cloakwise/config.yaml'))"

# Or use yq
yq eval '.' /etc/cloakwise/config.yaml

# Common issues:
# - Tabs instead of spaces (YAML requires spaces)
# - Missing colons after keys
# - Unquoted special characters
```

---

### Unknown field in config

**Error:**
```
Error: Unknown field `unknwon_field` at line 15
```

**Solution:**
Check for typos in field names. See [Configuration](Configuration) for valid fields.

---

## Network Issues

### Port already in use

**Error:**
```
Error: Address already in use (os error 98)
```

**Solution:**
```bash
# Find what's using the port
sudo lsof -i :443
sudo netstat -tlnp | grep 443

# Kill the process or change port in config
# In config.yaml:
profiles:
  https_clone:
    port: 8443  # Use different port
```

---

### Cannot bind to port 443

**Error:**
```
Error: Permission denied (os error 13) binding to 0.0.0.0:443
```

**Solution:**
```bash
# Option 1: Run as root
sudo cloakwise ...

# Option 2: Use capabilities
sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/cloakwise

# Option 3: Use port > 1024 and redirect
# Use port 8443 in config, then:
sudo iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8443
```

---

### Clients cannot connect

**Checklist:**
1. Check firewall allows ports
   ```bash
   sudo ufw status
   sudo iptables -L -n
   ```

2. Check service is listening
   ```bash
   ss -tlnp | grep cloakwise
   ```

3. Check from client
   ```bash
   nc -zv server.example.com 443
   ```

4. Check VPN interface exists
   ```bash
   ip link show wg0
   ```

5. Review logs
   ```bash
   journalctl -u cloakwise -f
   ```

---

### Connection drops frequently

**Possible causes:**
1. DPI detection triggering protocol switches too often
2. Health checks failing
3. Network instability

**Solutions:**
```yaml
# Reduce AI sensitivity
confidence:
  specialist_threshold: 0.90  # Higher = less switches

# Increase health check tolerance
fallback:
  failure_threshold: 100      # More failures before switching
  health_check_interval_secs: 120  # Less frequent checks
```

---

## AI Issues

### AI models not loading

**Error:**
```
Error: Failed to load model: threat-detector-0.5b.gguf
```

**Solution:**
```bash
# Download models
cloakwise models download

# Or manually download
mkdir -p /opt/cloakwise/models
cd /opt/cloakwise/models
wget https://github.com/Rekonquest/Dynamic-VPN/releases/download/models-v1/threat-detector-0.5b.gguf

# Check permissions
ls -la /opt/cloakwise/models/
chmod 644 /opt/cloakwise/models/*.gguf
```

---

### AI decisions too slow

**Symptom:** Decision latency >200ms

**Solutions:**
```yaml
# Reduce model complexity
models:
  inference:
    threads: 2        # Reduce if CPU-bound
    context_size: 1024  # Smaller context
    batch_size: 256     # Smaller batches
    timeout_ms: 150     # Increase timeout slightly

# Or disable one model
confidence:
  min_specialists_for_consensus: 1
```

---

### AI making wrong decisions

**Symptom:** Switching protocols unnecessarily

**Solutions:**
```yaml
# Increase confidence threshold
confidence:
  specialist_threshold: 0.92  # Require higher confidence

# Enable fallback for uncertain decisions
fallback:
  timed_rotation_hours: 0  # Disable time-based rotation
```

---

## SDR Issues

### SDR device not detected

**Error:**
```
Error: No SDR devices found
```

**Solution:**
```bash
# Check USB device
lsusb | grep -i "rtl\|hackrf"

# Install drivers
# RTL-SDR
sudo apt install rtl-sdr
# HackRF
sudo apt install hackrf

# Check kernel driver isn't blocking
sudo rmmod dvb_usb_rtl28xxu 2>/dev/null

# Add udev rules
sudo tee /etc/udev/rules.d/rtl-sdr.rules << 'EOF'
SUBSYSTEM=="usb", ATTRS{idVendor}=="0bda", ATTRS{idProduct}=="2838", GROUP="plugdev", MODE="0666"
EOF
sudo udevadm control --reload-rules
sudo udevadm trigger

# Reconnect device
```

---

### Poor SDR range

**Solutions:**
1. Use proper antenna (matched to frequency)
2. Position antenna higher with clear view
3. Increase spreading factor (LoRa)
   ```yaml
   sdr:
     lora:
       spreading_factor: 12  # Max range, lowest speed
   ```
4. Increase TX power (within legal limits)
   ```yaml
   sdr:
     lora:
       tx_power_dbm: 20  # Check local regulations!
   ```

---

### SDR transmission errors

**Error:**
```
Error: TX underrun
```

**Solution:**
Reduce data rate or increase buffer:
```yaml
sdr:
  lora:
    spreading_factor: 10  # Slower but more reliable
    bandwidth_khz: 62.5   # Narrower bandwidth
```

---

## Security Tool Issues

### Suricata not working

**Error:**
```
Error: Suricata not found at /usr/bin/suricata
```

**Solution:**
```bash
# Install Suricata
sudo apt install suricata

# Update rules
sudo suricata-update

# Start Suricata
sudo systemctl start suricata
```

---

### Too many false positives

**Symptom:** DPI detector triggering on normal traffic

**Solutions:**
```yaml
security:
  dpi_detector:
    sensitivity: low  # Reduce sensitivity

  # Or whitelist known IPs
  whitelist:
    - "192.168.0.0/16"
    - "10.0.0.0/8"
```

---

### Rate limiter blocking legitimate users

**Solution:**
```yaml
security:
  rate_limiter:
    per_ip:
      requests_per_minute: 500  # Increase limit
    whitelist:
      - "your-office-ip/32"
```

---

## Performance Issues

### High CPU usage

**Diagnosis:**
```bash
# Check which component is using CPU
top -H -p $(pgrep cloakwise)
```

**Solutions:**
```yaml
# Reduce AI threads
models:
  inference:
    threads: 2

# Reduce sensor polling
telemetry:
  sample_rate: 0.5  # Sample 50% of traffic

# Disable expensive security tools
security:
  deep_capture:
    enabled: false
  suricata:
    enabled: false
```

---

### High memory usage

**Diagnosis:**
```bash
# Check memory breakdown
cat /proc/$(pgrep cloakwise)/smaps | grep -E "^(Size|Rss):" | awk '{sum+=$2} END {print sum/1024 "MB"}'
```

**Solutions:**
```yaml
# Reduce buffer pool
# In config or code adjustment

# Reduce model context
models:
  inference:
    context_size: 1024

# Limit connection tracking
security:
  flow_collector:
    max_flows: 10000
```

---

### Slow protocol switching

**Symptom:** Switch takes >50ms

**Solutions:**
```yaml
# Pre-warm connections
profiles:
  xray:
    keep_warm: true  # Maintain standby connection

# Reduce drain timeout
# In API calls:
{
  "drain_timeout_ms": 1000
}
```

---

## Log Analysis

### Enable debug logging

```yaml
logging:
  level: debug
```

Or at runtime:
```bash
curl -X PUT http://localhost:8080/api/config \
  -H "Content-Type: application/json" \
  -d '{"logging": {"level": "debug"}}'
```

### Key log patterns

**Normal operation:**
```
[INFO] Cloakwise started, node: node-alpha-01
[INFO] Protocol xray listening on 0.0.0.0:443
[INFO] AI models loaded: 3/3
[DEBUG] Health check passed: google.com
```

**Threat detection:**
```
[WARN] DPI probe detected from 1.2.3.4
[INFO] AI decision: SWITCH_PROTOCOL (confidence: 0.89)
[INFO] Switching protocol: xray -> cloak
[INFO] Protocol switch complete in 7ms
```

**Errors:**
```
[ERROR] Failed to connect to peer: Connection refused
[ERROR] AI model inference timeout
[ERROR] SDR TX failed: device busy
```

### Grep useful patterns

```bash
# Find all errors
journalctl -u cloakwise | grep -i error

# Find protocol switches
journalctl -u cloakwise | grep "switch"

# Find threat detections
journalctl -u cloakwise | grep -i "threat\|probe\|dpi"

# Find AI decisions
journalctl -u cloakwise | grep "ai_decision\|AI decision"
```

---

## Getting Help

### Gather diagnostics

```bash
# Create diagnostics bundle
cloakwise diagnostics > diagnostics.txt

# Or manually:
{
  echo "=== System Info ==="
  uname -a
  echo "=== Cloakwise Version ==="
  cloakwise --version
  echo "=== Config (redacted) ==="
  cat /etc/cloakwise/config.yaml | grep -v password | grep -v token
  echo "=== Recent Logs ==="
  journalctl -u cloakwise -n 200 --no-pager
  echo "=== Network ==="
  ss -tlnp | grep cloakwise
  echo "=== Memory ==="
  free -h
} > diagnostics.txt
```

### Report issues

1. Check existing issues: https://github.com/Rekonquest/Dynamic-VPN/issues
2. Create new issue with:
   - Cloakwise version
   - OS version
   - Config (sensitive values redacted)
   - Steps to reproduce
   - Error messages
   - Diagnostics bundle

---

## Next Steps

- [Configuration](Configuration) - Configuration reference
- [API Reference](API-Reference) - API documentation
- [Installation](Installation) - Installation guide
