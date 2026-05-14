# Installation Guide

This guide covers installing Cloakwise on various platforms.

## Prerequisites

- Linux (Ubuntu 20.04+, Debian 11+, Fedora 35+, or similar)
- Rust 1.70+ (for building from source)
- Root access (for VPN interface management)

### System Dependencies

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y build-essential pkg-config libssl-dev wireguard-tools

# Fedora/RHEL
sudo dnf install -y gcc pkg-config openssl-devel wireguard-tools

# Arch Linux
sudo pacman -S base-devel openssl wireguard-tools
```

## Installation Methods

### 1. Pre-built Binaries (Recommended)

Download the latest release:

```bash
# Download latest release
curl -LO https://github.com/Rekonquest/Dynamic-VPN/releases/latest/download/cloakwise-linux-amd64.tar.gz

# Extract
tar -xzf cloakwise-linux-amd64.tar.gz

# Install
sudo mv cloakwise /usr/local/bin/
sudo chmod +x /usr/local/bin/cloakwise

# Verify installation
cloakwise --version
```

### 2. Build from Source

```bash
# Clone repository
git clone https://github.com/Rekonquest/Dynamic-VPN.git
cd Dynamic-VPN

# Build release binary
cargo build --release

# Install
sudo cp target/release/cloakwise /usr/local/bin/
```

### 3. Docker

```bash
# Pull image
docker pull rekonquest/cloakwise:latest

# Run with host networking (required for VPN)
docker run -d \
  --name cloakwise \
  --net=host \
  --cap-add=NET_ADMIN \
  -v /etc/cloakwise:/etc/cloakwise \
  -v /var/log/cloakwise:/var/log/cloakwise \
  rekonquest/cloakwise:latest
```

## Post-Installation Setup

### 1. Run Setup Wizard

The easiest way to configure Cloakwise:

```bash
sudo cloakwise setup
```

This interactive wizard will:
- Detect your hardware capabilities
- Help you select protocols
- Configure AI settings
- Generate a config file

See [Setup Wizard](Setup-Wizard) for details.

### 2. Manual Configuration

Create the configuration directory:

```bash
sudo mkdir -p /etc/cloakwise
sudo mkdir -p /var/log/cloakwise
```

Copy the example configuration:

```bash
sudo cp examples/config.yaml /etc/cloakwise/config.yaml
```

Edit to match your environment:

```bash
sudo nano /etc/cloakwise/config.yaml
```

See [Configuration](Configuration) for all options.

### 3. Download AI Models (Optional)

If using AI features:

```bash
# Download micro-models
cloakwise models download

# Or specify model directory
cloakwise models download --dir /opt/cloakwise/models
```

### 4. Create Systemd Service

```bash
# Create service file
sudo tee /etc/systemd/system/cloakwise.service > /dev/null << 'EOF'
[Unit]
Description=Cloakwise Adaptive VPN Defense
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/cloakwise -c /etc/cloakwise/config.yaml
Restart=always
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
EOF

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable cloakwise
sudo systemctl start cloakwise
```

### 5. Verify Installation

```bash
# Check service status
sudo systemctl status cloakwise

# View logs
journalctl -u cloakwise -f

# Check API
curl http://localhost:8080/api/status
```

## Platform-Specific Notes

### Raspberry Pi

For Raspberry Pi 3/4:

```bash
# Use ARM binary
curl -LO https://github.com/Rekonquest/Dynamic-VPN/releases/latest/download/cloakwise-linux-arm64.tar.gz

# Or build natively (slower)
cargo build --release
```

Recommended: Use "Minimal" hardware tier in setup wizard.

### VPS/Cloud

For cloud servers:

1. Ensure your provider allows VPN traffic
2. Open required ports in firewall/security groups
3. Consider using "Standard" tier (AI disabled for CPU efficiency)

### With SDR Hardware

For SDR radio bridge functionality:

```bash
# Install SDR dependencies
sudo apt install -y rtl-sdr librtlsdr-dev

# Add udev rules for RTL-SDR
sudo tee /etc/udev/rules.d/rtl-sdr.rules > /dev/null << 'EOF'
SUBSYSTEM=="usb", ATTRS{idVendor}=="0bda", ATTRS{idProduct}=="2838", GROUP="plugdev", MODE="0666"
EOF

sudo udevadm control --reload-rules
sudo udevadm trigger
```

## Upgrading

### From Pre-built Binary

```bash
# Stop service
sudo systemctl stop cloakwise

# Download new version
curl -LO https://github.com/Rekonquest/Dynamic-VPN/releases/latest/download/cloakwise-linux-amd64.tar.gz
tar -xzf cloakwise-linux-amd64.tar.gz
sudo mv cloakwise /usr/local/bin/

# Start service
sudo systemctl start cloakwise
```

### From Source

```bash
cd Dynamic-VPN
git pull
cargo build --release
sudo systemctl stop cloakwise
sudo cp target/release/cloakwise /usr/local/bin/
sudo systemctl start cloakwise
```

## Uninstallation

```bash
# Stop and disable service
sudo systemctl stop cloakwise
sudo systemctl disable cloakwise

# Remove files
sudo rm /usr/local/bin/cloakwise
sudo rm /etc/systemd/system/cloakwise.service
sudo rm -rf /etc/cloakwise
sudo rm -rf /var/log/cloakwise

# Reload systemd
sudo systemctl daemon-reload
```

## Next Steps

- [Quick Start](Quick-Start) - Get running in 5 minutes
- [Configuration](Configuration) - Full configuration reference
- [Setup Wizard](Setup-Wizard) - Interactive configuration guide
