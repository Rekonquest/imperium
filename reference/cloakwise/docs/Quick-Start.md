# Quick Start Guide

Get Cloakwise running in 5 minutes.

## 1. Install

```bash
# Download and install
curl -LO https://github.com/Rekonquest/Dynamic-VPN/releases/latest/download/cloakwise-linux-amd64.tar.gz
tar -xzf cloakwise-linux-amd64.tar.gz
sudo mv cloakwise /usr/local/bin/
```

## 2. Run Setup Wizard

```bash
sudo cloakwise setup
```

Follow the prompts to:
- Detect your hardware
- Select VPN protocols
- Configure settings

## 3. Start the Service

```bash
# Start manually
sudo cloakwise -c /etc/cloakwise/config.yaml

# Or use systemd
sudo systemctl start cloakwise
```

## 4. Verify It's Working

```bash
# Check status
curl http://localhost:8080/api/status

# View dashboard
open http://localhost:8080/
```

## 5. Connect Clients

Generate client configurations:

```bash
# Via API
curl http://localhost:8080/api/clients/new -X POST \
  -H "Content-Type: application/json" \
  -d '{"name": "my-laptop"}'
```

## What's Next?

- [Configuration](Configuration) - Customize your setup
- [Protocols](Protocols) - Learn about available protocols
- [Security Tools](Security-Tools) - Enable threat detection
- [Troubleshooting](Troubleshooting) - Fix common issues
