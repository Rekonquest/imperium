# API Reference

Cloakwise provides a REST API for monitoring, configuration, and control.

## Base URL

```
http://localhost:8080/api
```

Configure in `config.yaml`:
```yaml
clients:
  config_api_port: 8080
  api_bind_address: "127.0.0.1"  # "0.0.0.0" for remote access
  api_auth_token: "your-secret-token"  # Optional
```

## Authentication

If `api_auth_token` is set, include it in requests:

```bash
curl -H "Authorization: Bearer your-secret-token" \
  http://localhost:8080/api/status
```

---

## System Status

### GET /api/status

Get overall system status.

**Response:**
```json
{
  "node_id": "node-alpha-01",
  "version": "0.1.0",
  "uptime_secs": 86400,
  "mode": "vpn",
  "active_protocol": "xray",
  "active_connections": 42,
  "ai_enabled": true,
  "sdr_active": false,
  "health": "healthy"
}
```

### GET /api/health

Health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "checks": {
    "vpn": "ok",
    "ai": "ok",
    "internet": "ok",
    "sdr": "standby"
  }
}
```

---

## Protocol Management

### GET /api/protocols

List all available protocols.

**Response:**
```json
{
  "protocols": [
    {
      "id": "xray",
      "name": "Xray/VLESS",
      "enabled": true,
      "active": true,
      "port": 443,
      "stealth_level": 9,
      "connections": 35
    },
    {
      "id": "cloak",
      "name": "Cloak",
      "enabled": true,
      "active": false,
      "port": 443,
      "stealth_level": 9,
      "connections": 0
    }
  ]
}
```

### GET /api/protocols/{id}

Get details for a specific protocol.

**Response:**
```json
{
  "id": "xray",
  "name": "Xray/VLESS",
  "enabled": true,
  "active": true,
  "port": 443,
  "stealth_level": 9,
  "connections": 35,
  "metrics": {
    "bytes_in": 1234567890,
    "bytes_out": 9876543210,
    "avg_latency_ms": 45,
    "errors_last_hour": 2
  },
  "config": {
    "transport": "ws",
    "path": "/api/v1/data",
    "host": "cdn.example.com"
  }
}
```

### POST /api/protocols/{id}/switch

Switch to a specific protocol.

**Request:**
```json
{
  "drain_timeout_ms": 5000,
  "force": false
}
```

**Response:**
```json
{
  "success": true,
  "previous_protocol": "cloak",
  "new_protocol": "xray",
  "switch_time_ms": 7
}
```

### PUT /api/protocols/{id}/config

Update protocol configuration.

**Request:**
```json
{
  "port": 8443,
  "custom_config": {
    "path": "/new-path"
  }
}
```

**Response:**
```json
{
  "success": true,
  "restart_required": false
}
```

---

## Client Management

### GET /api/clients

List all clients.

**Response:**
```json
{
  "clients": [
    {
      "id": "client-001",
      "name": "my-laptop",
      "created_at": "2024-01-15T10:30:00Z",
      "last_seen": "2024-01-15T14:22:33Z",
      "connected": true,
      "protocol": "xray",
      "ip": "10.0.0.2",
      "bytes_in": 123456,
      "bytes_out": 654321
    }
  ]
}
```

### POST /api/clients

Create a new client.

**Request:**
```json
{
  "name": "my-phone",
  "allowed_protocols": ["xray", "cloak"],
  "expires_at": "2024-12-31T23:59:59Z"
}
```

**Response:**
```json
{
  "id": "client-002",
  "name": "my-phone",
  "config": {
    "xray": "vmess://...",
    "cloak": "ss://...",
    "wireguard": "[Interface]\nPrivateKey=..."
  },
  "qr_codes": {
    "xray": "data:image/png;base64,...",
    "wireguard": "data:image/png;base64,..."
  }
}
```

### GET /api/clients/{id}

Get client details.

### DELETE /api/clients/{id}

Remove a client.

### GET /api/clients/{id}/config/{protocol}

Get client configuration for specific protocol.

**Response:**
```json
{
  "protocol": "xray",
  "config_text": "vmess://eyJ2IjoiMiIsInBzIjoi...",
  "config_json": {
    "v": "2",
    "ps": "my-phone",
    "add": "server.example.com",
    "port": "443"
  },
  "qr_code": "data:image/png;base64,..."
}
```

---

## AI System

### GET /api/ai/status

Get AI system status.

**Response:**
```json
{
  "enabled": true,
  "models_loaded": 3,
  "models": {
    "threat_detector": {"loaded": true, "version": "0.5.0"},
    "pattern_matcher": {"loaded": true, "version": "0.5.0"},
    "action_selector": {"loaded": true, "version": "0.5.0"}
  },
  "stats": {
    "decisions_total": 15234,
    "decisions_last_hour": 423,
    "avg_decision_time_ms": 67,
    "avg_confidence": 0.89,
    "fallback_triggers": 12
  }
}
```

### GET /api/ai/decisions

Get recent AI decisions.

**Query Parameters:**
- `limit` (int): Number of decisions (default: 100)
- `since` (timestamp): Filter by time

**Response:**
```json
{
  "decisions": [
    {
      "timestamp": "2024-01-15T14:22:33.123Z",
      "threat_type": "DPI_PROBE",
      "pattern": "CHINA_GFW",
      "action": "SWITCH_PROTOCOL",
      "confidence": 0.89,
      "latency_ms": 67,
      "executed": true
    }
  ]
}
```

### POST /api/ai/enable

Enable AI system.

### POST /api/ai/disable

Disable AI system (fallback to rules).

---

## Security

### GET /api/security/status

Get security tools status.

**Response:**
```json
{
  "tools": {
    "dpi_detector": {"enabled": true, "alerts_last_hour": 5},
    "probe_detector": {"enabled": true, "probes_blocked": 23},
    "rate_limiter": {"enabled": true, "limited_ips": 3},
    "ip_blocker": {"enabled": true, "blocked_ips": 15}
  },
  "threat_level": "medium",
  "last_threat": "2024-01-15T14:20:00Z"
}
```

### GET /api/security/threats

Get recent threats.

**Response:**
```json
{
  "threats": [
    {
      "id": "threat-001",
      "timestamp": "2024-01-15T14:20:00Z",
      "type": "DPI_PROBE",
      "source_ip": "1.2.3.4",
      "confidence": 0.87,
      "action_taken": "SWITCH_PROTOCOL",
      "resolved": true
    }
  ]
}
```

### GET /api/security/blocks

Get blocked IPs.

**Response:**
```json
{
  "blocks": [
    {
      "ip": "1.2.3.4",
      "reason": "probe_attempts",
      "blocked_at": "2024-01-15T14:00:00Z",
      "expires_at": "2024-01-16T14:00:00Z",
      "hits": 156
    }
  ]
}
```

### POST /api/security/block

Manually block an IP.

**Request:**
```json
{
  "ip": "5.6.7.8",
  "duration_hours": 24,
  "reason": "manual"
}
```

### DELETE /api/security/block/{ip}

Unblock an IP.

---

## SDR Radio Bridge

### GET /api/sdr/status

Get SDR status.

**Response:**
```json
{
  "enabled": true,
  "active": false,
  "protocol": "lora",
  "devices": [
    {
      "type": "hackrf",
      "path": "/dev/hackrf0",
      "status": "ready"
    }
  ],
  "mesh": {
    "known_nodes": 5,
    "reachable_nodes": 3,
    "messages_sent": 123,
    "messages_received": 456,
    "messages_relayed": 78
  }
}
```

### POST /api/sdr/activate

Manually activate SDR (for testing).

### POST /api/sdr/deactivate

Deactivate SDR.

### GET /api/sdr/mesh/nodes

List known mesh nodes.

**Response:**
```json
{
  "nodes": [
    {
      "id": "node-beta",
      "callsign": "W1ABC",
      "last_seen": "2024-01-15T14:22:00Z",
      "hops": 1,
      "signal_strength_dbm": -65,
      "capabilities": ["relay", "exit"]
    }
  ]
}
```

### POST /api/sdr/send

Send a mesh message.

**Request:**
```json
{
  "destination": "node-beta",
  "message": "Hello from node-alpha",
  "priority": "normal"
}
```

---

## Telemetry

### GET /api/telemetry/stats

Get traffic statistics.

**Response:**
```json
{
  "period": "1h",
  "bytes_in": 1234567890,
  "bytes_out": 9876543210,
  "packets_in": 123456,
  "packets_out": 654321,
  "connections_total": 1500,
  "connections_active": 42,
  "protocols": {
    "xray": {"bytes_in": 1000000, "bytes_out": 5000000},
    "cloak": {"bytes_in": 234567, "bytes_out": 4876543}
  }
}
```

### GET /api/telemetry/timeseries

Get time-series data.

**Query Parameters:**
- `metric`: bytes_in, bytes_out, connections, latency
- `period`: 1h, 24h, 7d, 30d
- `resolution`: 1m, 5m, 1h

**Response:**
```json
{
  "metric": "bytes_in",
  "period": "24h",
  "resolution": "1h",
  "data": [
    {"timestamp": "2024-01-14T15:00:00Z", "value": 123456789},
    {"timestamp": "2024-01-14T16:00:00Z", "value": 234567890}
  ]
}
```

---

## Configuration

### GET /api/config

Get current configuration (sensitive values redacted).

### PUT /api/config

Update configuration.

**Request:**
```json
{
  "logging": {
    "level": "debug"
  }
}
```

**Response:**
```json
{
  "success": true,
  "restart_required": false,
  "changes": ["logging.level"]
}
```

### POST /api/config/reload

Reload configuration from file.

---

## System Control

### POST /api/system/restart

Restart Cloakwise.

### POST /api/system/shutdown

Graceful shutdown.

### GET /api/system/logs

Get recent logs.

**Query Parameters:**
- `lines` (int): Number of lines (default: 100)
- `level`: error, warn, info, debug

**Response:**
```json
{
  "logs": [
    {
      "timestamp": "2024-01-15T14:22:33.123Z",
      "level": "info",
      "target": "cloakwise::core",
      "message": "Protocol switched: cloak -> xray"
    }
  ]
}
```

---

## WebSocket Endpoints

### /api/ws/events

Real-time event stream.

**Events:**
```json
{"type": "threat", "data": {"type": "DPI_PROBE", ...}}
{"type": "protocol_switch", "data": {"from": "cloak", "to": "xray"}}
{"type": "client_connect", "data": {"id": "client-001"}}
{"type": "sdr_activate", "data": {"reason": "blackout"}}
```

### /api/ws/stats

Real-time statistics stream (1 update/second).

```json
{
  "connections": 42,
  "bytes_in_rate": 1234567,
  "bytes_out_rate": 7654321,
  "ai_decisions_rate": 5
}
```

---

## Error Responses

All errors follow this format:

```json
{
  "error": {
    "code": "PROTOCOL_NOT_FOUND",
    "message": "Protocol 'invalid' not found",
    "details": {}
  }
}
```

**Common Error Codes:**
| Code | HTTP Status | Description |
|------|-------------|-------------|
| UNAUTHORIZED | 401 | Missing or invalid auth token |
| NOT_FOUND | 404 | Resource not found |
| VALIDATION_ERROR | 400 | Invalid request data |
| PROTOCOL_NOT_FOUND | 404 | Unknown protocol |
| CLIENT_NOT_FOUND | 404 | Unknown client |
| AI_DISABLED | 503 | AI system not available |
| SDR_NOT_AVAILABLE | 503 | SDR hardware not found |
| RATE_LIMITED | 429 | Too many requests |

---

## Rate Limiting

API requests are rate-limited:
- Default: 100 requests/minute per IP
- Authenticated: 1000 requests/minute

Headers:
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1705329600
```

---

## Examples

### Switch to most stealthy protocol on threat

```bash
#!/bin/bash
# Monitor for threats and switch protocols

curl -s http://localhost:8080/api/ws/events | while read line; do
  if echo "$line" | grep -q '"type":"threat"'; then
    # Switch to Cloak (most stealthy)
    curl -X POST http://localhost:8080/api/protocols/cloak/switch
  fi
done
```

### Generate client config and QR code

```bash
# Create client
response=$(curl -s -X POST http://localhost:8080/api/clients \
  -H "Content-Type: application/json" \
  -d '{"name": "my-device"}')

# Extract Xray config
echo "$response" | jq -r '.config.xray'

# Save QR code
echo "$response" | jq -r '.qr_codes.xray' | \
  sed 's/data:image\/png;base64,//' | \
  base64 -d > xray-qr.png
```

---

## Next Steps

- [Configuration](Configuration) - Full config reference
- [Architecture](Architecture) - System internals
- [Troubleshooting](Troubleshooting) - Common issues
