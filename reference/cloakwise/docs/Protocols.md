# Supported Protocols

Cloakwise supports multiple VPN protocols, each with different stealth characteristics and performance profiles. The system can hot-swap between protocols in <10ms to evade detection.

## Protocol Comparison

| Protocol | Stealth | Speed | Complexity | Best For |
|----------|---------|-------|------------|----------|
| Xray/VLESS | 9/10 | High | Medium | General censorship evasion |
| Cloak | 9/10 | Medium | Low | Mimicking HTTPS exactly |
| Trojan-Go | 8/10 | High | Low | Simple, effective obfuscation |
| NaiveProxy | 8/10 | High | Medium | Using Chrome's network stack |
| Briar | 8/10 | Low | High | P2P mesh, no servers needed |
| AmneziaWG | 7/10 | Very High | Low | Speed with obfuscation |
| Snowflake | 7/10 | Medium | High | Tor integration |
| Hysteria2 | 6/10 | Very High | Medium | Speed over stealth |
| Iodine | 6/10 | Low | Medium | When only DNS works |
| Shadowsocks | 5/10 | High | Low | Legacy compatibility |

## Detailed Protocol Information

### Xray/VLESS

**Stealth: 9/10 | Speed: High**

Xray is a modern, highly configurable protocol that supports multiple transport layers and can perfectly mimic HTTPS traffic.

```yaml
profiles:
  xray_https:
    protocol: xray
    port: 443
    obfuscation: tls1_3
    custom_config:
      transport: ws          # websocket, grpc, tcp, h2
      path: "/api/v1/data"
      host: "cdn.example.com"
      security: tls
      sni: "www.microsoft.com"
      alpn: ["h2", "http/1.1"]
```

**Features:**
- VLESS protocol (lightweight, no encryption overhead)
- Multiple transports: WebSocket, gRPC, HTTP/2, TCP
- XTLS for reduced latency
- Fallback to real websites on probe

**Use when:** You need maximum configurability and stealth

---

### Cloak

**Stealth: 9/10 | Speed: Medium**

Cloak makes VPN traffic indistinguishable from normal HTTPS by perfectly mimicking TLS handshakes and traffic patterns.

```yaml
profiles:
  cloak_https:
    protocol: cloak
    port: 443
    obfuscation: tls1_3
    timing: web_browsing
    padding: variable
    custom_config:
      domain: "www.microsoft.com"
      browser_sig: "chrome"
      num_conn: 4
      stream_timeout: 300
```

**Features:**
- Perfect TLS 1.3 mimicry
- Real certificate from target domain
- Browser fingerprint simulation
- Multiplexed connections

**Use when:** Facing sophisticated DPI that detects VPN fingerprints

---

### Trojan-Go

**Stealth: 8/10 | Speed: High**

Trojan-Go disguises traffic as normal HTTPS. Failed authentication serves a real website, making probing ineffective.

```yaml
profiles:
  trojan_stealth:
    protocol: trojan
    port: 443
    custom_config:
      password: "your-password"
      sni: "your-domain.com"
      fallback_addr: "127.0.0.1"
      fallback_port: 80
      websocket:
        enabled: true
        path: "/ws"
```

**Features:**
- Looks like normal HTTPS
- Fallback to real web server
- WebSocket support for CDN compatibility
- Multiplexing support

**Use when:** You need simple setup with good stealth

---

### AmneziaWG

**Stealth: 7/10 | Speed: Very High**

AmneziaWG is obfuscated WireGuard that resists protocol fingerprinting while maintaining WireGuard's excellent performance.

```yaml
profiles:
  amnezia_fast:
    protocol: amneziawg
    port: 51820
    timing: interactive
    custom_config:
      junk_packet_count: 4
      junk_packet_min_size: 40
      junk_packet_max_size: 70
      init_packet_junk_size: 0
      response_packet_junk_size: 0
      init_packet_magic_header: 1
      response_packet_magic_header: 2
      transport_packet_magic_header: 3
      underload_packet_magic_header: 4
```

**Features:**
- WireGuard performance (~800 Mbps)
- Randomized packet headers
- Junk packet injection
- Timing obfuscation

**Use when:** Speed is priority but basic obfuscation needed

---

### NaiveProxy

**Stealth: 8/10 | Speed: High**

Uses Chromium's network stack to generate traffic identical to Chrome browser.

```yaml
profiles:
  naive_chrome:
    protocol: naiveproxy
    port: 443
    custom_config:
      username: "user"
      password: "pass"
      host: "your-domain.com"
      padding: true
```

**Features:**
- Real Chrome network fingerprint
- HTTP/2 with proper HPACK
- Indistinguishable from browser traffic
- CDN-compatible

**Use when:** Censors are fingerprinting VPN client software

---

### Hysteria2

**Stealth: 6/10 | Speed: Very High**

QUIC-based protocol optimized for unstable networks and high speed.

```yaml
profiles:
  hysteria_speed:
    protocol: hysteria2
    port: 443
    custom_config:
      password: "your-password"
      up_mbps: 100
      down_mbps: 100
      obfs: salamander
      obfs_password: "obfs-password"
```

**Features:**
- QUIC-based (UDP)
- Excellent on lossy networks
- Brutal congestion control
- Optional obfuscation layer

**Use when:** Network is unstable or you need maximum speed

---

### Snowflake

**Stealth: 7/10 | Speed: Medium**

Tor's pluggable transport using WebRTC to hide traffic.

```yaml
profiles:
  snowflake_tor:
    protocol: snowflake
    port: 443
    custom_config:
      broker_url: "https://snowflake-broker.torproject.net/"
      stun_urls:
        - "stun:stun.l.google.com:19302"
      front_domain: "cdn.sstatic.net"
```

**Features:**
- WebRTC-based (looks like video call)
- Uses volunteer proxies
- Domain fronting support
- Tor network integration

**Use when:** Need to access Tor in heavily censored regions

---

### Iodine

**Stealth: 6/10 | Speed: Low**

DNS tunneling for when HTTP/HTTPS is blocked but DNS queries work.

```yaml
profiles:
  iodine_dns:
    protocol: iodine
    port: 53
    custom_config:
      domain: "t.example.com"
      password: "your-password"
      max_downstream_frag: 1232
      lazy_mode: true
```

**Features:**
- Works when only DNS is available
- Survives captive portals
- Very hard to block completely
- Low bandwidth (~100kbps)

**Use when:** All other protocols are blocked, only DNS works

---

### Briar

**Stealth: 8/10 | Speed: Low**

P2P mesh messaging that works without internet via Bluetooth, WiFi, and Tor.

```yaml
profiles:
  briar_mesh:
    protocol: briar
    custom_config:
      enable_bluetooth: true
      enable_wifi: true
      enable_tor: true
      sync_interval_minutes: 5
```

**Features:**
- No central server required
- Bluetooth mesh networking
- WiFi direct connections
- Tor integration when internet available

**Use when:** Internet is completely unavailable, need local mesh

---

### Shadowsocks

**Stealth: 5/10 | Speed: High**

Classic proxy protocol. Less stealthy but widely supported.

```yaml
profiles:
  shadowsocks_legacy:
    protocol: shadowsocks
    port: 8388
    custom_config:
      method: "aes-256-gcm"
      password: "your-password"
      plugin: "v2ray-plugin"
      plugin_opts: "server;tls;host=cdn.example.com"
```

**Features:**
- Simple and reliable
- Wide client support
- Plugin system (v2ray, obfs)
- Good performance

**Use when:** Need compatibility with existing clients

---

## Protocol Selection Strategy

### For Maximum Stealth

Enable these protocols in priority order:
1. Xray/VLESS with WebSocket + TLS
2. Cloak
3. Trojan-Go
4. NaiveProxy

### For Maximum Speed

Enable these protocols:
1. AmneziaWG
2. Hysteria2
3. Xray/VLESS with gRPC

### For Hostile Networks

Enable fallback protocols:
1. Primary: Xray or Trojan
2. Secondary: Snowflake
3. Emergency: Iodine (DNS tunnel)
4. Blackout: Briar (mesh)

### Resource-Constrained Devices

For Raspberry Pi or similar:
1. AmneziaWG (low overhead)
2. Shadowsocks (simple)
3. Trojan-Go (moderate)

## Hot-Swapping

Cloakwise can switch protocols in <10ms without dropping connections:

```
Internet ────┬──── Xray ──────┐
             ├──── Cloak ─────┤
             ├──── Trojan ────┼──── Your Traffic
             ├──── AmneziaWG ─┤
             └──── Hysteria ──┘
                     ↑
              AI selects best
              protocol in real-time
```

The AI monitors:
- DPI detection attempts
- Connection failures
- Latency changes
- Probe patterns

And automatically switches to evade blocking.

## Next Steps

- [Configuration](Configuration) - Configure protocol options
- [AI System](AI-System) - How AI selects protocols
- [Security Tools](Security-Tools) - Threat detection
