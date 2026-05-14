# Architecture Overview

Cloakwise is designed as a modular, high-performance system for adaptive VPN defense.

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              CLOAKWISE                                  │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                        ORCHESTRATOR                              │   │
│  │  Coordinates all components, manages state, handles events       │   │
│  └──────────────────────────────┬──────────────────────────────────┘   │
│                                 │                                       │
│  ┌──────────────────────────────┼──────────────────────────────────┐   │
│  │                              │                                   │   │
│  │  ┌───────────────┐  ┌───────┴───────┐  ┌───────────────┐        │   │
│  │  │  AI LAYER     │  │  CORE SWITCH  │  │  SECURITY     │        │   │
│  │  │               │  │               │  │  TOOLKIT      │        │   │
│  │  │ Threat Det.   │  │ Mode Manager  │  │               │        │   │
│  │  │ Pattern Match │  │ Session Mgr   │  │ DPI Detector  │        │   │
│  │  │ Action Select │  │ Blackout Det. │  │ Probe Det.    │        │   │
│  │  └───────┬───────┘  └───────┬───────┘  │ Rate Limiter  │        │   │
│  │          │                  │          └───────┬───────┘        │   │
│  │          └──────────────────┼──────────────────┘                │   │
│  │                             │                                   │   │
│  │  ┌──────────────────────────┴──────────────────────────────┐   │   │
│  │  │                    UNIFIED SENSOR BUS                    │   │   │
│  │  │  Collects, normalizes, and distributes telemetry data    │   │   │
│  │  └──────────────────────────┬──────────────────────────────┘   │   │
│  │                             │                                   │   │
│  └─────────────────────────────┼───────────────────────────────────┘   │
│                                │                                       │
│  ┌─────────────────────────────┴───────────────────────────────────┐   │
│  │                      UNIFIED TRANSPORT CORE                      │   │
│  ├─────────────────────────────────────────────────────────────────┤   │
│  │                                                                  │   │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐   │   │
│  │  │  Xray   │ │  Cloak  │ │ Trojan  │ │ Amnezia │ │Hysteria │   │   │
│  │  └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘   │   │
│  │       │           │           │           │           │         │   │
│  │  ┌────┴───────────┴───────────┴───────────┴───────────┴────┐   │   │
│  │  │              OUTBOUND REGISTRY (Hot-Swap)               │   │   │
│  │  └─────────────────────────┬───────────────────────────────┘   │   │
│  │                            │                                    │   │
│  │  ┌─────────────────────────┴───────────────────────────────┐   │   │
│  │  │  Crypto Engine  │  Buffer Pool  │  Hardware Abstraction │   │   │
│  │  └─────────────────────────────────────────────────────────┘   │   │
│  │                                                                  │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                │                                       │
│  ┌─────────────────────────────┴───────────────────────────────────┐   │
│  │                         SDR RADIO BRIDGE                         │   │
│  │  LoRa  │  AX.25  │  JS8  │  APRS  │  Mesh Controller            │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

## Core Components

### Orchestrator

The central coordinator that manages system state and event flow.

**Location:** `src/orchestrator/`

**Responsibilities:**
- Receives events from all components
- Coordinates AI decisions with actions
- Manages graceful shutdown
- Maintains system state

```rust
pub struct Orchestrator {
    config: Config,
    shutdown_tx: watch::Sender<bool>,
    state: Arc<RwLock<SystemState>>,
}
```

---

### Unified Transport Core

Single, efficient core for all VPN protocol handling.

**Location:** `src/core/`

**Components:**

#### Outbound Registry
Hot-swappable protocol registry with <10ms switching.

```rust
pub trait Outbound: Send + Sync {
    fn protocol_id(&self) -> &str;
    async fn connect(&self, target: SocketAddr) -> Result<BoxedAsyncStream>;
    fn get_telemetry(&self) -> ProtocolMetrics;
    async fn mutate(&self, mutation: ProtocolMutation) -> Result<()>;
    async fn drain(&self, timeout: Duration) -> Result<()>;
}

pub struct OutboundRegistry {
    outbounds: RwLock<HashMap<String, Arc<dyn Outbound>>>,
    active_outbound: RwLock<Option<String>>,
}
```

#### Crypto Engine
Shared cryptographic primitives with key caching.

```rust
pub struct CryptoEngine {
    aes_pool: RwLock<Vec<Aes256Gcm>>,
    chacha_pool: RwLock<Vec<ChaCha20Poly1305>>,
    kdf_cache: RwLock<LruCache<String, Zeroizing<Vec<u8>>>>,
}
```

#### Buffer Pool
Zero-copy buffer management with automatic return.

```rust
pub struct BufferPool {
    buffers: Mutex<Vec<BytesMut>>,
    buffer_size: usize,
}

pub struct PooledBuffer<'a> {
    inner: BytesMut,
    pool: &'a BufferPool,
}
// Auto-returns to pool on drop
```

#### Core Switch
Manages transport mode transitions.

```rust
pub enum TransportMode {
    Direct,     // No VPN
    Vpn,        // VPN only
    Radio,      // SDR only
    RadioVpn,   // SDR + VPN
    SafeMode,   // Most conservative
    Blackout,   // Emergency mode
}
```

---

### AI Layer

Micro-model architecture for real-time decisions.

**Location:** `src/bigmomma/` (historical name), `src/specialists/`

**Components:**

```
┌─────────────────────────────────────────────────────────┐
│                    MICRO-MODELS                         │
│                                                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     │
│  │   Threat    │  │   Pattern   │  │   Action    │     │
│  │  Detector   │  │   Matcher   │  │  Selector   │     │
│  │   (~0.5B)   │  │   (~0.5B)   │  │   (~0.5B)   │     │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘     │
│         │                │                │             │
│         └────────────────┼────────────────┘             │
│                          ▼                              │
│              ┌───────────────────────┐                  │
│              │   Consensus Engine    │                  │
│              └───────────────────────┘                  │
│                          │                              │
│                          ▼                              │
│              ┌───────────────────────┐                  │
│              │   Fallback System     │                  │
│              │  (rule-based backup)  │                  │
│              └───────────────────────┘                  │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

### Unified Sensor Bus

Collects and normalizes telemetry from all sources.

**Location:** `src/core/sensors.rs`

```rust
pub struct SensorBus {
    readings: RwLock<HashMap<SensorSource, VecDeque<SensorReading>>>,
    output_tx: broadcast::Sender<SensorReading>,
    threat_cache: RwLock<HashMap<String, ThreatAssessment>>,
}

pub enum SensorSource {
    PacketCapture,
    DpiDetector,
    ProbeDetector,
    FlowCollector,
    SdrReceiver,
    HardwareTelemetry,
}
```

---

### Security Toolkit

Threat detection and response tools.

**Location:** `src/security/`

**Components:**
- `dpi_detector.rs` - Deep packet inspection detection
- `probe_detector.rs` - Active probing detection
- `rate_limiter.rs` - Connection rate limiting
- `ip_blocker.rs` - IP blocking
- `geo_blocker.rs` - Geographic blocking

---

### SDR Radio Bridge

Radio communication for blackout scenarios.

**Location:** `src/sdr/`

**Components:**
- `mod.rs` - SDR module coordinator
- `lora.rs` - LoRa protocol implementation
- `ax25.rs` - AX.25 packet radio
- `mesh.rs` - Mesh networking logic

---

### Hardware Abstraction Layer

Unified access to hardware sensors.

**Location:** `src/core/hardware.rs`

```rust
pub trait HardwareDevice: Send + Sync {
    fn component(&self) -> HardwareComponent;
    fn poll(&self) -> Result<HardwareHealth>;
    fn is_available(&self) -> bool;
}

pub enum HardwareComponent {
    Tpm,
    SmartNic,
    Cpu,
    Memory,
    SdrDevice,
}
```

---

## Data Flow

### Normal Operation

```
1. Client connects
      │
      ▼
2. Telemetry collected ────────────────────┐
      │                                     │
      ▼                                     ▼
3. Security tools analyze          Sensor Bus aggregates
      │                                     │
      ▼                                     │
4. AI models evaluate  ◄───────────────────┘
      │
      ▼
5. Decision made (continue/switch/block)
      │
      ▼
6. Action executed via Core Switch
```

### Threat Detection Flow

```
1. DPI Detector sees anomaly
      │
      ▼
2. Sensor Bus receives reading
      │
      ▼
3. Reading sent to AI models
      │
      ▼
4. Threat Detector: "DPI_PROBE" (0.87)
   Pattern Matcher: "GFW_PATTERN" (0.92)
   Action Selector: "SWITCH_PROTOCOL" (0.89)
      │
      ▼
5. Consensus Engine validates (avg 0.89 > 0.85)
      │
      ▼
6. Core Switch executes protocol change
      │
      ▼
7. Outbound Registry hot-swaps in <10ms
```

### Blackout Activation Flow

```
1. Health checks fail 3x
      │
      ▼
2. Blackout detector confirms
      │
      ▼
3. Core Switch enters BLACKOUT mode
      │
      ▼
4. SDR Radio Bridge activates
      │
      ▼
5. Mesh network discovery begins
      │
      ▼
6. Traffic routes through radio mesh
      │
      ▼
7. Health checks continue in background
      │
      ▼
8. Internet restored → Return to normal
```

---

## Module Dependencies

```
                    ┌─────────────────┐
                    │   orchestrator  │
                    └────────┬────────┘
                             │
        ┌────────────────────┼────────────────────┐
        │                    │                    │
        ▼                    ▼                    ▼
┌───────────────┐   ┌───────────────┐   ┌───────────────┐
│     core      │   │   security    │   │      sdr      │
└───────┬───────┘   └───────┬───────┘   └───────┬───────┘
        │                   │                   │
        │                   │                   │
        └───────────────────┼───────────────────┘
                            │
                            ▼
                   ┌───────────────┐
                   │    config     │
                   └───────────────┘
```

---

## Concurrency Model

Cloakwise uses Tokio for async runtime:

- **Main tasks**: Orchestrator, telemetry collector, health checker
- **Per-connection tasks**: Protocol handlers
- **Background tasks**: AI inference, sensor polling

**Synchronization:**
- `RwLock` for read-heavy data (outbound registry, sensor cache)
- `Mutex` for write-heavy data (buffer pool)
- `watch` channels for shutdown coordination
- `broadcast` channels for sensor distribution

---

## Performance Targets

| Metric | Target | Typical |
|--------|--------|---------|
| Protocol switch | <10ms | 5-8ms |
| AI decision | <100ms | 60-80ms |
| Sensor latency | <10ms | 2-5ms |
| Memory (minimal) | <500MB | 200-300MB |
| Memory (full) | <2GB | 800MB-1.2GB |
| CPU (idle) | <5% | 1-2% |

---

## Configuration Flow

```
1. config.yaml loaded
      │
      ▼
2. Config struct validated
      │
      ▼
3. Components initialized with config
      │
      ▼
4. Runtime config changes via API
      │
      ▼
5. Hot-reload where supported
```

---

## Extension Points

### Adding New Protocols

1. Implement `Outbound` trait
2. Register in `OutboundRegistry`
3. Add configuration options
4. Update setup wizard

### Adding New Security Tools

1. Implement tool in `src/security/`
2. Register with `SensorBus`
3. Define sensor readings
4. Add AI training data

### Adding New Hardware Support

1. Implement `HardwareDevice` trait
2. Register in `HardwareAbstractionLayer`
3. Add detection logic
4. Update setup wizard

---

## File Structure

```
src/
├── main.rs              # Entry point
├── orchestrator/        # Central coordinator
│   └── mod.rs
├── core/                # Unified transport core
│   ├── mod.rs
│   ├── transport.rs     # Outbound trait & registry
│   ├── crypto.rs        # Crypto engine
│   ├── buffer.rs        # Buffer pool
│   ├── switch.rs        # Core switch
│   ├── sensors.rs       # Sensor bus
│   └── hardware.rs      # HAL
├── security/            # Security toolkit
│   ├── mod.rs
│   ├── dpi_detector.rs
│   ├── probe_detector.rs
│   └── rate_limiter.rs
├── sdr/                 # SDR radio bridge
│   ├── mod.rs
│   ├── lora.rs
│   └── mesh.rs
├── vpn/                 # VPN protocols
│   ├── mod.rs
│   ├── xray.rs
│   ├── cloak.rs
│   └── ...
├── bigmomma/            # AI models
│   └── mod.rs
├── specialists/         # Specialist models
│   └── mod.rs
├── config/              # Configuration
│   └── mod.rs
├── telemetry/           # Telemetry collection
│   └── mod.rs
├── ui/                  # Web UI
│   └── mod.rs
└── setup/               # Setup wizard
    ├── mod.rs
    ├── wizard.rs
    ├── prompts.rs
    ├── hardware_detect.rs
    └── config_builder.rs
```

## Next Steps

- [API Reference](API-Reference) - REST API documentation
- [Configuration](Configuration) - Config options
- [Contributing](Contributing) - Development guide
