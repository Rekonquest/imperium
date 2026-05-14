# AI System

Cloakwise uses lightweight AI models for real-time threat detection and response. The system is designed to make decisions in <100ms without cloud connectivity.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    SENSOR INPUTS                            │
│  Packet Capture │ DPI Signals │ Probe Detection │ Latency   │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                 MICRO-MODEL LAYER (~1.5B total)             │
│                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │   Threat    │  │   Pattern   │  │   Action    │         │
│  │  Detector   │  │   Matcher   │  │  Selector   │         │
│  │   (~0.5B)   │  │   (~0.5B)   │  │   (~0.5B)   │         │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘         │
│         │                │                │                 │
│         └────────────────┼────────────────┘                 │
│                          │                                  │
│                          ▼                                  │
│              ┌───────────────────────┐                      │
│              │   Consensus Engine    │                      │
│              │    (Vote + Merge)     │                      │
│              └───────────┬───────────┘                      │
│                          │                                  │
└──────────────────────────┼──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                    ACTION OUTPUT                            │
│  Switch Protocol │ Rate Limit │ Block IP │ Alert │ Log     │
└─────────────────────────────────────────────────────────────┘
```

## Micro-Model Philosophy

Instead of one large model, Cloakwise uses three specialized ~0.5B parameter models:

| Model | Purpose | Input | Output |
|-------|---------|-------|--------|
| **Threat Detector** | Identify attack patterns | Traffic features | Threat type + confidence |
| **Pattern Matcher** | Classify traffic intent | Packet signatures | Traffic classification |
| **Action Selector** | Choose response | Threat + context | Recommended action |

### Why Micro-Models?

1. **Speed**: <100ms decisions (vs seconds for large models)
2. **Resources**: ~200MB RAM total (vs 4GB+ for 7B models)
3. **Reliability**: No cloud dependency
4. **Privacy**: All processing local

### Decision Flow

```
1. Threat Detector analyzes incoming traffic
   → Output: "DPI_PROBE" with 0.87 confidence

2. Pattern Matcher classifies the probe
   → Output: "CHINA_GFW_PATTERN" with 0.92 confidence

3. Action Selector chooses response
   → Output: "SWITCH_TO_CLOAK" with 0.89 confidence

4. Consensus Engine validates
   → All models agree (0.87 + 0.92 + 0.89)/3 = 0.89 > 0.85 threshold
   → Execute: Switch to Cloak protocol

Total time: 67ms
```

## Model Configuration

### Basic Configuration

```yaml
models:
  specialists_dir: "/opt/cloakwise/models/"

  inference:
    threads: 4
    context_size: 2048
    batch_size: 512
    temperature: 0.1
    timeout_ms: 100

confidence:
  specialist_threshold: 0.85
  min_specialists_for_consensus: 2
```

### Advanced Configuration

```yaml
models:
  # Individual model paths (optional)
  threat_detector: "/opt/cloakwise/models/threat-0.5b.gguf"
  pattern_matcher: "/opt/cloakwise/models/pattern-0.5b.gguf"
  action_selector: "/opt/cloakwise/models/action-0.5b.gguf"

  # GPU acceleration (if available)
  use_gpu: true
  gpu_layers: 32

  inference:
    threads: 4
    context_size: 2048
    batch_size: 512
    temperature: 0.1
    max_tokens: 64
    timeout_ms: 100

    # Quantization for speed
    quantization: "q4_k_m"

confidence:
  specialist_threshold: 0.85
  escalation_timeout_ms: 5000
  min_specialists_for_consensus: 2

  # Per-model thresholds
  threat_detector_threshold: 0.80
  pattern_matcher_threshold: 0.85
  action_selector_threshold: 0.90
```

## Downloading Models

### Via CLI

```bash
# Download all micro-models
cloakwise models download

# Download to specific directory
cloakwise models download --dir /opt/cloakwise/models

# Download specific model
cloakwise models download --model threat-detector

# List available models
cloakwise models list
```

### Manual Download

Models are available at:
```
https://github.com/Rekonquest/Dynamic-VPN/releases/download/models-v1/
├── threat-detector-0.5b.gguf    (~200MB)
├── pattern-matcher-0.5b.gguf    (~200MB)
└── action-selector-0.5b.gguf    (~200MB)
```

```bash
mkdir -p /opt/cloakwise/models
cd /opt/cloakwise/models
wget https://github.com/Rekonquest/Dynamic-VPN/releases/download/models-v1/threat-detector-0.5b.gguf
wget https://github.com/Rekonquest/Dynamic-VPN/releases/download/models-v1/pattern-matcher-0.5b.gguf
wget https://github.com/Rekonquest/Dynamic-VPN/releases/download/models-v1/action-selector-0.5b.gguf
```

## Threat Types Detected

The Threat Detector recognizes these patterns:

| Threat Type | Description | Response |
|-------------|-------------|----------|
| `DPI_PROBE` | Deep packet inspection detected | Switch protocol |
| `ACTIVE_PROBE` | Server being probed | Serve decoy content |
| `REPLAY_ATTACK` | Captured packet replayed | Drop + rate limit |
| `TIMING_ANALYSIS` | Traffic timing correlation | Adjust padding |
| `BANDWIDTH_ANALYSIS` | Traffic volume fingerprinting | Normalize traffic |
| `PROTOCOL_FINGERPRINT` | VPN signature detected | Switch protocol |
| `CONNECTION_RESET` | Injected RST packets | Reconnect via different route |
| `DNS_POISONING` | DNS responses manipulated | Use DoH/DoT |
| `CERTIFICATE_MITM` | TLS interception detected | Alert + block |

## Traffic Classifications

The Pattern Matcher classifies traffic as:

| Pattern | Description |
|---------|-------------|
| `CHINA_GFW` | Great Firewall of China signature |
| `IRAN_NIN` | Iranian National Internet signature |
| `RUSSIA_TSPU` | Russian TSPU device signature |
| `CORPORATE_DLP` | Enterprise DLP system |
| `ISP_THROTTLE` | ISP bandwidth throttling |
| `GENERIC_DPI` | Unknown DPI system |
| `LEGITIMATE` | Normal internet traffic |
| `UNCERTAIN` | Cannot classify with confidence |

## Actions Available

The Action Selector can recommend:

| Action | Description |
|--------|-------------|
| `SWITCH_PROTOCOL` | Change to different VPN protocol |
| `INCREASE_PADDING` | Add more packet padding |
| `ADJUST_TIMING` | Modify traffic timing patterns |
| `ENABLE_DECOY` | Activate decoy traffic generator |
| `RATE_LIMIT` | Limit suspicious source |
| `BLOCK_IP` | Block malicious IP |
| `ALERT` | Send alert to admin |
| `SAFE_MODE` | Enter safe mode (most stealthy profile) |
| `BLACKOUT_MODE` | Switch to SDR radio |
| `CONTINUE` | No action needed |

## Fallback System

When AI is disabled or uncertain, rule-based fallback activates:

```yaml
fallback:
  # Rotate profiles on schedule
  timed_rotation_hours: 4

  # Switch after too many failures
  failure_threshold: 50
  failure_window_minutes: 10

  # Profile priority order
  profile_rotation_order:
    - "https_clone"    # Most stealthy first
    - "video_call"
    - "websocket"
    - "gaming"

  # Emergency profile
  safe_mode_profile: "https_clone"
  safe_mode_lock_minutes: 30
```

### Fallback Rules

1. **Connectivity Loss**: If health checks fail 3x in a row, switch to next profile
2. **High Failure Rate**: If >50 failures in 10 minutes, switch profile
3. **Timed Rotation**: Change profile every 4 hours regardless
4. **Safe Mode**: If 3 profiles fail, lock to safest profile for 30 minutes

## Hardware Requirements

| Tier | AI Capability | RAM for AI | Latency |
|------|--------------|------------|---------|
| Minimal | Disabled | 0MB | N/A |
| Standard | 2 models | ~400MB | ~150ms |
| Enhanced | 3 models | ~600MB | ~100ms |
| Lab | 3 models + GPU | ~2GB | ~30ms |

### GPU Acceleration

For NVIDIA GPUs:

```yaml
models:
  use_gpu: true
  gpu_layers: 32  # Layers to offload to GPU
```

For AMD GPUs (ROCm):

```bash
# Build with ROCm support
cargo build --release --features rocm
```

## Monitoring AI Performance

### Via API

```bash
# Get AI status
curl http://localhost:8080/api/ai/status

# Response
{
  "enabled": true,
  "models_loaded": 3,
  "avg_decision_time_ms": 67,
  "decisions_last_hour": 1423,
  "confidence_avg": 0.89,
  "fallback_triggers": 2
}
```

### Via Logs

```bash
# Watch AI decisions
journalctl -u cloakwise -f | grep "ai_decision"

# Example output
[INFO] ai_decision threat=DPI_PROBE confidence=0.87 action=SWITCH_PROTOCOL latency_ms=67
```

## Training Custom Models

For advanced users who want to train on their own traffic:

```bash
# Export training data
cloakwise ai export-training --output training_data.json

# Format: JSONL with features and labels
{"features": [...], "label": "DPI_PROBE", "action": "SWITCH_PROTOCOL"}
```

Training scripts and documentation available in the `training/` directory.

## Future: Big Momma Integration

For users with powerful hardware, Cloakwise supports an optional larger model for strategic reasoning:

```yaml
models:
  # Enable strategic reasoning (requires 8GB+ RAM)
  big_momma:
    enabled: true
    path: "/opt/cloakwise/models/big-momma-7b.gguf"

    # Only consult for complex decisions
    escalation_threshold: 0.70
    max_context: 8192
```

Big Momma provides:
- Long-term pattern analysis
- Predictive threat modeling
- Coordinated multi-node strategies

This is optional and not required for normal operation.

## Next Steps

- [Configuration](Configuration) - Full config reference
- [Security Tools](Security-Tools) - Threat detection sensors
- [Protocols](Protocols) - Protocol selection
