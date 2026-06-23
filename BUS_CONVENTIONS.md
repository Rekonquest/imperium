# Bus Topic Conventions

Topic strings on the in-process bus follow a hierarchical, dot-separated namespace.
`Bus::subscribe(prefix)` receives every event whose topic `starts_with(prefix)`.
This means topic segments must be ordered from general → specific so that prefix
subscriptions work correctly.

## Namespace layout

```
emergency.*              Runtime-level emergency shutdown signals
runtime.*                RuntimeCoordinator lifecycle
net.transport.*          Protocol controllers, orchestrator decisions
net.sensors.*            Classifier, signature engine
net.signatures.*         Signature staging, approval, activation, extraction
net.strainer.*           Strainer stack rejections
net.cluster.*            Cluster membership, config, gossip
net.mesh.*               Mesh transport (ping/pong)
net.toolkit.*            Toolkit activation, state
```

## Rules

1. **General → specific ordering.** The discriminating segment comes last so that
   prefix subscriptions remain valid. Example: `net.transport.event.wireguard`,
   not `net.transport.wireguard.event`.

2. **Emergency topics use the `emergency.*` namespace.** Any message that the
   `RuntimeCoordinator` must receive to trigger shutdown lives under `emergency.`.
   Subsystem-specific emergency topics use `emergency.{subsystem}.{reason}`.

3. **Subsystem ready topics** follow `{namespace}.ready` — e.g. `net.sensors.ready`,
   `net.transport.ready`.

4. **No implicit cross-namespace subscriptions.** A crate subscribing to `net.sensors.`
   should not receive `net.signatures.` events. Keep namespaces disjoint.

5. **Dynamic segments** (protocol kind, subsystem name) are always the final segment.

## Audit table

Generated 2026-05-13 (Round 5 update). Covers every `bus.publish()` and `bus.subscribe()` call in production code.

### Publishers

| # | Crate | File | Topic | Message | Subscriber match |
|---|-------|------|-------|---------|-----------------|
| 1 | imperium-runtime | lib.rs | `runtime.subsystem.ready.{name}` | SubsystemReady | `runtime.subsystem.ready` (runtime tests) ✓ |
| 2 | imperium-cli | control.rs | `emergency.cli.operator_shutdown` | EmergencyShutdown | `emergency` (coordinator) ✓ |
| 3 | imperium-cli | control.rs | `net.signatures.approve_request` | SubsystemReady | `net.signatures.` (signatures init) ✓ |
| 4 | imperium-cli | control.rs | `net.signatures.reject_request` | SignatureRejected | `net.signatures.` (signatures init) ✓ |
| 5 | imperium-cli | control.rs | `net.signatures.extraction_request` | ExtractionRequest | `net.signatures.extraction_request` (extraction loop) ✓ |
| 6 | imperium-net-transport | orchestrator.rs | `emergency.transport.double_degraded` | EmergencyShutdown | `emergency` (coordinator) ✓ |
| 7 | imperium-net-transport | orchestrator.rs | `net.transport.command` | ProtocolCmd | `net.transport.` (transport init) ✓ |
| 8 | imperium-net-transport | orchestrator.rs | `net.transport.decision` | OrchestratorDecision | `net.transport.` (transport init) ✓ |
| 9 | imperium-net-transport | controller.rs | `net.transport.event.{kind}` | ProtocolEvt | `net.transport.event` (orchestrator) ✓ |
| 10 | imperium-net-transport | lib.rs | `net.transport.ready` | SubsystemReady | `net.transport.` (transport init) ✓ |
| 11 | imperium-net-sensors | lib.rs | `net.sensors.ready` | SubsystemReady | `net.sensors.` (sensors init, orchestrator) ✓ |
| 12 | imperium-net-sensors | classifier.rs | `net.sensors.threat` | ThreatAssessment | `net.sensors.` (orchestrator) ✓ |
| 13 | imperium-net-sensors | signature_engine.rs | `net.sensors.signature_match` | ThreatAssessment | `net.sensors.` (orchestrator) ✓ |
| 14 | imperium-net-sensors | signature_engine.rs | `net.signatures.activated` | SignatureActivated | `net.signatures.` (signatures init) ✓ |
| 15 | imperium-net-sensors | signature_engine.rs | `net.signatures.activation_failed` | SignatureActivationFailed | `net.signatures.` (signatures init) ✓ |
| 16 | imperium-net-signatures | lib.rs | `net.signatures.ready` | SubsystemReady | `net.signatures.` (signatures init) ✓ |
| 17 | imperium-net-signatures | staging.rs | `net.signatures.candidate` | SignatureCandidate | `net.signatures.` (signatures init) ✓ |
| 18 | imperium-net-signatures | staging.rs | `net.signatures.approved` | SignatureApproved | `net.signatures.approved` (engine) ✓ |
| 19 | imperium-net-signatures | staging.rs | `net.signatures.rejected` | SignatureRejected | `net.signatures.` (signatures init) ✓ |
| 20 | imperium-net-signatures | extractor.rs | `net.signatures.candidate_pending` | SignatureCandidatePending | `net.signatures.` (signatures init) ✓ |
| 21 | imperium-net-signatures | extractor.rs | `net.signatures.extraction_failed` | ExtractionFailed | `net.signatures.` (signatures init) ✓ |
| 22 | imperium-net-strainer | lib.rs | `net.strainer.ready` | SubsystemReady | `net.strainer.` (strainer init) ✓ |
| 23 | imperium-net-strainer | stack.rs | `net.strainer.rejection` | StrainerRejection | `net.strainer.rejection` (memory-log), `net.strainer.` (init) ✓ |
| 24 | imperium-net-cluster | lib.rs | `net.cluster.ready` | SubsystemReady | `net.cluster.` (cluster init) ✓ |
| 25 | imperium-net-cluster | membership.rs | `net.cluster.membership.request` | MembershipApprovalReq | `net.cluster.` (cluster init) ✓ |
| 26 | imperium-net-cluster | membership.rs | `net.cluster.membership.granted` | MembershipGrant | `net.cluster.membership.granted` (membership), `net.cluster.` (init) ✓ |
| 27 | imperium-net-cluster | membership.rs | `net.cluster.membership.gossip` | MembershipGossip | `net.cluster.` (cluster init) ✓ |
| 28 | imperium-net-cluster | config.rs | `net.cluster.config.updated` | ConfigVersion | `net.cluster.` (cluster init) ✓ |
| 29 | imperium-net-cluster | config.rs | `net.cluster.config.fetch_request` | ConfigFetchReq | `net.cluster.` (cluster init) ✓ |
| 30 | imperium-net-cluster | config.rs | `net.cluster.config.fetch_response` | ConfigFetchResp | `net.cluster.config.fetch_response` (config), `net.cluster.` (init) ✓ |
| 34 | imperium-net-mesh | lib.rs | `net.mesh.ready` | SubsystemReady | `net.mesh.` (mesh init) ✓ |
| 35 | imperium-net-mesh | transport.rs | `net.mesh.ping.sent` | MeshPing | `net.mesh.` (mesh init) ✓ |
| 36 | imperium-net-mesh | transport.rs | `net.mesh.pong.sent` | MeshPong | `net.mesh.` (mesh init) ✓ |
| 37 | imperium-net-toolkit | lib.rs | `net.toolkit.activation` | ToolActivationReq | — (skeleton, no subscriber) ✓ |
| 38 | imperium-net-toolkit | lib.rs | `net.toolkit.state` | ToolStateChange | — (skeleton, no subscriber) ✓ |

### Subscribers

| # | Crate | File | Pattern | Matches topics |
|---|-------|------|---------|---------------|
| 1 | imperium-runtime | lib.rs | `emergency` | `emergency`, `emergency.*` |
| 2 | imperium-runtime | lib.rs (tests) | `runtime.subsystem.ready` | `runtime.subsystem.ready.*` |
| 3 | imperium-net-transport | lib.rs | `net.transport.` | all `net.transport.*` |
| 4 | imperium-net-transport | orchestrator.rs | `net.transport.event` | `net.transport.event`, `net.transport.event.*` |
| 5 | imperium-net-transport | orchestrator.rs | `net.sensors.` | all `net.sensors.*` |
| 7 | imperium-net-sensors | lib.rs | `net.sensors.` | all `net.sensors.*` |
| 8 | imperium-net-sensors | signature_engine.rs | `net.signatures.approved` | `net.signatures.approved` |
| 9 | imperium-net-signatures | lib.rs | `net.signatures.` | all `net.signatures.*` |
| 10 | imperium-net-signatures | extractor.rs | `net.signatures.extraction_request` | `net.signatures.extraction_request` |
| 11 | imperium-net-strainer | lib.rs | `net.strainer.` | all `net.strainer.*` |
| 12 | imperium-net-cluster | lib.rs | `net.cluster.` | all `net.cluster.*` |
| 13 | imperium-net-cluster | config.rs | `net.cluster.config.fetch_response` | exact match |
| 14 | imperium-net-cluster | membership.rs | `net.cluster.membership.granted` | `net.cluster.membership.granted` |
| 16 | imperium-net-mesh | lib.rs | `net.mesh.` | all `net.mesh.*` |
| 17 | imperium-memory-log | lib.rs | `net.strainer.rejection` | `net.strainer.rejection` |
| 18 | imperium-memory-log | lib.rs | `net.transport.` | all `net.transport.*` |

### Known issues

| Issue | Status |
|-------|--------|
| Toolkit orphan publishers (`net.toolkit.*`) | Expected — skeleton crate, no subscriber yet |
