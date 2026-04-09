# Epic: PolyPass CE App Graph

| Field | Value |
|-------|-------|
| **Priority** | P1 |
| **Status** | Open |
| **Spec** | `specs/POLYPASS_CE_APP_GRAPH_SPEC.md` |
| **Lex** | `polyqlabs/qpass` |

## Summary

Implement the PolyPass CE app graph: 12 module registrations (10 circuits + 2 graphs), 3 CE meaning domains, noise filter, 2 SME panels, and bridge edges to PolyOAuth + PolyAuthenticator.

## Task Checklist

- [ ] **App graph**: Implement `qpass_app_graph.fl` — 12 ModuleNode definitions, `make_qpass_module` helper, `qpass_app_graph_register`, intra-graph REQUIRES edges
- [ ] **Bridge edges**: Implement `qpass_register_bridge_edges` — PolyOAuth SSO autofill bridge, PolyAuthenticator TOTP/FIDO2 bridge
- [ ] **CE meaning domains**: Implement `qpass_meaning.fl` — `security/vault_health`, `security/autofill_accuracy`, `security/sharing_patterns`
- [ ] **Noise filter**: Implement `qpass_noise_filter` — suppress autofill cache misses, heartbeats, sync ACKs, TOTP ticks, metering increments
- [ ] **SME panels**: Implement vault security posture panel + credential sharing governance panel
- [ ] **CE orchestrator**: Implement `qpass_register_ce` — register all domains, noise rules, and panels
- [ ] **Golden tests**: Verify module count (12), bridge edge count (2), domain count (3), panel count (2), noise rule count (5)
- [ ] **Spec review**: Validate `POLYPASS_CE_APP_GRAPH_SPEC.md` against implementation
- [ ] **Platform inventory**: Register PolyPass counts in capability inventory

## Acceptance Criteria

1. `qpass_app_graph_register` adds exactly 12 modules with correct aperture partitions and SLA tiers
2. All intra-graph REQUIRES edges reflect actual circuit dependencies
3. Bridge edges to PolyOAuth and PolyAuthenticator use `BridgeScope::Product` with correct shared/redacted fields
4. CE meaning domains produce observable signals from the correct source modules
5. Noise filter suppresses 5 high-frequency low-signal event types
6. SME panels convene on specified trigger conditions with FOR/AGAINST synthesis
7. All golden tests pass
