# PolyPass CE App Graph Specification

| Field | Value |
|-------|-------|
| **Version** | v0.1.0 |
| **Status** | Draft |
| **Lex Namespace** | `polylabs/polypass` |
| **App Graph** | `circuits/fl/polypass_app_graph.fl` |
| **CE Meaning** | `circuits/fl/polypass_meaning.fl` |
| **Upstream Dependency** | eStream v0.22.0+, PolyKit v0.1.0+ |

---

## 1. Module Inventory

PolyPass comprises 12 modules (10 circuits + 2 graphs):

| Module | Type | Description |
|--------|------|-------------|
| `polypass_encrypt` | Circuit | PQ vault encryption — ML-KEM-1024 key wrap, scatter-CAS credential storage, per-entry AES-256-GCM |
| `polypass_autofill` | Circuit | Browser/app autofill engine — credential matching, form detection, phishing-resistant origin validation |
| `polypass_breach` | Circuit | Breach detection — k-anonymity HaveIBeenPwned check, dark web monitoring, credential rotation triggers |
| `polypass_totp` | Circuit | TOTP/HOTP generator — RFC 6238/4226 compliant, PQ-signed seed storage, time-drift correction |
| `polypass_share` | Circuit | Credential sharing — k-of-n threshold sharing, time-bounded access, revocable share tokens |
| `polypass_import` | Circuit | Vault import/export — Chrome CSV, 1Password 1PUX, Bitwarden JSON, LastPass CSV, KeePass KDBX |
| `polypass_rbac` | Circuit | Role-based access — vault owner, family member, team admin, read-only auditor profiles |
| `polypass_audit` | Circuit | Audit trail — ML-DSA-87 signed access logs, delta-curate credential change history |
| `polypass_metering` | Circuit | Usage metering — per-user credential count, autofill events, share operations, breach checks |
| `polypass_platform_health` | Circuit | Platform health — vault integrity checks, encryption key rotation scheduling, sync health |
| `vault_graph` | Graph | Credential vault DAG — folders, tags, credential entries, attachment blobs, favorites |
| `share_graph` | Graph | Share relationship graph — share tokens, recipient SPARK IDs, expiry, revocation state |

---

## 2. CE Meaning Domains

### 2.1 `security/vault_health`

Monitors vault-wide security posture derived from breach detection results and password strength analysis.

| Signal | Source | Meaning |
|--------|--------|---------|
| Breach alert fired | `polypass_breach` | Credential compromised — immediate rotation required |
| Weak password pattern | `polypass_encrypt` | Repeated or low-entropy passwords across vault entries |
| Reused credential detected | `polypass_encrypt` | Same password used across multiple origins |
| Encryption key age | `polypass_platform_health` | Key rotation overdue if age exceeds policy threshold |
| Vault integrity check failure | `polypass_platform_health` | Scatter-CAS shard inconsistency or corruption detected |

### 2.2 `security/autofill_accuracy`

Tracks autofill match quality and phishing detection effectiveness.

| Signal | Source | Meaning |
|--------|--------|---------|
| Autofill match rate | `polypass_autofill` | Percentage of form fills matched correctly on first attempt |
| Phishing origin blocked | `polypass_autofill` | Homograph or redirect-based phishing attempt intercepted |
| Multi-credential disambiguation | `polypass_autofill` | User has multiple credentials for same origin — disambiguation success rate |
| TOTP auto-paste rate | `polypass_totp` | Percentage of TOTP codes auto-pasted vs manually copied |

### 2.3 `security/sharing_patterns`

Observes credential sharing behavior for governance and anomaly detection.

| Signal | Source | Meaning |
|--------|--------|---------|
| Share token created | `polypass_share` | New credential share — recipient, scope, TTL |
| Share revocation velocity | `polypass_share` | Shares revoked within minutes of creation — possible accidental share |
| Expired share access attempt | `polypass_share` | Recipient attempted access after token expiry |
| Bulk share event | `polypass_share` | Multiple credentials shared in single session — onboarding vs exfiltration signal |

---

## 3. Noise Filter

Suppress high-frequency, low-signal events to prevent CE observation saturation:

| Suppressed Event | Reason |
|------------------|--------|
| Autofill cache miss (browser extension heartbeat) | Extension periodic cache refresh — no user action |
| Browser extension heartbeat ping | Liveness check — no security meaning |
| Vault sync ACK (per-shard) | Scatter-CAS replication protocol noise |
| TOTP code generation tick | 30-second timer tick — signal only on paste/use |
| Metering counter increment | Raw counter — aggregate in metering circuit, not CE |

Signal through (always observe):

| Signal Event | Reason |
|--------------|--------|
| Breach alert (any severity) | Immediate security meaning |
| Weak/reused password pattern detection | Vault health degradation |
| Phishing origin block | Active attack indicator |
| Share token creation/revocation | Governance-relevant behavior |
| Vault integrity check failure | Data integrity threat |
| Import/export operation | Bulk credential movement — security boundary event |

---

## 4. SME Panels

### 4.1 Vault Security Posture Panel

Convenes on vault health threshold crossings: breach count > 0, reused password ratio > 10%, weak password ratio > 15%, or encryption key age > rotation policy.

| Panelist | Focus |
|----------|-------|
| **Security Advocate** | Immediate rotation urgency, attack surface reduction, encryption freshness |
| **Usability Advocate** | User friction from forced rotation, autofill disruption risk, notification fatigue |
| **Synthesis** | Risk-adjusted recommendation: which credentials rotate now vs scheduled vs deferred |

### 4.2 Credential Sharing Governance Panel

Convenes on sharing anomalies: bulk share event, share-then-revoke pattern, or expired share access spike.

| Panelist | Focus |
|----------|-------|
| **Governance Advocate** | Access minimization, TTL enforcement, revocation completeness |
| **Collaboration Advocate** | Legitimate onboarding flows, team credential sharing needs, friction reduction |
| **Synthesis** | Classify event as normal onboarding, accidental share, or potential exfiltration |

---

## 5. Bridge Edges

### 5.1 PolyOAuth Bridge

| Direction | Shared Fields | Purpose |
|-----------|---------------|---------|
| `polypass` → `polyoauth` | `spark_id`, `sso_session_token`, `credential_origin` | SSO autofill — when user authenticates via PolyOAuth, PolyPass pre-fills the SSO credential without re-prompting |
| `polyoauth` → `polypass` | `sso_provider_metadata`, `token_refresh_status` | SSO provider registration — PolyOAuth informs PolyPass of registered SSO providers for autofill routing |

### 5.2 PolyAuthenticator Bridge

| Direction | Shared Fields | Purpose |
|-----------|---------------|---------|
| `polypass` → `polyauthenticator` | `totp_seed_encrypted`, `totp_issuer`, `totp_account` | TOTP seed sync — PolyPass vault stores TOTP seeds, PolyAuthenticator provides dedicated 2FA UX |
| `polyauthenticator` → `polypass` | `fido2_credential_id`, `webauthn_attestation` | FIDO2 credential store — PolyAuthenticator manages WebAuthn, PolyPass stores the credential reference |

---

## 6. Strategic Grants

| Grantor | Grant | Purpose |
|---------|-------|---------|
| **eStream** | `scatter-cas`, `ml-kem-1024`, `ml-dsa-87`, `spark`, `delta-curate`, `rbac`, `alert-pipeline`, `ssm` | Platform primitives for PQ encryption, identity, audit, access control, CE |
| **Paragon** | None (no Paragon dependency) | PolyPass is a consumer product — no family office platform dependency |

PolyPass operates as a standalone consumer/enterprise product. It consumes eStream platform primitives directly and bridges laterally to PolyOAuth and PolyAuthenticator within the Poly Labs product family.

---

## 7. Platform Graph Registration

### Circuit Counts

| Category | Count |
|----------|-------|
| App Graph modules | 12 (10 circuits + 2 graphs) |
| CE meaning domains | 3 |
| SME panels | 2 |
| Bridge edges | 2 (PolyOAuth, PolyAuthenticator) |
| **Total** | **12 modules** |

### Capability Inventory Update

```
polypass: {
    modules: 12,
    circuits: 10,
    graphs: 2,
    ce_meaning_domains: 3,
    sme_panels: 2,
    bridge_edges: 2,
    import_formats: 5 (Chrome, 1Password, Bitwarden, LastPass, KeePass),
    noise_filter_suppressed: 5,
    noise_filter_signaled: 6,
}
```
