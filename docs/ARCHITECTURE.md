# Poly Pass Architecture

**Version**: 3.0
**Date**: February 2026
**Platform**: eStream v0.8.3
**Upstream**: PolyKit v0.3.0, eStream scatter-cas, graph/DAG constructs
**Build Pipeline**: FastLang (.fl) → ESCIR → Rust/WASM codegen → .escd

---

## Overview

Poly Pass is a post-quantum encrypted password manager with SPARK biometric authentication. No master password — vaults are unlocked exclusively via device-bound biometric keys. Credentials are individually PQ-encrypted, scatter-distributed via classification-driven k-of-n erasure coding, and synced across devices over the eStream wire protocol.

### What Changed in v3.0

| Area | v2.0 | v3.0 |
|------|------|------|
| Vault model | Flat encrypted container | `graph vault_registry` with typed overlays |
| Sharing | Flat ACL stream | `graph share_network` with typed edges + `share_lifecycle` state machine |
| Credential state | Implicit | `state_machine credential_lifecycle` (ACTIVE → DELETED) |
| Circuit format | ESCIR YAML (`circuit.escir.yaml`) | FastLang `.fl` with PolyKit profiles |
| RBAC | Per-circuit annotations | eStream `rbac.fl` composed via PolyKit |
| Platform | eStream v0.8.1 | eStream v0.8.3 |

---

## Zero-Linkage Privacy

Poly Pass operates under the Poly Labs zero-linkage privacy architecture:

- **HKDF context**: `poly-pass-v1` — produces `user_id`, signing key, and encryption key that cannot be correlated with any other Poly product
- **Lex namespace**: `esn/global/org/polylabs/pass` — completely isolated from other product namespaces
- **StreamSight**: Telemetry stays within `polylabs.pass.*` lex paths
- **Metering**: Own `metering_graph` instance under `polylabs.pass.metering` lex
- **Billing**: Tier checked via blinded token status, not cross-product identity

---

## Identity & Authentication

### SPARK Derivation Context

```
SPARK biometric → Secure Enclave/TEE → master_seed (in WASM, never exposed to JS)
                                            │
                                            ▼
                                   HKDF-SHA3-256(master_seed, "poly-pass-v1")
                                            │
                                            ├── ML-DSA-87 signing key pair
                                            │   (vault manifests, credential changes, ACL changes)
                                            │
                                            └── ML-KEM-1024 encryption key pair
                                                (credential key wrapping, share key exchange)
```

### User Identity

```
user_id = SHA3-256(spark_ml_dsa_87_public_key)[0..16]   # 16-byte truncated hash
```

All stream topics, vault ownership, and ACLs reference this SPARK-derived `user_id`. There are no usernames, emails, or phone numbers. This `user_id` is unique to Poly Pass and cannot be linked to identities in other Poly products.

### No Master Password

| Traditional Password Managers | Poly Pass |
|-------------------------------|-----------|
| Master password → PBKDF2/Argon2 → vault key | SPARK biometric → Secure Enclave → ML-DSA-87 key pair → ML-KEM-1024 → vault decryption key |
| Phishable (password to steal) | Cannot be phished (biometric, not typed) |
| Keyloggable (typed input) | Cannot be keylogged (hardware biometric) |
| Brute-forceable (entropy-limited) | Hardware-enforced rate limiting |

Recovery: K-of-N guardian recovery via PolyKit `user_graph` guardian edges.

---

## Core Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Poly Pass Client                              │
│                                                                       │
│  ┌─────────────┐  ┌─────────────┐  ┌──────────┐  ┌──────────────┐  │
│  │ Vault       │  │ Autofill    │  │ Password │  │ Security     │  │
│  │ Manager(UI) │  │ Engine      │  │ Generator│  │ Audit (UI)   │  │
│  └──────┬──────┘  └──────┬──────┘  └────┬─────┘  └──────┬───────┘  │
│         │                │              │               │           │
│  ┌──────┴────────────────┴──────────────┴───────────────┴────────┐  │
│  │              FastLang Circuits (WASM via .escd)                  │  │
│  │                                                                 │  │
│  │  polypass_encrypt.fl │ polypass_autofill.fl │ polypass_audit.fl │  │
│  │  polypass_share.fl   │ polypass_metering.fl │ polypass_import.fl│  │
│  │  (all ML-DSA-87 signed .escd packages, StreamSight-annotated)  │  │
│  └──────────────────────────┬──────────────────────────────────────┘  │
│                              │                                        │
│  ┌──────────────────────────┴──────────────────────────────────────┐  │
│  │  Graph/DAG Layer (WASM, backed by scatter-cas)                    │  │
│  │                                                                   │  │
│  │  graph vault_registry  — credential store as a graph              │  │
│  │  graph share_network   — sharing ACLs + family/team vaults        │  │
│  │  graph metering_graph  — per-app 8D usage (from PolyKit)         │  │
│  │  graph user_graph      — per-product identity (from PolyKit)      │  │
│  └──────────────────────────┬──────────────────────────────────────┘  │
│                              │                                        │
│  ┌──────────────────────────┴──────────────────────────────────────┐  │
│  │  ESLite (Client-Side State)                                       │  │
│  │  /polypass/vault/*    — credential metadata + encrypted cache     │  │
│  │  /polypass/autofill/* — URL → credential index                   │  │
│  │  /polypass/audit/*    — breach check cache, strength scores       │  │
│  └──────────────────────────┬──────────────────────────────────────┘  │
│                              │                                        │
│  ┌──────────────────────────┴──────────────────────────────────────┐  │
│  │  eStream SDK (@estream/sdk-browser or react-native)              │  │
│  │  Wire protocol only: UDP :5000 / WebTransport :4433             │  │
│  └──────────────────────────┬──────────────────────────────────────┘  │
└──────────────────────────────┼────────────────────────────────────────┘
                               │
                        eStream Wire Protocol (QUIC/UDP)
                               │
┌──────────────────────────────┼────────────────────────────────────────┐
│                         eStream Network                                │
│                               │                                        │
│  ┌────────────────────────────┴─────────────────────────────────────┐ │
│  │  Lattice-Hosted Circuits                                           │ │
│  │                                                                    │ │
│  │  polypass_vault_sync.fl │ polypass_share_relay.fl                  │ │
│  │  polypass_metering.fl   │ scatter-cas runtime                     │ │
│  └────┬───────────┬──────────────┬──────────────────────────────────┘ │
│       │           │              │                                     │
│  ┌────┴──────────────────────────────────────────────────────────┐   │
│  │              Scatter Storage Layer (via scatter-cas)              │   │
│  │  AWS │ GCP │ Azure │ Cloudflare │ Hetzner │ Self-host           │   │
│  └─────────────────────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────────────────────┘
```

---

## Graph/DAG Constructs

### Vault Registry Graph (`polypass_vault_graph.fl`)

The credential vault is modeled as a typed graph. Credentials, folders, and shared vaults are nodes; containment and sharing are edges. Overlays provide real-time state (breach status, password age, strength score) without mutating the base graph.

```fastlang
type CredentialNode = struct {
    credential_id: bytes(16),
    site: bytes(256),
    username_hash: bytes(32),
    encrypted_password: bytes(512),
    totp_seed_encrypted: bytes(256),
    passkey_credential_id: bytes(128),
    classification: u8,
    created_at: u64,
    updated_at: u64,
}

type FolderNode = struct {
    folder_id: bytes(16),
    name: bytes(128),
    icon: u16,
    created_at: u64,
}

type SharedVaultNode = struct {
    vault_id: bytes(16),
    name: bytes(128),
    owner_id: bytes(16),
    max_members: u32,
    created_at: u64,
}

type ContainsEdge = struct {
    added_at: u64,
}

type SharedWithEdge = struct {
    recipient_id: bytes(16),
    wrapped_key: bytes(1568),
    permission: u8,
    granted_at: u64,
    granted_by: bytes(16),
    expires_at: u64,
}

graph vault_registry {
    node CredentialNode
    node FolderNode
    node SharedVaultNode
    edge ContainsEdge
    edge SharedWithEdge

    overlay breach_status: u8 curate delta_curate
    overlay password_age_days: u32 bitmask delta_curate
    overlay strength_score: u8 curate delta_curate
    overlay last_used_ns: u64 bitmask delta_curate
    overlay autofill_count: u64 bitmask delta_curate

    storage csr {
        hot @bram,
        warm @ddr,
        cold @nvme,
    }

    ai_feed breach_alerting

    observe vault_registry: [breach_status, strength_score, password_age_days] threshold: {
        anomaly_score 0.85
        baseline_window 120
    }
}

series vault_series: vault_registry
    merkle_chain true
    lattice_imprint true
    witness_attest true
```

Key circuits: `create_credential`, `update_credential`, `delete_credential`, `create_folder`, `move_credential`, `search_vault`, `autofill_lookup`.

### Share Network Graph (`polypass_share_graph.fl`)

Sharing relationships are a graph. Users, shared vaults, and credentials are nodes; share permissions are edges with typed access levels. Family and team sharing both use the same graph — team vaults are `SharedVaultNode` with enterprise RBAC.

```fastlang
type ShareUserNode = struct {
    user_id: bytes(16),
    signing_pubkey: bytes(2592),
    encryption_pubkey: bytes(1568),
}

type SharedCredentialNode = struct {
    credential_id: bytes(16),
    wrapped_key: bytes(1568),
}

type MemberOfEdge = struct {
    role: u8,
    joined_at: u64,
}

type CredentialAccessEdge = struct {
    permission: u8,
    granted_at: u64,
    granted_by: bytes(16),
}

state_machine share_lifecycle {
    initial PENDING
    persistence wal
    terminal [REVOKED, EXPIRED]
    li_anomaly_detection true

    PENDING -> ACTIVE when signature_verified guard acl_signed
    ACTIVE -> REVOKED when owner_revoked
    ACTIVE -> EXPIRED when ttl_expired
}

graph share_network {
    node ShareUserNode
    node SharedCredentialNode
    node SharedVaultNode
    edge MemberOfEdge
    edge CredentialAccessEdge
    edge SharedWithEdge

    overlay permission_level: u8 curate delta_curate
    overlay access_count: u32 bitmask delta_curate
    overlay last_accessed_ns: u64 bitmask delta_curate

    storage csr {
        hot @bram,
        warm @ddr,
        cold @nvme,
    }

    observe share_network: [permission_level, access_count] threshold: {
        anomaly_score 0.9
        baseline_window 300
    }
}

series share_series: share_network
    merkle_chain true
    lattice_imprint true
    witness_attest true
```

Key circuits: `share_credential`, `revoke_share`, `create_shared_vault`, `add_vault_member`, `remove_vault_member`, `re_wrap_key`.

### Credential Lifecycle State Machine (`polypass_credential_lifecycle.fl`)

Every credential follows a strict lifecycle with anomaly detection on state transitions.

```fastlang
state_machine credential_lifecycle {
    initial ACTIVE
    persistence wal
    terminal [DELETED]
    li_anomaly_detection true

    ACTIVE -> EXPIRED when password_age_exceeded guard age_policy_set
    ACTIVE -> COMPROMISED when breach_detected
    ACTIVE -> DELETED when user_deleted

    EXPIRED -> ROTATED when user_rotated_password
    EXPIRED -> COMPROMISED when breach_detected
    EXPIRED -> DELETED when user_deleted

    ROTATED -> ACTIVE when rotation_confirmed
    ROTATED -> COMPROMISED when breach_detected

    COMPROMISED -> ROTATED when user_rotated_password
    COMPROMISED -> DELETED when user_deleted
}
```

State transitions update the `breach_status` and `password_age_days` overlays on `vault_registry`. The `observe` block flags anomalies (e.g., mass credential compromise, unusual deletion patterns).

---

## Sharing

### Family/Friends

Per-credential keys are re-wrapped with the recipient's SPARK ML-KEM-1024 public key. The shared credential is published to a shared vault stream. Both parties can update (conflict resolution via CRDT). The owner can revoke by re-encrypting the shared vault without the recipient's key.

```
Owner shares credential with recipient:
    1. Encrypt per-credential key with recipient's ML-KEM-1024 public key
    2. Create SharedWithEdge in share_network graph
    3. Publish wrapped credential to polylabs.pass.{vault_id}.share
    4. Recipient decrypts with their SPARK ML-KEM-1024 private key
    5. Owner revokes: re-wrap vault without recipient's key, transition share_lifecycle → REVOKED
```

### Enterprise Teams

Team vaults are `SharedVaultNode` instances in the `share_network` graph. `MemberOfEdge` carries a role (admin, editor, viewer). RBAC is composed from eStream `rbac.fl` via PolyKit profiles.

```fastlang
circuit polypass_team_vault(vault_id: bytes(16), user_id: bytes(16), action: u8) -> bool
    profile poly_framework_sensitive
    composes: [polykit_identity, polykit_metering, polykit_rbac]
    lex esn/global/org/polylabs/pass/team
    constant_time true
{
    rbac_check(user_id, vault_id, action)
}
```

---

## Autofill

### Browser Extension

```
Webpage loads
    │
    ▼
Extension detects login form (heuristic + ML)
    │
    ▼
Query polypass_autofill circuit for matching credentials (URL → vault_registry lookup)
    │
    ▼
SPARK biometric prompt (if not recently authenticated)
    │
    ▼
Decrypt matching credential via ML-KEM-1024
    │
    ▼
Fill form fields (username, password)
    │
    ▼
If TOTP available: auto-copy 2FA code to clipboard (auto-clear after 30s)
```

### Mobile (iOS/Android)
- iOS: AutoFill Credential Provider extension
- Android: Autofill Framework service
- Same `poly-pass-core` Rust engine via FFI

### Desktop (Tauri)
- System-wide autofill via OS accessibility APIs
- Tray icon for quick access
- Keyboard shortcut for credential search

### Passkey Support (FIDO2/WebAuthn)

Poly Pass stores and serves FIDO2 passkey credentials. The `passkey_credential_id` field on `CredentialNode` holds the WebAuthn credential ID. On authentication, the browser extension or OS integration invokes the passkey ceremony using the stored credential, with the SPARK biometric gating access to the private key material.

---

## Security Audit

Continuous background analysis via the `polypass_audit.fl` circuit:

| Check | Description | Graph Source |
|-------|-------------|--------------|
| Weak passwords | Entropy below threshold | `strength_score` overlay |
| Reused passwords | Same password hash across multiple sites | Cross-credential hash comparison |
| Compromised | Breach database check (privacy-preserving k-anonymity) | `breach_status` overlay |
| Old passwords | Not rotated past policy threshold | `password_age_days` overlay |
| Missing 2FA | Sites supporting 2FA but `totp_seed_encrypted` is empty | `CredentialNode` field check |
| Missing passkey | Sites supporting passkeys but `passkey_credential_id` is empty | `CredentialNode` field check |
| Unused credentials | Not accessed in >1 year | `last_used_ns` overlay |

Breach checking uses **k-anonymity** (SHA-1 prefix query) so the full password hash is never sent to any server. The `ai_feed breach_alerting` on `vault_registry` triggers proactive notifications when new breaches are published.

---

## scatter-cas Integration

Poly Pass builds on eStream's `scatter-cas` runtime for all vault storage. Classification-driven k-of-n erasure coding distributes encrypted credentials across providers.

### Storage Layers

```
scatter-cas ObjectStore
  ├── PackStore      (local ESLite, offline cache)
  └── ScatterStore   (distributed k-of-n erasure coded)
        ├── k-of-n scatter per credential classification:
        │   PERSONAL:     3-of-5, 2+ jurisdictions
        │   SENSITIVE:    5-of-7, 3+ jurisdictions
        │   CRITICAL:     7-of-9, 3+ jurisdictions, no offline
        └── Providers: AWS, GCP, Azure, Cloudflare, Hetzner, self-host
```

Each credential is individually encrypted and scatter-stored — compromise of one provider shard reveals nothing about any credential.

---

## FastLang Circuits

All circuits are written in FastLang `.fl` using PolyKit profiles. The build pipeline is:

```bash
estream-dev build-wasm-client --from-fl circuits/fl/ --sign key.pem --enforce-budget
```

### Client-Side Circuits (compiled to `.escd` WASM)

| Circuit | File | Purpose | Size Budget |
|---------|------|---------|-------------|
| `polypass_encrypt` | `polypass_encrypt.fl` | ML-KEM-1024 key gen, per-credential AES-256-GCM encryption | ≤128 KB |
| `polypass_autofill` | `polypass_autofill.fl` | URL matching, credential lookup, form field mapping | ≤128 KB |
| `polypass_audit` | `polypass_audit.fl` | Breach check, strength scoring, reuse detection | ≤128 KB |
| `polypass_share` | `polypass_share.fl` | Key re-wrapping, share lifecycle management | ≤128 KB |
| `polypass_import` | `polypass_import.fl` | Multi-format import parsing, deduplication | ≤128 KB |

All circuits compose PolyKit:
```fastlang
circuit polypass_encrypt(user_id: bytes(16), cred_key: bytes(32), plaintext: bytes) -> bytes
    profile poly_framework_sensitive
    composes: [polykit_identity, polykit_metering, polykit_sanitize]
    lex esn/global/org/polylabs/pass/encrypt
    constant_time true
    observe metrics: [encrypt_ops, cred_count, latency_ns]
{
    aes_gcm_encrypt(cred_key, plaintext)
}
```

### Server-Side Circuits (lattice-hosted)

| Circuit | File | Purpose |
|---------|------|---------|
| `polypass_vault_sync` | `polypass_vault_sync.fl` | Scatter policy enforcement, cross-device sync |
| `polypass_share_relay` | `polypass_share_relay.fl` | Share invitation relay, ACL enforcement |
| `polypass_metering` | `polypass_metering.fl` | Per-product 8D metering (isolated) |

---

## Import

Importers for major password managers:

| Source | Format |
|--------|--------|
| 1Password | 1PUX, CSV |
| Bitwarden | JSON, CSV |
| LastPass | CSV |
| Dashlane | DASH, CSV |
| Chrome | CSV |
| Firefox | CSV |
| Safari/Keychain | CSV |
| KeePass | KDBX |
| Proton Pass | JSON |

Import is handled by the `polypass_import.fl` circuit (WASM). Parsing runs entirely on-device — no credential data is sent to any server during import. Imported credentials are deduplicated against existing `vault_registry` entries by `site` + `username_hash`.

---

## StreamSight Observability

Per-product isolated telemetry within the `polylabs.pass.*` lex namespace.

### Telemetry Stream Paths

```
lex://estream/apps/polylabs.pass/telemetry
lex://estream/apps/polylabs.pass/telemetry/sli
lex://estream/apps/polylabs.pass/metrics/baseline
lex://estream/apps/polylabs.pass/metrics/deviations
lex://estream/apps/polylabs.pass/incidents
lex://estream/apps/polylabs.pass/eslm/breach_alerting
```

No telemetry path references any other Poly product. StreamSight baseline gate learns per-operation latency distributions and flags deviations.

---

## Console Widgets

| Widget ID | Category | Description |
|-----------|----------|-------------|
| `polypass-vault-health` | observability | Credential count, breach %, strength distribution |
| `polypass-autofill-latency` | observability | Autofill latency gauge (lookup + decrypt + fill) |
| `polypass-breach-feed` | observability | Real-time breach detection feed |
| `polypass-deviation-feed` | observability | StreamSight baseline deviation feed |
| `polypass-share-activity` | observability | Sharing activity and access patterns |
| `polypass-credential-lifecycle` | governance | Credential state distribution (active/expired/compromised) |
| `polypass-audit-summary` | governance | Security audit score and recommendations |

---

## Enterprise

### Poly OAuth Integration

When enterprise uses Poly OAuth + Poly Pass:

1. Employee authenticates via Poly OAuth (SPARK biometric)
2. Poly Pass auto-provisions credentials for SSO apps
3. Non-SSO apps: Poly Pass autofills credentials
4. Admin console manages both identity and credential policies
5. Offboarding: revoke Poly OAuth → all credentials inaccessible

### Lex Bridge (Opt-In)

Enterprise admins can opt-in to cross-product visibility via an explicit lex bridge between `esn/global/org/polylabs/pass` and the enterprise admin namespace. The bridge is gated by **k-of-n admin witness attestation** and is revocable.

```
Enterprise admin namespace ←──lex bridge──→ polylabs.pass.{org_id}.*
                              │
                              └── gated by k-of-n witness attestation
                              └── org-level aggregates only (no individual user vault data)
                              └── revocable
```

Even with the bridge, individual user vault contents are never exposed — only org-level aggregates (credential count, breach rate, compliance posture) flow across the bridge.

---

## Pricing

| Tier | Credentials | Devices | Features | Price |
|------|-------------|---------|----------|-------|
| Free | 50 | 2 | Vault, autofill, generator | $0 |
| Premium | Unlimited | Unlimited | + 2FA, secure notes, sharing (5 users), breach monitor | $2.99/mo |
| Family | Unlimited | Unlimited | + 6 members, family vault, shared folders | $4.99/mo |
| Enterprise | Unlimited | Unlimited | + SSO via Poly OAuth, SCIM, admin console, audit, teams | Per-seat (custom) |

Tier enforcement via PolyKit `metering_graph` + `subscription_lifecycle` state machine. Billing uses blinded payment tokens — backend cannot correlate which SPARK identity subscribes to which tier.

---

## Directory Structure

```
polypass/
├── circuits/fl/
│   ├── polypass_encrypt.fl
│   ├── polypass_autofill.fl
│   ├── polypass_audit.fl
│   ├── polypass_share.fl
│   ├── polypass_import.fl
│   ├── polypass_vault_sync.fl
│   ├── polypass_share_relay.fl
│   ├── polypass_metering.fl
│   └── graphs/
│       ├── polypass_vault_graph.fl
│       └── polypass_share_graph.fl
├── crates/
│   └── poly-pass-core/
├── apps/
│   ├── extension/          Browser extension (Chrome, Firefox, Safari)
│   ├── desktop/            Tauri vault manager
│   └── mobile/             React Native with Rust FFI
├── packages/
│   └── sdk/
├── apps/console/
│   └── src/widgets/
├── docs/
│   └── ARCHITECTURE.md
├── CLAUDE.md
└── package.json
```

---

## Roadmap

### Phase 1: Core Vault (Q3 2026)
- `vault_registry` graph with typed overlays
- FastLang circuits for encryption, autofill, audit
- Desktop app (Tauri) with vault management
- Browser extension (Chrome, Firefox, Safari)
- SPARK biometric auth (`poly-pass-v1`)
- Password generator
- Scatter-stored vault (3-of-5)
- StreamSight L0 metrics

### Phase 2: Mobile + Features (Q4 2026)
- iOS + Android apps
- TOTP/2FA support
- Passkey storage (FIDO2/WebAuthn)
- Security audit dashboard
- Import from major managers
- `credential_lifecycle` state machine

### Phase 3: Sharing + Enterprise (Q1 2027)
- `share_network` graph with `share_lifecycle` state machine
- Family/friend sharing via ML-KEM-1024 key re-wrapping
- Team vaults with RBAC
- Poly OAuth integration
- Enterprise admin console
- SCIM provisioning
- Console widgets (7 widgets)

### Phase 4: Advanced (2027+)
- Lex bridge for enterprise cross-product visibility (opt-in, k-of-n gated)
- Poly Vault HSM integration (credential encryption keys in hardware)
- Poly Mind integration (credential recommendations via ESLM)
- Enterprise compliance (DLP, retention policies)
- ESN-AI optimization recommendations
