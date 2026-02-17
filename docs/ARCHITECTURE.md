# Poly Pass Architecture

**Version**: 1.0
**Last Updated**: February 2026
**Platform**: eStream v0.8.1

---

## Overview

Poly Pass is a post-quantum encrypted password manager with SPARK biometric authentication. No master password. Vaults are E2E encrypted with ML-KEM-1024, scatter-distributed, and synced across devices via eStream Wire Protocol.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   Poly Pass Client                           │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │ Vault    │  │ Autofill │  │ Password │  │ Security │   │
│  │ Manager  │  │ Engine   │  │ Generator│  │ Audit    │   │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘   │
│       │              │              │              │         │
│  ┌────┴──────────────┴──────────────┴──────────────┴─────┐  │
│  │              poly-pass-core (Rust)                      │  │
│  │  SPARK Auth | PQ Encrypt | Vault Sync | TOTP | Passkey │  │
│  └──────────────────────┬────────────────────────────────┘  │
└─────────────────────────┼───────────────────────────────────┘
                          │
                   eStream Wire Protocol (QUIC/UDP)
                          │
┌─────────────────────────┼───────────────────────────────────┐
│  ┌──────────────────────┴────────────────────────────────┐  │
│  │         ESCIR Vault Sync Circuit                       │  │
│  │  Conflict Resolution | Share Management | Audit       │  │
│  └──────────────────────┬────────────────────────────────┘  │
│                          │                                   │
│              Scatter Storage (k-of-n)                        │
└─────────────────────────────────────────────────────────────┘
```

---

## Authentication: No Master Password

### Traditional Password Managers
```
Master Password -> PBKDF2/Argon2 -> Vault Decryption Key
                   ^
                   Phishable, keyloggable, brute-forceable
```

### Poly Pass
```
SPARK Biometric -> Secure Enclave/TEE -> ML-DSA-87 Key Pair
                                          |
                                          v
                                   Key Agreement (ML-KEM-1024)
                                          |
                                          v
                                   Vault Decryption Key
```

- Private key **never leaves** the Secure Enclave / TEE
- Cannot be phished (no password to steal)
- Cannot be keylogged (biometric, not typed)
- Cannot be brute-forced (hardware-enforced rate limiting)
- Recovery: K-of-N guardian recovery (same as Poly Mind digital legacy)

---

## Vault Structure

```
Vault (PQ-encrypted container)
├── Login credentials
│   ├── URL, username, password
│   ├── TOTP secrets (if 2FA)
│   ├── Passkey credentials (FIDO2)
│   └── Notes
├── Credit cards
│   ├── Number, expiry, CVV
│   └── Billing address
├── Secure notes
│   ├── Free-form text
│   └── Classification tag
├── Identities
│   ├── Personal info for form filling
│   └── Addresses
└── Shared items
    ├── Family shared credentials
    └── Team shared credentials
```

Each vault item:
- Individually encrypted (compromise of one doesn't expose others)
- PQ-signed with ML-DSA-87 (tampering detection)
- Hash-chained (version history integrity)
- Classification-tagged (drives scatter policy)

---

## Autofill

### Browser Extension
```
Webpage loads
    |
    v
Extension detects login form (heuristic + ML)
    |
    v
Query poly-pass-core for matching credentials
    |
    v
SPARK biometric prompt (if not recently authenticated)
    |
    v
Decrypt matching credential
    |
    v
Fill form fields (username, password)
    |
    v
If TOTP available: auto-copy 2FA code
```

### Mobile (iOS/Android)
- iOS: AutoFill Credential Provider extension
- Android: Autofill Framework service
- Same `poly-pass-core` Rust engine via FFI

### Desktop (Tauri)
- System-wide autofill via OS accessibility APIs
- Tray icon for quick access
- Keyboard shortcut for credential search

---

## Password Generator

```yaml
# Configurable generator
generator:
  type: random  # or passphrase
  length: 24
  uppercase: true
  lowercase: true
  numbers: true
  symbols: true
  exclude_ambiguous: true  # Exclude 0/O, 1/l/I

# Passphrase generator
passphrase:
  words: 5
  separator: "-"
  capitalize: true
  include_number: true
  # e.g., "Correct-Horse-Battery-Staple-42"
```

---

## Security Audit

Continuous background analysis:

| Check | Description |
|-------|-------------|
| Weak passwords | Entropy below threshold |
| Reused passwords | Same password across multiple sites |
| Compromised | Check against breach databases (privacy-preserving k-anonymity) |
| Old passwords | Not rotated in >1 year |
| Missing 2FA | Sites that support 2FA but none configured |
| Missing passkey | Sites that support passkeys but not configured |

Breach checking uses **k-anonymity** (SHA-1 prefix query) so the full password hash is never sent to any server.

---

## Sharing

### Family/Friends
```
User A shares credential with User B:
    1. A encrypts item with B's ML-KEM-1024 public key
    2. Shared item published to shared vault stream
    3. B receives and decrypts
    4. Both can update (conflict resolution via CRDT)
    5. A can revoke: re-encrypt shared vault without B's key
```

### Enterprise Teams
```yaml
# Team vault
team: engineering
members:
  - spark:did:alice (admin)
  - spark:did:bob (editor)
  - spark:did:carol (viewer)
items:
  - AWS root credentials (admin-only)
  - GitHub deploy tokens (editor+)
  - Internal wiki login (all)
```

---

## Poly OAuth Integration (Enterprise)

When enterprise uses Poly OAuth + Poly Pass:

1. Employee authenticates via Poly OAuth (SPARK biometric)
2. Poly Pass auto-provisions credentials for SSO apps
3. Non-SSO apps: Poly Pass autofills credentials
4. Admin console manages both identity and credential policies
5. Offboarding: revoke Poly OAuth -> all credentials inaccessible

---

## ESCIR Circuits

### Vault Sync Circuit

```yaml
escir: "0.8.1"
name: poly-pass-vault-sync
version: "1.0.0"
lex: polylabs.pass

stream:
  - topic: "polylabs.pass.{user_id}.vault.sync"
    pattern: scatter
    retention: permanent
    hash_chain: true
    signature_required: true

  - topic: "polylabs.pass.{user_id}.vault.share.{vault_id}"
    pattern: scatter
    retention: permanent
    signature_required: true

  - topic: "polylabs.pass.{user_id}.audit"
    pattern: scatter
    retention: 1y
    hash_chain: true
```

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

---

## Pricing

| Tier | Credentials | Devices | Features | Price |
|------|-------------|---------|----------|-------|
| Free | 50 | 2 | Vault, autofill, generator | $0 |
| Premium | Unlimited | Unlimited | + 2FA, notes, sharing (5), breach monitor | $2.99/mo |
| Family | Unlimited | Unlimited | + 6 users, family vault | $4.99/mo |
| Enterprise | Unlimited | Unlimited | + SSO, SCIM, admin, audit, teams | Per-seat |

---

## Roadmap

### Phase 1: Core (Q3 2026)
- Desktop app (Tauri) with vault management
- Browser extension (Chrome, Firefox, Safari)
- SPARK biometric auth
- Password generator
- Scatter-stored vault (3-of-5)

### Phase 2: Mobile + Features (Q4 2026)
- iOS + Android apps
- TOTP/2FA support
- Passkey storage
- Security audit
- Import from major managers

### Phase 3: Sharing + Enterprise (Q1 2027)
- Family/friend sharing
- Team vaults
- Poly OAuth integration
- Enterprise admin console
- SCIM provisioning

### Phase 4: Advanced (2027+)
- Poly Vault HSM integration (master key in hardware)
- Poly Mind integration (credential recommendations)
- Enterprise compliance features

---

## Related Documents

- [polylabs/business/PRODUCT_FAMILY.md] -- Product specifications
- [polylabs/business/PROTON_REFERENCE.md] -- Proton Pass reference
