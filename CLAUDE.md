# Q Pass

Post-quantum encrypted password manager built on eStream v0.22.0 and QKit v0.3.0. **100% FastLang — no hand-written Rust.**

## Overview

Q Pass is a quantum-safe password manager where credentials are individually PQ-encrypted and scatter-distributed. No master password — SPARK biometric is the sole authentication factor. Device-bound ML-DSA-87 keys mean private keys never leave the Secure Enclave / TEE.

## Key Patterns

- **Zero-linkage**: HKDF context `q-pass-v1`, lex `esn/global/org/polyqlabs/pass`, isolated StreamSight + metering + billing
- **Graph model**: `graph vault_registry` (CredentialNode, FolderNode, SharedVaultNode) with CSR tiered storage, `graph share_network` for sharing
- **State machine**: `credential_lifecycle` (ACTIVE → EXPIRED → ROTATED → COMPROMISED → DELETED)
- **Overlays**: breach_status, password_age_days, strength_score, last_used_ns, autofill_count
- **ai_feed**: breach_alerting on vault_registry
- **Build**: FastLang `.fl` → FLIR → Rust/WASM → `.escd`
- **RBAC**: eStream `rbac.fl` composed via QKit profiles

## FL Circuits (12)

All product logic lives in FastLang circuits. No hand-written Rust in the application layer.

| Circuit | Location | Purpose |
|---------|----------|---------|
| Vault Graph | `circuits/fl/graphs/qpass_vault_graph.fl` | Credential store as typed graph |
| Share Graph | `circuits/fl/graphs/qpass_share_graph.fl` | Sharing ACLs + family/team vaults |
| Encrypt | `circuits/fl/qpass_encrypt.fl` | ML-KEM-1024 key gen, AES-256-GCM encryption |
| Autofill | `circuits/fl/qpass_autofill.fl` | URL matching, credential lookup |
| Audit | `circuits/fl/qpass_audit.fl` | Breach check, strength scoring |
| Share | `circuits/fl/qpass_share.fl` | Key re-wrapping, share lifecycle |
| Import | `circuits/fl/qpass_import.fl` | Multi-format import (1Password, Bitwarden, etc.) |
| TOTP | `circuits/fl/qpass_totp.fl` | TOTP/HOTP generation and verification |
| Breach | `circuits/fl/qpass_breach.fl` | Breach monitoring and alerting |
| RBAC | `circuits/fl/qpass_rbac.fl` | Role-based access control |
| Metering | `circuits/fl/qpass_metering.fl` | 8-dimension usage metering |
| Platform Health | `circuits/fl/qpass_platform_health.fl` | Circuit health and diagnostics |

## Legacy Rust Crates (Superseded)

The `crates/` directory contains legacy hand-written Rust code that has been fully superseded by the FL circuits above. These crates are retained for reference but are **not compiled or deployed**:

- `crates/q-pass-core/` — Types, crypto/vault_crypto, graphs, circuit wrappers
- `crates/q-pass-wasm/` — WASM entry crate

All functionality previously in these crates is now implemented in FL circuits, which compile via FLIR codegen to Rust/WASM.

## Apps

| App | Location | Stack |
|-----|----------|-------|
| Browser Extension | `apps/extension/` | Autofill, password generator |
| Desktop App | `apps/desktop/` | Tauri-based vault manager |
| Mobile App | `apps/mobile/` | React Native with FLIR-generated FFI |

## No REST API

All sync uses the eStream Wire Protocol (QUIC/UDP). No REST/HTTP endpoints.

## Pricing

| Tier | Creds | Devices | Price |
|------|-------|---------|-------|
| Free | 50 | 2 | $0 |
| Premium | Unlimited | Unlimited | $2.99/mo |
| Family | Unlimited (6 members) | Unlimited | $4.99/mo |
| Enterprise | Unlimited | Unlimited | Per-seat |

## Platform

- eStream v0.22.0
- QKit v0.3.0
- ML-KEM-1024, ML-DSA-87, SHA3-256
- 8-Dimension metering
- Blinded billing tokens

## Cross-Repo Coordination

This repo is part of the [polylabs-dev](https://github.com/polylabs-dev) organization, coordinated through the **AI Toolkit hub** at `toddrooke/ai-toolkit/`.

For cross-repo context, strategic priorities, and the master work queue:
- `toddrooke/ai-toolkit/CLAUDE-CONTEXT.md` — org map and priorities
- `toddrooke/ai-toolkit/scratch/BACKLOG.md` — master backlog
- `toddrooke/ai-toolkit/repos/polylabs-dev.md` — this org's status summary
