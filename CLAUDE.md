# Poly Pass

Post-quantum encrypted password manager built on eStream v0.8.3 and PolyKit v0.3.0.

## Overview

Poly Pass is a quantum-safe password manager where credentials are individually PQ-encrypted and scatter-distributed. No master password — SPARK biometric is the sole authentication factor. Device-bound ML-DSA-87 keys mean private keys never leave the Secure Enclave / TEE.

## Key Patterns

- **Zero-linkage**: HKDF context `poly-pass-v1`, lex `esn/global/org/polylabs/pass`, isolated StreamSight + metering + billing
- **Graph model**: `graph vault_registry` (CredentialNode, FolderNode, SharedVaultNode) with CSR tiered storage, `graph share_network` for sharing
- **State machine**: `credential_lifecycle` (ACTIVE → EXPIRED → ROTATED → COMPROMISED → DELETED)
- **Overlays**: breach_status, password_age_days, strength_score, last_used_ns, autofill_count
- **ai_feed**: breach_alerting on vault_registry
- **Build**: FastLang `.fl` → ESCIR → Rust/WASM → `.escd`
- **RBAC**: eStream `rbac.fl` composed via PolyKit profiles

## Architecture

See `docs/ARCHITECTURE.md` for full specification including graph/DAG constructs, FastLang circuits, scatter-cas integration, and sharing design.

## Key Components

| Component | Location | Purpose |
|-----------|----------|---------|
| Vault Graph | `circuits/fl/graphs/polypass_vault_graph.fl` | Credential store as typed graph |
| Share Graph | `circuits/fl/graphs/polypass_share_graph.fl` | Sharing ACLs + family/team vaults |
| Encrypt | `circuits/fl/polypass_encrypt.fl` | ML-KEM-1024 key gen, AES-256-GCM encryption |
| Autofill | `circuits/fl/polypass_autofill.fl` | URL matching, credential lookup |
| Audit | `circuits/fl/polypass_audit.fl` | Breach check, strength scoring |
| Share | `circuits/fl/polypass_share.fl` | Key re-wrapping, share lifecycle |
| Import | `circuits/fl/polypass_import.fl` | Multi-format import (1Password, Bitwarden, etc.) |
| Core SDK | `crates/poly-pass-core/` | Rust core for vault encrypt/decrypt, autofill |
| Browser Extension | `apps/extension/` | Autofill, password generator |
| Desktop App | `apps/desktop/` | Tauri-based vault manager |
| Mobile App | `apps/mobile/` | React Native with Rust FFI |

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

- eStream v0.8.3
- PolyKit v0.3.0
- ML-KEM-1024, ML-DSA-87, SHA3-256
- 8-Dimension metering
- Blinded billing tokens
