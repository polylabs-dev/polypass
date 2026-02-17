# Poly Pass

Post-quantum encrypted password manager built on eStream v0.8.1.

## Overview

Poly Pass is a quantum-safe password manager where vaults are E2E encrypted with ML-KEM-1024 and scatter-distributed. No master password -- SPARK biometric is the sole authentication factor. Device-bound ML-DSA-87 keys mean private keys never leave the device.

## Architecture

```
Client (Tauri/Browser Extension/Mobile)
    |
    +-- SPARK Auth (ML-DSA-87 biometric)
    |
    +-- Vault (credentials, notes, 2FA, passkeys)
    |
    v
eStream Wire Protocol (QUIC/UDP)
    |
    v
ESCIR Vault Sync Circuit
    |
    +-- PQ Encrypt vault items
    +-- Scatter-store across providers
    +-- Sync across devices
    |
    v
Scatter Storage (k-of-n)
```

## Key Components

| Component | Location | Purpose |
|-----------|----------|---------|
| Vault Sync | circuits/ | ESCIR circuit for vault sync, sharing |
| Core SDK | crates/poly-pass-core/ | Rust core for vault encrypt/decrypt, autofill |
| Browser Extension | apps/extension/ | Autofill, password generator |
| Desktop App | apps/desktop/ | Tauri-based vault manager |
| Mobile App | apps/mobile/ | React Native with Rust FFI |

## Key Differentiator

No master password. SPARK biometric (face/fingerprint) generates device-bound ML-DSA-87 keys. The private key never leaves the Secure Enclave / TEE. Vault decryption key derived from SPARK authentication -- cannot be phished, keylogged, or brute-forced.

## No REST API

All sync uses the eStream Wire Protocol. No REST/HTTP endpoints.

## Platform

- eStream v0.8.1
- ESCIR SmartCircuits
- ML-KEM-1024, ML-DSA-87, SHA3-256
- 8-Dimension metering
- L2 multi-token payments
