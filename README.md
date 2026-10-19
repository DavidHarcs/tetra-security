# tetra-security

TETRA air-interface security primitives in Rust: **TAA1** authentication and key
management, the **TEA** key-stream generators, and the **OTAR** key-sealing
algorithms, per ETSI EN 300 392-7 and TS 104 053.

> **Licence:** Apache-2.0.

This crate is the standalone, reusable home of the TETRA security code first
developed for a [FlowStation](https://flowstation.dev) base-station fork. It is
consumed by [`tetra-kmf`](https://github.com/DavidHarcs/tetra-kmf) (the key
management facility) and can back any TETRA SwMI or tooling.

## Contents

- `ksg/` — key-stream generators TEA1, TEA2, TEA3 (register-level, validated
  against reference vectors).
- `taa1/` — TAA1 authentication: HURDLE-II block cipher, the TA1x/TA2x key
  derivations, and OTAR sealing (TA51/TA52, TA41 → KSO).
- `auth.rs` — MS/BS challenge–response (RES/XRES, DCK derivation).
- `aie.rs` — air-interface encryption helpers (ECK/ESI, key stream application).
- `keys.rs` — key store and key types.

## Status

Extracted as a standalone crate so the key-management facility, the base station
and the network core can share one tested implementation. 32 unit tests pass
(key streams and TAA1 derivations cross-checked against published vectors).

## Security note

These are research/amateur-radio and infrastructure building blocks. Air
interface encryption on the amateur bands is not permitted; use for
authentication, interoperability and testing within the rules that apply to you.
