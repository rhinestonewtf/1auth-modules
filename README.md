# 1auth-modules

ERC-7579 validator modules for smart accounts with WebAuthn (passkey) authentication, cross-chain merkle batch signing, and guardian recovery.

## Overview

This repo contains a **Solidity smart contract** (`OneAuthValidator`) and a **cross-platform SDK** (Rust WASM + TypeScript) that produce byte-identical outputs — verified by a golden test suite that runs Forge and Rust against the same fixture data.

### What it does

- **Passkey authentication** for ERC-4337 smart accounts using P-256 (secp256r1) WebAuthn signatures
- **Merkle batch signing** — sign multiple operations across chains with a single passkey tap (the user signs a merkle root, each chain verifies its operation against a proof)
- **EIP-712 challenge wrapping** — all challenges are wrapped in typed data so hardware authenticators and wallets can display human-readable signing requests
- **Guardian recovery** — recover access via an existing passkey or an EIP-1271 guardian contract
- **Stateless validation** — third-party contracts can verify signatures without on-chain credential storage

### Architecture

```
Solidity (source of truth)        SDK (client-side encoding)
─────────────────────────         ──────────────────────────
OneAuthValidator.sol              Rust (encoding-core + oneauth)
OneAuthRecoveryBase.sol               ↓ wasm-pack
                                  WASM binary (.wasm)
                                      ↓ wasm-bindgen
                                  TypeScript wrapper (viem-compatible)
```

The Solidity contract defines the on-chain validation logic. The SDK handles all client-side encoding: `onInstall` calldata, EIP-712 challenge computation, signature packing, merkle tree construction, and recovery digest generation. Both layers must produce identical bytes — this is enforced by golden tests.

## Solidity Contracts

### `OneAuthValidator` (`src/OneAuth/OneAuthValidator.sol`)

An ERC-7579 hybrid validator (stateful + stateless) with:

- **Multi-credential support** — up to 64 passkeys per account, each with a 2-byte `keyId` and `requireUV` flag packed into a single storage key
- **Two signing paths**:
  - `proofLength = 0`: Regular signing. Challenge = `_passkeyDigest(hash)` — chain-specific EIP-712 typed data
  - `proofLength > 0`: Merkle signing. Challenge = `_passkeyMultichain(merkleRoot)` — chain-agnostic EIP-712 typed data (uses Solady's `_hashTypedDataSansChainId`)
- **Tightly packed signature format** — custom calldata encoding (~10x cheaper than ABI-encoded structs) with inline assembly for WebAuthnAuth parsing
- **EIP-1271 support** via `isValidSignatureWithSender`
- **Stateless validation** via `validateSignatureWithData` — credentials provided externally

EIP-712 domain: `OneAuthValidator v1.0.0`

Typehashes:
- `PasskeyDigest(bytes32 digest)` — single-chain operations
- `PasskeyMultichain(bytes32 root)` — cross-chain merkle root
- `RecoverPasskey(address account,uint256 chainId,uint16 newKeyId,uint256 newPubKeyX,uint256 newPubKeyY,bool newRequireUV,uint256 nonce,uint48 expiry)` — recovery

### `OneAuthRecoveryBase` (`src/OneAuth/OneAuthRecoveryBase.sol`)

Abstract recovery mixin providing two recovery paths:

1. **Passkey recovery** — an existing credential signs a `RecoverPasskey` EIP-712 message
2. **Guardian recovery** — an EIP-1271 smart contract (e.g., multisig, social recovery) signs the same message

Recovery uses the chain-agnostic domain separator (`_hashTypedDataSansChainId`) with `chainId` embedded in the struct hash. Setting `chainId = 0` makes the recovery valid on any chain.

## SDK

### Rust Workspace (`sdk/`)

Two crates in a Cargo workspace:

#### `encoding-core` — Shared ERC-7579 trait system

Defines the trait hierarchy that any ERC-7579 module SDK can implement:

```rust
pub trait IERC7579Module {
    fn module_type(&self) -> ModuleType;
    fn name(&self) -> &str;
    fn version(&self) -> &str;
}

pub trait IERC7579Validator: IERC7579Module {
    type InstallData;
    type SignatureConfig;
    fn encode_install(&self, data: &Self::InstallData) -> Result<Vec<u8>, EncodeError>;
    fn encode_uninstall(&self) -> Vec<u8>;
    fn encode_signature(&self, config: &Self::SignatureConfig, auth: &[u8]) -> Vec<u8>;
}

pub trait IERC7579StatelessValidator: IERC7579Validator {
    type StatelessConfig;
    fn encode_stateless_data(&self, config: &Self::StatelessConfig) -> Vec<u8>;
}
```

Also provides shared utilities: `keccak256` and `MerkleTree` (Solady-compatible sorted-pair hashing).

#### `oneauth` — OneAuthValidator SDK

Implements all three traits via the zero-sized `OneAuthValidator` struct. Compiles to both native Rust (`rlib`) and WebAssembly (`cdylib`).

**Modules:**

| Module | Purpose |
|--------|---------|
| `encode.rs` | `onInstall` / `onUninstall` ABI encoding via `alloy-sol-types` |
| `signature.rs` | Stateful + stateless signature packing (both regular and merkle paths) |
| `digest.rs` | EIP-712 domain separators, challenge wrapping (`passkey_digest`, `passkey_multichain`), recovery digest, typed data builders |
| `merkle.rs` | Re-export of `encoding-core::merkle` (Solady-compatible merkle tree) |
| `module.rs` | `OneAuthValidator` struct implementing the ERC-7579 trait hierarchy |
| `lib.rs` | WASM entry points (`wasm-bindgen` exports) — all route through the trait system |

**WASM Exports:**

| JS Function | Description |
|-------------|-------------|
| `encodeInstall(json)` | Encode `onInstall` calldata from JSON input |
| `getDigest(digests, chainId, contract)` | Smart digest preparation (auto-selects single vs merkle path) |
| `passkeyDigest(digest, chainId, contract)` | Single-chain EIP-712 challenge |
| `passkeyMultichain(root, contract)` | Cross-chain EIP-712 challenge |
| `getPasskeyDigestTypedData(digest, chainId, contract)` | Viem-compatible typed data for PasskeyDigest |
| `getPasskeyMultichainTypedData(root, contract)` | Viem-compatible typed data for PasskeyMultichain |
| `encodeStatefulSignature(config, auth)` | Pack stateful signature bytes |
| `encodeStatelessData(config)` | Pack stateless validator data |
| `getRecoveryDigest(json)` | Compute recovery EIP-712 digest |
| `buildMerkleTree(leaves)` | Build merkle tree, returns root + proofs |
| `verifyMerkleProof(proof, root, leaf)` | Verify a merkle proof |

### TypeScript Wrapper (`sdk/ts/`)

Thin TypeScript layer over the WASM module, adding viem type safety and ergonomic APIs:

```typescript
import { getDigest, encodeInstall, encodeSignature } from "./oneauth";

// 1. Install the module with a passkey credential
const { address, initData } = encodeInstall({
  credentials: [{ keyId: 0, pubKeyX: "0x...", pubKeyY: "0x...", requireUV: true }],
  guardian: "0x..."
});

// 2. Prepare a digest for signing (auto merkle if multiple)
const result = getDigest([typedData1, typedData2], chainId, validatorAddress);
// result.challenge — what the passkey signs
// result.proofs — merkle proofs per operation

// 3. Encode the signature for on-chain verification
const sig = encodeSignature(
  { keyId: 0, requireUV: true, usePrecompile: true, merkle: { root, proof } },
  webauthnAuthHex
);
```

Key design: the TS layer uses `viem`'s `hashTypedData` for EIP-712 hashing (ensuring compatibility with the broader ecosystem) while delegating all ABI encoding and binary packing to WASM for correctness guarantees.

## Golden Tests

A cross-language test system ensures the Rust SDK produces byte-identical outputs to the Solidity contract.

### How it works

```
forge script GenerateGoldenVectors.s.sol
    → deploys OneAuthValidator
    → computes all outputs using the Solidity contract
    → writes test/OneAuth/fixtures/golden-vectors.json

cargo test (in sdk/)
    → reads golden-vectors.json
    → computes the same outputs using Rust code
    → asserts exact match
```

### What's covered

| Category | Vectors |
|----------|---------|
| Typehashes | `PASSKEY_DIGEST_TYPEHASH`, `PASSKEY_MULTICHAIN_TYPEHASH`, `RECOVER_PASSKEY_TYPEHASH` |
| PasskeyDigest | 3 different input digests, each producing an EIP-712 wrapped challenge |
| PasskeyMultichain | 3 different merkle roots, each producing a chain-agnostic challenge |
| RecoveryDigest | Full `RecoverPasskey` struct with account, chainId, new credential, nonce, expiry |
| Merkle tree | 3 leaves → root + 3 proofs, verified bidirectionally |

### Running

```bash
# Regenerate golden vectors (only needed if contract logic changes)
forge script script/GenerateGoldenVectors.s.sol -vvv

# Run Rust tests (includes golden parity tests)
cd sdk && cargo test --workspace
```

### Bug found by golden tests

During development, the golden tests caught a real EIP-712 domain separator bug: the Rust implementation was using `EIP712Domain(string name,string version)` for the chain-agnostic domain, but Solady's `_hashTypedDataSansChainId` actually uses `EIP712Domain(string name,string version,address verifyingContract)` — the contract address is included even when chainId is omitted. The golden tests failed immediately, making this trivial to catch and fix.

## Project Structure

```
src/
  OneAuth/
    OneAuthValidator.sol         # Main validator contract
    OneAuthRecoveryBase.sol      # Recovery mixin (passkey + guardian)

test/
  OneAuth/
    unit/concrete/
      OneAuthValidator.t.sol     # OneAuthValidator unit tests
      OneAuthRecovery.t.sol      # Recovery tests
      GasComparison.t.sol        # Gas benchmarks
    integration/
      OneAuthValidator.t.sol     # Integration tests
    fixtures/
      golden-vectors.json        # Generated golden test vectors

script/
  GenerateGoldenVectors.s.sol    # Forge script to generate golden JSON
  ComputeTestChallenge.s.sol     # Helper for manual challenge computation

sdk/
  Cargo.toml                     # Rust workspace manifest
  build.sh                       # WASM build script (wasm-pack + wasm-bindgen)
  encoding-core/                 # Shared ERC-7579 traits + utilities
    src/
      traits.rs                  # IERC7579Module, IERC7579Validator, IERC7579StatelessValidator
      types.rs                   # ModuleType, EncodeError
      keccak.rs                  # keccak256
      merkle.rs                  # Solady-compatible merkle tree
  oneauth/                       # OneAuthValidator SDK (Rust + WASM)
    src/
      encode.rs                  # onInstall/onUninstall ABI encoding
      signature.rs               # Stateful + stateless signature packing
      digest.rs                  # EIP-712 domains, challenges, recovery, typed data
      merkle.rs                  # Re-export from encoding-core
      module.rs                  # Trait implementations
      lib.rs                     # WASM exports (wasm-bindgen)
    tests/
      golden.rs                  # Golden parity tests (Rust vs Solidity)
  ts/                            # TypeScript wrapper
    src/
      oneauth.ts                 # Main API (viem-typed)
      types.ts                   # TypeScript interfaces
      index.ts                   # Package entry point
      wasm/oneauth/              # Built WASM artifacts
```

## Building

```bash
# Solidity
forge build

# Rust tests
cd sdk && cargo test --workspace

# WASM build (requires wasm-pack)
cd sdk && ./build.sh

# TypeScript (after WASM build)
cd sdk/ts && npm install && npx tsc
```

## Key Design Decisions

1. **Tightly packed calldata** — The signature format uses custom byte packing instead of ABI encoding, saving ~10x gas on calldata costs (significant for L2s).

2. **Trait-based SDK** — The `encoding-core` crate defines generic ERC-7579 traits. Any future module (executor, hook, etc.) can implement the same interfaces, enabling shared tooling.

3. **WASM as single source of truth** — All binary encoding happens in Rust/WASM. TypeScript is a thin typed wrapper. This eliminates the risk of encoding divergence between languages.

4. **EIP-712 typed data passthrough** — The SDK exposes viem-compatible typed data objects so wallets can display human-readable signing prompts. The raw challenge bytes are also available for direct WebAuthn signing.

5. **Golden tests as a safety net** — The Forge script generates canonical outputs from the deployed contract. Rust tests assert parity. Any change to either side that breaks compatibility is caught immediately.

## License

AGPL-3.0-only (Solidity contracts)
