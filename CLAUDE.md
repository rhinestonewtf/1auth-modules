# 1Auth Modules

ERC-7579 validator module for smart accounts. Uses WebAuthn/P-256 passkeys for transaction signing and supports guardian-based account recovery.

## Architecture

```
src/OneAuth/
├── OneAuthValidator.sol      # Main ERC-7579 validator (install/uninstall, validateUserOp, ERC-1271)
├── OneAuthRecoveryBase.sol   # Guardian recovery logic (dual-guardian, EIP-712 recovery digests)
├── Guardian.sol              # Guardian signature verification (ERC-1271 smart contract guardians)
├── IOneAuthValidator.sol     # Interface
└── lib/
    ├── P256Lib.sol            # P-256 curve utilities
    ├── EIP712Lib.sol          # EIP-712 typed data helpers
    └── Constants.sol          # Shared constants

sdk/
├── oneauth/                   # Rust crate — ABI encoding, EIP-712 digests, merkle trees, signatures
│   └── src/
│       ├── lib.rs             # WASM entry points (#[wasm_bindgen] exports)
│       ├── encode.rs          # onInstall ABI encoding (InstallInput struct)
│       ├── digest.rs          # EIP-712 digest computation (PasskeyDigest, PasskeyMultichain, recovery)
│       ├── merkle.rs          # Solady-compatible sorted-pair keccak256 merkle tree
│       ├── signature.rs       # Stateful/stateless signature encoding
│       └── module.rs          # ERC-7579 module trait implementation
├── encoding-core/             # Shared encoding trait (IERC7579Validator, IERC7579StatelessValidator)
└── ts/                        # TypeScript SDK — thin wrappers around WASM
    ├── src/
    │   ├── oneauth.ts         # Public API: encodeInstall, getDigest, encodeSignature, etc.
    │   ├── types.ts           # TypeScript types (InstallInput, DigestResult, etc.)
    │   └── wasm/oneauth/      # Compiled WASM output (checked into git)
    └── dist/                  # Built TS + WASM (npm package output)
```

## How the layers connect

1. **Solidity contracts** define the on-chain logic (credential storage, signature validation, recovery)
2. **Rust SDK** (`sdk/oneauth`) implements the off-chain encoding that produces calldata the contracts expect — ABI-encoded install data, EIP-712 digests, signature packing, merkle proofs
3. **WASM bridge** — the Rust crate compiles to WebAssembly via `wasm-pack`. Functions annotated with `#[wasm_bindgen]` in `lib.rs` are exported and callable from JS
4. **TypeScript SDK** (`sdk/ts`) wraps the WASM functions with typed interfaces, integrates with `viem` for EIP-712 utilities, and is the public API consumers use

The Rust SDK is the source of truth for encoding logic. The TS SDK delegates to it via WASM — it does not duplicate encoding.

## Build commands

```bash
# Solidity
forge build                    # Compile contracts
forge test                     # Run all tests
forge test --mc OneAuth -vv    # Run OneAuth tests with verbosity

# Rust SDK
cd sdk/oneauth && cargo test   # Run Rust tests (includes golden ABI tests)

# WASM + TypeScript
npm run build:wasm             # Compile Rust → WASM (output: sdk/ts/src/wasm/oneauth/)
npm run build:ts               # Compile TypeScript
npm run build:sdk              # Full SDK build (wasm + ts + copy)
npm run build                  # Everything (sol + sdk)
```

## PR checklist

When modifying the Rust SDK (`sdk/oneauth/src/`), you **must**:

1. Run `cd sdk/oneauth && cargo test` — the golden tests catch ABI encoding regressions
2. Run `npm run build:wasm` — recompile the WASM so the checked-in files at `sdk/ts/src/wasm/oneauth/` stay in sync
3. Verify the TypeScript wrappers in `sdk/ts/src/oneauth.ts` and `sdk/ts/src/types.ts` still match the WASM exports (e.g., if you add/remove a field from `InstallInput` in Rust, update the TS `InstallInput` type too)
4. Commit the regenerated WASM files alongside your Rust changes

When modifying Solidity contracts that change the ABI (e.g., `onInstall` parameters, new functions):

1. Update the Rust SDK encoding to match
2. Follow the Rust SDK steps above
3. Update Solidity tests — unit, fuzz, invariant, and integration

## Testing

- **Unit tests**: `test/OneAuth/unit/concrete/` — individual function behavior
- **Fuzz tests**: `test/OneAuth/unit/fuzz/` — randomized inputs for validators
- **Invariant tests**: `test/OneAuth/invariant/` — stateful property testing with ghost state tracking (credential liveness, nonce non-reusability, ghost-state consistency)
- **Integration tests**: `test/OneAuth/integration/` — full ERC-7579 module lifecycle via ModuleKit
- **Rust tests**: `sdk/oneauth/src/` — golden ABI encoding tests, digest computation tests

## Key concepts

- **Credentials**: P-256 public keys identified by `uint16 keyId`, stored per-account. Max 64 per account.
- **Guardian recovery**: Dual-guardian model (user guardian + external guardian) with configurable threshold (1 or 2). Guardians are ERC-1271 smart contracts. Recovery uses EIP-712 signed digests with nonces and expiry.
- **Signature formats**: Stateful (keyId-based, on-chain credential lookup) and stateless (pubkey embedded in signature data). Both support optional merkle proofs for multichain batch signing.
- **EIP-712 domains**: `PasskeyDigest` (chain-specific, single op) and `PasskeyMultichain` (chain-agnostic, merkle root).
