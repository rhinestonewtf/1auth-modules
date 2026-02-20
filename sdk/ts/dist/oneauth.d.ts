/**
 * @module @rhinestone/1auth-modules
 *
 * TypeScript SDK for the OneAuth ERC-7579 validator module.
 * All encoding logic delegates to a Rust WASM core for ABI-correctness.
 *
 * ## Flows
 *
 * ### 1. Installation
 * ```ts
 * import { encodeInstall } from "@rhinestone/1auth-modules";
 *
 * const { address, initData } = encodeInstall({
 *   credentials: [{ keyId: 0, pubKeyX: "0x...", pubKeyY: "0x..." }],
 *   userGuardian: "0xGuardianAddress",     // optional
 *   externalGuardian: "0xGuardianContract", // optional
 *   guardianThreshold: 1,                   // 1 = either, 2 = both
 * });
 *
 * // Use with ERC-7579 installModule:
 * await smartAccountClient.installModule({
 *   type: "validator", address, initData,
 * });
 * ```
 *
 * ### 2. Credential management (post-install)
 * ```ts
 * import { encodeAddCredential, encodeRemoveCredential } from "@rhinestone/1auth-modules";
 *
 * // Add a new passkey credential (returns full calldata with selector)
 * const addCalldata = encodeAddCredential({
 *   keyId: 1,
 *   pubKeyX: "0x...",
 *   pubKeyY: "0x...",
 * });
 * await smartAccountClient.sendTransaction({
 *   to: validatorAddress, data: addCalldata,
 * });
 *
 * // Remove a credential by keyId
 * const removeCalldata = encodeRemoveCredential(1);
 * ```
 *
 * ### 3. Guardian configuration
 * ```ts
 * import { encodeSetGuardianConfig } from "@rhinestone/1auth-modules";
 *
 * const calldata = encodeSetGuardianConfig({
 *   userGuardian: "0xNewGuardian",
 *   externalGuardian: "0x0000000000000000000000000000000000000000",
 *   threshold: 1,  // 1 = either guardian, 2 = both required
 * });
 * await smartAccountClient.sendTransaction({
 *   to: validatorAddress, data: calldata,
 * });
 * ```
 *
 * ### 4. Signing a UserOperation
 * ```ts
 * import { getDigest, encodeSignature, encodeSignatureFromDigest } from "@rhinestone/1auth-modules";
 *
 * // Single chain operation:
 * const { challenge, typedData } = getDigest(accountAddress, [userOpTypedData], chainId);
 * const webauthnAuth = await passkey.sign(challenge); // WebAuthn assertion
 * const signature = encodeSignature({ keyId: 0 }, webauthnAuth);
 *
 * // Multichain (batch) operations — signs all at once via merkle tree:
 * const result = getDigest(accountAddress, [msg1, msg2, msg3], chainId);
 * const webauthnAuth = await passkey.sign(result.challenge);
 * // Encode per-chain signature with merkle proof:
 * const sig0 = encodeSignatureFromDigest(result, 0, { keyId: 0 }, webauthnAuth);
 * ```
 *
 * ### 5. Recovery
 * ```ts
 * import {
 *   getRecoveryDigest, encodeSingleGuardianSig, encodeDualGuardianSig,
 * } from "@rhinestone/1auth-modules";
 *
 * // Step 1: Compute the EIP-712 digest the guardian(s) must sign
 * const digest = getRecoveryDigest({
 *   account: "0xSmartAccount",
 *   chainId: 1,         // 0 = valid on any chain
 *   newKeyId: 0,
 *   newPubKeyX: "0x...",
 *   newPubKeyY: "0x...",
 *   replace: true,      // true = rotate in-place, false = additive
 *   nonce: "0x01",
 *   expiry: 1700000000,
 * });
 *
 * // Step 2a: Single guardian (threshold=1)
 * const guardianSig = await guardian.signMessage(digest);
 * const sig = encodeSingleGuardianSig(0, guardianSig); // 0 = user, 1 = external
 *
 * // Step 2b: Dual guardian (threshold=2)
 * const userSig = await userGuardian.signMessage(digest);
 * const externalSig = await externalGuardian.signMessage(digest);
 * const sig = encodeDualGuardianSig(userSig, externalSig);
 *
 * // Step 3: Submit recovery (permissionless — anyone can call)
 * await publicClient.writeContract({
 *   address: validatorAddress,
 *   abi: oneAuthAbi,
 *   functionName: "recoverWithGuardian",
 *   args: [account, chainId, newCredential, nonce, expiry, sig],
 * });
 * ```
 *
 * ### 6. Guardian.sol multisig entries
 * ```ts
 * import { encodeGuardianEntries } from "@rhinestone/1auth-modules";
 *
 * // For a Guardian.sol contract with 2-of-3 threshold:
 * const sig = encodeGuardianEntries([
 *   { id: 0, sig: guardian0Signature },
 *   { id: 2, sig: guardian2Signature },
 * ]);
 * // Pass `sig` as the guardian signature in recovery
 * ```
 */
import { type Hex, type Address, hashTypedData } from "viem";
import type { InstallInput, AppInstallInput, DigestResult, StatefulSignatureConfig, StatelessSignatureConfig, RecoveryDigestInput, AppRecoveryDigestInput, AddCredentialInput, SetGuardianConfigInput, GuardianEntry, AccountDigestEntry, MultiAccountDigestResult, BatchSigningOperation } from "./types.js";
/** Deployed OneAuthValidator module address. */
declare const MODULE_ADDRESS: Address;
/** Deployed OneAuthAppValidator module address (placeholder until deployed). */
declare const APP_MODULE_ADDRESS: Address;
/** viem-compatible EIP-712 typed data input (for hashTypedData / signTypedData). */
export type EIP712Input = Parameters<typeof hashTypedData>[0];
/**
 * Get viem-compatible EIP-712 typed data for PasskeyDigest (chain-specific, account-bound).
 * Use with viem's `signTypedData()` for wallet display, or `hashTypedData()` to compute the digest.
 *
 * @param account - Smart account address bound into the challenge
 * @param digest - The bytes32 digest to wrap
 * @param chainId - Target chain ID
 * @param verifyingContract - Deployed OneAuthValidator address
 */
export declare function getPasskeyDigestTypedData(account: Address, digest: Hex, chainId: number, verifyingContract: Address): EIP712Input;
/**
 * Get viem-compatible EIP-712 typed data for PasskeyMultichain (chain-agnostic).
 * Used for merkle batch signing — the domain omits chainId.
 *
 * @param root - Merkle root of the batch
 * @param validatorAddress - Deployed OneAuthValidator address
 */
export declare function getPasskeyMultichainTypedData(root: Hex, validatorAddress?: Address): EIP712Input;
/**
 * Compute the chain-specific EIP-712 challenge for single-op signing.
 * This is the bytes32 value the passkey should sign.
 * Matches `_passkeyDigest(account, digest)` in the Solidity contract.
 *
 * @param account - Smart account address bound into the challenge
 * @param digest - The bytes32 digest to wrap
 * @param chainId - Target chain ID
 * @param verifyingContract - Deployed OneAuthValidator address
 */
export declare function passkeyDigest(account: Address, digest: Hex, chainId: number, verifyingContract: Address): Hex;
/**
 * Compute the chain-agnostic EIP-712 challenge for merkle batch signing.
 * Matches `_passkeyMultichain()` in the Solidity contract.
 */
export declare function passkeyMultichain(root: Hex, validatorAddress?: Address): Hex;
/**
 * Encode `onInstall` calldata for the OneAuthValidator module.
 * Returns the module address and ABI-encoded init data.
 *
 * @param input.credentials - Array of WebAuthn P-256 credentials (keyId + pubKey)
 * @param input.userGuardian - Optional user guardian address (EOA or contract)
 * @param input.externalGuardian - Optional external guardian (Guardian.sol contract)
 * @param input.guardianThreshold - 1 = either guardian, 2 = both required (default: 1)
 * @returns `{ address, initData }` — pass to ERC-7579 installModule
 */
export declare function encodeInstall(input: InstallInput): {
    address: Address;
    initData: Hex;
};
/**
 * Encode `onInstall` calldata for the OneAuthAppValidator module.
 * Returns the module address and ABI-encoded init data.
 *
 * NOTE: When computing digests for signing, use the **main validator's address**
 * (not the app validator's), since the EIP-712 domain uses verifyingContract = mainValidator.
 *
 * @param input.mainAccount - The main account whose passkey credentials to reuse
 * @returns `{ address, initData }` — pass to ERC-7579 installModule
 */
export declare function encodeAppInstall(input: AppInstallInput): {
    address: Address;
    initData: Hex;
};
/**
 * Encode `addCredential(uint16, bytes32, bytes32)` calldata.
 * Returns full calldata (4-byte selector + ABI-encoded params).
 * Execute via the smart account targeting the validator address.
 *
 * @param input.keyId - Unique credential identifier (uint16)
 * @param input.pubKeyX - P-256 public key X coordinate (bytes32)
 * @param input.pubKeyY - P-256 public key Y coordinate (bytes32)
 */
export declare function encodeAddCredential(input: AddCredentialInput): Hex;
/**
 * Encode `removeCredential(uint16)` calldata.
 * Returns full calldata (4-byte selector + ABI-encoded params).
 * Cannot remove the last credential (contract enforces >= 1).
 *
 * @param keyId - The credential keyId to remove
 */
export declare function encodeRemoveCredential(keyId: number): Hex;
/**
 * Encode `setGuardianConfig(address, address, uint8)` calldata.
 * Returns full calldata (4-byte selector + ABI-encoded params).
 * Changes take effect immediately.
 *
 * @param input.userGuardian - User guardian address (use zero address to clear)
 * @param input.externalGuardian - External guardian address (use zero address to clear)
 * @param input.threshold - 1 = either guardian can authorize recovery, 2 = both required
 */
export declare function encodeSetGuardianConfig(input: SetGuardianConfigInput): Hex;
/**
 * Encode a single-guardian recovery signature (threshold=1).
 * Format: `[type_byte][sig]`
 *
 * The type byte selects which guardian's signature this is:
 * - `0` = user guardian
 * - `1` = external guardian
 *
 * Pass the result as `guardianSig` to `recoverWithGuardian()`.
 *
 * @param guardianType - 0 for user guardian, 1 for external guardian
 * @param sig - The guardian's ERC-1271 or ECDSA signature over the recovery digest
 */
export declare function encodeSingleGuardianSig(guardianType: 0 | 1, sig: Hex): Hex;
/**
 * Encode a dual-guardian recovery signature (threshold=2).
 * Format: `[user_sig_len: uint16][user_sig][external_sig]`
 *
 * Both guardians must sign the same recovery digest.
 * Pass the result as `guardianSig` to `recoverWithGuardian()`.
 *
 * @param userGuardianSig - User guardian's signature
 * @param externalGuardianSig - External guardian's signature
 */
export declare function encodeDualGuardianSig(userGuardianSig: Hex, externalGuardianSig: Hex): Hex;
/**
 * Encode Guardian.sol multisig entries for ERC-1271 validation.
 * Each entry: `[id: uint8][sigLen: uint16][sig: bytes]`
 *
 * Guardian.sol is an M-of-N multisig contract used as an external guardian.
 * Each entry identifies a guardian slot (0, 1, or 2) and provides that guardian's
 * signature. The contract requires exactly `threshold` entries with unique IDs.
 *
 * Guardians can be EOAs (65-byte ECDSA) or nested ERC-1271 contracts (variable length).
 *
 * @param entries - Array of `{ id, sig }` for each signing guardian
 */
export declare function encodeGuardianEntries(entries: GuardianEntry[]): Hex;
/**
 * Prepare digest(s) for signing with EIP-712 challenge wrapping.
 *
 * - **Single message**: wraps with PasskeyDigest (chain-specific, account-bound EIP-712).
 * - **Multiple messages**: builds a merkle tree with account-bound leaves, wraps root with
 *   PasskeyMultichain (chain-agnostic). Returns per-leaf proofs.
 *
 * The returned `challenge` is what the passkey should sign via WebAuthn.
 * The returned `typedData` can be passed to viem's `signTypedData()` for wallet display.
 *
 * @param account - Smart account address bound into the challenge
 * @param messages - viem EIP-712 typed data objects (e.g., from `getUserOperationTypedData`)
 * @param chainId - Chain ID (used only for single-message path)
 * @param validatorAddress - Deployed OneAuthValidator address
 */
export declare function getDigest(account: Address, messages: EIP712Input[], chainId: number, validatorAddress?: Address): DigestResult;
/**
 * Same as {@link getDigest} but takes pre-hashed bytes32 digests instead of EIP-712 objects.
 * Use when you already have the hashed digests (e.g., userOpHash from the bundler).
 *
 * @param account - Smart account address bound into the challenge
 * @param hashes - Pre-hashed bytes32 digests
 * @param chainId - Chain ID (used only for single-hash path)
 * @param validatorAddress - Deployed OneAuthValidator address
 */
export declare function getDigestFromHashes(account: Address, hashes: Hex[], chainId: number, validatorAddress?: Address): DigestResult;
/**
 * Encode a stateful WebAuthn signature for validateUserOp / isValidSignatureWithSender.
 * "Stateful" means the credential's public key is stored on-chain, referenced by keyId.
 *
 * Format (no merkle): `[proofLength=0][keyId: uint16][webauthnAuth]`
 * Format (merkle): `[proofLength][root][proof...][keyId: uint16][webauthnAuth]`
 *
 * @param config.keyId - The on-chain credential keyId
 * @param config.merkle - Optional merkle proof for multichain batch signing
 * @param webauthnAuth - Raw WebAuthn authenticator response (authenticatorData + clientDataJSON + r + s)
 */
export declare function encodeSignature(config: StatefulSignatureConfig, webauthnAuth: Hex): Hex;
/**
 * Convenience wrapper around {@link encodeSignature} that extracts merkle proof
 * from a {@link DigestResult} (returned by {@link getDigest}).
 *
 * @param digestResult - Result from getDigest() or getDigestFromHashes()
 * @param leafIndex - Index of the message in the original array
 * @param config - `{ keyId }` — the credential to sign with
 * @param webauthnAuth - Raw WebAuthn authenticator response
 */
export declare function encodeSignatureFromDigest(digestResult: DigestResult, leafIndex: number, config: Omit<StatefulSignatureConfig, "merkle">, webauthnAuth: Hex): Hex;
/**
 * Encode stateless validation data for `validateSignatureWithData`.
 * "Stateless" means the public key is provided in the signature data itself,
 * not looked up on-chain. Used for external credential verification.
 *
 * @param config.account - Smart account address (prepended to data)
 * @param config.pubKeyX - P-256 public key X coordinate
 * @param config.pubKeyY - P-256 public key Y coordinate
 * @param config.merkle - Optional merkle proof for multichain
 */
export declare function encodeStatelessData(config: StatelessSignatureConfig): Hex;
/**
 * Compute the EIP-712 recovery digest that must be signed by either
 * an existing passkey (for `recoverWithPasskey`) or guardian(s) (for `recoverWithGuardian`).
 *
 * Uses a chain-agnostic domain separator (no chainId in domain) with chainId embedded
 * in the struct hash — this enables cross-chain recovery when chainId=0.
 *
 * @param input.account - Smart account address being recovered
 * @param input.chainId - Target chain (0 = valid on any chain)
 * @param input.newKeyId - Credential keyId for the new/replacement key
 * @param input.newPubKeyX - New P-256 public key X coordinate
 * @param input.newPubKeyY - New P-256 public key Y coordinate
 * @param input.replace - true = overwrite existing keyId (rotation), false = add new (additive)
 * @param input.nonce - Unique nonce (hex string). Each nonce can only be used once, even across reinstalls.
 * @param input.expiry - Unix timestamp after which the recovery message expires
 * @param input.verifyingContract - OneAuthValidator address (defaults to MODULE_ADDRESS)
 */
export declare function getRecoveryDigest(input: RecoveryDigestInput): Hex;
/** Get the `RecoverPasskey(...)` EIP-712 typehash constant. */
export declare function getRecoveryTypehash(): Hex;
/**
 * Compute the EIP-712 app recovery digest that must be signed by guardian(s)
 * to change the mainAccount pointer on an OneAuthAppValidator.
 *
 * Uses a chain-agnostic domain separator (no chainId in domain) with chainId embedded
 * in the struct hash -- this enables cross-chain recovery when chainId=0.
 *
 * @param input.account - Smart account address being recovered
 * @param input.chainId - Target chain (0 = valid on any chain)
 * @param input.newMainAccount - New main account address to point to
 * @param input.nonce - Unique nonce (hex string). Each nonce can only be used once.
 * @param input.expiry - Unix timestamp after which the recovery message expires
 * @param input.verifyingContract - OneAuthAppValidator address (defaults to APP_MODULE_ADDRESS)
 */
export declare function getAppRecoveryDigest(input: AppRecoveryDigestInput): Hex;
/** Get the `RecoverAppValidator(...)` EIP-712 typehash constant. */
export declare function getAppRecoveryTypehash(): Hex;
/**
 * Build a Solady-compatible merkle tree from bytes32 leaves.
 * Uses sorted-pair keccak256 hashing (matches Solady's MerkleProofLib).
 *
 * @param leaves - Array of bytes32 hex strings
 * @returns `{ root, proofs }` — root is the merkle root, proofs[i] is the proof for leaves[i]
 */
export declare function buildMerkleTree(leaves: Hex[]): {
    root: Hex;
    proofs: Hex[][];
};
/**
 * Verify a merkle proof against a root and leaf.
 *
 * @param proof - Array of bytes32 sibling hashes
 * @param root - Expected merkle root
 * @param leaf - Leaf to verify membership of
 */
export declare function verifyMerkleProof(proof: Hex[], root: Hex, leaf: Hex): boolean;
/**
 * Compute the account-bound merkle leaf: keccak256(abi.encode(account, digest)).
 * Used in merkle paths to bind each leaf to a specific account.
 *
 * @param account - Smart account address
 * @param digest - The bytes32 digest
 */
export declare function getAccountLeaf(account: Address, digest: Hex): Hex;
/**
 * Build a multi-account merkle tree for signing across multiple accounts with one passkey signature.
 * Returns a single challenge to sign plus per-entry proofs for constructing per-account signatures.
 *
 * @param entries - Array of { account, hash } pairs — each account+hash becomes an account-bound leaf
 * @param validatorAddress - Deployed OneAuthValidator address
 */
export declare function getMultiAccountDigest(entries: AccountDigestEntry[], validatorAddress?: Address): MultiAccountDigestResult;
/**
 * Build a single-signature digest for operations across a main account and one or more app accounts.
 * Handles app-account pre-binding automatically — the integrator just provides account + hash pairs.
 *
 * Returns a standard {@link DigestResult} that works directly with {@link encodeSignatureFromDigest}.
 *
 * @example
 * ```ts
 * const result = getBatchSigningDigest(mainAccount, [
 *   { account: mainAccount, hash: mainUserOpHash },
 *   { account: appAccount1, hash: app1UserOpHash },
 *   { account: appAccount2, hash: app2UserOpHash },
 * ]);
 *
 * const auth = await passkey.sign(result.challenge);
 * const mainSig = encodeSignatureFromDigest(result, 0, { keyId: 0 }, auth);
 * const app1Sig = encodeSignatureFromDigest(result, 1, { keyId: 0 }, auth);
 * const app2Sig = encodeSignatureFromDigest(result, 2, { keyId: 0 }, auth);
 * ```
 *
 * @param mainAccount - The main account whose passkey credentials are used for signing
 * @param operations - Array of { account, hash } — each account can be the main account or an app account
 * @param validatorAddress - Deployed OneAuthValidator address
 */
export declare function getBatchSigningDigest(mainAccount: Address, operations: BatchSigningOperation[], validatorAddress?: Address): DigestResult;
export { MODULE_ADDRESS, APP_MODULE_ADDRESS };
