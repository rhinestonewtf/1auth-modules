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
 * const { challenge, typedData } = getDigest([userOpTypedData], chainId);
 * const webauthnAuth = await passkey.sign(challenge); // WebAuthn assertion
 * const signature = encodeSignature({ keyId: 0 }, webauthnAuth);
 *
 * // Multichain (batch) operations — signs all at once via merkle tree:
 * const result = getDigest([msg1, msg2, msg3], chainId);
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
import { hashTypedData } from "viem";
// WASM imports — bundler target auto-initializes on import.
import { encodeInstall as wasmEncodeInstall, encodeAddCredential as wasmEncodeAddCredential, encodeRemoveCredential as wasmEncodeRemoveCredential, encodeSetGuardianConfig as wasmEncodeSetGuardianConfig, encodeStatefulSignature as wasmEncodeSignature, encodeStatelessData as wasmEncodeStatelessData, encodeSingleGuardianSig as wasmEncodeSingleGuardianSig, encodeDualGuardianSig as wasmEncodeDualGuardianSig, encodeGuardianEntries as wasmEncodeGuardianEntries, buildMerkleTree as wasmBuildMerkleTree, verifyMerkleProof as wasmVerifyMerkleProof, getPasskeyDigestTypedData as wasmPasskeyDigestTypedData, getPasskeyMultichainTypedData as wasmPasskeyMultichainTypedData, getRecoveryDigest as wasmGetRecoveryDigest, getRecoveryTypehash as wasmGetRecoveryTypehash, } from "./wasm/oneauth/oneauth.js";
/** Deployed OneAuthValidator module address. */
const MODULE_ADDRESS = "0x6B8Fb8E8862a752913Ed5aDa5696be2C381437e5";
/**
 * Get viem-compatible EIP-712 typed data for PasskeyDigest (chain-specific).
 * Use with viem's `signTypedData()` for wallet display, or `hashTypedData()` to compute the digest.
 *
 * @param digest - The bytes32 digest to wrap
 * @param chainId - Target chain ID
 * @param verifyingContract - Deployed OneAuthValidator address
 */
export function getPasskeyDigestTypedData(digest, chainId, verifyingContract) {
    return JSON.parse(wasmPasskeyDigestTypedData(digest, BigInt(chainId), verifyingContract));
}
/**
 * Get viem-compatible EIP-712 typed data for PasskeyMultichain (chain-agnostic).
 * Used for merkle batch signing — the domain omits chainId.
 *
 * @param root - Merkle root of the batch
 * @param validatorAddress - Deployed OneAuthValidator address
 */
export function getPasskeyMultichainTypedData(root, validatorAddress = MODULE_ADDRESS) {
    return JSON.parse(wasmPasskeyMultichainTypedData(root, validatorAddress));
}
/**
 * Compute the chain-specific EIP-712 challenge for single-op signing.
 * This is the bytes32 value the passkey should sign.
 * Matches `_passkeyDigest()` in the Solidity contract.
 */
export function passkeyDigest(digest, chainId, verifyingContract) {
    return hashTypedData(getPasskeyDigestTypedData(digest, chainId, verifyingContract));
}
/**
 * Compute the chain-agnostic EIP-712 challenge for merkle batch signing.
 * Matches `_passkeyMultichain()` in the Solidity contract.
 */
export function passkeyMultichain(root, validatorAddress = MODULE_ADDRESS) {
    return hashTypedData(getPasskeyMultichainTypedData(root, validatorAddress));
}
// ── Install encoding ──
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
export function encodeInstall(input) {
    const wasmInput = JSON.stringify({
        key_ids: input.credentials.map((c) => c.keyId),
        credentials: input.credentials.map((c) => ({
            pub_key_x: c.pubKeyX,
            pub_key_y: c.pubKeyY,
        })),
        user_guardian: input.userGuardian ?? "0x0000000000000000000000000000000000000000",
        external_guardian: input.externalGuardian ?? "0x0000000000000000000000000000000000000000",
        guardian_threshold: input.guardianThreshold ?? 0,
    });
    const result = JSON.parse(wasmEncodeInstall(wasmInput));
    return { address: result.address, initData: result.initData };
}
// ── Credential management calldata ──
/**
 * Encode `addCredential(uint16, bytes32, bytes32)` calldata.
 * Returns full calldata (4-byte selector + ABI-encoded params).
 * Execute via the smart account targeting the validator address.
 *
 * @param input.keyId - Unique credential identifier (uint16)
 * @param input.pubKeyX - P-256 public key X coordinate (bytes32)
 * @param input.pubKeyY - P-256 public key Y coordinate (bytes32)
 */
export function encodeAddCredential(input) {
    const wasmInput = JSON.stringify({
        key_id: input.keyId,
        pub_key_x: input.pubKeyX,
        pub_key_y: input.pubKeyY,
    });
    return wasmEncodeAddCredential(wasmInput);
}
/**
 * Encode `removeCredential(uint16)` calldata.
 * Returns full calldata (4-byte selector + ABI-encoded params).
 * Cannot remove the last credential (contract enforces >= 1).
 *
 * @param keyId - The credential keyId to remove
 */
export function encodeRemoveCredential(keyId) {
    return wasmEncodeRemoveCredential(keyId);
}
// ── Guardian configuration calldata ──
/**
 * Encode `setGuardianConfig(address, address, uint8)` calldata.
 * Returns full calldata (4-byte selector + ABI-encoded params).
 * Changes take effect immediately.
 *
 * @param input.userGuardian - User guardian address (use zero address to clear)
 * @param input.externalGuardian - External guardian address (use zero address to clear)
 * @param input.threshold - 1 = either guardian can authorize recovery, 2 = both required
 */
export function encodeSetGuardianConfig(input) {
    const wasmInput = JSON.stringify({
        user_guardian: input.userGuardian,
        external_guardian: input.externalGuardian,
        threshold: input.threshold,
    });
    return wasmEncodeSetGuardianConfig(wasmInput);
}
// ── Guardian recovery signature encoding ──
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
export function encodeSingleGuardianSig(guardianType, sig) {
    return wasmEncodeSingleGuardianSig(guardianType, sig);
}
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
export function encodeDualGuardianSig(userGuardianSig, externalGuardianSig) {
    return wasmEncodeDualGuardianSig(userGuardianSig, externalGuardianSig);
}
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
export function encodeGuardianEntries(entries) {
    return wasmEncodeGuardianEntries(JSON.stringify(entries));
}
// ── Digest preparation ──
/**
 * Prepare digest(s) for signing with EIP-712 challenge wrapping.
 *
 * - **Single message**: wraps with PasskeyDigest (chain-specific EIP-712 domain with chainId).
 * - **Multiple messages**: builds a merkle tree, wraps root with PasskeyMultichain
 *   (chain-agnostic domain without chainId). Returns per-leaf proofs.
 *
 * The returned `challenge` is what the passkey should sign via WebAuthn.
 * The returned `typedData` can be passed to viem's `signTypedData()` for wallet display.
 *
 * @param messages - viem EIP-712 typed data objects (e.g., from `getUserOperationTypedData`)
 * @param chainId - Chain ID (used only for single-message path)
 * @param validatorAddress - Deployed OneAuthValidator address
 */
export function getDigest(messages, chainId, validatorAddress = MODULE_ADDRESS) {
    if (messages.length === 0)
        throw new Error("at least one message required");
    const digests = messages.map((m) => hashTypedData(m));
    if (digests.length === 1) {
        const typedData = getPasskeyDigestTypedData(digests[0], chainId, validatorAddress);
        const challenge = hashTypedData(typedData);
        return { challenge, raw: digests[0], typedData, proofs: null, is_merkle: false };
    }
    const { root, proofs } = buildMerkleTree(digests);
    const typedData = getPasskeyMultichainTypedData(root, validatorAddress);
    const challenge = hashTypedData(typedData);
    const merkleProofs = digests.map((d, i) => ({
        leaf: d,
        proof: proofs[i],
        index: i,
    }));
    return { challenge, raw: root, typedData, proofs: merkleProofs, is_merkle: true };
}
/**
 * Same as {@link getDigest} but takes pre-hashed bytes32 digests instead of EIP-712 objects.
 * Use when you already have the hashed digests (e.g., userOpHash from the bundler).
 */
export function getDigestFromHashes(hashes, chainId, validatorAddress = MODULE_ADDRESS) {
    if (hashes.length === 0)
        throw new Error("at least one hash required");
    if (hashes.length === 1) {
        const typedData = getPasskeyDigestTypedData(hashes[0], chainId, validatorAddress);
        const challenge = hashTypedData(typedData);
        return { challenge, raw: hashes[0], typedData, proofs: null, is_merkle: false };
    }
    const { root, proofs } = buildMerkleTree(hashes);
    const typedData = getPasskeyMultichainTypedData(root, validatorAddress);
    const challenge = hashTypedData(typedData);
    const merkleProofs = hashes.map((d, i) => ({
        leaf: d,
        proof: proofs[i],
        index: i,
    }));
    return { challenge, raw: root, typedData, proofs: merkleProofs, is_merkle: true };
}
// ── Signature encoding ──
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
export function encodeSignature(config, webauthnAuth) {
    const wasmConfig = JSON.stringify({
        key_id: config.keyId,
        merkle: config.merkle
            ? {
                root: hexToBytes32(config.merkle.root),
                proof: config.merkle.proof.map(hexToBytes32),
            }
            : null,
    });
    return wasmEncodeSignature(wasmConfig, webauthnAuth);
}
/**
 * Convenience wrapper around {@link encodeSignature} that extracts merkle proof
 * from a {@link DigestResult} (returned by {@link getDigest}).
 *
 * @param digestResult - Result from getDigest() or getDigestFromHashes()
 * @param leafIndex - Index of the message in the original array
 * @param config - `{ keyId }` — the credential to sign with
 * @param webauthnAuth - Raw WebAuthn authenticator response
 */
export function encodeSignatureFromDigest(digestResult, leafIndex, config, webauthnAuth) {
    let merkle;
    if (digestResult.is_merkle && digestResult.proofs) {
        const p = digestResult.proofs[leafIndex];
        merkle = { root: digestResult.raw, proof: p.proof };
    }
    return encodeSignature({ ...config, merkle }, webauthnAuth);
}
// ── Stateless data encoding ──
/**
 * Encode stateless validation data for `validateSignatureWithData`.
 * "Stateless" means the public key is provided in the signature data itself,
 * not looked up on-chain. Used for external credential verification.
 *
 * @param config.pubKeyX - P-256 public key X coordinate
 * @param config.pubKeyY - P-256 public key Y coordinate
 * @param config.merkle - Optional merkle proof for multichain
 */
export function encodeStatelessData(config) {
    const wasmConfig = JSON.stringify({
        pub_key_x: hexToBytes32(config.pubKeyX),
        pub_key_y: hexToBytes32(config.pubKeyY),
        merkle: config.merkle
            ? {
                root: hexToBytes32(config.merkle.root),
                proof: config.merkle.proof.map(hexToBytes32),
            }
            : null,
    });
    return wasmEncodeStatelessData(wasmConfig);
}
// ── Recovery ──
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
export function getRecoveryDigest(input) {
    const wasmInput = JSON.stringify({
        account: input.account,
        chain_id: input.chainId,
        new_key_id: input.newKeyId,
        new_pub_key_x: input.newPubKeyX,
        new_pub_key_y: input.newPubKeyY,
        replace: input.replace ?? false,
        nonce: input.nonce,
        expiry: input.expiry,
        verifying_contract: input.verifyingContract ?? MODULE_ADDRESS,
    });
    return wasmGetRecoveryDigest(wasmInput);
}
/** Get the `RecoverPasskey(...)` EIP-712 typehash constant. */
export function getRecoveryTypehash() {
    return wasmGetRecoveryTypehash();
}
// ── Merkle tree ──
/**
 * Build a Solady-compatible merkle tree from bytes32 leaves.
 * Uses sorted-pair keccak256 hashing (matches Solady's MerkleProofLib).
 *
 * @param leaves - Array of bytes32 hex strings
 * @returns `{ root, proofs }` — root is the merkle root, proofs[i] is the proof for leaves[i]
 */
export function buildMerkleTree(leaves) {
    const result = JSON.parse(wasmBuildMerkleTree(JSON.stringify(leaves)));
    return { root: result.root, proofs: result.proofs };
}
/**
 * Verify a merkle proof against a root and leaf.
 *
 * @param proof - Array of bytes32 sibling hashes
 * @param root - Expected merkle root
 * @param leaf - Leaf to verify membership of
 */
export function verifyMerkleProof(proof, root, leaf) {
    return wasmVerifyMerkleProof(JSON.stringify(proof), root, leaf);
}
// ── Helpers ──
export { MODULE_ADDRESS };
function hexToBytes32(hex) {
    const s = hex.startsWith("0x") ? hex.slice(2) : hex;
    const bytes = [];
    for (let i = 0; i < s.length; i += 2) {
        bytes.push(parseInt(s.substring(i, i + 2), 16));
    }
    return bytes;
}
