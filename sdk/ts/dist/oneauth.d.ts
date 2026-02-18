import { type Hex, type Address, hashTypedData } from "viem";
import type { InstallInput, DigestResult, StatefulSignatureConfig, StatelessSignatureConfig, RecoveryDigestInput } from "./types.js";
declare const MODULE_ADDRESS: Address;
export type EIP712Input = Parameters<typeof hashTypedData>[0];
/** Get the viem-compatible EIP-712 typed data for PasskeyDigest (chain-specific). */
export declare function getPasskeyDigestTypedData(digest: Hex, chainId: number, verifyingContract: Address): EIP712Input;
/** Get the viem-compatible EIP-712 typed data for PasskeyMultichain (chain-agnostic). */
export declare function getPasskeyMultichainTypedData(root: Hex, validatorAddress?: Address): EIP712Input;
/** Chain-specific EIP-712 challenge for single op signing. Matches _passkeyDigest(). */
export declare function passkeyDigest(digest: Hex, chainId: number, verifyingContract: Address): Hex;
/** Chain-agnostic EIP-712 challenge for merkle batch signing. Matches _passkeyMultichain(). */
export declare function passkeyMultichain(root: Hex, validatorAddress?: Address): Hex;
export declare function encodeInstall(input: InstallInput): {
    address: Address;
    initData: Hex;
};
/**
 * Prepare digest(s) for signing with EIP-712 challenge wrapping.
 *
 * - Single message → PasskeyDigest (chain-specific).
 * - Multiple messages → merkle tree + PasskeyMultichain (chain-agnostic).
 *
 * Returns { challenge, raw, typedData, proofs, is_merkle }.
 * `challenge` is what the passkey should sign.
 * `typedData` is the viem-compatible EIP-712 object (pass to signTypedData for wallet display).
 * `raw` is the original digest or merkle root before EIP-712 wrapping.
 */
export declare function getDigest(messages: EIP712Input[], chainId: number, validatorAddress?: Address): DigestResult;
/**
 * Same as getDigest but takes pre-hashed bytes32 digests.
 */
export declare function getDigestFromHashes(hashes: Hex[], chainId: number, validatorAddress?: Address): DigestResult;
export declare function encodeSignature(config: StatefulSignatureConfig, webauthnAuth: Hex): Hex;
export declare function encodeSignatureFromDigest(digestResult: DigestResult, leafIndex: number, config: Omit<StatefulSignatureConfig, "merkle">, webauthnAuth: Hex): Hex;
/** Encode stateless validation data for validateSignatureWithData (external credentials). */
export declare function encodeStatelessData(config: StatelessSignatureConfig): Hex;
/** Compute the EIP-712 recovery digest for passkey/guardian recovery. */
export declare function getRecoveryDigest(input: RecoveryDigestInput): Hex;
/** Get the RECOVER_PASSKEY EIP-712 typehash. */
export declare function getRecoveryTypehash(): Hex;
export declare function buildMerkleTree(leaves: Hex[]): {
    root: Hex;
    proofs: Hex[][];
};
/** Verify a merkle proof against a root and leaf. */
export declare function verifyMerkleProof(proof: Hex[], root: Hex, leaf: Hex): boolean;
export { MODULE_ADDRESS };
