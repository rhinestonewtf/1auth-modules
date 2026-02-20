/* tslint:disable */
/* eslint-disable */

export function buildMerkleTree(leaves_json: string): string;

export function encodeAddCredential(input_json: string): string;

export function encodeAppInstall(input_json: string): string;

export function encodeDualGuardianSig(user_sig_hex: string, external_sig_hex: string): string;

export function encodeGuardianEntries(entries_json: string): string;

export function encodeInstall(input_json: string): string;

export function encodeRemoveCredential(key_id: number): string;

export function encodeSetGuardianConfig(input_json: string): string;

export function encodeSingleGuardianSig(guardian_type: number, sig_hex: string): string;

export function encodeStatefulSignature(config_json: string, webauthn_auth_hex: string): string;

export function encodeStatelessData(config_json: string): string;

/**
 * Compute the account-bound merkle leaf: keccak256(abi.encode(account, digest)).
 */
export function getAccountLeaf(account_hex: string, digest_hex: string): string;

export function getAppRecoveryDigest(input_json: string): string;

export function getAppRecoveryTypehash(): string;

/**
 * Prepare digest(s) with EIP-712 challenge wrapping.
 * account_hex: the smart account address bound into the challenge
 * digests_json: JSON array of hex bytes32 strings
 * chain_id: chain ID for single-digest (PasskeyDigest) path
 * verifying_contract_hex: deployed OneAuthValidator address
 */
export function getDigest(account_hex: string, digests_json: string, chain_id: bigint, verifying_contract_hex: string): string;

/**
 * Build a multi-account merkle tree for signing across multiple accounts with one passkey signature.
 * entries_json: JSON array of { account: "0x...", digest: "0x..." }
 * verifying_contract_hex: deployed OneAuthValidator address
 */
export function getMultiAccountDigest(entries_json: string, verifying_contract_hex: string): string;

/**
 * Returns a viem-compatible EIP-712 typed data object for PasskeyDigest.
 * Pass the result to viem's hashTypedData() or signTypedData().
 */
export function getPasskeyDigestTypedData(account_hex: string, digest_hex: string, chain_id: bigint, verifying_contract_hex: string): string;

/**
 * Returns a viem-compatible EIP-712 typed data object for PasskeyMultichain.
 * Pass the result to viem's hashTypedData() or signTypedData().
 */
export function getPasskeyMultichainTypedData(root_hex: string, verifying_contract_hex: string): string;

export function getRecoveryDigest(input_json: string): string;

export function getRecoveryTypehash(): string;

/**
 * Compute PasskeyDigest challenge (single op, chain-specific, account-bound).
 */
export function passkeyDigest(account_hex: string, digest_hex: string, chain_id: bigint, verifying_contract_hex: string): string;

/**
 * Compute PasskeyMultichain challenge (merkle batch, chain-agnostic).
 */
export function passkeyMultichain(root_hex: string, verifying_contract_hex: string): string;

export function verifyMerkleProof(proof_json: string, root_hex: string, leaf_hex: string): boolean;
