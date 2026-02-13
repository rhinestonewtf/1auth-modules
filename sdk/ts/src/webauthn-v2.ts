import { type Hex, type Address, hashTypedData } from "viem";
import type {
  InstallInput,
  DigestResult,
  MerkleProofResult,
  StatefulSignatureConfig,
} from "./types.js";

// WASM imports — bundler target auto-initializes on import.
import {
  encodeInstall as wasmEncodeInstall,
  encodeStatefulSignature as wasmEncodeSignature,
  buildMerkleTree as wasmBuildMerkleTree,
  getPasskeyDigestTypedData as wasmPasskeyDigestTypedData,
  getPasskeyMultichainTypedData as wasmPasskeyMultichainTypedData,
} from "./wasm/webauthn-v2/webauthn_v2.js";

const MODULE_ADDRESS: Address = "0x0000000000578c4cb0e472a5462da43c495c3f33";

// ── EIP-712 typed data (from WASM) ──

export type EIP712Input = Parameters<typeof hashTypedData>[0];

/** Get the viem-compatible EIP-712 typed data for PasskeyDigest (chain-specific). */
export function getPasskeyDigestTypedData(
  digest: Hex,
  chainId: number,
  verifyingContract: Address
): EIP712Input {
  return JSON.parse(wasmPasskeyDigestTypedData(digest, BigInt(chainId), verifyingContract));
}

/** Get the viem-compatible EIP-712 typed data for PasskeyMultichain (chain-agnostic). */
export function getPasskeyMultichainTypedData(root: Hex): EIP712Input {
  return JSON.parse(wasmPasskeyMultichainTypedData(root));
}

/** Chain-specific EIP-712 challenge for single op signing. Matches _passkeyDigest(). */
export function passkeyDigest(
  digest: Hex,
  chainId: number,
  verifyingContract: Address
): Hex {
  return hashTypedData(getPasskeyDigestTypedData(digest, chainId, verifyingContract));
}

/** Chain-agnostic EIP-712 challenge for merkle batch signing. Matches _passkeyMultichain(). */
export function passkeyMultichain(root: Hex): Hex {
  return hashTypedData(getPasskeyMultichainTypedData(root));
}

// ── Install encoding (delegates to WASM) ──

export function encodeInstall(input: InstallInput): { address: Address; initData: Hex } {
  const wasmInput = JSON.stringify({
    key_ids: input.credentials.map((c) => c.keyId),
    credentials: input.credentials.map((c) => ({
      pub_key_x: c.pubKeyX,
      pub_key_y: c.pubKeyY,
    })),
    guardian: input.guardian ?? "0x0000000000000000000000000000000000000000",
  });
  const result = JSON.parse(wasmEncodeInstall(wasmInput));
  return { address: result.address as Address, initData: result.initData as Hex };
}

// ── Digest preparation ──

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
export function getDigest(
  messages: EIP712Input[],
  chainId: number,
  validatorAddress: Address = MODULE_ADDRESS
): DigestResult {
  if (messages.length === 0) throw new Error("at least one message required");

  const digests: Hex[] = messages.map((m) => hashTypedData(m));

  if (digests.length === 1) {
    const typedData = getPasskeyDigestTypedData(digests[0], chainId, validatorAddress);
    const challenge = hashTypedData(typedData);
    return { challenge, raw: digests[0], typedData, proofs: null, is_merkle: false };
  }

  const { root, proofs } = buildMerkleTree(digests);
  const typedData = getPasskeyMultichainTypedData(root);
  const challenge = hashTypedData(typedData);
  const merkleProofs: MerkleProofResult[] = digests.map((d, i) => ({
    leaf: d,
    proof: proofs[i],
    index: i,
  }));

  return { challenge, raw: root, typedData, proofs: merkleProofs, is_merkle: true };
}

/**
 * Same as getDigest but takes pre-hashed bytes32 digests.
 */
export function getDigestFromHashes(
  hashes: Hex[],
  chainId: number,
  validatorAddress: Address = MODULE_ADDRESS
): DigestResult {
  if (hashes.length === 0) throw new Error("at least one hash required");

  if (hashes.length === 1) {
    const typedData = getPasskeyDigestTypedData(hashes[0], chainId, validatorAddress);
    const challenge = hashTypedData(typedData);
    return { challenge, raw: hashes[0], typedData, proofs: null, is_merkle: false };
  }

  const { root, proofs } = buildMerkleTree(hashes);
  const typedData = getPasskeyMultichainTypedData(root);
  const challenge = hashTypedData(typedData);
  const merkleProofs: MerkleProofResult[] = hashes.map((d, i) => ({
    leaf: d,
    proof: proofs[i],
    index: i,
  }));

  return { challenge, raw: root, typedData, proofs: merkleProofs, is_merkle: true };
}

// ── Signature encoding (delegates to WASM) ──

export function encodeSignature(
  config: StatefulSignatureConfig,
  webauthnAuth: Hex
): Hex {
  const wasmConfig = JSON.stringify({
    key_id: config.keyId,
    use_precompile: config.usePrecompile,
    merkle: config.merkle
      ? {
          root: hexToBytes32(config.merkle.root),
          proof: config.merkle.proof.map(hexToBytes32),
        }
      : null,
  });
  return wasmEncodeSignature(wasmConfig, webauthnAuth) as Hex;
}

export function encodeSignatureFromDigest(
  digestResult: DigestResult,
  leafIndex: number,
  config: Omit<StatefulSignatureConfig, "merkle">,
  webauthnAuth: Hex
): Hex {
  let merkle: StatefulSignatureConfig["merkle"];

  if (digestResult.is_merkle && digestResult.proofs) {
    const p = digestResult.proofs[leafIndex];
    merkle = { root: digestResult.raw, proof: p.proof };
  }

  return encodeSignature({ ...config, merkle }, webauthnAuth);
}

// ── Merkle tree (delegates to WASM — Solady sorted-pair keccak256) ──

export function buildMerkleTree(leaves: Hex[]): { root: Hex; proofs: Hex[][] } {
  const result = JSON.parse(wasmBuildMerkleTree(JSON.stringify(leaves)));
  return { root: result.root as Hex, proofs: result.proofs as Hex[][] };
}

// ── Helpers ──

export { MODULE_ADDRESS };

/** Convert hex string to number array for WASM JSON serialization of [u8; 32]. */
function hexToBytes32(hex: Hex): number[] {
  const s = hex.startsWith("0x") ? hex.slice(2) : hex;
  const bytes: number[] = [];
  for (let i = 0; i < s.length; i += 2) {
    bytes.push(parseInt(s.substring(i, i + 2), 16));
  }
  return bytes;
}
