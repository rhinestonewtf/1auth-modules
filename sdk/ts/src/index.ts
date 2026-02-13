export {
  encodeInstall,
  getDigest,
  getDigestFromHashes,
  getPasskeyDigestTypedData,
  getPasskeyMultichainTypedData,
  passkeyDigest,
  passkeyMultichain,
  encodeSignature,
  encodeSignatureFromDigest,
  encodeStatelessData,
  getRecoveryDigest,
  getRecoveryTypehash,
  buildMerkleTree,
  verifyMerkleProof,
  MODULE_ADDRESS,
} from "./webauthn-v2.js";

export type {
  CredentialInput,
  InstallInput,
  DigestResult,
  MerkleProofResult,
  StatefulSignatureConfig,
  StatelessSignatureConfig,
  RecoveryDigestInput,
} from "./types.js";

export {
  getWebAuthnV2Validator,
  getWebAuthnV2ValidatorSignature,
  getWebAuthnV2ValidatorMockSignature,
  WEBAUTHN_V2_VALIDATOR_ADDRESS,
} from "./rhinestone.js";

export type { Module } from "./rhinestone.js";
