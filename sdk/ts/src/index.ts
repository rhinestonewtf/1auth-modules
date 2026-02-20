export {
  // Install / uninstall
  encodeInstall,
  // Credential management
  encodeAddCredential,
  encodeRemoveCredential,
  // Guardian configuration
  encodeSetGuardianConfig,
  // Digest / challenge computation
  getDigest,
  getDigestFromHashes,
  getPasskeyDigestTypedData,
  getPasskeyMultichainTypedData,
  passkeyDigest,
  passkeyMultichain,
  // Signature encoding
  encodeSignature,
  encodeSignatureFromDigest,
  encodeStatelessData,
  // Guardian recovery signatures
  encodeSingleGuardianSig,
  encodeDualGuardianSig,
  encodeGuardianEntries,
  // Recovery
  getRecoveryDigest,
  getRecoveryTypehash,
  // Merkle tree
  buildMerkleTree,
  verifyMerkleProof,
  // Constants
  MODULE_ADDRESS,
} from "./oneauth.js";

export type {
  CredentialInput,
  InstallInput,
  AddCredentialInput,
  SetGuardianConfigInput,
  NewCredential,
  GuardianEntry,
  DigestResult,
  MerkleProofResult,
  StatefulSignatureConfig,
  StatelessSignatureConfig,
  RecoveryDigestInput,
} from "./types.js";

export {
  getOneAuthValidator,
  getOneAuthValidatorSignature,
  getOneAuthValidatorMockSignature,
  ONEAUTH_VALIDATOR_ADDRESS,
} from "./rhinestone.js";

export type { Module } from "./rhinestone.js";
