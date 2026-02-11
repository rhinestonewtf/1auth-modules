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
  buildMerkleTree,
  MODULE_ADDRESS,
} from "./webauthn-v2.js";

export type {
  CredentialInput,
  InstallInput,
  DigestResult,
  MerkleProofResult,
  StatefulSignatureConfig,
  RecoveryDigestInput,
} from "./types.js";
