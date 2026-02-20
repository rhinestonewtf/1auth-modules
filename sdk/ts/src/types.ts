import type { Hex, Address } from "viem";

export interface CredentialInput {
  keyId: number;
  pubKeyX: Hex;
  pubKeyY: Hex;
}

export interface InstallInput {
  credentials: CredentialInput[];
  userGuardian?: Address;
  externalGuardian?: Address;
  guardianThreshold?: number;
}

export interface DigestResult {
  /** EIP-712 wrapped challenge — what the passkey should sign. */
  challenge: Hex;
  /** Raw digest or merkle root before EIP-712 wrapping. */
  raw: Hex;
  /** Viem-compatible EIP-712 typed data for the challenge. Pass to signTypedData() for wallet display. */
  typedData: object;
  proofs: MerkleProofResult[] | null;
  is_merkle: boolean;
}

export interface MerkleProofResult {
  leaf: Hex;
  proof: Hex[];
  index: number;
}

export interface StatefulSignatureConfig {
  keyId: number;
  merkle?: {
    root: Hex;
    proof: Hex[];
  };
}

export interface StatelessSignatureConfig {
  pubKeyX: Hex;
  pubKeyY: Hex;
  merkle?: {
    root: Hex;
    proof: Hex[];
  };
}

export interface RecoveryDigestInput {
  account: Address;
  chainId: number;
  newKeyId: number;
  newPubKeyX: Hex;
  newPubKeyY: Hex;
  replace?: boolean;
  nonce: Hex;
  expiry: number;
  verifyingContract?: Address;
}

export interface AddCredentialInput {
  keyId: number;
  pubKeyX: Hex;
  pubKeyY: Hex;
}

export interface SetGuardianConfigInput {
  userGuardian: Address;
  externalGuardian: Address;
  threshold: number;
}

export interface NewCredential {
  keyId: number;
  pubKeyX: Hex;
  pubKeyY: Hex;
  replace: boolean;
}

export interface GuardianEntry {
  id: number;
  sig: Hex;
}

export interface AppInstallInput {
  /** The main account whose passkey credentials this app account will reuse. */
  mainAccount: Address;
  userGuardian?: Address;
  externalGuardian?: Address;
  guardianThreshold?: number;
}

export interface AppRecoveryDigestInput {
  account: Address;
  chainId: number;
  newMainAccount: Address;
  nonce: Hex;
  expiry: number;
  verifyingContract?: Address;
}
