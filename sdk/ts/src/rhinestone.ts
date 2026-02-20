import type { Address, Hex } from "viem";
import { encodeInstall, encodeAppInstall, encodeSignature, MODULE_ADDRESS, APP_MODULE_ADDRESS } from "./oneauth.js";
import type { InstallInput, AppInstallInput, StatefulSignatureConfig } from "./types.js";

/**
 * Rhinestone module-sdk compatible Module type.
 * Matches the Module interface from @rhinestone/module-sdk for use with
 * permissionless.js installModule() and similar tooling.
 */
export interface Module {
  address: Address;
  module: Address;
  initData: Hex;
  deInitData: Hex;
  additionalContext: Hex;
  type: "validator";
  hook?: Address;
}

/**
 * Create a Rhinestone-compatible Module object for OneAuthValidator.
 *
 * Usage with permissionless.js:
 * ```ts
 * const module = getOneAuthValidator({
 *   credentials: [{ keyId: 0, pubKeyX: "0x...", pubKeyY: "0x..." }],
 * });
 * const hash = await smartAccountClient.installModule(module);
 * ```
 */
export function getOneAuthValidator(
  input: InstallInput & { hook?: Address }
): Module {
  const { address, initData } = encodeInstall(input);
  return {
    address,
    module: address,
    initData,
    deInitData: "0x",
    additionalContext: "0x",
    type: "validator",
    ...(input.hook ? { hook: input.hook } : {}),
  };
}

/**
 * Encode a WebAuthn signature in the format expected by OneAuthValidator.
 * Rhinestone naming convention wrapper around encodeSignature.
 */
export function getOneAuthValidatorSignature(
  config: StatefulSignatureConfig,
  webauthnAuth: Hex
): Hex {
  return encodeSignature(config, webauthnAuth);
}

/**
 * Mock signature for ERC-4337 gas estimation (estimateUserOperationGas).
 *
 * Structurally valid per P256Lib.parseWebAuthnAuth but with dummy r/s values
 * that will fail P-256 verification. The validator returns VALIDATION_FAILED
 * (does not revert), allowing the bundler to estimate gas correctly.
 *
 * Format:
 *   [0]      proofLength = 0
 *   [1:3]    keyId = 0
 *   [3:35]   r = 1
 *   [35:67]  s = 1
 *   [67:69]  challengeIndex = 36
 *   [69:71]  typeIndex = 9
 *   [71:73]  authenticatorDataLen = 37
 *   [73:110] authenticatorData (37 bytes, zeros)
 *   [110:]   clientDataJSON (minimal valid JSON)
 */
export function getOneAuthValidatorMockSignature(): Hex {
  return MOCK_SIGNATURE;
}

// Pre-computed mock signature constant (192 bytes).
// clientDataJSON = {"type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}
const MOCK_SIGNATURE: Hex =
  ("0x" +
  // proofLength (1 byte) + keyId (2 bytes)
  "00" + "0000" +
  // r (32 bytes)
  "0000000000000000000000000000000000000000000000000000000000000001" +
  // s (32 bytes)
  "0000000000000000000000000000000000000000000000000000000000000001" +
  // challengeIndex = 36 (uint16)
  "0024" +
  // typeIndex = 9 (uint16)
  "0009" +
  // authenticatorDataLen = 37 (uint16)
  "0025" +
  // authenticatorData: rpIdHash(32) + flags(1) + signCount(4)
  "0000000000000000000000000000000000000000000000000000000000000000" + "00" + "00000000" +
  // clientDataJSON (82 bytes)
  // {"type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}
  "7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a22" +
  "414141414141414141414141414141414141414141414141414141414141414141414141414141414141" +
  "413d227d") as Hex;

/**
 * Create a Rhinestone-compatible Module object for OneAuthAppValidator.
 *
 * NOTE: When computing digests for signing, use the **main validator's address**
 * (not the app validator's), since the EIP-712 domain uses verifyingContract = mainValidator.
 *
 * Usage with permissionless.js:
 * ```ts
 * const module = getOneAuthAppValidator({
 *   mainAccount: "0xMainAccountAddress",
 * });
 * const hash = await smartAccountClient.installModule(module);
 * ```
 */
export function getOneAuthAppValidator(
  input: AppInstallInput & { hook?: Address }
): Module {
  const { address, initData } = encodeAppInstall(input);
  return {
    address,
    module: address,
    initData,
    deInitData: "0x",
    additionalContext: "0x",
    type: "validator",
    ...(input.hook ? { hook: input.hook } : {}),
  };
}

/**
 * Mock signature for gas estimation with OneAuthAppValidator.
 * Same format as the main validator since it uses the same signature format.
 */
export function getOneAuthAppValidatorMockSignature(): Hex {
  return MOCK_SIGNATURE;
}

export { MODULE_ADDRESS as ONEAUTH_VALIDATOR_ADDRESS };
export { APP_MODULE_ADDRESS as ONEAUTH_APP_VALIDATOR_ADDRESS };
