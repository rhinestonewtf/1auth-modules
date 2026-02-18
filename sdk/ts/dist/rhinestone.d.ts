import type { Address, Hex } from "viem";
import { MODULE_ADDRESS } from "./oneauth.js";
import type { InstallInput, StatefulSignatureConfig } from "./types.js";
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
export declare function getOneAuthValidator(input: InstallInput & {
    hook?: Address;
}): Module;
/**
 * Encode a WebAuthn signature in the format expected by OneAuthValidator.
 * Rhinestone naming convention wrapper around encodeSignature.
 */
export declare function getOneAuthValidatorSignature(config: StatefulSignatureConfig, webauthnAuth: Hex): Hex;
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
export declare function getOneAuthValidatorMockSignature(): Hex;
export { MODULE_ADDRESS as ONEAUTH_VALIDATOR_ADDRESS };
