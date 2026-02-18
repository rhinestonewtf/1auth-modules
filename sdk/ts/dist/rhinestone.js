import { encodeInstall, encodeSignature, MODULE_ADDRESS } from "./oneauth.js";
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
export function getOneAuthValidator(input) {
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
export function getOneAuthValidatorSignature(config, webauthnAuth) {
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
export function getOneAuthValidatorMockSignature() {
    return MOCK_SIGNATURE;
}
// Pre-computed mock signature constant (192 bytes).
// clientDataJSON = {"type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}
const MOCK_SIGNATURE = ("0x" +
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
    "413d227d");
export { MODULE_ADDRESS as ONEAUTH_VALIDATOR_ADDRESS };
