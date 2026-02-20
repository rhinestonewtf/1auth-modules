/* @ts-self-types="./oneauth.d.ts" */

import * as wasm from "./oneauth_bg.wasm";
import { __wbg_set_wasm } from "./oneauth_bg.js";
__wbg_set_wasm(wasm);
wasm.__wbindgen_start();
export {
    buildMerkleTree, encodeAddCredential, encodeAppInstall, encodeDualGuardianSig, encodeGuardianEntries, encodeInstall, encodeRemoveCredential, encodeSetGuardianConfig, encodeSingleGuardianSig, encodeStatefulSignature, encodeStatelessData, getAppRecoveryDigest, getAppRecoveryTypehash, getDigest, getPasskeyDigestTypedData, getPasskeyMultichainTypedData, getRecoveryDigest, getRecoveryTypehash, passkeyDigest, passkeyMultichain, verifyMerkleProof
} from "./oneauth_bg.js";
