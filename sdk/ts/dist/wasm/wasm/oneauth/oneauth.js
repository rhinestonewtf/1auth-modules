/* @ts-self-types="./oneauth.d.ts" */

import * as wasm from "./oneauth_bg.wasm";
import { __wbg_set_wasm } from "./oneauth_bg.js";
__wbg_set_wasm(wasm);
wasm.__wbindgen_start();
export {
    buildMerkleTree, encodeAddCredential, encodeDualGuardianSig, encodeGuardianEntries, encodeInstall, encodeRemoveCredential, encodeSetGuardianConfig, encodeSingleGuardianSig, encodeStatefulSignature, encodeStatelessData, getDigest, getPasskeyDigestTypedData, getPasskeyMultichainTypedData, getRecoveryDigest, getRecoveryTypehash, passkeyDigest, passkeyMultichain, verifyMerkleProof
} from "./oneauth_bg.js";
