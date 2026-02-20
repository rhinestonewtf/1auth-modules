/* tslint:disable */
/* eslint-disable */
export const memory: WebAssembly.Memory;
export const encodeInstall: (a: number, b: number) => [number, number, number, number];
export const encodeAddCredential: (a: number, b: number) => [number, number, number, number];
export const encodeRemoveCredential: (a: number) => [number, number];
export const encodeSetGuardianConfig: (a: number, b: number) => [number, number, number, number];
export const encodeSingleGuardianSig: (a: number, b: number, c: number) => [number, number, number, number];
export const encodeDualGuardianSig: (a: number, b: number, c: number, d: number) => [number, number, number, number];
export const encodeGuardianEntries: (a: number, b: number) => [number, number, number, number];
export const getDigest: (a: number, b: number, c: bigint, d: number, e: number) => [number, number, number, number];
export const passkeyDigest: (a: number, b: number, c: bigint, d: number, e: number) => [number, number, number, number];
export const passkeyMultichain: (a: number, b: number, c: number, d: number) => [number, number, number, number];
export const getPasskeyDigestTypedData: (a: number, b: number, c: bigint, d: number, e: number) => [number, number];
export const getPasskeyMultichainTypedData: (a: number, b: number, c: number, d: number) => [number, number];
export const encodeStatefulSignature: (a: number, b: number, c: number, d: number) => [number, number, number, number];
export const encodeStatelessData: (a: number, b: number) => [number, number, number, number];
export const getRecoveryDigest: (a: number, b: number) => [number, number, number, number];
export const getRecoveryTypehash: () => [number, number];
export const buildMerkleTree: (a: number, b: number) => [number, number, number, number];
export const verifyMerkleProof: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number];
export const __wbindgen_externrefs: WebAssembly.Table;
export const __wbindgen_malloc: (a: number, b: number) => number;
export const __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
export const __externref_table_dealloc: (a: number) => void;
export const __wbindgen_free: (a: number, b: number, c: number) => void;
export const __wbindgen_start: () => void;
