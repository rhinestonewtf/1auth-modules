pub mod digest;
pub mod encode;
pub mod merkle;
pub mod module;
pub mod signature;

use encoding_core::{IERC7579StatelessValidator, IERC7579Validator};
use module::OneAuthValidator;
use wasm_bindgen::prelude::*;

const MODULE_ADDRESS: &str = "0x6B8Fb8E8862a752913Ed5aDa5696be2C381437e5";
const APP_MODULE_ADDRESS: &str = "0x0000000000000000000000000000000000000000"; // placeholder until deployed
const VALIDATOR: OneAuthValidator = OneAuthValidator;

// ── onInstall / onUninstall ──

#[wasm_bindgen(js_name = encodeInstall)]
pub fn wasm_encode_install(input_json: &str) -> Result<String, JsError> {
    let input: encode::InstallInput =
        serde_json::from_str(input_json).map_err(|e| JsError::new(&e.to_string()))?;
    let bytes = VALIDATOR
        .encode_install(&input)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let hex_str = format!("0x{}", hex::encode(&bytes));

    let result = serde_json::json!({
        "address": MODULE_ADDRESS,
        "initData": hex_str,
    });
    Ok(result.to_string())
}

// ── App validator onInstall ──

#[wasm_bindgen(js_name = encodeAppInstall)]
pub fn wasm_encode_app_install(input_json: &str) -> Result<String, JsError> {
    let input: encode::AppInstallInput =
        serde_json::from_str(input_json).map_err(|e| JsError::new(&e.to_string()))?;
    let (hex_str, _) = encode::encode_app_install(&input).map_err(|e| JsError::new(&e))?;

    let result = serde_json::json!({
        "address": APP_MODULE_ADDRESS,
        "initData": hex_str,
    });
    Ok(result.to_string())
}

// ── Credential management calldata ──

#[wasm_bindgen(js_name = encodeAddCredential)]
pub fn wasm_encode_add_credential(input_json: &str) -> Result<String, JsError> {
    let input: encode::AddCredentialInput =
        serde_json::from_str(input_json).map_err(|e| JsError::new(&e.to_string()))?;
    let bytes = encode::encode_add_credential(&input).map_err(|e| JsError::new(&e))?;
    Ok(format!("0x{}", hex::encode(&bytes)))
}

#[wasm_bindgen(js_name = encodeRemoveCredential)]
pub fn wasm_encode_remove_credential(key_id: u16) -> String {
    let bytes = encode::encode_remove_credential(key_id);
    format!("0x{}", hex::encode(&bytes))
}

// ── Guardian configuration calldata ──

#[wasm_bindgen(js_name = encodeSetGuardianConfig)]
pub fn wasm_encode_set_guardian_config(input_json: &str) -> Result<String, JsError> {
    let input: encode::SetGuardianConfigInput =
        serde_json::from_str(input_json).map_err(|e| JsError::new(&e.to_string()))?;
    let bytes = encode::encode_set_guardian_config(&input).map_err(|e| JsError::new(&e))?;
    Ok(format!("0x{}", hex::encode(&bytes)))
}

// ── Guardian recovery signature encoding ──

#[wasm_bindgen(js_name = encodeSingleGuardianSig)]
pub fn wasm_encode_single_guardian_sig(
    guardian_type: u8,
    sig_hex: &str,
) -> Result<String, JsError> {
    let sig_hex = sig_hex.strip_prefix("0x").unwrap_or(sig_hex);
    let sig = hex::decode(sig_hex).map_err(|e| JsError::new(&format!("invalid sig hex: {e}")))?;
    let result = signature::encode_single_guardian_sig(guardian_type, &sig);
    Ok(format!("0x{}", hex::encode(&result)))
}

#[wasm_bindgen(js_name = encodeDualGuardianSig)]
pub fn wasm_encode_dual_guardian_sig(
    user_sig_hex: &str,
    external_sig_hex: &str,
) -> Result<String, JsError> {
    let user_hex = user_sig_hex.strip_prefix("0x").unwrap_or(user_sig_hex);
    let user_sig =
        hex::decode(user_hex).map_err(|e| JsError::new(&format!("invalid user sig hex: {e}")))?;
    let ext_hex = external_sig_hex
        .strip_prefix("0x")
        .unwrap_or(external_sig_hex);
    let ext_sig = hex::decode(ext_hex)
        .map_err(|e| JsError::new(&format!("invalid external sig hex: {e}")))?;
    let result = signature::encode_dual_guardian_sig(&user_sig, &ext_sig);
    Ok(format!("0x{}", hex::encode(&result)))
}

#[wasm_bindgen(js_name = encodeGuardianEntries)]
pub fn wasm_encode_guardian_entries(entries_json: &str) -> Result<String, JsError> {
    let raw_entries: Vec<GuardianEntryInput> =
        serde_json::from_str(entries_json).map_err(|e| JsError::new(&e.to_string()))?;

    let entries: Vec<(u8, Vec<u8>)> = raw_entries
        .into_iter()
        .map(|e| {
            let sig_hex = e.sig.strip_prefix("0x").unwrap_or(&e.sig);
            let sig =
                hex::decode(sig_hex).map_err(|err| format!("invalid sig hex for id {}: {err}", e.id))?;
            Ok((e.id, sig))
        })
        .collect::<Result<Vec<_>, String>>()
        .map_err(|e| JsError::new(&e))?;

    let result = signature::encode_guardian_entries(&entries);
    Ok(format!("0x{}", hex::encode(&result)))
}

#[derive(serde::Deserialize)]
struct GuardianEntryInput {
    id: u8,
    sig: String,
}

// ── Digest preparation ──

/// Prepare digest(s) with EIP-712 challenge wrapping.
/// digests_json: JSON array of hex bytes32 strings
/// chain_id: chain ID for single-digest (PasskeyDigest) path
/// verifying_contract_hex: deployed OneAuthValidator address
#[wasm_bindgen(js_name = getDigest)]
pub fn wasm_get_digest(
    digests_json: &str,
    chain_id: u64,
    verifying_contract_hex: &str,
) -> Result<String, JsError> {
    let hex_strs: Vec<String> =
        serde_json::from_str(digests_json).map_err(|e| JsError::new(&e.to_string()))?;

    let parsed: Vec<[u8; 32]> = hex_strs
        .iter()
        .map(|s| {
            let s = s.strip_prefix("0x").unwrap_or(s);
            let bytes = hex::decode(s).map_err(|e| format!("invalid hex: {e}"))?;
            if bytes.len() != 32 {
                return Err(format!("digest must be 32 bytes, got {}", bytes.len()));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Ok(arr)
        })
        .collect::<Result<Vec<_>, String>>()
        .map_err(|e| JsError::new(&e))?;

    let contract = parse_address20(verifying_contract_hex)?;
    let result =
        digest::get_digest(&parsed, chain_id, &contract).map_err(|e| JsError::new(&e))?;
    serde_json::to_string(&result).map_err(|e| JsError::new(&e.to_string()))
}

/// Compute PasskeyDigest challenge (single op, chain-specific).
#[wasm_bindgen(js_name = passkeyDigest)]
pub fn wasm_passkey_digest(
    digest_hex: &str,
    chain_id: u64,
    verifying_contract_hex: &str,
) -> Result<String, JsError> {
    let digest = parse_bytes32(digest_hex)?;
    let contract = parse_address20(verifying_contract_hex)?;
    let challenge = digest::passkey_digest(&digest, chain_id, &contract);
    Ok(format!("0x{}", hex::encode(challenge)))
}

/// Compute PasskeyMultichain challenge (merkle batch, chain-agnostic).
#[wasm_bindgen(js_name = passkeyMultichain)]
pub fn wasm_passkey_multichain(
    root_hex: &str,
    verifying_contract_hex: &str,
) -> Result<String, JsError> {
    let root = parse_bytes32(root_hex)?;
    let contract = parse_address20(verifying_contract_hex)?;
    let challenge = digest::passkey_multichain(&root, &contract);
    Ok(format!("0x{}", hex::encode(challenge)))
}

// ── EIP-712 typed data (viem-compatible JSON) ──

/// Returns a viem-compatible EIP-712 typed data object for PasskeyDigest.
/// Pass the result to viem's hashTypedData() or signTypedData().
#[wasm_bindgen(js_name = getPasskeyDigestTypedData)]
pub fn wasm_passkey_digest_typed_data(
    digest_hex: &str,
    chain_id: u64,
    verifying_contract_hex: &str,
) -> String {
    digest::passkey_digest_typed_data(digest_hex, chain_id, verifying_contract_hex).to_string()
}

/// Returns a viem-compatible EIP-712 typed data object for PasskeyMultichain.
/// Pass the result to viem's hashTypedData() or signTypedData().
#[wasm_bindgen(js_name = getPasskeyMultichainTypedData)]
pub fn wasm_passkey_multichain_typed_data(
    root_hex: &str,
    verifying_contract_hex: &str,
) -> String {
    digest::passkey_multichain_typed_data(root_hex, verifying_contract_hex).to_string()
}

// ── Signature encoding ──

#[wasm_bindgen(js_name = encodeStatefulSignature)]
pub fn wasm_encode_stateful_signature(
    config_json: &str,
    webauthn_auth_hex: &str,
) -> Result<String, JsError> {
    let config: signature::StatefulSignatureConfig =
        serde_json::from_str(config_json).map_err(|e| JsError::new(&e.to_string()))?;

    let auth_hex = webauthn_auth_hex
        .strip_prefix("0x")
        .unwrap_or(webauthn_auth_hex);
    let auth_bytes =
        hex::decode(auth_hex).map_err(|e| JsError::new(&format!("invalid auth hex: {e}")))?;

    let sig = VALIDATOR.encode_signature(&config, &auth_bytes);
    Ok(format!("0x{}", hex::encode(&sig)))
}

#[wasm_bindgen(js_name = encodeStatelessData)]
pub fn wasm_encode_stateless_data(config_json: &str) -> Result<String, JsError> {
    let config: signature::StatelessSignatureConfig =
        serde_json::from_str(config_json).map_err(|e| JsError::new(&e.to_string()))?;

    let data = VALIDATOR.encode_stateless_data(&config);
    Ok(format!("0x{}", hex::encode(&data)))
}

// ── Recovery EIP-712 ──

#[wasm_bindgen(js_name = getRecoveryDigest)]
pub fn wasm_get_recovery_digest(input_json: &str) -> Result<String, JsError> {
    let input: digest::RecoveryDigestInput =
        serde_json::from_str(input_json).map_err(|e| JsError::new(&e.to_string()))?;
    let d = digest::recovery_digest(&input).map_err(|e| JsError::new(&e))?;
    Ok(format!("0x{}", hex::encode(d)))
}

#[wasm_bindgen(js_name = getRecoveryTypehash)]
pub fn wasm_get_recovery_typehash() -> String {
    format!("0x{}", hex::encode(digest::recover_passkey_typehash()))
}

// ── App Recovery EIP-712 ──

#[wasm_bindgen(js_name = getAppRecoveryDigest)]
pub fn wasm_get_app_recovery_digest(input_json: &str) -> Result<String, JsError> {
    let input: digest::AppRecoveryDigestInput =
        serde_json::from_str(input_json).map_err(|e| JsError::new(&e.to_string()))?;
    let d = digest::app_recovery_digest(&input).map_err(|e| JsError::new(&e))?;
    Ok(format!("0x{}", hex::encode(d)))
}

#[wasm_bindgen(js_name = getAppRecoveryTypehash)]
pub fn wasm_get_app_recovery_typehash() -> String {
    format!("0x{}", hex::encode(digest::recover_app_validator_typehash()))
}

// ── Merkle helpers ──

#[wasm_bindgen(js_name = buildMerkleTree)]
pub fn wasm_build_merkle_tree(leaves_json: &str) -> Result<String, JsError> {
    let hex_strs: Vec<String> =
        serde_json::from_str(leaves_json).map_err(|e| JsError::new(&e.to_string()))?;

    let leaves: Vec<[u8; 32]> = hex_strs
        .iter()
        .map(|s| {
            let s = s.strip_prefix("0x").unwrap_or(s);
            let bytes = hex::decode(s).map_err(|e| format!("invalid hex: {e}"))?;
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Ok(arr)
        })
        .collect::<Result<Vec<_>, String>>()
        .map_err(|e| JsError::new(&e))?;

    let tree = merkle::MerkleTree::new(leaves);
    let (root, proofs) = tree.build().map_err(|e| JsError::new(&e))?;

    let result = serde_json::json!({
        "root": format!("0x{}", hex::encode(root)),
        "proofs": proofs.iter().map(|p|
            p.iter().map(|b| format!("0x{}", hex::encode(b))).collect::<Vec<_>>()
        ).collect::<Vec<_>>(),
    });
    Ok(result.to_string())
}

#[wasm_bindgen(js_name = verifyMerkleProof)]
pub fn wasm_verify_merkle_proof(
    proof_json: &str,
    root_hex: &str,
    leaf_hex: &str,
) -> Result<bool, JsError> {
    let proof_strs: Vec<String> =
        serde_json::from_str(proof_json).map_err(|e| JsError::new(&e.to_string()))?;

    let proof: Vec<[u8; 32]> = proof_strs
        .iter()
        .map(|s| {
            let s = s.strip_prefix("0x").unwrap_or(s);
            let bytes = hex::decode(s).map_err(|e| format!("invalid hex: {e}"))?;
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Ok(arr)
        })
        .collect::<Result<Vec<_>, String>>()
        .map_err(|e| JsError::new(&e))?;

    let root = parse_bytes32(root_hex)?;
    let leaf = parse_bytes32(leaf_hex)?;

    Ok(merkle::MerkleTree::verify(&proof, &root, &leaf))
}

fn parse_address20(hex_str: &str) -> Result<[u8; 20], JsError> {
    let s = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(s).map_err(|e| JsError::new(&format!("invalid hex: {e}")))?;
    if bytes.len() != 20 {
        return Err(JsError::new(&format!(
            "expected 20 bytes address, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 20];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn parse_bytes32(hex_str: &str) -> Result<[u8; 32], JsError> {
    let s = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(s).map_err(|e| JsError::new(&format!("invalid hex: {e}")))?;
    if bytes.len() != 32 {
        return Err(JsError::new(&format!(
            "expected 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}
