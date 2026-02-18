pub mod digest;
pub mod encode;
pub mod merkle;
pub mod module;
pub mod signature;

use encoding_core::{IERC7579StatelessValidator, IERC7579Validator};
use module::OneAuthValidator;
use wasm_bindgen::prelude::*;

const MODULE_ADDRESS: &str = "0x6B8Fb8E8862a752913Ed5aDa5696be2C381437e5";
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
