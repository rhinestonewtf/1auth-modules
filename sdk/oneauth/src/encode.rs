use alloy_primitives::{B256, U256};
use alloy_sol_types::{sol, SolCall, SolValue};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

sol! {
    struct WebAuthnCredential {
        bytes32 pubKeyX;
        bytes32 pubKeyY;
    }

    function addCredential(uint16 keyId, bytes32 pubKeyX, bytes32 pubKeyY);
    function removeCredential(uint16 keyId);
    function setGuardianConfig(address _userGuardian, address _externalGuardian, uint8 _threshold);
}

/// Hex-encoded string aliases — we use String instead of alloy Address/U256
/// because these structs cross the WASM boundary via JSON (wasm-bindgen
/// can't serialize alloy primitives directly).
type HexAddress = String;
type HexU256 = String;

/// Input for encoding onInstall data for OneAuthValidator.
/// Matches: abi.encode(uint16[] keyIds, WebAuthnCredential[] creds, address userGuardian, address externalGuardian, uint8 guardianThreshold)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallInput {
    pub key_ids: Vec<u16>,
    pub credentials: Vec<CredentialInput>,
    pub user_guardian: Option<HexAddress>,
    pub external_guardian: Option<HexAddress>,
    /// Guardian threshold: 1 = either guardian, 2 = both required. 0 or None = default (1).
    pub guardian_threshold: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialInput {
    pub pub_key_x: HexU256,
    pub pub_key_y: HexU256,
}

pub fn encode_install(input: &InstallInput) -> Result<(String, Vec<u8>), String> {
    let n = input.key_ids.len();
    if n != input.credentials.len() {
        return Err("key_ids and credentials must have same length".to_string());
    }
    if n == 0 {
        return Err("at least one credential required".to_string());
    }

    let key_ids: Vec<U256> = input.key_ids.iter().map(|&k| U256::from(k)).collect();

    let creds: Vec<WebAuthnCredential> = input
        .credentials
        .iter()
        .map(|c| {
            let pub_key_x =
                B256::from_str(&c.pub_key_x).map_err(|e| format!("invalid pubKeyX: {e}"))?;
            let pub_key_y =
                B256::from_str(&c.pub_key_y).map_err(|e| format!("invalid pubKeyY: {e}"))?;
            Ok(WebAuthnCredential {
                pubKeyX: pub_key_x,
                pubKeyY: pub_key_y,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;

    let user_guardian = if let Some(ref addr) = input.user_guardian {
        alloy_primitives::Address::from_str(addr)
            .map_err(|e| format!("invalid user_guardian address: {e}"))?
    } else {
        alloy_primitives::Address::ZERO
    };

    let external_guardian = if let Some(ref addr) = input.external_guardian {
        alloy_primitives::Address::from_str(addr)
            .map_err(|e| format!("invalid external_guardian address: {e}"))?
    } else {
        alloy_primitives::Address::ZERO
    };

    let guardian_threshold = U256::from(input.guardian_threshold.unwrap_or(0));

    let encoded = (key_ids, creds, user_guardian, external_guardian, guardian_threshold).abi_encode_params();

    let hex_str = format!("0x{}", hex::encode(&encoded));
    Ok((hex_str, encoded))
}

pub fn encode_uninstall() -> Vec<u8> {
    // onUninstall takes empty bytes
    vec![]
}

// ── Credential management calldata ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddCredentialInput {
    pub key_id: u16,
    pub pub_key_x: HexU256,
    pub pub_key_y: HexU256,
}

pub fn encode_add_credential(input: &AddCredentialInput) -> Result<Vec<u8>, String> {
    let pub_key_x =
        B256::from_str(&input.pub_key_x).map_err(|e| format!("invalid pubKeyX: {e}"))?;
    let pub_key_y =
        B256::from_str(&input.pub_key_y).map_err(|e| format!("invalid pubKeyY: {e}"))?;

    let call = addCredentialCall {
        keyId: input.key_id,
        pubKeyX: pub_key_x,
        pubKeyY: pub_key_y,
    };
    Ok(call.abi_encode())
}

pub fn encode_remove_credential(key_id: u16) -> Vec<u8> {
    let call = removeCredentialCall { keyId: key_id };
    call.abi_encode()
}

// ── Guardian configuration calldata ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetGuardianConfigInput {
    pub user_guardian: HexAddress,
    pub external_guardian: HexAddress,
    pub threshold: u8,
}

pub fn encode_set_guardian_config(input: &SetGuardianConfigInput) -> Result<Vec<u8>, String> {
    let user_guardian = alloy_primitives::Address::from_str(&input.user_guardian)
        .map_err(|e| format!("invalid user_guardian address: {e}"))?;
    let external_guardian = alloy_primitives::Address::from_str(&input.external_guardian)
        .map_err(|e| format!("invalid external_guardian address: {e}"))?;

    let call = setGuardianConfigCall {
        _userGuardian: user_guardian,
        _externalGuardian: external_guardian,
        _threshold: input.threshold,
    };
    Ok(call.abi_encode())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_single_credential() {
        let input = InstallInput {
            key_ids: vec![0],
            credentials: vec![CredentialInput {
                pub_key_x: "0x580a9af0569ad3905b26a703201b358aa0904236642ebe79b22a19d00d373763"
                    .to_string(),
                pub_key_y: "0x7d46f725a5427ae45a9569259bf67e1e16b187d7b3ad1ed70138c4f0409677d1"
                    .to_string(),
            }],
            user_guardian: None,
            external_guardian: None,
            guardian_threshold: None,
        };
        let (hex_str, _raw) = encode_install(&input).unwrap();
        assert!(hex_str.starts_with("0x"));
        assert!(hex_str.len() > 2);
    }

    #[test]
    fn encode_two_credentials_with_guardian() {
        let input = InstallInput {
            key_ids: vec![0, 1],
            credentials: vec![
                CredentialInput {
                    pub_key_x: "0x1111111111111111111111111111111111111111111111111111111111111111"
                        .to_string(),
                    pub_key_y: "0x2222222222222222222222222222222222222222222222222222222222222222"
                        .to_string(),
                },
                CredentialInput {
                    pub_key_x: "0x3333333333333333333333333333333333333333333333333333333333333333"
                        .to_string(),
                    pub_key_y: "0x4444444444444444444444444444444444444444444444444444444444444444"
                        .to_string(),
                },
            ],
            user_guardian: Some("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045".to_string()),
            external_guardian: None,
            guardian_threshold: Some(1),
        };
        let (hex_str, _raw) = encode_install(&input).unwrap();
        assert!(hex_str.starts_with("0x"));
    }

    #[test]
    fn mismatched_lengths_fails() {
        let input = InstallInput {
            key_ids: vec![0, 1],
            credentials: vec![CredentialInput {
                pub_key_x: "0x01".to_string(),
                pub_key_y: "0x02".to_string(),
            }],
            user_guardian: None,
            external_guardian: None,
            guardian_threshold: None,
        };
        assert!(encode_install(&input).is_err());
    }

    #[test]
    fn encode_add_credential_has_correct_selector() {
        let input = AddCredentialInput {
            key_id: 42,
            pub_key_x: "0x580a9af0569ad3905b26a703201b358aa0904236642ebe79b22a19d00d373763"
                .to_string(),
            pub_key_y: "0x7d46f725a5427ae45a9569259bf67e1e16b187d7b3ad1ed70138c4f0409677d1"
                .to_string(),
        };
        let calldata = encode_add_credential(&input).unwrap();
        // selector = keccak256("addCredential(uint16,bytes32,bytes32)")[..4]
        let expected_selector = &addCredentialCall::SELECTOR;
        assert_eq!(&calldata[..4], expected_selector);
        assert_eq!(calldata.len(), 4 + 3 * 32); // selector + 3 ABI words
    }

    #[test]
    fn encode_remove_credential_has_correct_selector() {
        let calldata = encode_remove_credential(7);
        let expected_selector = &removeCredentialCall::SELECTOR;
        assert_eq!(&calldata[..4], expected_selector);
        assert_eq!(calldata.len(), 4 + 32); // selector + 1 ABI word
        // keyId=7 should be in the last byte of the first word
        assert_eq!(calldata[4 + 31], 7);
    }

    #[test]
    fn encode_set_guardian_config_has_correct_selector() {
        let input = SetGuardianConfigInput {
            user_guardian: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045".to_string(),
            external_guardian: "0x0000000000000000000000000000000000000000".to_string(),
            threshold: 1,
        };
        let calldata = encode_set_guardian_config(&input).unwrap();
        let expected_selector = &setGuardianConfigCall::SELECTOR;
        assert_eq!(&calldata[..4], expected_selector);
        assert_eq!(calldata.len(), 4 + 3 * 32); // selector + 3 ABI words
    }

    #[test]
    fn encode_set_guardian_config_invalid_address_fails() {
        let input = SetGuardianConfigInput {
            user_guardian: "not_an_address".to_string(),
            external_guardian: "0x0000000000000000000000000000000000000000".to_string(),
            threshold: 1,
        };
        assert!(encode_set_guardian_config(&input).is_err());
    }
}
