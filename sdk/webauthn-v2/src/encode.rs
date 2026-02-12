use alloy_primitives::{B256, U256};
use alloy_sol_types::{sol, SolValue};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

sol! {
    struct WebAuthnCredential {
        bytes32 pubKeyX;
        bytes32 pubKeyY;
    }
}

/// Hex-encoded string aliases — we use String instead of alloy Address/U256
/// because these structs cross the WASM boundary via JSON (wasm-bindgen
/// can't serialize alloy primitives directly).
type HexAddress = String;
type HexU256 = String;

/// Input for encoding onInstall data for WebAuthnValidatorV2.
/// Matches: abi.encode(uint16[] keyIds, WebAuthnCredential[] creds, address guardian, uint48 guardianTimelock)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallInput {
    pub key_ids: Vec<u16>,
    pub credentials: Vec<CredentialInput>,
    pub guardian: Option<HexAddress>,
    /// Guardian timelock duration in seconds. 0 or None means proposeGuardian takes effect immediately.
    pub guardian_timelock: Option<u64>,
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

    let guardian = if let Some(ref addr) = input.guardian {
        alloy_primitives::Address::from_str(addr)
            .map_err(|e| format!("invalid guardian address: {e}"))?
    } else {
        alloy_primitives::Address::ZERO
    };

    let guardian_timelock = U256::from(input.guardian_timelock.unwrap_or(0));

    let encoded = (key_ids, creds, guardian, guardian_timelock).abi_encode_params();

    let hex_str = format!("0x{}", hex::encode(&encoded));
    Ok((hex_str, encoded))
}

pub fn encode_uninstall() -> Vec<u8> {
    // onUninstall takes empty bytes
    vec![]
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
            guardian: None,
            guardian_timelock: None,
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
            guardian: Some("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045".to_string()),
            guardian_timelock: Some(86400), // 1 day
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
            guardian: None,
            guardian_timelock: None,
        };
        assert!(encode_install(&input).is_err());
    }
}
