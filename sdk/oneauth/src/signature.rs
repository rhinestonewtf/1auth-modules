use serde::{Deserialize, Serialize};

/// Configuration for encoding a stateful signature (stored credentials).
///
/// Stateful regular format:
///   [0]     proofLength = 0 (uint8)
///   [1:3]   keyId (uint16 big-endian)
///   [3:]    packed WebAuthnAuth
///
/// Stateful merkle format:
///   [0]              proofLength (uint8) > 0
///   [1:33]           merkleRoot (bytes32)
///   [33:proofEnd]    proof (bytes32[proofLength])
///   [proofEnd:+2]    keyId (uint16 big-endian)
///   [proofEnd+2:]    packed WebAuthnAuth
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatefulSignatureConfig {
    pub key_id: u16,
    /// If Some, this is a merkle flow. Contains (root, proof_for_this_leaf).
    pub merkle: Option<MerkleSignatureData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleSignatureData {
    pub root: [u8; 32],
    pub proof: Vec<[u8; 32]>,
}

/// Configuration for encoding a stateless signature (externally provided creds).
///
/// Data format (regular, proofLength=0):
///   [0]     proofLength = 0
///   [1:33]  pubKeyX
///   [33:65] pubKeyY
///
/// Data format (merkle, proofLength>0):
///   [0]                      proofLength
///   [1:33]                   merkleRoot
///   [33:33+proofLen*32]      proof[]
///   [proofEnd:proofEnd+32]   pubKeyX
///   [proofEnd+32:proofEnd+64] pubKeyY
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatelessSignatureConfig {
    pub pub_key_x: [u8; 32],
    pub pub_key_y: [u8; 32],
    pub merkle: Option<MerkleSignatureData>,
}

/// Encode a stateful signature (for validateUserOp / isValidSignatureWithSender).
pub fn encode_stateful_signature(
    config: &StatefulSignatureConfig,
    webauthn_auth: &[u8],
) -> Vec<u8> {
    let mut result = Vec::new();

    match &config.merkle {
        None => {
            // Regular: proofLength=0 + keyId + auth
            result.push(0u8); // proofLength = 0
            result.extend_from_slice(&config.key_id.to_be_bytes()); // 2 bytes
            result.extend_from_slice(webauthn_auth);
        }
        Some(merkle) => {
            // Merkle: proofLength + root + proof + keyId + auth
            let proof_len = merkle.proof.len() as u8;
            result.push(proof_len);
            result.extend_from_slice(&merkle.root);
            for p in &merkle.proof {
                result.extend_from_slice(p);
            }
            result.extend_from_slice(&config.key_id.to_be_bytes());
            result.extend_from_slice(webauthn_auth);
        }
    }

    result
}

/// Encode stateless data (for validateSignatureWithData).
pub fn encode_stateless_data(config: &StatelessSignatureConfig) -> Vec<u8> {
    let mut result = Vec::new();

    match &config.merkle {
        None => {
            result.push(0u8);
            result.extend_from_slice(&config.pub_key_x);
            result.extend_from_slice(&config.pub_key_y);
        }
        Some(merkle) => {
            let proof_len = merkle.proof.len() as u8;
            result.push(proof_len);
            result.extend_from_slice(&merkle.root);
            for p in &merkle.proof {
                result.extend_from_slice(p);
            }
            // Credential data after proof (matches stateful layout)
            result.extend_from_slice(&config.pub_key_x);
            result.extend_from_slice(&config.pub_key_y);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regular_stateful_signature() {
        let config = StatefulSignatureConfig {
            key_id: 0,
            merkle: None,
        };
        let auth = vec![0xAA; 64]; // mock webauthn auth
        let sig = encode_stateful_signature(&config, &auth);

        assert_eq!(sig[0], 0); // proofLength = 0
        assert_eq!(sig[1..3], [0, 0]); // keyId = 0
        assert_eq!(&sig[3..], &auth[..]);
    }

    #[test]
    fn merkle_stateful_signature() {
        let root = [0xBBu8; 32];
        let proof_elem = [0xCCu8; 32];
        let config = StatefulSignatureConfig {
            key_id: 1,
            merkle: Some(MerkleSignatureData {
                root,
                proof: vec![proof_elem],
            }),
        };
        let auth = vec![0xDD; 32];
        let sig = encode_stateful_signature(&config, &auth);

        assert_eq!(sig[0], 1); // proofLength = 1
        assert_eq!(&sig[1..33], &root); // merkleRoot
        assert_eq!(&sig[33..65], &proof_elem); // proof[0]
        // proofEnd = 33 + 32 = 65
        assert_eq!(sig[65..67], [0, 1]); // keyId = 1
        assert_eq!(&sig[67..], &auth[..]);
    }

    #[test]
    fn regular_stateless_data() {
        let config = StatelessSignatureConfig {
            pub_key_x: [0x11; 32],
            pub_key_y: [0x22; 32],
            merkle: None,
        };
        let data = encode_stateless_data(&config);

        assert_eq!(data[0], 0);
        assert_eq!(&data[1..33], &[0x11; 32]);
        assert_eq!(&data[33..65], &[0x22; 32]);
        assert_eq!(data.len(), 65);
    }

    #[test]
    fn merkle_stateless_data() {
        let root = [0xAA; 32];
        let proof_elem = [0xBB; 32];
        let config = StatelessSignatureConfig {
            pub_key_x: [0x11; 32],
            pub_key_y: [0x22; 32],
            merkle: Some(MerkleSignatureData {
                root,
                proof: vec![proof_elem],
            }),
        };
        let data = encode_stateless_data(&config);

        assert_eq!(data[0], 1); // proofLength
        assert_eq!(&data[1..33], &root); // merkleRoot
        assert_eq!(&data[33..65], &proof_elem); // proof[0]
        // proofEnd = 33 + 32 = 65
        assert_eq!(&data[65..97], &[0x11; 32]); // pubKeyX
        assert_eq!(&data[97..129], &[0x22; 32]); // pubKeyY
        assert_eq!(data.len(), 129);
    }
}
