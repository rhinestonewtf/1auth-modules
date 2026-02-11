use serde::{Deserialize, Serialize};

/// Configuration for encoding a stateful signature (stored credentials).
///
/// Stateful regular format:
///   [0]     proofLength = 0 (uint8)
///   [1:3]   keyId (uint16 big-endian)
///   [3]     requireUV (uint8)
///   [4]     usePrecompile (uint8)
///   [5:]    packed WebAuthnAuth
///
/// Stateful merkle format:
///   [0]              proofLength (uint8) > 0
///   [1:33]           merkleRoot (bytes32)
///   [33:proofEnd]    proof (bytes32[proofLength])
///   [proofEnd:+2]    keyId (uint16 big-endian)
///   [proofEnd+2]     requireUV (uint8)
///   [proofEnd+3]     usePrecompile (uint8)
///   [proofEnd+4:]    packed WebAuthnAuth
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatefulSignatureConfig {
    pub key_id: u16,
    pub require_uv: bool,
    pub use_precompile: bool,
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
///   [65]    requireUV
///   [66]    usePrecompile
///
/// Data format (merkle, proofLength>0):
///   [0]                     proofLength
///   [1:33]                  merkleRoot
///   [33:65]                 pubKeyX
///   [65:97]                 pubKeyY
///   [97]                    requireUV
///   [98]                    usePrecompile
///   [99:99+proofLen*32]     proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatelessSignatureConfig {
    pub pub_key_x: [u8; 32],
    pub pub_key_y: [u8; 32],
    pub require_uv: bool,
    pub use_precompile: bool,
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
            // Regular: proofLength=0 + keyId + requireUV + usePrecompile + auth
            result.push(0u8); // proofLength = 0
            result.extend_from_slice(&config.key_id.to_be_bytes()); // 2 bytes
            result.push(config.require_uv as u8);
            result.push(config.use_precompile as u8);
            result.extend_from_slice(webauthn_auth);
        }
        Some(merkle) => {
            // Merkle: proofLength + root + proof + keyId + requireUV + usePrecompile + auth
            let proof_len = merkle.proof.len() as u8;
            result.push(proof_len);
            result.extend_from_slice(&merkle.root);
            for p in &merkle.proof {
                result.extend_from_slice(p);
            }
            result.extend_from_slice(&config.key_id.to_be_bytes());
            result.push(config.require_uv as u8);
            result.push(config.use_precompile as u8);
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
            result.push(config.require_uv as u8);
            result.push(config.use_precompile as u8);
        }
        Some(merkle) => {
            let proof_len = merkle.proof.len() as u8;
            result.push(proof_len);
            result.extend_from_slice(&merkle.root);
            result.extend_from_slice(&config.pub_key_x);
            result.extend_from_slice(&config.pub_key_y);
            result.push(config.require_uv as u8);
            result.push(config.use_precompile as u8);
            for p in &merkle.proof {
                result.extend_from_slice(p);
            }
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
            require_uv: false,
            use_precompile: true,
            merkle: None,
        };
        let auth = vec![0xAA; 64]; // mock webauthn auth
        let sig = encode_stateful_signature(&config, &auth);

        assert_eq!(sig[0], 0); // proofLength = 0
        assert_eq!(sig[1..3], [0, 0]); // keyId = 0
        assert_eq!(sig[3], 0); // requireUV = false
        assert_eq!(sig[4], 1); // usePrecompile = true
        assert_eq!(&sig[5..], &auth[..]);
    }

    #[test]
    fn merkle_stateful_signature() {
        let root = [0xBBu8; 32];
        let proof_elem = [0xCCu8; 32];
        let config = StatefulSignatureConfig {
            key_id: 1,
            require_uv: true,
            use_precompile: false,
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
        assert_eq!(sig[67], 1); // requireUV = true
        assert_eq!(sig[68], 0); // usePrecompile = false
        assert_eq!(&sig[69..], &auth[..]);
    }

    #[test]
    fn regular_stateless_data() {
        let config = StatelessSignatureConfig {
            pub_key_x: [0x11; 32],
            pub_key_y: [0x22; 32],
            require_uv: false,
            use_precompile: true,
            merkle: None,
        };
        let data = encode_stateless_data(&config);

        assert_eq!(data[0], 0);
        assert_eq!(&data[1..33], &[0x11; 32]);
        assert_eq!(&data[33..65], &[0x22; 32]);
        assert_eq!(data[65], 0);
        assert_eq!(data[66], 1);
        assert_eq!(data.len(), 67);
    }

    #[test]
    fn merkle_stateless_data() {
        let root = [0xAA; 32];
        let proof_elem = [0xBB; 32];
        let config = StatelessSignatureConfig {
            pub_key_x: [0x11; 32],
            pub_key_y: [0x22; 32],
            require_uv: true,
            use_precompile: false,
            merkle: Some(MerkleSignatureData {
                root,
                proof: vec![proof_elem],
            }),
        };
        let data = encode_stateless_data(&config);

        assert_eq!(data[0], 1); // proofLength
        assert_eq!(&data[1..33], &root);
        assert_eq!(&data[33..65], &[0x11; 32]); // pubKeyX
        assert_eq!(&data[65..97], &[0x22; 32]); // pubKeyY
        assert_eq!(data[97], 1); // requireUV
        assert_eq!(data[98], 0); // usePrecompile
        assert_eq!(&data[99..131], &proof_elem); // proof
        assert_eq!(data.len(), 131);
    }
}
