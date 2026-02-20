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
///   [0:20]  account (address)
///   [20]    proofLength = 0
///   [21:53] pubKeyX
///   [53:85] pubKeyY
///
/// Data format (merkle, proofLength>0):
///   [0:20]                           account (address)
///   [20]                             proofLength
///   [21:53]                          merkleRoot
///   [53:53+proofLen*32]              proof[]
///   [proofEnd:proofEnd+32]           pubKeyX
///   [proofEnd+32:proofEnd+64]        pubKeyY
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatelessSignatureConfig {
    pub account: [u8; 20],
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

// ── Guardian recovery signature encoding ──

/// Encode a single-guardian recovery signature.
/// Format: [type_byte][sig]
/// type_byte: 0x00 = user guardian, 0x01 = external guardian
pub fn encode_single_guardian_sig(guardian_type: u8, sig: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(1 + sig.len());
    result.push(guardian_type);
    result.extend_from_slice(sig);
    result
}

/// Encode a dual-guardian recovery signature (threshold=2).
/// Format: [user_sig_len: uint16 big-endian][user_sig][external_sig]
pub fn encode_dual_guardian_sig(user_sig: &[u8], external_sig: &[u8]) -> Vec<u8> {
    let len = user_sig.len() as u16;
    let mut result = Vec::with_capacity(2 + user_sig.len() + external_sig.len());
    result.extend_from_slice(&len.to_be_bytes());
    result.extend_from_slice(user_sig);
    result.extend_from_slice(external_sig);
    result
}

/// Encode a single Guardian.sol multisig entry.
/// Format: [id: uint8][sigLen: uint16 big-endian][sig]
pub fn encode_guardian_entry(id: u8, sig: &[u8]) -> Vec<u8> {
    let sig_len = sig.len() as u16;
    let mut result = Vec::with_capacity(3 + sig.len());
    result.push(id);
    result.extend_from_slice(&sig_len.to_be_bytes());
    result.extend_from_slice(sig);
    result
}

/// Encode multiple Guardian.sol entries into a single signature blob.
/// Each entry: [id: uint8][sigLen: uint16][sig]
pub fn encode_guardian_entries(entries: &[(u8, Vec<u8>)]) -> Vec<u8> {
    let mut result = Vec::new();
    for (id, sig) in entries {
        result.extend_from_slice(&encode_guardian_entry(*id, sig));
    }
    result
}

/// Encode stateless data (for validateSignatureWithData).
/// Prepends 20-byte account before proofLength.
pub fn encode_stateless_data(config: &StatelessSignatureConfig) -> Vec<u8> {
    let mut result = Vec::new();

    // Account is always first (20 bytes)
    result.extend_from_slice(&config.account);

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
        let account = [0xAB; 20];
        let config = StatelessSignatureConfig {
            account,
            pub_key_x: [0x11; 32],
            pub_key_y: [0x22; 32],
            merkle: None,
        };
        let data = encode_stateless_data(&config);

        // [0:20] account, [20] proofLength=0, [21:53] pubKeyX, [53:85] pubKeyY
        assert_eq!(&data[0..20], &account);
        assert_eq!(data[20], 0);
        assert_eq!(&data[21..53], &[0x11; 32]);
        assert_eq!(&data[53..85], &[0x22; 32]);
        assert_eq!(data.len(), 85);
    }

    #[test]
    fn merkle_stateless_data() {
        let account = [0xAB; 20];
        let root = [0xAA; 32];
        let proof_elem = [0xBB; 32];
        let config = StatelessSignatureConfig {
            account,
            pub_key_x: [0x11; 32],
            pub_key_y: [0x22; 32],
            merkle: Some(MerkleSignatureData {
                root,
                proof: vec![proof_elem],
            }),
        };
        let data = encode_stateless_data(&config);

        // [0:20] account, [20] proofLength=1, [21:53] root, [53:85] proof[0], [85:117] pubKeyX, [117:149] pubKeyY
        assert_eq!(&data[0..20], &account);
        assert_eq!(data[20], 1); // proofLength
        assert_eq!(&data[21..53], &root); // merkleRoot
        assert_eq!(&data[53..85], &proof_elem); // proof[0]
        assert_eq!(&data[85..117], &[0x11; 32]); // pubKeyX
        assert_eq!(&data[117..149], &[0x22; 32]); // pubKeyY
        assert_eq!(data.len(), 149);
    }

    #[test]
    fn single_guardian_sig_user() {
        let sig = vec![0xAA; 65];
        let result = encode_single_guardian_sig(0x00, &sig);
        assert_eq!(result[0], 0x00); // user guardian type
        assert_eq!(&result[1..], &sig[..]);
        assert_eq!(result.len(), 66);
    }

    #[test]
    fn single_guardian_sig_external() {
        let sig = vec![0xBB; 65];
        let result = encode_single_guardian_sig(0x01, &sig);
        assert_eq!(result[0], 0x01); // external guardian type
        assert_eq!(&result[1..], &sig[..]);
    }

    #[test]
    fn dual_guardian_sig() {
        let user_sig = vec![0xAA; 65];
        let ext_sig = vec![0xBB; 65];
        let result = encode_dual_guardian_sig(&user_sig, &ext_sig);

        // First 2 bytes = user_sig length (65 = 0x0041)
        assert_eq!(result[0], 0x00);
        assert_eq!(result[1], 0x41);
        // user sig
        assert_eq!(&result[2..67], &user_sig[..]);
        // external sig
        assert_eq!(&result[67..], &ext_sig[..]);
        assert_eq!(result.len(), 2 + 65 + 65);
    }

    #[test]
    fn guardian_entry_format() {
        let sig = vec![0xCC; 65];
        let entry = encode_guardian_entry(1, &sig);

        assert_eq!(entry[0], 1); // id
        assert_eq!(entry[1], 0x00); // sigLen high byte
        assert_eq!(entry[2], 0x41); // sigLen low byte (65)
        assert_eq!(&entry[3..], &sig[..]);
        assert_eq!(entry.len(), 3 + 65);
    }

    #[test]
    fn guardian_entries_packs_multiple() {
        let sig0 = vec![0xAA; 65];
        let sig1 = vec![0xBB; 65];
        let entries = vec![(0u8, sig0.clone()), (1u8, sig1.clone())];
        let result = encode_guardian_entries(&entries);

        // Two entries, each 3 + 65 = 68 bytes
        assert_eq!(result.len(), 2 * 68);
        // First entry
        assert_eq!(result[0], 0); // id=0
        assert_eq!(&result[3..68], &sig0[..]);
        // Second entry
        assert_eq!(result[68], 1); // id=1
        assert_eq!(&result[71..], &sig1[..]);
    }
}
