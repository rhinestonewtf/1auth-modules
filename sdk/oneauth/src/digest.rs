use crate::merkle::{keccak256, MerkleTree};
use serde::{Deserialize, Serialize};

/// Hex-encoded bytes32 — String because of WASM/JSON boundary.
type HexBytes32 = String;
type HexAddress = String;
type HexU256 = String;

// ── EIP-712 typehashes (matching OneAuthValidator.sol) ──

/// keccak256("PasskeyDigest(bytes32 digest)")
/// Used for chain-specific single operation signing.
pub fn passkey_digest_typehash() -> [u8; 32] {
    keccak256(b"PasskeyDigest(bytes32 digest)")
}

/// keccak256("PasskeyMultichain(bytes32 root)")
/// Used for chain-agnostic merkle batch signing.
pub fn passkey_multichain_typehash() -> [u8; 32] {
    keccak256(b"PasskeyMultichain(bytes32 root)")
}

// ── EIP-712 domain (matching Solady EIP712 + OneAuthRecoveryBase) ──

const DOMAIN_NAME: &[u8] = b"OneAuthValidator";
const DOMAIN_VERSION: &[u8] = b"1.0.0";

/// Full EIP-712 domain separator (with chainId + verifyingContract).
/// Matches Solady's _hashTypedData path.
/// domainSep = keccak256(typeHash ++ nameHash ++ versionHash ++ chainId ++ verifyingContract)
pub fn domain_separator(chain_id: u64, verifying_contract: &[u8; 20]) -> [u8; 32] {
    let type_hash = keccak256(
        b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
    );
    let name_hash = keccak256(DOMAIN_NAME);
    let version_hash = keccak256(DOMAIN_VERSION);

    let mut buf = Vec::with_capacity(5 * 32);
    buf.extend_from_slice(&type_hash);
    buf.extend_from_slice(&name_hash);
    buf.extend_from_slice(&version_hash);
    buf.extend_from_slice(&u256_from_u64(chain_id));
    // address is left-padded to 32 bytes
    let mut addr_word = [0u8; 32];
    addr_word[12..].copy_from_slice(verifying_contract);
    buf.extend_from_slice(&addr_word);

    keccak256(&buf)
}

/// EIP-712 domain separator sans chainId (name + version + verifyingContract).
/// Matches Solady's _hashTypedDataSansChainId path.
/// Note: Solady uses `EIP712Domain(string name,string version,address verifyingContract)` —
/// the domain includes the contract address but omits chainId.
pub fn domain_separator_sans_chain_id(verifying_contract: &[u8; 20]) -> [u8; 32] {
    let type_hash =
        keccak256(b"EIP712Domain(string name,string version,address verifyingContract)");
    let name_hash = keccak256(DOMAIN_NAME);
    let version_hash = keccak256(DOMAIN_VERSION);

    let mut addr_word = [0u8; 32];
    addr_word[12..].copy_from_slice(verifying_contract);

    let mut buf = Vec::with_capacity(4 * 32);
    buf.extend_from_slice(&type_hash);
    buf.extend_from_slice(&name_hash);
    buf.extend_from_slice(&version_hash);
    buf.extend_from_slice(&addr_word);

    keccak256(&buf)
}

// ── Challenge wrapping (matching _passkeyDigest / _passkeyMultichain) ──

/// Compute the EIP-712 wrapped challenge for single operation signing.
/// Matches `_passkeyDigest(digest)` in the contract.
/// Returns: keccak256("\x19\x01" ++ domainSep(chainId, contract) ++ keccak256(abi.encode(PASSKEY_DIGEST_TYPEHASH, digest)))
pub fn passkey_digest(
    digest: &[u8; 32],
    chain_id: u64,
    verifying_contract: &[u8; 20],
) -> [u8; 32] {
    let domain_sep = domain_separator(chain_id, verifying_contract);

    // structHash = keccak256(abi.encode(typehash, digest))
    let mut struct_buf = [0u8; 64];
    struct_buf[..32].copy_from_slice(&passkey_digest_typehash());
    struct_buf[32..].copy_from_slice(digest);
    let struct_hash = keccak256(&struct_buf);

    // EIP-712 encode
    let mut buf = Vec::with_capacity(66);
    buf.extend_from_slice(&[0x19, 0x01]);
    buf.extend_from_slice(&domain_sep);
    buf.extend_from_slice(&struct_hash);

    keccak256(&buf)
}

/// Compute the EIP-712 wrapped challenge for merkle batch signing.
/// Matches `_passkeyMultichain(root)` in the contract.
/// Returns: keccak256("\x19\x01" ++ domainSepSansChainId ++ keccak256(abi.encode(PASSKEY_MULTICHAIN_TYPEHASH, root)))
pub fn passkey_multichain(root: &[u8; 32], verifying_contract: &[u8; 20]) -> [u8; 32] {
    let domain_sep = domain_separator_sans_chain_id(verifying_contract);

    // structHash = keccak256(abi.encode(typehash, root))
    let mut struct_buf = [0u8; 64];
    struct_buf[..32].copy_from_slice(&passkey_multichain_typehash());
    struct_buf[32..].copy_from_slice(root);
    let struct_hash = keccak256(&struct_buf);

    // EIP-712 encode
    let mut buf = Vec::with_capacity(66);
    buf.extend_from_slice(&[0x19, 0x01]);
    buf.extend_from_slice(&domain_sep);
    buf.extend_from_slice(&struct_hash);

    keccak256(&buf)
}

// ── EIP-712 typed data builders (viem-compatible JSON) ──

const DOMAIN_NAME_STR: &str = "OneAuthValidator";
const DOMAIN_VERSION_STR: &str = "1.0.0";

/// Build a viem-compatible EIP-712 typed data object for PasskeyDigest.
/// Chain-specific: domain includes chainId + verifyingContract.
pub fn passkey_digest_typed_data(
    digest_hex: &str,
    chain_id: u64,
    verifying_contract_hex: &str,
) -> serde_json::Value {
    serde_json::json!({
        "domain": {
            "name": DOMAIN_NAME_STR,
            "version": DOMAIN_VERSION_STR,
            "chainId": chain_id,
            "verifyingContract": verifying_contract_hex
        },
        "types": {
            "PasskeyDigest": [
                { "name": "digest", "type": "bytes32" }
            ]
        },
        "primaryType": "PasskeyDigest",
        "message": {
            "digest": digest_hex
        }
    })
}

/// Build a viem-compatible EIP-712 typed data object for PasskeyMultichain.
/// Chain-agnostic: domain has name + version + verifyingContract (no chainId).
pub fn passkey_multichain_typed_data(
    root_hex: &str,
    verifying_contract_hex: &str,
) -> serde_json::Value {
    serde_json::json!({
        "domain": {
            "name": DOMAIN_NAME_STR,
            "version": DOMAIN_VERSION_STR,
            "verifyingContract": verifying_contract_hex
        },
        "types": {
            "PasskeyMultichain": [
                { "name": "root", "type": "bytes32" }
            ]
        },
        "primaryType": "PasskeyMultichain",
        "message": {
            "root": root_hex
        }
    })
}

// ── Digest preparation ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DigestResult {
    /// The digest to sign (EIP-712 wrapped).
    pub challenge: HexBytes32,
    /// Raw digest or merkle root before EIP-712 wrapping.
    pub raw: HexBytes32,
    pub proofs: Option<Vec<MerkleProofEntry>>,
    pub is_merkle: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProofEntry {
    pub leaf: HexBytes32,
    pub proof: Vec<HexBytes32>,
    pub index: usize,
}

/// Prepare digest(s) for signing with EIP-712 challenge wrapping.
///
/// - Single digest → wraps with PasskeyDigest EIP-712 (chain-specific).
/// - Multiple digests → builds merkle tree, wraps root with PasskeyMultichain (chain-agnostic).
///
/// Returns the challenge the user's passkey should actually sign.
pub fn get_digest(
    digests: &[[u8; 32]],
    chain_id: u64,
    verifying_contract: &[u8; 20],
) -> Result<DigestResult, String> {
    if digests.is_empty() {
        return Err("at least one digest required".to_string());
    }

    if digests.len() == 1 {
        let challenge = passkey_digest(&digests[0], chain_id, verifying_contract);
        return Ok(DigestResult {
            challenge: format!("0x{}", hex::encode(challenge)),
            raw: format!("0x{}", hex::encode(digests[0])),
            proofs: None,
            is_merkle: false,
        });
    }

    // Merkle path
    let tree = MerkleTree::new(digests.to_vec());
    let (root, proofs) = tree.build()?;
    let challenge = passkey_multichain(&root, verifying_contract);

    let merkle_proofs: Vec<MerkleProofEntry> = digests
        .iter()
        .enumerate()
        .map(|(i, leaf)| MerkleProofEntry {
            leaf: format!("0x{}", hex::encode(leaf)),
            proof: proofs[i]
                .iter()
                .map(|p| format!("0x{}", hex::encode(p)))
                .collect(),
            index: i,
        })
        .collect();

    Ok(DigestResult {
        challenge: format!("0x{}", hex::encode(challenge)),
        raw: format!("0x{}", hex::encode(root)),
        proofs: Some(merkle_proofs),
        is_merkle: true,
    })
}

// ── Recovery EIP-712 ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryDigestInput {
    pub account: HexAddress,
    pub chain_id: u64,
    pub new_key_id: u16,
    pub new_pub_key_x: HexU256,
    pub new_pub_key_y: HexU256,
    /// When true, overwrites the existing credential at new_key_id in-place (rotation).
    /// When false, adds a new credential at new_key_id (additive).
    #[serde(default)]
    pub replace: bool,
    pub nonce: HexU256,
    pub expiry: u64,
    pub verifying_contract: HexAddress,
}

/// keccak256("RecoverPasskey(address account,uint256 chainId,uint16 newKeyId,...)")
pub fn recover_passkey_typehash() -> [u8; 32] {
    keccak256(
        b"RecoverPasskey(address account,uint256 chainId,uint16 newKeyId,bytes32 newPubKeyX,bytes32 newPubKeyY,bool replace,uint256 nonce,uint48 expiry)",
    )
}

/// structHash = keccak256(abi.encode(typehash, account, chainId, ...))
pub fn recovery_struct_hash(input: &RecoveryDigestInput) -> Result<[u8; 32], String> {
    let typehash = recover_passkey_typehash();
    let account = parse_address(&input.account)?;
    let chain_id = u256_from_u64(input.chain_id);
    let key_id = u256_from_u64(input.new_key_id as u64);
    let pub_key_x = parse_u256(&input.new_pub_key_x)?;
    let pub_key_y = parse_u256(&input.new_pub_key_y)?;
    let replace_val = u256_from_u64(if input.replace { 1 } else { 0 });
    let nonce = parse_u256(&input.nonce)?;
    let expiry = u256_from_u64(input.expiry);

    let mut buf = Vec::with_capacity(9 * 32);
    buf.extend_from_slice(&typehash);
    buf.extend_from_slice(&account);
    buf.extend_from_slice(&chain_id);
    buf.extend_from_slice(&key_id);
    buf.extend_from_slice(&pub_key_x);
    buf.extend_from_slice(&pub_key_y);
    buf.extend_from_slice(&replace_val);
    buf.extend_from_slice(&nonce);
    buf.extend_from_slice(&expiry);

    Ok(keccak256(&buf))
}

/// Full recovery EIP-712 digest (uses domain sans chainId).
pub fn recovery_digest(input: &RecoveryDigestInput) -> Result<[u8; 32], String> {
    let contract = parse_address_raw(&input.verifying_contract)?;
    let domain_sep = domain_separator_sans_chain_id(&contract);
    let struct_hash = recovery_struct_hash(input)?;

    let mut buf = Vec::with_capacity(66);
    buf.extend_from_slice(&[0x19, 0x01]);
    buf.extend_from_slice(&domain_sep);
    buf.extend_from_slice(&struct_hash);

    Ok(keccak256(&buf))
}

// ── Helpers ──

fn parse_address(addr: &str) -> Result<[u8; 32], String> {
    let s = addr.strip_prefix("0x").unwrap_or(addr);
    let bytes = hex::decode(s).map_err(|e| format!("invalid address hex: {e}"))?;
    if bytes.len() != 20 {
        return Err(format!("address must be 20 bytes, got {}", bytes.len()));
    }
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(&bytes);
    Ok(word)
}

fn parse_address_raw(addr: &str) -> Result<[u8; 20], String> {
    let s = addr.strip_prefix("0x").unwrap_or(addr);
    let bytes = hex::decode(s).map_err(|e| format!("invalid address hex: {e}"))?;
    if bytes.len() != 20 {
        return Err(format!("address must be 20 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_u256(val: &str) -> Result<[u8; 32], String> {
    let s = val.strip_prefix("0x").unwrap_or(val);
    let bytes = hex::decode(s).map_err(|e| format!("invalid hex: {e}"))?;
    if bytes.len() > 32 {
        return Err(format!("value too large: {} bytes", bytes.len()));
    }
    let mut word = [0u8; 32];
    word[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(word)
}

fn u256_from_u64(val: u64) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[24..].copy_from_slice(&val.to_be_bytes());
    word
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_bytes32(val: &str) -> Result<[u8; 32], String> {
        let s = val.strip_prefix("0x").unwrap_or(val);
        let bytes = hex::decode(s).map_err(|e| format!("invalid hex: {e}"))?;
        if bytes.len() != 32 {
            return Err(format!("expected 32 bytes, got {}", bytes.len()));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(out)
    }

    const TEST_CONTRACT: [u8; 20] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x57, 0x8c, 0x4c, 0xb0, 0xe4, 0x72, 0xa5, 0x46, 0x2d,
        0xa4, 0x3c, 0x49, 0x5c, 0x3f, 0x33,
    ];

    #[test]
    fn passkey_digest_typehash_matches() {
        let h = passkey_digest_typehash();
        assert_ne!(h, [0u8; 32]);
        // Verify determinism
        assert_eq!(h, passkey_digest_typehash());
    }

    #[test]
    fn passkey_multichain_typehash_matches() {
        let h = passkey_multichain_typehash();
        assert_ne!(h, [0u8; 32]);
        // Different from digest typehash
        assert_ne!(h, passkey_digest_typehash());
    }

    #[test]
    fn single_digest_wraps_with_passkey_digest() {
        let digest = keccak256(b"test_op");
        let result = get_digest(&[digest], 1, &TEST_CONTRACT).unwrap();
        assert!(!result.is_merkle);
        assert!(result.proofs.is_none());
        // challenge != raw (because of EIP-712 wrapping)
        assert_ne!(result.challenge, result.raw);
        // raw should be the original digest
        assert_eq!(result.raw, format!("0x{}", hex::encode(digest)));
    }

    #[test]
    fn multi_digest_wraps_with_passkey_multichain() {
        let d1 = keccak256(b"op1");
        let d2 = keccak256(b"op2");
        let d3 = keccak256(b"op3");

        let result = get_digest(&[d1, d2, d3], 1, &TEST_CONTRACT).unwrap();
        assert!(result.is_merkle);
        let proofs = result.proofs.unwrap();
        assert_eq!(proofs.len(), 3);

        // raw is the merkle root
        let root = parse_bytes32(&result.raw).unwrap();
        // challenge is EIP-712 wrapped
        assert_ne!(result.challenge, result.raw);

        // Verify each merkle proof against the raw root
        for (i, leaf) in [d1, d2, d3].iter().enumerate() {
            let proof: Vec<[u8; 32]> = proofs[i]
                .proof
                .iter()
                .map(|p| parse_bytes32(p).unwrap())
                .collect();
            assert!(MerkleTree::verify(&proof, &root, leaf));
        }
    }

    #[test]
    fn multichain_is_chain_agnostic() {
        let d1 = keccak256(b"op1");
        let d2 = keccak256(b"op2");

        let r1 = get_digest(&[d1, d2], 1, &TEST_CONTRACT).unwrap();
        let r2 = get_digest(&[d1, d2], 137, &TEST_CONTRACT).unwrap();

        // Merkle challenge should be same regardless of chainId (uses sansChainId domain)
        assert_eq!(r1.challenge, r2.challenge);
    }

    #[test]
    fn single_digest_is_chain_specific() {
        let digest = keccak256(b"test_op");

        let r1 = get_digest(&[digest], 1, &TEST_CONTRACT).unwrap();
        let r2 = get_digest(&[digest], 137, &TEST_CONTRACT).unwrap();

        // Single challenge should differ per chain
        assert_ne!(r1.challenge, r2.challenge);
    }

    #[test]
    fn typed_data_passkey_digest_has_correct_shape() {
        let digest_hex = format!("0x{}", hex::encode(keccak256(b"test_op")));
        let contract_hex = format!("0x{}", hex::encode(TEST_CONTRACT));
        let td = passkey_digest_typed_data(&digest_hex, 1, &contract_hex);

        assert_eq!(td["domain"]["name"], "OneAuthValidator");
        assert_eq!(td["domain"]["version"], "1.0.0");
        assert_eq!(td["domain"]["chainId"], 1);
        assert_eq!(td["domain"]["verifyingContract"], contract_hex);
        assert_eq!(td["primaryType"], "PasskeyDigest");
        assert_eq!(td["types"]["PasskeyDigest"][0]["name"], "digest");
        assert_eq!(td["types"]["PasskeyDigest"][0]["type"], "bytes32");
        assert_eq!(td["message"]["digest"], digest_hex);
    }

    #[test]
    fn typed_data_passkey_multichain_has_correct_shape() {
        let root_hex = format!("0x{}", hex::encode(keccak256(b"test_root")));
        let contract_hex = format!("0x{}", hex::encode(TEST_CONTRACT));
        let td = passkey_multichain_typed_data(&root_hex, &contract_hex);

        assert_eq!(td["domain"]["name"], "OneAuthValidator");
        assert_eq!(td["domain"]["version"], "1.0.0");
        // No chainId for multichain, but verifyingContract is present
        assert!(td["domain"].get("chainId").is_none());
        assert_eq!(td["domain"]["verifyingContract"], contract_hex);
        assert_eq!(td["primaryType"], "PasskeyMultichain");
        assert_eq!(td["types"]["PasskeyMultichain"][0]["name"], "root");
        assert_eq!(td["message"]["root"], root_hex);
    }

    #[test]
    fn recovery_digest_roundtrip() {
        let input = RecoveryDigestInput {
            account: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045".to_string(),
            chain_id: 1,
            new_key_id: 0,
            new_pub_key_x: "0x580a9af0569ad3905b26a703201b358aa0904236642ebe79b22a19d00d373763"
                .to_string(),
            new_pub_key_y: "0x7d46f725a5427ae45a9569259bf67e1e16b187d7b3ad1ed70138c4f0409677d1"
                .to_string(),
            replace: false,
            verifying_contract: format!("0x{}", hex::encode(TEST_CONTRACT)),
            nonce: "0x01".to_string(),
            expiry: 1700000000,
        };
        let digest = recovery_digest(&input).unwrap();
        assert_ne!(digest, [0u8; 32]);
    }
}
