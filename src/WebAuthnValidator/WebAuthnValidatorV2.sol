// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.28;

import { ERC7579HybridValidatorBase } from "modulekit/Modules.sol";
import { PackedUserOperation } from "modulekit/external/ERC4337.sol";
import { MerkleProofLib } from "solady/utils/MerkleProofLib.sol";
import { EnumerableSetLib } from "solady/utils/EnumerableSetLib.sol";
import { WebAuthn } from "solady/utils/WebAuthn.sol";
import {
    MODULE_TYPE_STATELESS_VALIDATOR as TYPE_STATELESS_VALIDATOR
} from "modulekit/module-bases/utils/ERC7579Constants.sol";
import { WebAuthnRecoveryBase } from "./WebAuthnRecoveryBase.sol";
import { EIP712Lib } from "./EIP712Lib.sol";

/// @title WebAuthnValidatorV2
/// @notice ERC-7579 WebAuthn passkey validator module with merkle tree batch signing support
/// @dev The user signs a merkle root (tree of operation digests) with their passkey.
///      Each operation provides a merkle proof showing its digest is a leaf in the tree.
///      When proofLength = 0, falls back to regular signing (user signs digest directly).
///      Supports multiple passkeys via 2-byte keyIds; any single credential can sign.
///      requireUV is packed into the credential key to avoid a 3rd storage slot.
///
///      KNOWN SECURITY CONSIDERATIONS:
///
///      Recovery is additive: Recovery (via WebAuthnRecoveryBase) only adds new credentials --
///      compromised keys remain active until explicitly removed via removeCredential(). If
///      recovery is needed because a key was compromised, the account must separately revoke
///      the old key after regaining control.
///
///      Guardian timelock: Guardian changes support an optional timelock via proposeGuardian().
///      When guardianTimelock is zero (the default), changes take effect immediately. When
///      non-zero, changes are queued and must be confirmed via confirmGuardian() after the
///      timelock elapses, giving the account owner time to detect and cancel malicious changes.
///
///      Same keyId, different requireUV: The same keyId with different requireUV values creates
///      separate credential storage keys (credKeys). If the same physical passkey is registered
///      under both requireUV=false and requireUV=true, the requireUV=false variant bypasses
///      biometric/PIN verification, defeating the purpose of the requireUV=true registration.
///
///      Cross-chain merkle signing requires same contract address: _passkeyMultichain() uses
///      _hashTypedDataSansChainId which omits chainId but still includes verifyingContract in
///      the EIP-712 domain separator. The module must be deployed at the same address on all
///      target chains (e.g., via CREATE2) for cross-chain signatures to verify.
contract WebAuthnValidatorV2 is ERC7579HybridValidatorBase, WebAuthnRecoveryBase {
    using EnumerableSetLib for EnumerableSetLib.Uint256Set;

    /*//////////////////////////////////////////////////////////////
                                STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Stores the P-256 public key coordinates for a single WebAuthn credential
    /// @param pubKeyX X coordinate of the P-256 (secp256r1) public key
    /// @param pubKeyY Y coordinate of the P-256 (secp256r1) public key
    struct WebAuthnCredential {
        uint256 pubKeyX;
        uint256 pubKeyY;
    }

    /// @notice Per-account credential storage: a mapping from credKey to credential plus
    ///         an enumerable set of active credKeys for iteration during uninstall
    /// @dev credKey = uint256(keyId) | (requireUV ? _REQUIRE_UV_BIT : 0). The enumerable
    ///      set enables iterating all credentials during onUninstall cleanup and provides
    ///      O(1) membership checks for add/remove operations.
    struct PasskeyCredentials {
        mapping(uint256 credKey => WebAuthnCredential) credentials;
        EnumerableSetLib.Uint256Set enabledCredKeys;
    }

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Emitted when the module is installed for a smart account
    event ModuleInitialized(address indexed account);
    /// @notice Emitted when the module is uninstalled, after all credentials and guardian are cleared
    event ModuleUninitialized(address indexed account);
    /// @notice Emitted when a new passkey credential is registered for an account
    event CredentialAdded(
        address indexed account, uint16 indexed keyId, bool requireUV, uint256 pubKeyX, uint256 pubKeyY
    );
    /// @notice Emitted when a passkey credential is removed from an account
    event CredentialRemoved(address indexed account, uint16 indexed keyId);

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Thrown when signature calldata is malformed or too short to parse
    error InvalidSignatureData();
    /// @notice Thrown when the provided merkle proof does not verify against the merkle root
    error InvalidMerkleProof();
    /// @notice Thrown when proofLength exceeds MAX_MERKLE_DEPTH (DoS prevention)
    error ProofTooLong();
    /// @notice Thrown when a public key is not on the P-256 curve or has zero coordinates
    error InvalidPublicKey();
    /// @notice Thrown when attempting to remove a credential that does not exist
    error CredentialNotFound(uint16 keyId);
    /// @notice Thrown when attempting to remove the last remaining credential (liveness guarantee)
    error CannotRemoveLastCredential();
    /// @notice Thrown when adding a credential with a keyId+requireUV combination that already exists
    error KeyIdAlreadyExists(uint16 keyId);
    /// @notice Thrown when the account already has MAX_CREDENTIALS registered
    error TooManyCredentials();

    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @dev Maximum allowed merkle proof depth. Bounds-checks prevent DoS via oversized proofs.
    ///      32 levels supports trees with up to 2^32 (~4 billion) leaves.
    uint256 constant MAX_MERKLE_DEPTH = 32;

    /// @dev Maximum number of credentials per account. Prevents unbounded gas costs during
    ///      onUninstall iteration and limits storage growth.
    uint256 constant MAX_CREDENTIALS = 64;

    /// @dev Bit mask for the requireUV flag in a credKey. Positioned at bit 16 so it does not
    ///      overlap with the 16-bit keyId in bits [0:15]. This packing allows same keyId with
    ///      different requireUV to coexist as separate credentials in the mapping.
    uint256 private constant _REQUIRE_UV_BIT = 1 << 16;

    /// @dev P-256 (secp256r1) curve parameters for on-curve validation
    uint256 private constant _P256_P =
        0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF;
    uint256 private constant _P256_A =
        0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC;
    uint256 private constant _P256_B =
        0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B;

    /// @dev EIP-712 typehash for single-operation (chain-specific) passkey signing.
    ///      Sourced from EIP712Lib (single source of truth).
    bytes32 public constant PASSKEY_DIGEST_TYPEHASH = EIP712Lib.PASSKEY_DIGEST_TYPEHASH;

    /// @dev EIP-712 typehash for merkle batch (chain-agnostic) passkey signing.
    ///      Sourced from EIP712Lib (single source of truth).
    bytes32 public constant PASSKEY_MULTICHAIN_TYPEHASH = EIP712Lib.PASSKEY_MULTICHAIN_TYPEHASH;

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Passkey credentials per account
    /// @dev credKey = uint256(keyId) | (requireUV ? _REQUIRE_UV_BIT : 0)
    mapping(address account => PasskeyCredentials) internal _passkeyCredentials;

    /*//////////////////////////////////////////////////////////////
                                 CONFIG
    //////////////////////////////////////////////////////////////*/

    /// @notice Install the module with initial credentials, optional guardian, and optional timelock
    /// @dev Called by the smart account during module installation (ERC-7579 lifecycle).
    ///      msg.sender is the smart account itself, not an EOA or external caller.
    ///      The data payload is ABI-encoded as parallel arrays plus guardian config:
    ///        - keyIds: 16-bit credential identifiers (must be unique across requireUV values)
    ///        - creds: P-256 public key coordinates, validated to be on the secp256r1 curve
    ///        - requireUVs: whether each credential requires user verification (biometric/PIN)
    ///        - guardian: optional recovery guardian address (address(0) to skip)
    ///        - guardianTimelock: optional timelock duration in seconds for guardian changes (0 = immediate)
    /// @param data abi.encode(uint16[] keyIds, WebAuthnCredential[] creds, bool[] requireUVs, address guardian, uint48 guardianTimelock)
    function onInstall(bytes calldata data) external override {
        // msg.sender is the smart account (ERC-7579: the account calls onInstall during module setup)
        address account = msg.sender;
        if (isInitialized(account)) revert ModuleAlreadyInitialized(account);

        // Decode the parallel arrays, optional guardian, and optional guardian timelock
        (
            uint16[] memory keyIds,
            WebAuthnCredential[] memory creds,
            bool[] memory requireUVs,
            address _guardian,
            uint48 _guardianTimelock
        ) = abi.decode(data, (uint16[], WebAuthnCredential[], bool[], address, uint48));
        uint256 length = creds.length;

        // All three arrays must be non-empty and equal length
        if (length == 0 || length != keyIds.length || length != requireUVs.length) {
            revert InvalidPublicKey();
        }
        if (length > MAX_CREDENTIALS) revert TooManyCredentials();

        PasskeyCredentials storage pc = _passkeyCredentials[account];
        for (uint256 i; i < length; ++i) {
            // Validate that each public key lies on the P-256 curve. This prevents registering
            // invalid keys that would always fail verification, locking the account.
            if (!_isOnP256Curve(creds[i].pubKeyX, creds[i].pubKeyY)) revert InvalidPublicKey();

            // Pack keyId + requireUV into a single storage key. EnumerableSetLib.add returns
            // false if the key already exists, catching duplicate keyId+requireUV combinations.
            uint256 ck = _credKey(keyIds[i], requireUVs[i]);
            // Reject if the same keyId exists with opposite requireUV — prevents a requireUV=false
            // variant from bypassing the biometric verification of a requireUV=true registration.
            if (pc.enabledCredKeys.contains(_credKey(keyIds[i], !requireUVs[i]))) {
                revert KeyIdAlreadyExists(keyIds[i]);
            }
            if (!pc.enabledCredKeys.add(ck)) revert KeyIdAlreadyExists(keyIds[i]);
            pc.credentials[ck] = creds[i];
            emit CredentialAdded(account, keyIds[i], requireUVs[i], creds[i].pubKeyX, creds[i].pubKeyY);
        }

        // Guardian is optional -- address(0) means no guardian is configured.
        // Guardian can be set or changed later via proposeGuardian() (inherited from WebAuthnRecoveryBase).
        if (_guardian != address(0)) {
            _setGuardianImmediate(account, _guardian);
        }

        // Guardian timelock is optional -- 0 means proposeGuardian takes effect immediately.
        if (_guardianTimelock != 0) {
            _recoveryConfig[account].guardianTimelock = _guardianTimelock;
            emit GuardianTimelockSet(account, _guardianTimelock);
        }

        emit ModuleInitialized(account);
    }

    /// @notice Uninstall the module, clearing all credentials and guardian
    /// @dev Called by the smart account during module removal (ERC-7579 lifecycle).
    ///      msg.sender is the smart account. Iterates all enabled credKeys, deletes each
    ///      credential's public key data, removes it from the enumerable set, and clears
    ///      the guardian address.
    ///      NOTE: Used recovery nonces (in _recoveryConfig[account].nonceUsed) are intentionally
    ///      NOT cleared. This prevents replay attacks where a previously-used recovery signature
    ///      could be replayed after reinstalling the module.
    function onUninstall(bytes calldata) external override {
        // msg.sender is the smart account (ERC-7579 lifecycle)
        address account = msg.sender;
        PasskeyCredentials storage pc = _passkeyCredentials[account];

        // Snapshot all credKeys into memory before mutating the set
        uint256[] memory credKeys = pc.enabledCredKeys.values();

        // Delete each credential's public key and remove from the enumerable set
        for (uint256 i; i < credKeys.length; ++i) {
            delete pc.credentials[credKeys[i]];
            pc.enabledCredKeys.remove(credKeys[i]);
        }

        // Clear guardian + pending guardian state but leave nonceUsed intact to prevent replay after reinstallation
        delete _recoveryConfig[account].guardian;
        delete _recoveryConfig[account].pendingGuardian;
        delete _recoveryConfig[account].guardianActivatesAt;

        emit ModuleUninitialized(account);
    }

    /// @notice Check whether the module is installed for a given smart account
    /// @dev An account is considered initialized if it has at least one credential registered.
    ///      Since onInstall requires at least one credential and removeCredential prevents
    ///      removing the last one, a zero count means never installed or fully uninstalled.
    /// @param smartAccount The smart account address to check
    /// @return True if the account has at least one registered credential
    function isInitialized(address smartAccount) public view returns (bool) {
        return _passkeyCredentials[smartAccount].enabledCredKeys.length() > 0;
    }

    /// @notice Get the number of credentials for an account
    /// @param account The smart account address
    /// @return The count of currently registered credentials
    function credentialCount(address account) external view returns (uint256) {
        return _passkeyCredentials[account].enabledCredKeys.length();
    }

    /// @notice Get all enabled credential keys for an account
    /// @dev Each credKey encodes keyId in bits [0:15] and requireUV in bit 16.
    ///      To extract the components: keyId = uint16(credKey), requireUV = (credKey >> 16) & 1.
    /// @param account The smart account address
    /// @return Array of packed credKey values
    function getCredKeys(address account) external view returns (uint256[] memory) {
        return _passkeyCredentials[account].enabledCredKeys.values();
    }

    /// @notice Add a new credential with a specific keyId
    /// @dev msg.sender is the smart account calling this function directly (not via entrypoint).
    ///      The module must already be installed (isInitialized check in _addCredential), preventing
    ///      credentials from being added before onInstall establishes the account's credential set.
    /// @param keyId 16-bit identifier for this credential
    /// @param pubKeyX X coordinate of the P-256 public key (validated to be on curve)
    /// @param pubKeyY Y coordinate of the P-256 public key (validated to be on curve)
    /// @param requireUV Whether this credential requires user verification (biometric/PIN)
    function addCredential(uint16 keyId, uint256 pubKeyX, uint256 pubKeyY, bool requireUV) external {
        // msg.sender is the smart account calling directly
        _addCredential(msg.sender, keyId, pubKeyX, pubKeyY, requireUV);
    }

    /// @notice Remove a credential by keyId and requireUV
    /// @dev msg.sender is the smart account calling this function directly. Prevents removing
    ///      the last credential to maintain a liveness guarantee -- the account must always
    ///      have at least one credential capable of signing to avoid permanent lockout.
    /// @param keyId 16-bit identifier of the credential to remove
    /// @param requireUV The requireUV flag of the credential to remove (needed to compute credKey)
    function removeCredential(uint16 keyId, bool requireUV) external {
        // msg.sender is the smart account calling directly
        address account = msg.sender;
        PasskeyCredentials storage pc = _passkeyCredentials[account];
        uint256 len = pc.enabledCredKeys.length();

        // Must be initialized (has at least one credential)
        if (len == 0) revert NotInitialized(account);

        // Prevent removing the last credential -- the account would be permanently locked
        // since there would be no valid signer to authorize operations or add new credentials
        if (len <= 1) revert CannotRemoveLastCredential();

        // Both keyId and requireUV must match to compute the correct credKey for removal
        uint256 ck = _credKey(keyId, requireUV);

        // EnumerableSetLib.remove returns false if the key was not in the set
        if (!pc.enabledCredKeys.remove(ck)) revert CredentialNotFound(keyId);
        delete pc.credentials[ck];
        emit CredentialRemoved(account, keyId);
    }

    /// @notice Get the P-256 public key coordinates for a specific credential
    /// @dev Returns (0, 0) if the credential does not exist. Both keyId and requireUV are
    ///      needed because they together form the credKey used for storage lookup.
    /// @param keyId 16-bit identifier of the credential
    /// @param requireUV The requireUV flag of the credential
    /// @param account The smart account address that owns the credential
    /// @return pubKeyX X coordinate of the P-256 public key (0 if not found)
    /// @return pubKeyY Y coordinate of the P-256 public key (0 if not found)
    function getCredential(
        uint16 keyId,
        bool requireUV,
        address account
    )
        external
        view
        returns (uint256 pubKeyX, uint256 pubKeyY)
    {
        uint256 ck = _credKey(keyId, requireUV);
        WebAuthnCredential storage cred = _passkeyCredentials[account].credentials[ck];
        return (cred.pubKeyX, cred.pubKeyY);
    }

    /*//////////////////////////////////////////////////////////////
                                VALIDATE
    //////////////////////////////////////////////////////////////*/

    /// @notice ERC-4337 user operation validation (called by the EntryPoint)
    /// @dev The account address is userOp.sender, NOT msg.sender (msg.sender is the EntryPoint).
    ///      Returns VALIDATION_SUCCESS (0) if the signature is valid, or VALIDATION_FAILED (1)
    ///      otherwise. Must never revert per ERC-4337 spec -- all failure cases return
    ///      VALIDATION_FAILED instead.
    /// @param userOp The packed user operation containing the signature in userOp.signature
    /// @param userOpHash The hash of the user operation (used as the digest to verify)
    /// @return ValidationData VALIDATION_SUCCESS (0) or VALIDATION_FAILED (1)
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    )
        external
        view
        override
        returns (ValidationData)
    {
        // account is userOp.sender (the smart account), not msg.sender (the EntryPoint)
        if (_validateSignatureWithConfig(userOp.sender, userOpHash, userOp.signature)) {
            return VALIDATION_SUCCESS;
        }
        return VALIDATION_FAILED;
    }

    /// @notice EIP-1271 signature validation (called by the smart account)
    /// @dev The first parameter (sender) is intentionally ignored. Per ERC-7579, the smart
    ///      account calls this function on the validator module, so msg.sender IS the smart
    ///      account and is used as the account for credential lookup. The sender parameter
    ///      (which would be the original caller of the smart account's isValidSignature)
    ///      is not relevant for credential-based validation.
    /// @param hash The hash of the data to validate
    /// @param data The packed signature data (same format as userOp.signature)
    /// @return bytes4 EIP1271_SUCCESS (0x1626ba7e) if valid, EIP1271_FAILED (0xffffffff) otherwise
    function isValidSignatureWithSender(
        address, /* sender -- ignored; msg.sender (the smart account) is the relevant account */
        bytes32 hash,
        bytes calldata data
    )
        external
        view
        override
        returns (bytes4)
    {
        // msg.sender is the smart account (ERC-7579: the account calls this on the validator)
        if (_validateSignatureWithConfig(msg.sender, hash, data)) {
            return EIP1271_SUCCESS;
        }
        return EIP1271_FAILED;
    }

    /// @notice ERC-7579 stateless validation extension -- credentials are provided externally
    ///         in `data` rather than fetched from on-chain storage
    /// @dev Unlike the stateful validateUserOp / isValidSignatureWithSender paths, this function
    ///      does not look up credentials by account. Instead, the caller provides the public key
    ///      and validation parameters in `data`, and the WebAuthn signature in `signature`.
    ///      This enables off-chain verifiers to validate signatures without the module being installed.
    ///
    ///      The `data` layout mirrors the stateful signature format (proof before credential data):
    ///        [0]       proofLength (uint8)
    ///        if proofLength == 0 (regular signing, challenge = _passkeyDigest(hash)):
    ///          [1:33]                         pubKeyX
    ///          [33:65]                        pubKeyY
    ///          [65]                           requireUV (uint8)
    ///        if proofLength > 0 (merkle proof, challenge = _passkeyMultichain(merkleRoot)):
    ///          [1:33]                         merkleRoot (bytes32)
    ///          [33:33+proofLength*32]         proof (bytes32[])
    ///          [proofEnd:proofEnd+32]         pubKeyX
    ///          [proofEnd+32:proofEnd+64]      pubKeyY
    ///          [proofEnd+64]                  requireUV (uint8)
    ///      `signature` is packed WebAuthnAuth (see _parseWebAuthnAuth for format).
    /// @param hash The digest to validate (or a leaf in the merkle tree for batch signing)
    /// @param signature Packed WebAuthnAuth struct (r, s, challengeIndex, typeIndex, authenticatorData, clientDataJSON)
    /// @param data Packed credential and proof data as described above
    /// @return True if the signature is valid for the provided credentials
    function validateSignatureWithData(
        bytes32 hash,
        bytes calldata signature,
        bytes calldata data
    )
        external
        view
        override
        returns (bool)
    {
        if (data.length < 1) revert InvalidSignatureData();
        uint256 proofLength = uint8(data[0]);

        // Regular path: proofLength == 0 means no merkle proof, challenge is chain-specific
        if (proofLength == 0) {
            // Minimum data: 1 (proofLength) + 32 (pubKeyX) + 32 (pubKeyY) + 1 (requireUV) = 66
            if (data.length < 66) revert InvalidSignatureData();
            (WebAuthn.WebAuthnAuth memory auth, bool ok) = _parseWebAuthnAuth(signature);
            if (!ok) revert InvalidSignatureData();

            // Challenge is _passkeyDigest(hash): chain-specific EIP-712 typed data
            return WebAuthn.verify(
                abi.encode(_passkeyDigest(hash)),
                uint8(data[65]) != 0, // requireUV
                auth,
                bytes32(data[1:33]), // pubKeyX
                bytes32(data[33:65]) // pubKeyY
            );
        }

        // Merkle proof path: challenge = _passkeyMultichain(merkleRoot) (chain-agnostic)
        if (proofLength > MAX_MERKLE_DEPTH) revert ProofTooLong();

        // proofEnd marks where the proof bytes end and credential data begins
        uint256 proofEnd = 33 + (proofLength << 5); // 33 + proofLength * 32
        // Minimum remaining data: pubKeyX (32) + pubKeyY (32) + requireUV (1) = 65
        if (data.length < proofEnd + 65) revert InvalidSignatureData();

        bytes32 merkleRoot = bytes32(data[1:33]);

        {
            // Assembly constructs a calldata slice pointing to the proof bytes32[] array.
            // This avoids copying the proof to memory -- MerkleProofLib.verifyCalldata reads
            // directly from calldata.
            bytes32[] calldata proof;
            /// @solidity memory-safe-assembly
            assembly {
                proof.offset := add(data.offset, 33)
                proof.length := proofLength
            }
            // Verify that `hash` (the operation digest) is a leaf in the merkle tree
            if (!MerkleProofLib.verifyCalldata(proof, merkleRoot, hash)) {
                revert InvalidMerkleProof();
            }
        }

        {
            (WebAuthn.WebAuthnAuth memory auth, bool ok) = _parseWebAuthnAuth(signature);
            if (!ok) revert InvalidSignatureData();

            // Challenge is _passkeyMultichain(merkleRoot): chain-agnostic EIP-712 hash of the
            // merkle root, enabling a single passkey signature to cover multiple operations
            // across multiple chains
            return WebAuthn.verify(
                abi.encode(_passkeyMultichain(merkleRoot)),
                uint8(data[proofEnd + 64]) != 0, // requireUV
                auth,
                bytes32(data[proofEnd:proofEnd + 32]), // pubKeyX
                bytes32(data[proofEnd + 32:proofEnd + 64]) // pubKeyY
            );
        }
    }

    /*//////////////////////////////////////////////////////////////
                           RECOVERY HOOKS
    //////////////////////////////////////////////////////////////*/

    /// @dev Hook called by WebAuthnRecoveryBase during recovery (recoverWithPasskey or
    ///      recoverWithGuardian). Delegates to _addCredential which validates the public key
    ///      is on the P-256 curve and checks that the credential capacity has not been exceeded.
    ///      Recovery is additive only -- this adds a new credential but does NOT remove existing
    ///      ones. If recovery was triggered because a key was compromised, the compromised
    ///      credential must be separately removed via removeCredential() after regaining access.
    /// @param account The smart account to add the credential to
    /// @param cred The new credential parameters (keyId, pubKeyX, pubKeyY, requireUV)
    function _addCredentialRecovery(
        address account,
        NewCredential calldata cred
    )
        internal
        override
    {
        _addCredential(account, cred.keyId, cred.pubKeyX, cred.pubKeyY, cred.requireUV);
    }

    /*//////////////////////////////////////////////////////////////
                                INTERNAL
    //////////////////////////////////////////////////////////////*/

    /// @notice Validate that (x, y) is a point on the P-256 (secp256r1) curve
    /// @dev Verifies the Weierstrass equation: y^2 = x^3 + ax + b (mod p)
    ///      where a and b are the P-256 curve parameters. Also rejects the point at infinity
    ///      (zero coordinates) and values >= the field prime p.
    ///      This is the same validation as FreshCryptoLib's ecAff_isOnCurve but inlined here
    ///      to avoid importing the full FreshCryptoLib library just for this single check.
    /// @param x X coordinate of the candidate point
    /// @param y Y coordinate of the candidate point
    /// @return True if (x, y) lies on the P-256 curve
    function _isOnP256Curve(uint256 x, uint256 y) internal pure returns (bool) {
        // Reject zero coordinates (point at infinity) and values >= field prime
        if (x == 0 || y == 0 || x >= _P256_P || y >= _P256_P) return false;

        // LHS: y^2 mod p
        uint256 lhs = mulmod(y, y, _P256_P);

        // RHS: x^3 + ax + b mod p
        // Computed as: ((x * x mod p) * x mod p) + (x * a mod p) + b, all mod p
        uint256 rhs = addmod(
            addmod(mulmod(mulmod(x, x, _P256_P), x, _P256_P), mulmod(x, _P256_A, _P256_P), _P256_P),
            _P256_B,
            _P256_P
        );
        return lhs == rhs;
    }

    /// @notice Compute the credential storage key from keyId and requireUV
    /// @dev Packs keyId (16 bits, positions [0:15]) and requireUV (1 bit at position 16)
    ///      into a single uint256. This allows the same keyId with different requireUV values
    ///      to coexist as separate credentials in the mapping. For example, keyId=1 with
    ///      requireUV=false produces credKey=1, while keyId=1 with requireUV=true produces
    ///      credKey=65537 (1 | (1 << 16)).
    /// @param keyId 16-bit credential identifier
    /// @param requireUV Whether user verification is required for this credential
    /// @return The packed credential storage key
    function _credKey(uint16 keyId, bool requireUV) internal pure returns (uint256) {
        return uint256(keyId) | (requireUV ? _REQUIRE_UV_BIT : 0);
    }

    /// @notice Chain-specific EIP-712 challenge for single operation signing
    /// @dev Uses Solady's _hashTypedData which includes chainId in the EIP-712 domain separator.
    ///      This prevents cross-chain replay: a signature made on chain A cannot be reused on
    ///      chain B. The domain also includes verifyingContract (this module's address), which
    ///      prevents cross-contract replay.
    /// @param digest The operation digest to wrap in the EIP-712 typed data envelope
    /// @return The chain-specific EIP-712 hash to be used as the WebAuthn challenge
    function _passkeyDigest(bytes32 digest) internal view returns (bytes32) {
        return _hashTypedData(EIP712Lib.passkeyDigestHash(digest));
    }

    /// @notice Chain-agnostic EIP-712 challenge for merkle batch signing
    /// @dev Uses Solady's _hashTypedDataSansChainId which omits chainId from the EIP-712 domain
    ///      separator, enabling a single passkey signature over the merkle root to validate on
    ///      multiple chains. The domain still includes verifyingContract, so the module must be
    ///      deployed at the same address on all target chains (e.g., via CREATE2).
    /// @param root The merkle root covering multiple operation digests across chains
    /// @return The chain-agnostic EIP-712 hash to be used as the WebAuthn challenge
    function _passkeyMultichain(bytes32 root) internal view returns (bytes32) {
        return _hashTypedDataSansChainId(EIP712Lib.passkeyMultichainHash(root));
    }

    /// @notice Compute the passkey challenge for a single operation digest (chain-specific)
    /// @dev Public convenience wrapper around _passkeyDigest for off-chain tooling to compute
    ///      the exact challenge bytes the passkey must sign for regular (non-merkle) operations.
    /// @param digest The operation digest (e.g., userOpHash)
    /// @return The EIP-712 typed data hash to be used as the WebAuthn challenge
    function getPasskeyDigest(bytes32 digest) public view returns (bytes32) {
        return _passkeyDigest(digest);
    }

    /// @notice Compute the passkey challenge for a merkle root (chain-agnostic)
    /// @dev Public convenience wrapper around _passkeyMultichain for off-chain tooling to
    ///      compute the exact challenge bytes the passkey must sign for merkle batch operations.
    /// @param root The merkle root of the operation digest tree
    /// @return The chain-agnostic EIP-712 typed data hash to be used as the WebAuthn challenge
    function getPasskeyMultichain(bytes32 root) public view returns (bytes32) {
        return _passkeyMultichain(root);
    }

    /// @notice Add a credential with full validation
    /// @dev Shared by both addCredential() (user-initiated) and _addCredentialRecovery()
    ///      (recovery-initiated). Validates the public key is on the P-256 curve, checks
    ///      the module is initialized, ensures capacity is not exceeded, and rejects duplicate
    ///      keyId+requireUV combinations.
    /// @param account The smart account to add the credential to
    /// @param keyId 16-bit credential identifier
    /// @param pubKeyX X coordinate of the P-256 public key
    /// @param pubKeyY Y coordinate of the P-256 public key
    /// @param requireUV Whether this credential requires user verification
    function _addCredential(
        address account,
        uint16 keyId,
        uint256 pubKeyX,
        uint256 pubKeyY,
        bool requireUV
    )
        internal
    {
        // Validate public key is on the P-256 curve to prevent registering invalid keys
        if (!_isOnP256Curve(pubKeyX, pubKeyY)) revert InvalidPublicKey();

        PasskeyCredentials storage pc = _passkeyCredentials[account];
        uint256 len = pc.enabledCredKeys.length();

        // Cannot add credentials before the module is installed via onInstall
        if (len == 0) revert NotInitialized(account);

        // Enforce the credential cap to bound gas costs during onUninstall iteration
        if (len >= MAX_CREDENTIALS) revert TooManyCredentials();

        // Reject if the same keyId exists with opposite requireUV — prevents a requireUV=false
        // variant from bypassing the biometric verification of a requireUV=true registration.
        if (pc.enabledCredKeys.contains(_credKey(keyId, !requireUV))) revert KeyIdAlreadyExists(keyId);

        // Pack keyId + requireUV and attempt to add to the set
        uint256 ck = _credKey(keyId, requireUV);
        if (!pc.enabledCredKeys.add(ck)) revert KeyIdAlreadyExists(keyId);
        pc.credentials[ck] = WebAuthnCredential(pubKeyX, pubKeyY);
        emit CredentialAdded(account, keyId, requireUV, pubKeyX, pubKeyY);
    }

    /// @notice Core stateful validation -- router that dispatches to regular or merkle path
    /// @dev Returns false (not revert) for all failure cases. This is required by ERC-4337:
    ///      validateUserOp must not revert on invalid signatures, it must return VALIDATION_FAILED.
    ///      The same return-false-on-failure convention is used throughout the validation chain.
    ///
    ///      Packed signature format:
    ///        [0]                            proofLength (uint8)
    ///        if proofLength == 0 (regular signing, challenge = digest):
    ///          [1:3]                        keyId (uint16)
    ///          [3]                          requireUV (uint8)
    ///          [4:]                         packed WebAuthnAuth
    ///        if proofLength > 0 (merkle proof, challenge = merkleRoot):
    ///          [1:33]                       merkleRoot (bytes32)
    ///          [33:33+proofLength*32]       proof
    ///          [proofEnd:proofEnd+2]        keyId (uint16)
    ///          [proofEnd+2]                 requireUV (uint8)
    ///          [proofEnd+3:]                packed WebAuthnAuth
    /// @param account The smart account address (for credential lookup)
    /// @param digest The hash to validate (userOpHash or EIP-1271 hash)
    /// @param data The packed signature data
    /// @return True if the signature is valid
    function _validateSignatureWithConfig(
        address account,
        bytes32 digest,
        bytes calldata data
    )
        internal
        view
        override
        returns (bool)
    {
        // Minimum 4 bytes: 1 (proofLength) + 2 (keyId) + 1 (requireUV)
        if (data.length < 4) return false;

        uint256 proofLength = uint8(data[0]);

        // Dispatch: proofLength == 0 is regular signing, proofLength > 0 is merkle batch signing
        if (proofLength == 0) {
            return _validateRegular(account, digest, data);
        }

        return _validateMerkle(account, digest, data, proofLength);
    }

    /// @notice Regular signing path (proofLength=0): challenge = chain-specific EIP-712 digest
    /// @dev Extracts keyId and requireUV from the packed signature header, looks up the
    ///      credential by credKey, parses the WebAuthnAuth from the remaining calldata,
    ///      and delegates to WebAuthn.verify.
    /// @param account The smart account address for credential lookup
    /// @param digest The hash to validate (wrapped in _passkeyDigest for chain-specific EIP-712)
    /// @param data The full packed signature data (proofLength byte already consumed by caller)
    /// @return True if the WebAuthn signature is valid for the stored credential
    function _validateRegular(
        address account,
        bytes32 digest,
        bytes calldata data
    )
        internal
        view
        returns (bool)
    {
        // Extract the signature header fields from the packed calldata
        uint16 keyId = uint16(bytes2(data[1:3]));
        bool requireUV = uint8(data[3]) != 0;

        // Look up the credential by packing keyId + requireUV into the credKey
        uint256 ck = _credKey(keyId, requireUV);
        WebAuthnCredential storage cred = _passkeyCredentials[account].credentials[ck];

        // pubKeyX == 0 means this credential slot is empty (never registered or was deleted).
        // Valid P-256 keys cannot have x=0 since that fails the _isOnP256Curve check at registration.
        if (cred.pubKeyX == 0) return false;

        // Parse the packed WebAuthnAuth from the remaining calldata after the 4-byte header
        (WebAuthn.WebAuthnAuth memory auth, bool ok) = _parseWebAuthnAuth(data[4:]);
        if (!ok) return false;

        // Challenge is chain-specific: _passkeyDigest wraps digest in EIP-712 with chainId
        return WebAuthn.verify(
            abi.encode(_passkeyDigest(digest)), requireUV, auth, bytes32(cred.pubKeyX), bytes32(cred.pubKeyY)
        );
    }

    /// @notice Merkle signing path (proofLength>0): challenge = chain-agnostic EIP-712 hash of merkleRoot
    /// @dev Verifies that `digest` is a leaf in the merkle tree rooted at `merkleRoot`, then
    ///      validates the WebAuthn signature against the chain-agnostic challenge derived from
    ///      the merkle root. This allows a single passkey signature to authorize multiple
    ///      operations across multiple chains.
    /// @param account The smart account address for credential lookup
    /// @param digest The operation digest that should be a leaf in the merkle tree
    /// @param data The full packed signature data including merkle proof and credential header
    /// @param proofLength Number of 32-byte proof elements (already extracted from data[0])
    /// @return True if the merkle proof verifies AND the WebAuthn signature is valid
    function _validateMerkle(
        address account,
        bytes32 digest,
        bytes calldata data,
        uint256 proofLength
    )
        internal
        view
        returns (bool)
    {
        // Bounds-check the proof depth to prevent DoS via oversized proofs that would
        // consume excessive gas in the MerkleProofLib verification loop
        if (proofLength > MAX_MERKLE_DEPTH) return false;

        // Compute where the proof bytes end: 1 (proofLength) + 32 (merkleRoot) + proofLength * 32
        // Using left shift by 5 as an optimization for multiplication by 32
        uint256 proofEnd = 33 + (proofLength << 5);

        // Minimum remaining data after proof: keyId (2) + requireUV (1) = 3
        if (data.length < proofEnd + 3) return false;

        bytes32 merkleRoot = bytes32(data[1:33]);

        {
            // Assembly constructs a calldata slice for the bytes32[] proof array without copying
            // to memory. This sets the ABI calldata pointer and length for MerkleProofLib to
            // read directly from calldata, saving gas on memory allocation and copying.
            bytes32[] calldata proof;
            /// @solidity memory-safe-assembly
            assembly {
                proof.offset := add(data.offset, 33)
                proof.length := proofLength
            }
            // Verify that `digest` (the operation hash) is a leaf in the merkle tree
            if (!MerkleProofLib.verifyCalldata(proof, merkleRoot, digest)) return false;
        }

        // Extract credential header fields from after the proof
        uint16 keyId = uint16(bytes2(data[proofEnd:proofEnd + 2]));
        bool requireUV = uint8(data[proofEnd + 2]) != 0;

        // Look up the credential by credKey
        uint256 ck = _credKey(keyId, requireUV);
        WebAuthnCredential storage cred = _passkeyCredentials[account].credentials[ck];
        if (cred.pubKeyX == 0) return false;

        // Parse WebAuthnAuth from remaining calldata after the 3-byte credential header
        (WebAuthn.WebAuthnAuth memory auth, bool ok) = _parseWebAuthnAuth(data[proofEnd + 3:]);
        if (!ok) return false;

        // Challenge is chain-agnostic: _passkeyMultichain wraps merkleRoot in EIP-712 without chainId
        return WebAuthn.verify(
            abi.encode(_passkeyMultichain(merkleRoot)), requireUV, auth, bytes32(cred.pubKeyX), bytes32(cred.pubKeyY)
        );
    }

    /// @notice Parse tightly packed WebAuthnAuth from calldata
    /// @dev Returns (auth, ok) tuple -- returns false instead of reverting when the input is
    ///      malformed. This is required because callers in the validation path must return false
    ///      (not revert) on invalid data per ERC-4337 requirements.
    ///
    ///      Packed format (avoids ABI encoding overhead for gas savings):
    ///        [0:32]              r (uint256) -- ECDSA r component
    ///        [32:64]             s (uint256) -- ECDSA s component
    ///        [64:66]             challengeIndex (uint16) -- offset of challenge in clientDataJSON
    ///        [66:68]             typeIndex (uint16) -- offset of "type" field in clientDataJSON
    ///        [68:70]             authenticatorDataLen (uint16) -- length of authenticatorData
    ///        [70:70+adLen]       authenticatorData (bytes) -- raw authenticator data
    ///        [70+adLen:]         clientDataJSON (bytes) -- remaining bytes are the client data
    ///
    ///      WebAuthn.WebAuthnAuth memory layout (used by the assembly blocks):
    ///        0x00: authenticatorData (bytes pointer)
    ///        0x20: clientDataJSON (bytes pointer)
    ///        0x40: challengeIndex (uint256)
    ///        0x60: typeIndex (uint256)
    ///        0x80: r (uint256)
    ///        0xa0: s (uint256)
    /// @param raw The tightly packed WebAuthnAuth calldata
    /// @return auth The parsed WebAuthnAuth struct
    /// @return ok True if parsing succeeded, false if the input was too short
    function _parseWebAuthnAuth(bytes calldata raw)
        internal
        pure
        returns (WebAuthn.WebAuthnAuth memory auth, bool ok)
    {
        // Minimum 70 bytes: r (32) + s (32) + challengeIndex (2) + typeIndex (2) + adLen (2)
        if (raw.length < 70) return (auth, false);

        uint256 adLen;
        /// @solidity memory-safe-assembly
        assembly {
            let off := raw.offset

            // First assembly block: reads scalar fields directly from calldata into the
            // auth struct in memory. Uses calldataload for raw 32-byte reads of r and s.
            // For the three 2-byte fields (challengeIndex, typeIndex, adLen), a single
            // calldataload at offset 0x40 reads 32 bytes containing all three packed at the
            // high end. Each is extracted by shifting right to position it and masking to 16 bits.
            mstore(add(auth, 0x80), calldataload(off))           // r
            mstore(add(auth, 0xa0), calldataload(add(off, 0x20))) // s

            // Single calldataload reads 32 bytes starting at the challengeIndex position.
            // The three uint16 fields are packed in the high bytes of this 32-byte word:
            //   bits [240:255] = challengeIndex (shift right 240, implicit 16-bit value)
            //   bits [224:239] = typeIndex (shift right 224, mask to 16 bits)
            //   bits [208:223] = adLen (shift right 208, mask to 16 bits)
            let packed := calldataload(add(off, 0x40))
            mstore(add(auth, 0x40), shr(240, packed))                // challengeIndex
            mstore(add(auth, 0x60), and(shr(224, packed), 0xffff))   // typeIndex
            adLen := and(shr(208, packed), 0xffff)                   // authenticatorDataLen
        }

        // Ensure calldata is long enough to contain the authenticatorData bytes
        if (raw.length < 70 + adLen) return (auth, false);

        /// @solidity memory-safe-assembly
        assembly {
            // Second assembly block: allocates memory for the two dynamic byte arrays
            // (authenticatorData and clientDataJSON) and sets the struct pointers.

            let off := raw.offset
            // clientDataJSON is everything after the fixed header and authenticatorData
            let cdLen := sub(raw.length, add(70, adLen))
            let fmp := mload(0x40) // current free memory pointer

            // Allocate authenticatorData: write length prefix then copy bytes from calldata
            mstore(fmp, adLen)
            calldatacopy(add(fmp, 0x20), add(off, 70), adLen)
            mstore(auth, fmp) // auth.authenticatorData = pointer to this bytes array

            // Advance past authenticatorData allocation with 32-byte alignment
            // adAlloc = 32 (length prefix) + ceil(adLen / 32) * 32
            let adAlloc := add(0x20, and(add(adLen, 0x1f), not(0x1f)))
            let cdPtr := add(fmp, adAlloc)

            // Allocate clientDataJSON: write length prefix then copy remaining bytes
            mstore(cdPtr, cdLen)
            calldatacopy(add(cdPtr, 0x20), add(off, add(70, adLen)), cdLen)
            mstore(add(auth, 0x20), cdPtr) // auth.clientDataJSON = pointer to this bytes array

            // Update free memory pointer past both allocations with 32-byte alignment
            mstore(0x40, add(cdPtr, add(0x20, and(add(cdLen, 0x1f), not(0x1f)))))
        }

        ok = true;
    }

    /*//////////////////////////////////////////////////////////////
                                METADATA
    //////////////////////////////////////////////////////////////*/

    /// @notice ERC-7579 module type check -- reports this module as both a standard validator
    ///         (TYPE_VALIDATOR) and a stateless validator (TYPE_STATELESS_VALIDATOR)
    /// @param typeID The ERC-7579 module type identifier to check
    /// @return True if this module supports the given type
    function isModuleType(uint256 typeID) external pure override returns (bool) {
        return typeID == TYPE_VALIDATOR || typeID == TYPE_STATELESS_VALIDATOR;
    }

    /// @notice ERC-7579 module name
    function name() external pure virtual returns (string memory) {
        return "WebAuthnValidatorV2";
    }

    /// @notice ERC-7579 module version
    function version() external pure virtual returns (string memory) {
        return "2.0.0";
    }
}
