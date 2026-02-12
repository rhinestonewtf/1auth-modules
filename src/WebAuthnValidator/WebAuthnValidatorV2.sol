// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.28;

import { ERC7579HybridValidatorBase } from "modulekit/Modules.sol";
import { PackedUserOperation } from "modulekit/external/ERC4337.sol";
import { MerkleProofLib } from "solady/utils/MerkleProofLib.sol";
import { EnumerableSetLib } from "solady/utils/EnumerableSetLib.sol";
import { EfficientHashLib } from "solady/utils/EfficientHashLib.sol";
import { WebAuthn } from "solady/utils/WebAuthn.sol";
import {
    MODULE_TYPE_STATELESS_VALIDATOR as TYPE_STATELESS_VALIDATOR
} from "modulekit/module-bases/utils/ERC7579Constants.sol";
import { WebAuthnRecoveryBase } from "./WebAuthnRecoveryBase.sol";
import { UVExemptBase } from "./UVExemptBase.sol";
import { IWebAuthnValidatorV2 } from "./IWebAuthnValidatorV2.sol";
import { EIP712Lib } from "./lib/EIP712Lib.sol";
import { P256Lib } from "./lib/P256Lib.sol";
import { MAX_MERKLE_DEPTH, MAX_CREDENTIALS } from "./lib/Constants.sol";

/**
 * @title WebAuthnValidatorV2
 * @notice ERC-7579 WebAuthn passkey validator module with merkle tree batch signing support
 * @dev The user signs a merkle root (tree of operation digests) with their passkey.
 *      Each operation provides a merkle proof showing its digest is a leaf in the tree.
 *      When proofLength = 0, falls back to regular signing (user signs digest directly).
 *      Supports multiple passkeys via 2-byte keyIds; any single credential can sign.
 *
 *      KNOWN SECURITY CONSIDERATIONS:
 *
 *      Recovery supports in-place rotation: When replace is true in the recovery struct,
 *      the credential at keyId has its public key overwritten in-place. When replace is
 *      false, recovery is additive (new credential added, existing keys remain).
 *
 *      Guardian timelock: Guardian changes support an optional timelock via proposeGuardian().
 *      When guardianTimelock is zero (the default), changes take effect immediately. When
 *      non-zero, changes are queued and must be confirmed via confirmGuardian() after the
 *      timelock elapses, giving the account owner time to detect and cancel malicious changes.
 *
 *      Cross-chain merkle signing requires same contract address: _passkeyMultichain() uses
 *      _hashTypedDataSansChainId which omits chainId but still includes verifyingContract in
 *      the EIP-712 domain separator. The module must be deployed at the same address on all
 *      target chains (e.g., via CREATE2) for cross-chain signatures to verify.
 */
contract WebAuthnValidatorV2 is ERC7579HybridValidatorBase, WebAuthnRecoveryBase, UVExemptBase, IWebAuthnValidatorV2 {
    using EnumerableSetLib for EnumerableSetLib.Uint256Set;
    using EfficientHashLib for bytes32;

    /*//////////////////////////////////////////////////////////////
                                STRUCTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Stores the P-256 public key coordinates for a single WebAuthn credential
     * @param pubKeyX X coordinate of the P-256 (secp256r1) public key
     * @param pubKeyY Y coordinate of the P-256 (secp256r1) public key
     */
    struct WebAuthnCredential {
        bytes32 pubKeyX;
        bytes32 pubKeyY;
    }

    /**
     * @notice Per-account credential storage: a mapping from credKey to credential plus
     *         an enumerable set of active credKeys for iteration during uninstall
     * @dev credKey = uint256(keyId). The enumerable set enables iterating all credentials
     *      during onUninstall cleanup and provides O(1) membership checks for add/remove
     *      operations.
     */
    struct PasskeyCredentials {
        mapping(uint256 credKey => WebAuthnCredential) credentials;
        EnumerableSetLib.Uint256Set enabledCredKeys;
    }

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Passkey credentials per account
    /// @dev credKey = uint256(keyId)
    mapping(address account => PasskeyCredentials) internal _passkeyCredentials;

    /*//////////////////////////////////////////////////////////////
                                 CONFIG
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Install the module with initial credentials, optional guardian, and optional timelock
     * @dev Called by the smart account during module installation (ERC-7579 lifecycle).
     *      msg.sender is the smart account itself, not an EOA or external caller.
     *      The data payload is ABI-encoded as parallel arrays plus guardian config:
     *        - keyIds: 16-bit credential identifiers (must be unique)
     *        - creds: P-256 public key coordinates, validated to be on the secp256r1 curve
     *        - guardian: optional recovery guardian address (address(0) to skip)
     *        - guardianTimelock: optional timelock duration in seconds for guardian changes (0 = immediate)
     * @param data abi.encode(uint16[] keyIds, WebAuthnCredential[] creds, address guardian, uint48 guardianTimelock)
     */
    function onInstall(bytes calldata data) external override {
        // msg.sender is the smart account (ERC-7579: the account calls onInstall during module setup)
        address account = msg.sender;
        if (isInitialized(account)) revert ModuleAlreadyInitialized(account);

        // Decode the parallel arrays, optional guardian, and optional guardian timelock
        (
            uint16[] memory keyIds,
            WebAuthnCredential[] memory creds,
            address _guardian,
            uint48 _guardianTimelock
        ) = abi.decode(data, (uint16[], WebAuthnCredential[], address, uint48));
        uint256 length = creds.length;

        // Both arrays must be non-empty and equal length
        if (length == 0 || length != keyIds.length) {
            revert InvalidPublicKey();
        }
        if (length > MAX_CREDENTIALS) revert TooManyCredentials();

        PasskeyCredentials storage pc = _passkeyCredentials[account];
        for (uint256 i; i < length; ++i) {
            _storeCredential(pc, account, keyIds[i], creds[i].pubKeyX, creds[i].pubKeyY);
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

    /**
     * @notice Uninstall the module, clearing all credentials and guardian
     * @dev Called by the smart account during module removal (ERC-7579 lifecycle).
     *      msg.sender is the smart account. Iterates all enabled credKeys, deletes each
     *      credential's public key data, removes it from the enumerable set, and clears
     *      the guardian address.
     *      NOTE: Used recovery nonces (in _recoveryConfig[account].nonceUsed) are intentionally
     *      NOT cleared. This prevents replay attacks where a previously-used recovery signature
     *      could be replayed after reinstalling the module.
     */
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

        // Clear guardian + pending guardian + timelock state but leave nonceUsed intact to prevent replay after reinstallation
        delete _recoveryConfig[account].guardian;
        delete _recoveryConfig[account].pendingGuardian;
        delete _recoveryConfig[account].guardianActivatesAt;
        delete _recoveryConfig[account].guardianTimelock;

        _invalidateUVExemptions(account);

        emit ModuleUninitialized(account);
    }

    /**
     * @notice Check whether the module is installed for a given smart account
     * @dev An account is considered initialized if it has at least one credential registered.
     *      Since onInstall requires at least one credential and removeCredential prevents
     *      removing the last one, a zero count means never installed or fully uninstalled.
     * @param smartAccount The smart account address to check
     * @return True if the account has at least one registered credential
     */
    function isInitialized(address smartAccount) public view returns (bool) {
        return _passkeyCredentials[smartAccount].enabledCredKeys.length() > 0;
    }

    /**
     * @notice Get the number of credentials for an account
     * @param account The smart account address
     * @return The count of currently registered credentials
     */
    function credentialCount(address account) external view returns (uint256) {
        return _passkeyCredentials[account].enabledCredKeys.length();
    }

    /**
     * @notice Get all enabled credential keys for an account
     * @dev Each credKey is uint256(keyId).
     * @param account The smart account address
     * @return Array of credKey values
     */
    function getCredKeys(address account) external view returns (uint256[] memory) {
        return _passkeyCredentials[account].enabledCredKeys.values();
    }

    /**
     * @notice Add a new credential with a specific keyId
     * @dev msg.sender is the smart account calling this function directly (not via entrypoint).
     *      The module must already be installed (isInitialized check in _addCredential), preventing
     *      credentials from being added before onInstall establishes the account's credential set.
     * @param keyId 16-bit identifier for this credential
     * @param pubKeyX X coordinate of the P-256 public key (validated to be on curve)
     * @param pubKeyY Y coordinate of the P-256 public key (validated to be on curve)
     */
    function addCredential(uint16 keyId, bytes32 pubKeyX, bytes32 pubKeyY) external {
        // msg.sender is the smart account calling directly
        _addCredential(msg.sender, keyId, pubKeyX, pubKeyY);
    }

    /**
     * @notice Remove a credential by keyId
     * @dev msg.sender is the smart account calling this function directly. Prevents removing
     *      the last credential to maintain a liveness guarantee -- the account must always
     *      have at least one credential capable of signing to avoid permanent lockout.
     * @param keyId 16-bit identifier of the credential to remove
     */
    function removeCredential(uint16 keyId) external {
        // msg.sender is the smart account calling directly
        address account = msg.sender;
        PasskeyCredentials storage pc = _passkeyCredentials[account];
        uint256 len = pc.enabledCredKeys.length();

        // Must be initialized (has at least one credential)
        if (len == 0) revert NotInitialized(account);

        // Prevent removing the last credential -- the account would be permanently locked
        // since there would be no valid signer to authorize operations or add new credentials
        if (len <= 1) revert CannotRemoveLastCredential();

        uint256 ck = uint256(keyId);

        // EnumerableSetLib.remove returns false if the key was not in the set
        if (!pc.enabledCredKeys.remove(ck)) revert CredentialNotFound(keyId);
        delete pc.credentials[ck];
        emit CredentialRemoved(account, keyId);
    }

    /**
     * @notice Get the P-256 public key coordinates for a specific credential
     * @dev Returns (0, 0) if the credential does not exist.
     * @param keyId 16-bit identifier of the credential
     * @param account The smart account address that owns the credential
     * @return pubKeyX X coordinate of the P-256 public key (bytes32(0) if not found)
     * @return pubKeyY Y coordinate of the P-256 public key (bytes32(0) if not found)
     */
    function getCredential(
        uint16 keyId,
        address account
    )
        external
        view
        returns (bytes32 pubKeyX, bytes32 pubKeyY)
    {
        uint256 ck = uint256(keyId);
        WebAuthnCredential storage cred = _passkeyCredentials[account].credentials[ck];
        return (cred.pubKeyX, cred.pubKeyY);
    }

    /*//////////////////////////////////////////////////////////////
                                VALIDATE
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice ERC-4337 user operation validation (called by the EntryPoint)
     * @dev The account address is userOp.sender, NOT msg.sender (msg.sender is the EntryPoint).
     *      Returns VALIDATION_SUCCESS (0) if the signature is valid, or VALIDATION_FAILED (1)
     *      otherwise. Must never revert per ERC-4337 spec -- all failure cases return
     *      VALIDATION_FAILED instead.
     * @param userOp The packed user operation containing the signature in userOp.signature
     * @param userOpHash The hash of the user operation (used as the digest to verify)
     * @return ValidationData VALIDATION_SUCCESS (0) or VALIDATION_FAILED (1)
     */
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

    /**
     * @notice EIP-1271 signature validation (called by the smart account)
     * @dev The first parameter (sender) is intentionally ignored. Per ERC-7579, the smart
     *      account calls this function on the validator module, so msg.sender IS the smart
     *      account and is used as the account for credential lookup. The sender parameter
     *      (which would be the original caller of the smart account's isValidSignature)
     *      is not relevant for credential-based validation.
     * @param hash The hash of the data to validate
     * @param data The packed signature data (same format as userOp.signature)
     * @return bytes4 EIP1271_SUCCESS (0x1626ba7e) if valid, EIP1271_FAILED (0xffffffff) otherwise
     */
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

    /**
     * @notice ERC-7579 stateless validation extension -- credentials are provided externally
     *         in `data` rather than fetched from on-chain storage
     * @dev Unlike the stateful validateUserOp / isValidSignatureWithSender paths, this function
     *      does not look up credentials by account. Instead, the caller provides the public key
     *      and validation parameters in `data`, and the WebAuthn signature in `signature`.
     *      This enables off-chain verifiers to validate signatures without the module being installed.
     *
     *      NOTE: Unlike the stateful validation paths (validateUserOp, isValidSignatureWithSender)
     *      which return false/VALIDATION_FAILED on invalid input per ERC-4337, this function REVERTS
     *      on malformed input (InvalidSignatureData, ProofTooLong, InvalidMerkleProof). It only
     *      returns false for valid-format-but-wrong-signature cases (when WebAuthn.verify fails).
     *
     *      The `data` layout mirrors the stateful signature format (proof before credential data):
     *        [0]       proofLength (uint8)
     *        if proofLength == 0 (regular signing, challenge = _passkeyDigest(hash)):
     *          [1:33]                         pubKeyX
     *          [33:65]                        pubKeyY
     *          [65]                           requireUV (uint8)
     *        if proofLength > 0 (merkle proof, challenge = _passkeyMultichain(merkleRoot)):
     *          [1:33]                         merkleRoot (bytes32)
     *          [33:33+proofLength*32]         proof (bytes32[])
     *          [proofEnd:proofEnd+32]         pubKeyX
     *          [proofEnd+32:proofEnd+64]      pubKeyY
     *          [proofEnd+64]                  requireUV (uint8)
     *      `signature` is packed WebAuthnAuth (see P256Lib.parseWebAuthnAuth for format).
     * @param hash The digest to validate (or a leaf in the merkle tree for batch signing)
     * @param signature Packed WebAuthnAuth struct (r, s, challengeIndex, typeIndex, authenticatorData, clientDataJSON)
     * @param data Packed credential and proof data as described above
     * @return True if the signature is valid for the provided credentials
     */
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
            (WebAuthn.WebAuthnAuth memory auth, bool ok) = P256Lib.parseWebAuthnAuth(signature);
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
            (WebAuthn.WebAuthnAuth memory auth, bool ok) = P256Lib.parseWebAuthnAuth(signature);
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

    /**
     * @dev Hook called by WebAuthnRecoveryBase during recovery (recoverWithPasskey or
     *      recoverWithGuardian). When replace is false, delegates to _addCredential
     *      (additive). When replace is true, overwrites the existing credential at
     *      keyId in-place with the new public key (rotation).
     * @param account The smart account to add/replace the credential on
     * @param cred The new credential parameters (keyId, pubKeyX, pubKeyY, replace)
     */
    function _addCredentialRecovery(
        address account,
        NewCredential calldata cred
    )
        internal
        override
    {
        if (cred.replace) {
            _replaceCredential(account, cred.keyId, cred.pubKeyX, cred.pubKeyY);
        } else {
            _addCredential(account, cred.keyId, cred.pubKeyX, cred.pubKeyY);
        }
    }

    /*//////////////////////////////////////////////////////////////
                                INTERNAL
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Chain-specific EIP-712 challenge for single operation signing
     * @dev Uses Solady's _hashTypedData which includes chainId in the EIP-712 domain separator.
     *      This prevents cross-chain replay: a signature made on chain A cannot be reused on
     *      chain B. The domain also includes verifyingContract (this module's address), which
     *      prevents cross-contract replay.
     * @param digest The operation digest to wrap in the EIP-712 typed data envelope
     * @return The chain-specific EIP-712 hash to be used as the WebAuthn challenge
     */
    function _passkeyDigest(bytes32 digest) internal view returns (bytes32) {
        return _hashTypedData(EIP712Lib.PASSKEY_DIGEST_TYPEHASH.hash(digest));
    }

    /**
     * @notice Chain-agnostic EIP-712 challenge for merkle batch signing
     * @dev Uses Solady's _hashTypedDataSansChainId which omits chainId from the EIP-712 domain
     *      separator, enabling a single passkey signature over the merkle root to validate on
     *      multiple chains. The domain still includes verifyingContract, so the module must be
     *      deployed at the same address on all target chains (e.g., via CREATE2).
     * @param root The merkle root covering multiple operation digests across chains
     * @return The chain-agnostic EIP-712 hash to be used as the WebAuthn challenge
     */
    function _passkeyMultichain(bytes32 root) internal view returns (bytes32) {
        return _hashTypedDataSansChainId(EIP712Lib.PASSKEY_MULTICHAIN_TYPEHASH.hash(root));
    }

    /**
     * @notice Compute the passkey challenge for a single operation digest (chain-specific)
     * @dev Public convenience wrapper around _passkeyDigest for off-chain tooling to compute
     *      the exact challenge bytes the passkey must sign for regular (non-merkle) operations.
     * @param digest The operation digest (e.g., userOpHash)
     * @return The EIP-712 typed data hash to be used as the WebAuthn challenge
     */
    function getPasskeyDigest(bytes32 digest) public view returns (bytes32) {
        return _passkeyDigest(digest);
    }

    /**
     * @notice Compute the passkey challenge for a merkle root (chain-agnostic)
     * @dev Public convenience wrapper around _passkeyMultichain for off-chain tooling to
     *      compute the exact challenge bytes the passkey must sign for merkle batch operations.
     * @param root The merkle root of the operation digest tree
     * @return The chain-agnostic EIP-712 typed data hash to be used as the WebAuthn challenge
     */
    function getPasskeyMultichain(bytes32 root) public view returns (bytes32) {
        return _passkeyMultichain(root);
    }

    /**
     * @notice Add a credential to an initialized account with capacity checks
     * @dev Shared by addCredential() (user-initiated) and _addCredentialRecovery()
     *      (recovery-initiated). Validates initialization and capacity, then delegates
     *      to _storeCredential for the per-credential work.
     */
    function _addCredential(
        address account,
        uint16 keyId,
        bytes32 pubKeyX,
        bytes32 pubKeyY
    )
        internal
    {
        PasskeyCredentials storage pc = _passkeyCredentials[account];
        uint256 len = pc.enabledCredKeys.length();

        // Cannot add credentials before the module is installed via onInstall
        if (len == 0) revert NotInitialized(account);

        // Enforce the credential cap to bound gas costs during onUninstall iteration
        if (len >= MAX_CREDENTIALS) revert TooManyCredentials();

        _storeCredential(pc, account, keyId, pubKeyX, pubKeyY);
    }

    /**
     * @notice Validate and store a single credential
     * @dev Shared by onInstall (batch) and _addCredential (single). Validates the public key
     *      is on the P-256 curve, rejects duplicate keyIds, writes storage, and emits event.
     *      Callers are responsible for initialization and capacity checks.
     */
    function _storeCredential(
        PasskeyCredentials storage pc,
        address account,
        uint16 keyId,
        bytes32 pubKeyX,
        bytes32 pubKeyY
    )
        internal
    {
        if (!P256Lib.isOnCurve(uint256(pubKeyX), uint256(pubKeyY))) revert InvalidPublicKey();
        uint256 ck = uint256(keyId);
        if (!pc.enabledCredKeys.add(ck)) revert KeyIdAlreadyExists(keyId);
        pc.credentials[ck] = WebAuthnCredential(pubKeyX, pubKeyY);
        emit CredentialAdded(account, keyId, pubKeyX, pubKeyY);
    }

    /**
     * @notice In-place rotation of an existing credential's public key
     * @dev Used by recovery to overwrite a compromised key. The credential at keyId must
     *      already exist; its public key is replaced with the new one.
     */
    function _replaceCredential(
        address account,
        uint16 keyId,
        bytes32 pubKeyX,
        bytes32 pubKeyY
    )
        internal
    {
        PasskeyCredentials storage pc = _passkeyCredentials[account];
        uint256 len = pc.enabledCredKeys.length();

        if (len == 0) revert NotInitialized(account);
        if (!P256Lib.isOnCurve(uint256(pubKeyX), uint256(pubKeyY))) revert InvalidPublicKey();

        uint256 ck = uint256(keyId);
        if (!pc.enabledCredKeys.contains(ck)) revert CredentialNotFound(keyId);

        pc.credentials[ck] = WebAuthnCredential(pubKeyX, pubKeyY);

        emit CredentialRemoved(account, keyId);
        emit CredentialAdded(account, keyId, pubKeyX, pubKeyY);
    }

    /**
     * @notice Core stateful validation -- router that dispatches to regular or merkle path
     * @dev Returns false (not revert) for all failure cases. This is required by ERC-4337:
     *      validateUserOp must not revert on invalid signatures, it must return VALIDATION_FAILED.
     *      The same return-false-on-failure convention is used throughout the validation chain.
     *
     *      Packed signature format:
     *        [0]                            proofLength (uint8)
     *        if proofLength == 0 (regular signing, challenge = digest):
     *          [1:3]                        keyId (uint16)
     *          [3]                          requestSkipUV (uint8, 0=require UV [safe default], non-zero=request skip)
     *          [4:]                         packed WebAuthnAuth
     *        if proofLength > 0 (merkle proof, challenge = merkleRoot):
     *          [1:33]                       merkleRoot (bytes32)
     *          [33:33+proofLength*32]       proof
     *          [proofEnd:proofEnd+2]        keyId (uint16)
     *          [proofEnd+2]                 requestSkipUV (uint8, 0=require UV [safe default], non-zero=request skip)
     *          [proofEnd+3:]                packed WebAuthnAuth
     * @param account The smart account address (for credential lookup)
     * @param digest The hash to validate (userOpHash or EIP-1271 hash)
     * @param data The packed signature data
     * @return True if the signature is valid
     */
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
        // Minimum 4 bytes: 1 (proofLength) + 2 (keyId) + 1 (requestSkipUV)
        if (data.length < 4) return false;

        uint256 proofLength = uint8(data[0]);

        // Dispatch: proofLength == 0 is regular signing, proofLength > 0 is merkle batch signing
        if (proofLength == 0) {
            return _validateRegular(account, digest, data);
        }

        return _validateMerkle(account, digest, data, proofLength);
    }

    /**
     * @notice Regular signing path (proofLength=0): challenge = chain-specific EIP-712 digest
     * @dev Extracts keyId and requestSkipUV from the packed signature header, looks up the
     *      credential by credKey, parses the WebAuthnAuth from the remaining calldata,
     *      and delegates to WebAuthn.verify. When requestSkipUV is set, extracts origin
     *      hashes directly from clientDataJSON in calldata and checks the UV exemption mapping.
     * @param account The smart account address for credential lookup
     * @param digest The hash to validate (wrapped in _passkeyDigest for chain-specific EIP-712)
     * @param data The full packed signature data (proofLength byte already consumed by caller)
     * @return True if the WebAuthn signature is valid for the stored credential
     */
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
        bool requestSkipUV = uint8(data[3]) != 0;

        // Look up the credential by keyId — loaded into memory for cheaper repeated access
        uint256 ck = uint256(keyId);
        WebAuthnCredential memory cred = _passkeyCredentials[account].credentials[ck];

        // pubKeyX == 0 means this credential slot is empty (never registered or was deleted).
        // Valid P-256 keys cannot have x=0 since that fails the P256Lib.isOnCurve check at registration.
        if (cred.pubKeyX == bytes32(0)) return false;

        // When UV skip is requested, extract origin hashes from calldata before memory parse
        bool requireUV = true;
        if (requestSkipUV) {
            bool allowed;
            (requireUV, allowed) = _resolveSkipUV(account, data[4:]);
            if (!allowed) return false;
        }

        // Parse the packed WebAuthnAuth from the remaining calldata after the 4-byte header
        (WebAuthn.WebAuthnAuth memory auth, bool ok) = P256Lib.parseWebAuthnAuth(data[4:]);
        if (!ok) return false;

        // Challenge is chain-specific: _passkeyDigest wraps digest in EIP-712 with chainId
        return WebAuthn.verify(
            abi.encode(_passkeyDigest(digest)), requireUV, auth, cred.pubKeyX, cred.pubKeyY
        );
    }

    /**
     * @notice Merkle signing path (proofLength>0): challenge = chain-agnostic EIP-712 hash of merkleRoot
     * @dev Verifies that `digest` is a leaf in the merkle tree rooted at `merkleRoot`, then
     *      validates the WebAuthn signature against the chain-agnostic challenge derived from
     *      the merkle root. This allows a single passkey signature to authorize multiple
     *      operations across multiple chains.
     * @param account The smart account address for credential lookup
     * @param digest The operation digest that should be a leaf in the merkle tree
     * @param data The full packed signature data including merkle proof and credential header
     * @param proofLength Number of 32-byte proof elements (already extracted from data[0])
     * @return True if the merkle proof verifies AND the WebAuthn signature is valid
     */
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

        // Minimum remaining data after proof: keyId (2) + requestSkipUV (1) = 3
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
        bool requestSkipUV = uint8(data[proofEnd + 2]) != 0;

        // Look up the credential by keyId — loaded into memory for cheaper repeated access
        uint256 ck = uint256(keyId);
        WebAuthnCredential memory cred = _passkeyCredentials[account].credentials[ck];
        if (cred.pubKeyX == bytes32(0)) return false;

        // When UV skip is requested, extract origin hashes from calldata before memory parse
        bool requireUV = true;
        if (requestSkipUV) {
            bool allowed;
            (requireUV, allowed) = _resolveSkipUV(account, data[proofEnd + 3:]);
            if (!allowed) return false;
        }

        // Parse WebAuthnAuth from remaining calldata after the 3-byte credential header
        (WebAuthn.WebAuthnAuth memory auth, bool ok) = P256Lib.parseWebAuthnAuth(data[proofEnd + 3:]);
        if (!ok) return false;

        // Challenge is chain-agnostic: _passkeyMultichain wraps merkleRoot in EIP-712 without chainId
        return WebAuthn.verify(
            abi.encode(_passkeyMultichain(merkleRoot)), requireUV, auth, cred.pubKeyX, cred.pubKeyY
        );
    }

    /*//////////////////////////////////////////////////////////////
                                METADATA
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice ERC-7579 module type check -- reports this module as both a standard validator
     *         (TYPE_VALIDATOR) and a stateless validator (TYPE_STATELESS_VALIDATOR)
     * @param typeID The ERC-7579 module type identifier to check
     * @return True if this module supports the given type
     */
    function isModuleType(uint256 typeID) external pure override returns (bool) {
        return typeID == TYPE_VALIDATOR || typeID == TYPE_STATELESS_VALIDATOR;
    }

    /**
     * @notice ERC-7579 module name
     */
    function name() external pure virtual returns (string memory) {
        return "WebAuthnValidatorV2";
    }

    /**
     * @notice ERC-7579 module version
     */
    function version() external pure virtual returns (string memory) {
        return "2.0.0";
    }
}
