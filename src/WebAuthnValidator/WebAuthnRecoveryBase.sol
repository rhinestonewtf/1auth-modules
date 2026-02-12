// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.28;

import { EIP712 } from "solady/utils/EIP712.sol";
import { SignatureCheckerLib } from "solady/utils/SignatureCheckerLib.sol";
import { EIP712Lib } from "./EIP712Lib.sol";

/// @title WebAuthnRecoveryBase
/// @notice Abstract recovery mixin for WebAuthn validators with EIP-712 typed data
/// @dev Provides two recovery paths:
///      1. Existing passkey signs an EIP-712 RecoverPasskey message (`recoverWithPasskey`)
///      2. Guardian (EOA or EIP-1271 smart contract) signs the same EIP-712 message (`recoverWithGuardian`)
///
///      Uses chain-agnostic domain separator with chainId in the struct for cross-chain recovery.
///      chainId = 0 means valid on any chain; a non-zero chainId restricts recovery to that chain.
///      Inheriting contract must implement the abstract hooks `_validateSignatureWithConfig`
///      and `_addCredentialRecovery`.
///
///      SECURITY CONSIDERATIONS:
///
///      - Recovery is additive only: Both recovery paths (`recoverWithPasskey` and
///        `recoverWithGuardian`) only add a new credential. They do NOT revoke existing
///        compromised credentials. The account must separately call `removeCredential()` on
///        the inheriting validator to revoke compromised keys after recovery.
///
///      - Guardian timelock: Guardian changes support an optional timelock. When a non-zero
///        guardianTimelock is configured, `proposeGuardian` queues the change and the account
///        must call `confirmGuardian` after the timelock elapses. When the timelock is zero
///        (the default), `proposeGuardian` takes effect immediately for backwards compatibility.
///
///      - Recovery nonces survive uninstallation: `onUninstall` (in the inheriting contract)
///        does NOT clear the `nonceUsed` mapping. This is intentional -- it prevents replay
///        of old recovery signatures if the module is reinstalled.
///
///      - Chain-agnostic domain with chainId in struct: Recovery uses
///        `_hashTypedDataSansChainId` for the domain separator (no chainId in domain) but
///        embeds `chainId` in the struct hash. This allows cross-chain recovery with
///        chainId=0 while still supporting chain-specific recovery with a non-zero chainId.
abstract contract WebAuthnRecoveryBase is EIP712 {
    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Emitted when a guardian address is set or cleared for an account
    /// @param account The smart account whose guardian was updated
    /// @param guardian The new guardian address (address(0) to disable guardian recovery)
    event GuardianSet(address indexed account, address indexed guardian);

    /// @notice Emitted when a recovery is executed via an existing passkey signature
    /// @param account The smart account that was recovered
    /// @param newKeyId The keyId of the newly added credential
    /// @param nonce The recovery nonce that was consumed
    event PasskeyRecoveryExecuted(address indexed account, uint16 indexed newKeyId, uint256 nonce);

    /// @notice Emitted when a recovery is executed via a guardian signature
    /// @param account The smart account that was recovered
    /// @param guardian The guardian that authorized the recovery
    /// @param newKeyId The keyId of the newly added credential
    /// @param nonce The recovery nonce that was consumed
    event GuardianRecoveryExecuted(
        address indexed account, address indexed guardian, uint16 indexed newKeyId, uint256 nonce
    );

    event GuardianChangeProposed(address indexed account, address indexed newGuardian, uint48 activatesAt);
    event GuardianChangeCancelled(address indexed account);
    event GuardianTimelockSet(address indexed account, uint48 duration);

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Thrown when block.timestamp exceeds the recovery message's expiry timestamp
    error RecoveryExpired();

    /// @notice Thrown when the recovery nonce has already been consumed (replay protection)
    error NonceAlreadyUsed();

    /// @notice Thrown in `recoverWithGuardian` when no guardian is configured for the account
    error GuardianNotConfigured();

    /// @notice Thrown in `recoverWithPasskey` when the passkey signature over the recovery digest is invalid
    error InvalidRecoverySignature();

    /// @notice Thrown in `recoverWithGuardian` when the guardian's signature over the recovery digest is invalid
    error InvalidGuardianSignature();

    /// @notice Thrown when chainId is non-zero and does not match the current block.chainid
    error InvalidChainId();

    error GuardianTimelockNotElapsed();
    error NoPendingGuardianChange();

    /*//////////////////////////////////////////////////////////////
                               STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Parameters for a new WebAuthn credential to be added during recovery
    /// @dev All fields are bound in the EIP-712 signed digest to prevent parameter substitution
    /// @param keyId Unique 16-bit identifier for this credential within the account
    /// @param pubKeyX X coordinate of the P-256 public key
    /// @param pubKeyY Y coordinate of the P-256 public key
    struct NewCredential {
        uint16 keyId;
        bytes32 pubKeyX;
        bytes32 pubKeyY;
    }

    /// @notice Per-account recovery configuration
    /// @dev The nonceUsed mapping is intentionally NOT cleared on uninstall to prevent
    ///      replay of old recovery signatures if the module is reinstalled
    /// @param guardian Address authorized to sign recovery messages (address(0) = disabled)
    /// @param nonceUsed Tracks consumed recovery nonces to prevent replay attacks
    struct RecoveryConfig {
        address guardian;
        address pendingGuardian;
        uint48 guardianActivatesAt;
        uint48 guardianTimelock;
        mapping(uint256 nonce => bool) nonceUsed;
    }

    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice EIP-712 typehash for the RecoverPasskey struct
    /// @dev Sourced from EIP712Lib (single source of truth). All credential fields (keyId,
    ///      pubKeyX, pubKeyY) plus account, chainId, nonce, and expiry are included
    ///      in the signed digest, preventing front-running attacks that substitute credential data.
    bytes32 public constant RECOVER_PASSKEY_TYPEHASH = EIP712Lib.RECOVER_PASSKEY_TYPEHASH;

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Recovery configuration per smart account (guardian address + consumed nonces)
    /// @dev Keyed by the smart account address. The guardian and nonceUsed mapping persist
    ///      independently of credential state in the inheriting validator contract.
    mapping(address account => RecoveryConfig) internal _recoveryConfig;

    /*//////////////////////////////////////////////////////////////
                              EIP-712 DOMAIN
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Returns the EIP-712 domain name and version for this contract
     * @dev Domain name "WebAuthnValidator" and version "2.0.0" are used by both
     *      `_hashTypedData` (chain-specific, includes chainId in domain) and
     *      `_hashTypedDataSansChainId` (chain-agnostic, omits chainId from domain).
     *      Recovery operations use the chain-agnostic variant so that a single signature
     *      can be valid across multiple chains when chainId=0 in the struct.
     * @return name The EIP-712 domain name
     * @return version The EIP-712 domain version
     */
    function _domainNameAndVersion()
        internal
        pure
        override
        returns (string memory name, string memory version)
    {
        name = "WebAuthnValidator";
        version = "2.0.0";
    }

    /*//////////////////////////////////////////////////////////////
                            ABSTRACT HOOKS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Validates a WebAuthn signature against the account's stored credentials
     * @dev Must be implemented by the inheriting validator. Used in `recoverWithPasskey` to
     *      verify that an existing passkey authorized the recovery. The implementation should
     *      extract the keyId from `data`, look up the corresponding credential, and verify
     *      the WebAuthn signature over `digest`.
     * @param account The smart account whose credentials to validate against
     * @param digest The EIP-712 recovery digest that was signed
     * @param data The packed signature data containing keyId, credential selector, and WebAuthn auth
     * @return True if the signature is valid for any of the account's stored credentials
     */
    function _validateSignatureWithConfig(
        address account,
        bytes32 digest,
        bytes calldata data
    )
        internal
        view
        virtual
        returns (bool);

    /**
     * @notice Adds a new credential to the account during recovery
     * @dev Must be implemented by the inheriting validator. The implementation should validate
     *      the public key (e.g., on-curve check) and enforce that the module is initialized
     *      (i.e., the account has at least one existing credential). This check is what prevents
     *      recovery from being used to initialize an account that has not installed the module.
     * @param account The smart account to add the credential to
     * @param cred The new credential parameters (keyId, pubKeyX, pubKeyY)
     */
    function _addCredentialRecovery(address account, NewCredential calldata cred) internal virtual;

    /*//////////////////////////////////////////////////////////////
                              MODIFIERS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Validates common recovery preconditions and marks the nonce as consumed
     * @dev Performs three checks before executing the function body:
     *      1. Expiry: block.timestamp must not exceed the provided expiry timestamp
     *      2. Nonce: must not have been previously used (prevents replay attacks)
     *      3. ChainId: must be 0 (valid on any chain) or match block.chainid (chain-specific)
     *      The nonce is marked as used BEFORE executing the function body. This prevents
     *      re-entrancy on the nonce -- even if the function body makes external calls, the
     *      same nonce cannot be reused within the same transaction.
     * @param account The smart account being recovered
     * @param chainId The chain restriction (0 = any chain, non-zero = must match block.chainid)
     * @param nonce Unique nonce chosen by the signer to prevent replay
     * @param expiry Timestamp after which this recovery message is no longer valid
     */
    modifier validRecovery(address account, uint256 chainId, uint256 nonce, uint48 expiry) {
        // Reject expired recovery messages to limit the window of validity
        if (block.timestamp > expiry) revert RecoveryExpired();

        // Reject already-consumed nonces to prevent replay attacks
        if (_recoveryConfig[account].nonceUsed[nonce]) revert NonceAlreadyUsed();

        // Enforce chain restriction: chainId=0 allows any chain, otherwise must match exactly
        if (chainId != 0 && chainId != block.chainid) revert InvalidChainId();

        // Mark nonce as used BEFORE executing the function body (checks-effects pattern)
        // to prevent re-entrancy on the nonce
        _recoveryConfig[account].nonceUsed[nonce] = true;
        _;
    }

    /*//////////////////////////////////////////////////////////////
                              CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Internal immediate guardian set — used by onInstall for initial guardian setup
    /// @dev Bypasses the timelock since this is called during module installation
    function _setGuardianImmediate(address account, address _guardian) internal {
        _recoveryConfig[account].guardian = _guardian;
        emit GuardianSet(account, _guardian);
    }

    /// @notice Propose a new guardian for the caller's account
    /// @dev If guardianTimelock == 0, the change takes effect immediately.
    ///      Otherwise, the change is queued and must be confirmed after the timelock elapses.
    function proposeGuardian(address _guardian) external {
        RecoveryConfig storage rc = _recoveryConfig[msg.sender];
        uint48 timelock = rc.guardianTimelock;
        if (timelock == 0) {
            // No timelock — immediate effect
            rc.guardian = _guardian;
            emit GuardianSet(msg.sender, _guardian);
        } else {
            rc.pendingGuardian = _guardian;
            rc.guardianActivatesAt = uint48(block.timestamp) + timelock;
            emit GuardianChangeProposed(msg.sender, _guardian, rc.guardianActivatesAt);
        }
    }

    /// @notice Confirm a pending guardian change after the timelock has elapsed
    function confirmGuardian() external {
        RecoveryConfig storage rc = _recoveryConfig[msg.sender];
        if (rc.guardianActivatesAt == 0) revert NoPendingGuardianChange();
        if (block.timestamp < rc.guardianActivatesAt) revert GuardianTimelockNotElapsed();
        rc.guardian = rc.pendingGuardian;
        delete rc.pendingGuardian;
        delete rc.guardianActivatesAt;
        emit GuardianSet(msg.sender, rc.guardian);
    }

    /// @notice Cancel a pending guardian change
    function cancelGuardianChange() external {
        RecoveryConfig storage rc = _recoveryConfig[msg.sender];
        if (rc.guardianActivatesAt == 0) revert NoPendingGuardianChange();
        delete rc.pendingGuardian;
        delete rc.guardianActivatesAt;
        emit GuardianChangeCancelled(msg.sender);
    }

    /// @notice Set the guardian timelock duration for the caller's account
    /// @param duration Duration in seconds that guardian changes must wait before taking effect
    function setGuardianTimelock(uint48 duration) external {
        _recoveryConfig[msg.sender].guardianTimelock = duration;
        emit GuardianTimelockSet(msg.sender, duration);
    }

    /*//////////////////////////////////////////////////////////////
                                RECOVERY
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Recovers an account by adding a new credential, authorized by an existing passkey
     * @dev Callable by anyone (permissionless) -- security relies entirely on the cryptographic
     *      verification of the existing passkey's signature over the EIP-712 recovery digest.
     *      This requires at least one existing credential to sign the recovery; it cannot be
     *      used to recover from zero credentials.
     *
     *      The NewCredential struct fields (keyId, pubKeyX, pubKeyY) are all bound in the
     *      signed digest, preventing front-running attacks that substitute credential parameters
     *      between signature creation and on-chain submission.
     *
     *      NOTE: This only ADDS a new credential. It does NOT revoke the existing (potentially
     *      compromised) credential. The account must separately call `removeCredential()`.
     * @param account The smart account to recover
     * @param chainId Chain restriction: 0 for any chain, or a specific block.chainid
     * @param cred The new credential to add (keyId, pubKeyX, pubKeyY)
     * @param nonce Unique nonce to prevent replay (chosen by the signer)
     * @param expiry Timestamp after which this recovery is no longer valid
     * @param signature Packed WebAuthn signature from an existing credential on the account
     * @custom:security Permissionless -- anyone can submit, but only valid passkey signatures succeed
     */
    function recoverWithPasskey(
        address account,
        uint256 chainId,
        NewCredential calldata cred,
        uint256 nonce,
        uint48 expiry,
        bytes calldata signature
    )
        external
        validRecovery(account, chainId, nonce, expiry)
    {
        // Compute the EIP-712 digest binding all recovery parameters (account, chainId,
        // credential fields, nonce, expiry) into a single hash for signature verification
        bytes32 digest = getRecoverDigest(account, chainId, cred, nonce, expiry);

        // Verify an existing passkey on the account signed this recovery digest.
        // The signature contains the keyId selector + WebAuthn auth data.
        if (!_validateSignatureWithConfig(account, digest, signature)) {
            revert InvalidRecoverySignature();
        }

        // Add the new credential to the account. This is additive only -- existing
        // credentials remain active and must be removed separately if compromised.
        _addCredentialRecovery(account, cred);

        emit PasskeyRecoveryExecuted(account, cred.keyId, nonce);
    }

    /**
     * @notice Recovers an account by adding a new credential, authorized by the account's guardian
     * @dev Callable by anyone (permissionless) -- security relies on the guardian's signature
     *      over the EIP-712 recovery digest. The guardian must be pre-configured via `proposeGuardian`.
     *
     *      Uses Solady's `SignatureCheckerLib.isValidSignatureNowCalldata` which supports:
     *      - EOA guardians: standard ecrecover (65-byte ECDSA signatures)
     *      - Smart contract guardians: EIP-1271 `isValidSignature` via staticcall (no re-entrancy risk)
     *      This means the guardian can be a multisig, social recovery contract, or any EIP-1271 signer.
     *
     *      NOTE: This only ADDS a new credential. It does NOT revoke the existing (potentially
     *      compromised) credential. The account must separately call `removeCredential()`.
     * @param account The smart account to recover
     * @param chainId Chain restriction: 0 for any chain, or a specific block.chainid
     * @param cred The new credential to add (keyId, pubKeyX, pubKeyY)
     * @param nonce Unique nonce to prevent replay (chosen by the signer)
     * @param expiry Timestamp after which this recovery is no longer valid
     * @param guardianSig Signature from the guardian (ECDSA for EOA, or EIP-1271 for smart contract)
     * @custom:security Permissionless -- anyone can submit, but only valid guardian signatures succeed
     * @custom:security Uses staticcall for EIP-1271 verification, preventing re-entrancy via guardian
     */
    function recoverWithGuardian(
        address account,
        uint256 chainId,
        NewCredential calldata cred,
        uint256 nonce,
        uint48 expiry,
        bytes calldata guardianSig
    )
        external
        validRecovery(account, chainId, nonce, expiry)
    {
        // Load the guardian from storage; must be configured (non-zero) for guardian recovery
        address _guardian = _recoveryConfig[account].guardian;
        if (_guardian == address(0)) revert GuardianNotConfigured();

        // Compute the EIP-712 digest binding all recovery parameters
        bytes32 digest = getRecoverDigest(account, chainId, cred, nonce, expiry);

        // Verify the guardian signed this recovery digest.
        // isValidSignatureNowCalldata supports both EOA (ecrecover) and smart contract
        // (EIP-1271) guardians. The EIP-1271 check uses staticcall, so a malicious
        // guardian contract cannot re-enter this function.
        if (!SignatureCheckerLib.isValidSignatureNowCalldata(_guardian, digest, guardianSig)) {
            revert InvalidGuardianSignature();
        }

        // Add the new credential to the account. This is additive only -- existing
        // credentials remain active and must be removed separately if compromised.
        _addCredentialRecovery(account, cred);

        emit GuardianRecoveryExecuted(account, _guardian, cred.keyId, nonce);
    }

    /*//////////////////////////////////////////////////////////////
                              VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Returns the guardian address configured for an account
    /// @param account The smart account to query
    /// @return The guardian address, or address(0) if no guardian is configured
    function guardian(address account) external view returns (address) {
        return _recoveryConfig[account].guardian;
    }

    /// @notice Checks whether a specific recovery nonce has been consumed for an account
    /// @param account The smart account to query
    /// @param nonce The nonce to check
    /// @return True if the nonce has been used (recovery executed or replayed), false otherwise
    function nonceUsed(address account, uint256 nonce) external view returns (bool) {
        return _recoveryConfig[account].nonceUsed[nonce];
    }

    /// @notice Returns the guardian timelock duration for an account
    function guardianTimelock(address account) external view returns (uint48) {
        return _recoveryConfig[account].guardianTimelock;
    }

    /// @notice Returns pending guardian change info
    /// @return pendingGuardian The proposed guardian address (address(0) if none)
    /// @return activatesAt Timestamp when the change can be confirmed (0 if none)
    function pendingGuardianInfo(address account) external view returns (address pendingGuardian, uint48 activatesAt) {
        RecoveryConfig storage rc = _recoveryConfig[account];
        return (rc.pendingGuardian, rc.guardianActivatesAt);
    }

    /**
     * @notice Computes the EIP-712 recovery digest for off-chain or on-chain verification
     * @dev This is a public view function to allow off-chain tools to compute the exact digest
     *      that must be signed for recovery. The digest construction has two key design choices:
     *
     *      Uses `_hashTypedDataSansChainId` (chain-agnostic domain separator) so the domain
     *      does NOT include chainId. Instead, chainId is embedded in the struct hash. This
     *      allows a single signature with chainId=0 to be valid on any chain, while a
     *      non-zero chainId restricts validity to that specific chain.
     * @param account The smart account being recovered
     * @param chainId Chain restriction: 0 for any chain, or a specific block.chainid
     * @param cred The new credential parameters to bind in the digest
     * @param nonce Unique nonce for replay protection
     * @param expiry Timestamp deadline for the recovery
     * @return The EIP-712 typed data hash ready for signature verification
     */
    function getRecoverDigest(
        address account,
        uint256 chainId,
        NewCredential calldata cred,
        uint256 nonce,
        uint48 expiry
    )
        public
        view
        returns (bytes32)
    {
        // EIP712Lib.recoverPasskeyHash uses EfficientHashLib for gas-efficient struct hashing.
        // _hashTypedDataSansChainId omits chainId from the EIP-712 domain separator, but chainId
        // is included in the struct hash -- this enables the chainId=0 cross-chain recovery pattern.
        return _hashTypedDataSansChainId(
            EIP712Lib.recoverPasskeyHash(
                account, chainId, cred.keyId, cred.pubKeyX, cred.pubKeyY, nonce, expiry
            )
        );
    }
}
