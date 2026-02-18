// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.28;

import { EIP712 } from "solady/utils/EIP712.sol";
import { SignatureCheckerLib } from "solady/utils/SignatureCheckerLib.sol";
import { EIP712Lib } from "./lib/EIP712Lib.sol";

/// @title OneAuthRecoveryBase
/// @notice Abstract recovery mixin for OneAuth validators with EIP-712 typed data
/// @dev Provides two recovery paths:
///      1. Existing passkey signs an EIP-712 RecoverPasskey message (`recoverWithPasskey`)
///      2. Guardian signs the same EIP-712 message (`recoverWithGuardian`)
///
///      Supports two independent guardian types per account:
///      - **User guardian**: a simple address (typically EOA) stored directly in RecoveryConfig.
///        No contract deployment needed — ideal for a single trusted contact.
///      - **External guardian**: a Guardian.sol contract (EIP-1271). For M-of-N multisig cases
///        that need the full Guardian contract.
///      Both are optional. Recovery can be authorized by either one, selected via a type byte
///      prefix in `guardianSig`: `0x00` for user guardian, `0x01` for external guardian.
///
///      Uses chain-agnostic domain separator with chainId in the struct for cross-chain recovery.
///      chainId = 0 means valid on any chain; a non-zero chainId restricts recovery to that chain.
///      Inheriting contract must implement the abstract hooks `_validateSignatureWithConfig`
///      and `_addCredentialRecovery`.
///
///      SECURITY CONSIDERATIONS:
///
///      - Recovery supports in-place rotation: When `replace` is true in the `NewCredential`
///        struct, the credential at `keyId` has its public key overwritten in-place,
///        preventing the compromised key from being used. When `replace` is false,
///        recovery is additive only (new credential added, existing keys remain active).
///
///      - Guardian timelock: Guardian changes support an optional timelock. When a non-zero
///        guardianTimelock is configured and a guardian of the same type already exists,
///        `setUserGuardian`/`setExternalGuardian` queues the change and the account must call
///        `confirmGuardian` after the timelock elapses. Initial guardian set (when no guardian
///        of that type exists) always takes effect immediately regardless of timelock — adding
///        a guardian only makes the account more secure. When the timelock is zero (the default),
///        all changes take effect immediately. Only one pending guardian change is allowed at a
///        time; a new proposal overwrites any existing pending change.
///
///      - Recovery nonces survive uninstallation: `onUninstall` (in the inheriting contract)
///        does NOT clear the `nonceUsed` mapping. This is intentional -- it prevents replay
///        of old recovery signatures if the module is reinstalled.
///
///      - Chain-agnostic domain with chainId in struct: Recovery uses
///        `_hashTypedDataSansChainId` for the domain separator (no chainId in domain) but
///        embeds `chainId` in the struct hash. This allows cross-chain recovery with
///        chainId=0 while still supporting chain-specific recovery with a non-zero chainId.
abstract contract OneAuthRecoveryBase is EIP712 {
    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Emitted when a user guardian address is set or cleared for an account
    event UserGuardianSet(address indexed account, address indexed guardian);

    /// @notice Emitted when an external guardian address is set or cleared for an account
    event ExternalGuardianSet(address indexed account, address indexed guardian);

    /// @notice Emitted when a recovery is executed via an existing passkey signature
    event PasskeyRecoveryExecuted(address indexed account, uint16 indexed newKeyId, uint256 nonce);

    /// @notice Emitted when a recovery is executed via a guardian signature
    event GuardianRecoveryExecuted(
        address indexed account, address indexed guardian, uint16 indexed newKeyId, uint256 nonce
    );

    event GuardianChangeProposed(
        address indexed account, address indexed newGuardian, bool isExternal, uint48 activatesAt
    );
    event GuardianChangeCancelled(address indexed account);
    event GuardianTimelockSet(address indexed account, uint48 duration);

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Thrown when block.timestamp exceeds the recovery message's expiry timestamp
    error RecoveryExpired();

    /// @notice Thrown when the recovery nonce has already been consumed (replay protection)
    error NonceAlreadyUsed();

    /// @notice Thrown in `recoverWithGuardian` when the selected guardian type is not configured
    error GuardianNotConfigured();

    /// @notice Thrown in `recoverWithPasskey` when the passkey signature over the recovery digest is invalid
    error InvalidRecoverySignature();

    /// @notice Thrown in `recoverWithGuardian` when the guardian's signature over the recovery digest is invalid
    error InvalidGuardianSignature();

    /// @notice Thrown when chainId is non-zero and does not match the current block.chainid
    error InvalidChainId();

    /// @notice Thrown when the guardian type byte prefix is not 0x00 or 0x01
    error InvalidGuardianType();

    /// @notice Thrown when guardianSig is empty (no type byte)
    error EmptyGuardianSignature();

    error GuardianTimelockNotElapsed();
    error NoPendingGuardianChange();

    /*//////////////////////////////////////////////////////////////
                               STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Parameters for a new WebAuthn credential to be added during recovery
    struct NewCredential {
        uint16 keyId;
        bytes32 pubKeyX;
        bytes32 pubKeyY;
        bool replace;
    }

    /// @notice Per-account recovery configuration with two independent guardian types
    /// @dev The nonceUsed mapping is intentionally NOT cleared on uninstall to prevent
    ///      replay of old recovery signatures if the module is reinstalled
    struct RecoveryConfig {
        address userGuardian;
        address externalGuardian;
        address pendingGuardian;
        uint48 guardianActivatesAt;
        uint48 guardianTimelock;
        bool pendingIsExternal;
        mapping(uint256 nonce => bool) nonceUsed;
    }

    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Recovery configuration per smart account
    mapping(address account => RecoveryConfig) internal _recoveryConfig;

    /*//////////////////////////////////////////////////////////////
                              EIP-712 DOMAIN
    //////////////////////////////////////////////////////////////*/

    function _domainNameAndVersion()
        internal
        pure
        override
        returns (string memory name, string memory version)
    {
        name = "OneAuthValidator";
        version = "1.0.0";
    }

    /*//////////////////////////////////////////////////////////////
                            ABSTRACT HOOKS
    //////////////////////////////////////////////////////////////*/

    function _validateSignatureWithConfig(
        address account,
        bytes32 digest,
        bytes calldata data
    )
        internal
        view
        virtual
        returns (bool);

    function _addCredentialRecovery(address account, NewCredential calldata cred) internal virtual;

    /*//////////////////////////////////////////////////////////////
                              MODIFIERS
    //////////////////////////////////////////////////////////////*/

    modifier validRecovery(address account, uint256 chainId, uint256 nonce, uint48 expiry) {
        if (block.timestamp > expiry) revert RecoveryExpired();
        if (_recoveryConfig[account].nonceUsed[nonce]) revert NonceAlreadyUsed();
        if (chainId != 0 && chainId != block.chainid) revert InvalidChainId();
        _recoveryConfig[account].nonceUsed[nonce] = true;
        _;
    }

    /*//////////////////////////////////////////////////////////////
                              CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Internal immediate user guardian set — used by onInstall
    function _setUserGuardianImmediate(address account, address _guardian) internal {
        _recoveryConfig[account].userGuardian = _guardian;
        emit UserGuardianSet(account, _guardian);
    }

    /// @notice Internal immediate external guardian set — used by onInstall
    function _setExternalGuardianImmediate(address account, address _guardian) internal {
        _recoveryConfig[account].externalGuardian = _guardian;
        emit ExternalGuardianSet(account, _guardian);
    }

    /// @notice Set or change the user guardian for the caller's account
    /// @dev Initial set (when no user guardian exists) takes effect immediately regardless of
    ///      timelock. Subsequent changes are subject to the timelock if configured.
    ///      A new proposal overwrites any existing pending guardian change (of either type).
    function setUserGuardian(address _guardian) external {
        RecoveryConfig storage rc = _recoveryConfig[msg.sender];
        uint48 timelock = rc.guardianTimelock;
        if (timelock == 0 || rc.userGuardian == address(0)) {
            rc.userGuardian = _guardian;
            emit UserGuardianSet(msg.sender, _guardian);
        } else {
            rc.pendingGuardian = _guardian;
            rc.pendingIsExternal = false;
            rc.guardianActivatesAt = uint48(block.timestamp) + timelock;
            emit GuardianChangeProposed(msg.sender, _guardian, false, rc.guardianActivatesAt);
        }
    }

    /// @notice Set or change the external guardian for the caller's account
    /// @dev Initial set (when no external guardian exists) takes effect immediately regardless of
    ///      timelock. Subsequent changes are subject to the timelock if configured.
    ///      A new proposal overwrites any existing pending guardian change (of either type).
    function setExternalGuardian(address _guardian) external {
        RecoveryConfig storage rc = _recoveryConfig[msg.sender];
        uint48 timelock = rc.guardianTimelock;
        if (timelock == 0 || rc.externalGuardian == address(0)) {
            rc.externalGuardian = _guardian;
            emit ExternalGuardianSet(msg.sender, _guardian);
        } else {
            rc.pendingGuardian = _guardian;
            rc.pendingIsExternal = true;
            rc.guardianActivatesAt = uint48(block.timestamp) + timelock;
            emit GuardianChangeProposed(msg.sender, _guardian, true, rc.guardianActivatesAt);
        }
    }

    /// @notice Confirm a pending guardian change after the timelock has elapsed
    function confirmGuardian() external {
        RecoveryConfig storage rc = _recoveryConfig[msg.sender];
        if (rc.guardianActivatesAt == 0) revert NoPendingGuardianChange();
        if (block.timestamp < rc.guardianActivatesAt) revert GuardianTimelockNotElapsed();

        address newGuardian = rc.pendingGuardian;
        bool isExternal = rc.pendingIsExternal;

        delete rc.pendingGuardian;
        delete rc.guardianActivatesAt;
        delete rc.pendingIsExternal;

        if (isExternal) {
            rc.externalGuardian = newGuardian;
            emit ExternalGuardianSet(msg.sender, newGuardian);
        } else {
            rc.userGuardian = newGuardian;
            emit UserGuardianSet(msg.sender, newGuardian);
        }
    }

    /// @notice Cancel a pending guardian change
    function cancelGuardianChange() external {
        RecoveryConfig storage rc = _recoveryConfig[msg.sender];
        if (rc.guardianActivatesAt == 0) revert NoPendingGuardianChange();
        delete rc.pendingGuardian;
        delete rc.guardianActivatesAt;
        delete rc.pendingIsExternal;
        emit GuardianChangeCancelled(msg.sender);
    }

    /// @notice Set the guardian timelock duration for the caller's account
    function setGuardianTimelock(uint48 duration) external {
        _recoveryConfig[msg.sender].guardianTimelock = duration;
        emit GuardianTimelockSet(msg.sender, duration);
    }

    /*//////////////////////////////////////////////////////////////
                                RECOVERY
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Recovers an account by adding or replacing a credential, authorized by an existing passkey
     * @dev Callable by anyone (permissionless) -- security relies entirely on the cryptographic
     *      verification of the existing passkey's signature over the EIP-712 recovery digest.
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
        bytes32 digest = getRecoverDigest(account, chainId, cred, nonce, expiry);

        if (!_validateSignatureWithConfig(account, digest, signature)) {
            revert InvalidRecoverySignature();
        }

        _addCredentialRecovery(account, cred);

        emit PasskeyRecoveryExecuted(account, cred.keyId, nonce);
    }

    /**
     * @notice Recovers an account by adding or replacing a credential, authorized by a guardian
     * @dev Callable by anyone (permissionless). The first byte of `guardianSig` selects the
     *      guardian type: `0x00` for user guardian, `0x01` for external guardian. The remaining
     *      bytes are the actual signature passed to `SignatureCheckerLib`.
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
        _executeGuardianRecovery(account, chainId, cred, nonce, expiry, guardianSig);
    }

    function _executeGuardianRecovery(
        address account,
        uint256 chainId,
        NewCredential calldata cred,
        uint256 nonce,
        uint48 expiry,
        bytes calldata guardianSig
    )
        internal
    {
        (address _guardian, bytes calldata sig) = _resolveGuardian(account, guardianSig);

        bytes32 digest = getRecoverDigest(account, chainId, cred, nonce, expiry);

        if (!SignatureCheckerLib.isValidSignatureNowCalldata(_guardian, digest, sig)) {
            revert InvalidGuardianSignature();
        }

        _addCredentialRecovery(account, cred);

        emit GuardianRecoveryExecuted(account, _guardian, cred.keyId, nonce);
    }

    /// @dev Parses the type byte prefix from guardianSig and resolves the guardian address
    function _resolveGuardian(
        address account,
        bytes calldata guardianSig
    )
        internal
        view
        returns (address guardian_, bytes calldata sig)
    {
        if (guardianSig.length == 0) revert EmptyGuardianSignature();

        uint8 guardianType = uint8(guardianSig[0]);
        sig = guardianSig[1:];

        if (guardianType == 0x00) {
            guardian_ = _recoveryConfig[account].userGuardian;
        } else if (guardianType == 0x01) {
            guardian_ = _recoveryConfig[account].externalGuardian;
        } else {
            revert InvalidGuardianType();
        }

        if (guardian_ == address(0)) revert GuardianNotConfigured();
    }

    /*//////////////////////////////////////////////////////////////
                              VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Returns the user guardian address configured for an account
    function userGuardian(address account) external view returns (address) {
        return _recoveryConfig[account].userGuardian;
    }

    /// @notice Returns the external guardian address configured for an account
    function externalGuardian(address account) external view returns (address) {
        return _recoveryConfig[account].externalGuardian;
    }

    /// @notice Checks whether a specific recovery nonce has been consumed for an account
    function nonceUsed(address account, uint256 nonce) external view returns (bool) {
        return _recoveryConfig[account].nonceUsed[nonce];
    }

    /// @notice Returns the guardian timelock duration for an account
    function guardianTimelock(address account) external view returns (uint48) {
        return _recoveryConfig[account].guardianTimelock;
    }

    /// @notice Returns pending guardian change info
    /// @return pendingGuardian The proposed guardian address (address(0) if none)
    /// @return isExternal Whether the pending change is for the external guardian
    /// @return activatesAt Timestamp when the change can be confirmed (0 if none)
    function pendingGuardianInfo(address account)
        external
        view
        returns (address pendingGuardian, bool isExternal, uint48 activatesAt)
    {
        RecoveryConfig storage rc = _recoveryConfig[account];
        return (rc.pendingGuardian, rc.pendingIsExternal, rc.guardianActivatesAt);
    }

    /**
     * @notice Computes the EIP-712 recovery digest for off-chain or on-chain verification
     * @dev Uses `_hashTypedDataSansChainId` (chain-agnostic domain separator) so the domain
     *      does NOT include chainId. Instead, chainId is embedded in the struct hash.
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
        return _hashTypedDataSansChainId(
            EIP712Lib.recoverPasskeyHash(
                account, chainId, cred.keyId, cred.pubKeyX, cred.pubKeyY, cred.replace, nonce, expiry
            )
        );
    }
}
