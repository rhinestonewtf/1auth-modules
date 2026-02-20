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
///      Supports two guardian types per account with a configurable threshold:
///      - **User guardian**: a simple address (typically EOA) stored in GuardianConfig.
///        No contract deployment needed — ideal for a single trusted contact.
///      - **External guardian**: a Guardian.sol contract (EIP-1271). For M-of-N multisig cases
///        that need the full Guardian contract.
///      Both are optional. The **threshold** controls how many guardians must sign:
///      - threshold=1: recovery can be authorized by either guardian, selected via a type byte
///        prefix in `guardianSig`: `0x00` for user guardian, `0x01` for external guardian.
///      - threshold=2: both guardians must sign. The `guardianSig` format is
///        `[user_sig_len: uint16][user_sig][external_sig]`.
///
///      Guardian configuration (addresses + threshold) is set via `setGuardianConfig()`.
///      All changes take effect immediately.
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

    /// @notice Emitted when guardian configuration is applied for an account
    event GuardianConfigSet(
        address indexed account, address userGuardian, address externalGuardian, uint8 threshold
    );

    /// @notice Emitted when a recovery is executed via an existing passkey signature
    event PasskeyRecoveryExecuted(address indexed account, uint16 indexed newKeyId, uint256 nonce);

    /// @notice Emitted when a recovery is executed via a guardian signature
    event GuardianRecoveryExecuted(
        address indexed account, address indexed guardian, uint16 indexed newKeyId, uint256 nonce
    );

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

    /// @notice Thrown when threshold is not 1 or 2
    error InvalidThreshold();

    /// @notice Thrown when threshold=2 but both guardians are not configured
    error ThresholdRequiresBothGuardians();

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

    /// @notice Guardian addresses and signing threshold
    /// @dev threshold=1: either guardian can authorize recovery alone
    ///      threshold=2: both guardians must sign
    ///      threshold=0: treated as 1 (default for zero-initialized storage)
    struct GuardianConfig {
        address userGuardian;
        address externalGuardian;
        uint8 threshold;
    }

    /// @notice Per-account recovery configuration
    /// @dev The nonceUsed mapping is intentionally NOT cleared on uninstall to prevent
    ///      replay of old recovery signatures if the module is reinstalled
    struct RecoveryConfig {
        GuardianConfig guardian;
        mapping(uint256 nonce => bool) nonceUsed;
    }

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

    /// @notice Internal immediate guardian config set — used by onInstall
    function _setGuardianConfigImmediate(
        address account,
        address _userGuardian,
        address _externalGuardian,
        uint8 _threshold
    )
        internal
    {
        if (_threshold > 2) revert InvalidThreshold();
        if (_threshold == 2) {
            if (_userGuardian == address(0) || _externalGuardian == address(0)) {
                revert ThresholdRequiresBothGuardians();
            }
        }

        GuardianConfig storage gc = _recoveryConfig[account].guardian;
        gc.userGuardian = _userGuardian;
        gc.externalGuardian = _externalGuardian;
        gc.threshold = _threshold;

        emit GuardianConfigSet(account, _userGuardian, _externalGuardian, _threshold);
    }

    /// @notice Set or change the guardian configuration for the caller's account
    /// @param _userGuardian Address of the user guardian (address(0) to clear)
    /// @param _externalGuardian Address of the external guardian (address(0) to clear)
    /// @param _threshold 1 = either guardian, 2 = both required
    function setGuardianConfig(
        address _userGuardian,
        address _externalGuardian,
        uint8 _threshold
    )
        external
    {
        if (_threshold == 0 || _threshold > 2) revert InvalidThreshold();
        if (_threshold == 2) {
            if (_userGuardian == address(0) || _externalGuardian == address(0)) {
                revert ThresholdRequiresBothGuardians();
            }
        }

        GuardianConfig storage gc = _recoveryConfig[msg.sender].guardian;
        gc.userGuardian = _userGuardian;
        gc.externalGuardian = _externalGuardian;
        gc.threshold = _threshold;

        emit GuardianConfigSet(msg.sender, _userGuardian, _externalGuardian, _threshold);
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
     * @notice Recovers an account by adding or replacing a credential, authorized by guardian(s)
     * @dev Callable by anyone (permissionless). Signature format depends on the account's threshold:
     *      - threshold=1: `[type_byte][sig]` where type_byte is `0x00` (user) or `0x01` (external)
     *      - threshold=2: `[user_sig_len: uint16][user_sig][external_sig]` (both must sign)
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
        bytes32 digest = getRecoverDigest(account, chainId, cred, nonce, expiry);
        GuardianConfig storage gc = _recoveryConfig[account].guardian;
        uint8 t = gc.threshold;

        // threshold == 0 means default (1) for backward compatibility
        if (t <= 1) {
            _executeSingleGuardianRecovery(account, gc, digest, cred, nonce, guardianSig);
        } else {
            _executeDualGuardianRecovery(account, gc, digest, cred, nonce, guardianSig);
        }
    }

    /// @dev Single-guardian recovery path (threshold=1). Format: [type_byte][sig]
    function _executeSingleGuardianRecovery(
        address account,
        GuardianConfig storage gc,
        bytes32 digest,
        NewCredential calldata cred,
        uint256 nonce,
        bytes calldata guardianSig
    )
        internal
    {
        (address _guardian, bytes calldata sig) = _resolveGuardian(gc, guardianSig);

        if (!SignatureCheckerLib.isValidSignatureNowCalldata(_guardian, digest, sig)) {
            revert InvalidGuardianSignature();
        }

        _addCredentialRecovery(account, cred);

        emit GuardianRecoveryExecuted(account, _guardian, cred.keyId, nonce);
    }

    /// @dev Dual-guardian recovery path (threshold=2). Format: [user_sig_len: uint16][user_sig][external_sig]
    function _executeDualGuardianRecovery(
        address account,
        GuardianConfig storage gc,
        bytes32 digest,
        NewCredential calldata cred,
        uint256 nonce,
        bytes calldata guardianSig
    )
        internal
    {
        if (guardianSig.length < 2) revert EmptyGuardianSignature();

        uint256 userSigEnd = 2 + uint256(uint16(bytes2(guardianSig[0:2])));
        if (guardianSig.length < userSigEnd) revert InvalidGuardianSignature();

        if (gc.userGuardian == address(0) || gc.externalGuardian == address(0)) {
            revert GuardianNotConfigured();
        }

        if (!SignatureCheckerLib.isValidSignatureNowCalldata(gc.userGuardian, digest, guardianSig[2:userSigEnd]))
        {
            revert InvalidGuardianSignature();
        }
        if (!SignatureCheckerLib.isValidSignatureNowCalldata(gc.externalGuardian, digest, guardianSig[userSigEnd:]))
        {
            revert InvalidGuardianSignature();
        }

        address emitGuardian = gc.userGuardian;
        _addCredentialRecovery(account, cred);

        emit GuardianRecoveryExecuted(account, emitGuardian, cred.keyId, nonce);
    }

    /// @dev Parses the type byte prefix from guardianSig and resolves the guardian address
    function _resolveGuardian(
        GuardianConfig storage gc,
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
            guardian_ = gc.userGuardian;
        } else if (guardianType == 0x01) {
            guardian_ = gc.externalGuardian;
        } else {
            revert InvalidGuardianType();
        }

        if (guardian_ == address(0)) revert GuardianNotConfigured();
    }

    /*//////////////////////////////////////////////////////////////
                              VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Returns the full guardian configuration for an account
    function guardianConfig(address account)
        external
        view
        returns (address userGuardian, address externalGuardian, uint8 threshold)
    {
        GuardianConfig storage gc = _recoveryConfig[account].guardian;
        return (gc.userGuardian, gc.externalGuardian, gc.threshold);
    }

    /// @notice Returns the effective guardian threshold for an account (defaults to 1 if unset)
    function guardianThreshold(address account) external view returns (uint8) {
        uint8 t = _recoveryConfig[account].guardian.threshold;
        return t == 0 ? 1 : t;
    }

    /// @notice Checks whether a specific recovery nonce has been consumed for an account
    function nonceUsed(address account, uint256 nonce) external view returns (bool) {
        return _recoveryConfig[account].nonceUsed[nonce];
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
