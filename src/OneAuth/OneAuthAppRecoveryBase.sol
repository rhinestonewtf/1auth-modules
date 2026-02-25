// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.28;

import { EIP712 } from "solady/utils/EIP712.sol";
import { GuardianVerifierLib } from "./lib/GuardianVerifierLib.sol";
import { EIP712Lib } from "./lib/EIP712Lib.sol";

/// @title OneAuthAppRecoveryBase
/// @notice Abstract recovery mixin for the OneAuth app validator.
/// @dev Provides guardian-based recovery that changes the main account pointer.
///      No passkey recovery path — the account owner can execute transactions directly
///      through the installed validator.
///
///      Uses the same dual-guardian architecture as OneAuthRecoveryBase:
///      - threshold=1: either guardian can authorize recovery alone
///      - threshold=2: both guardians must sign
///
///      Guardian configuration is independent from the main validator's guardians.
///      Uses chain-agnostic domain separator with chainId in the struct for cross-chain recovery.
///      chainId = 0 means valid on any chain; a non-zero chainId restricts recovery to that chain.
///
///      SECURITY: Recovery nonces survive uninstallation to prevent replay attacks.
abstract contract OneAuthAppRecoveryBase is EIP712 {
    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Emitted when guardian configuration is applied for an app account
    event AppGuardianConfigSet(
        address indexed account, address userGuardian, address externalGuardian, uint8 threshold
    );

    /// @notice Emitted when a recovery is executed via a guardian signature
    event AppRecoveryExecuted(
        address indexed account, address indexed guardian, address indexed newMainAccount, uint256 nonce
    );

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Thrown when block.timestamp exceeds the recovery message's expiry timestamp
    error RecoveryExpired();

    /// @notice Thrown when the recovery nonce has already been consumed (replay protection)
    error NonceAlreadyUsed();

    /// @notice Thrown when chainId is non-zero and does not match the current block.chainid
    error InvalidChainId();

    /// @notice Thrown when threshold is not 1 or 2
    error InvalidThreshold();

    /// @notice Thrown when threshold=2 but both guardians are not configured
    error ThresholdRequiresBothGuardians();

    /// @notice Thrown when recovery receives address(0) as newMainAccount
    error InvalidNewMainAccount();

    /*//////////////////////////////////////////////////////////////
                               STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Per-account recovery configuration for app validator
    /// @dev The nonceUsed mapping is intentionally NOT cleared on uninstall to prevent
    ///      replay of old recovery signatures if the module is reinstalled
    struct AppRecoveryConfig {
        GuardianVerifierLib.GuardianConfig guardian;
        mapping(uint256 nonce => bool) nonceUsed;
    }

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Recovery configuration per app account
    mapping(address account => AppRecoveryConfig) internal _appRecoveryConfig;

    /*//////////////////////////////////////////////////////////////
                              EIP-712 DOMAIN
    //////////////////////////////////////////////////////////////*/

    function _domainNameAndVersion()
        internal
        pure
        override
        returns (string memory name, string memory version)
    {
        name = "OneAuthAppValidator";
        version = "1.0.0";
    }

    /*//////////////////////////////////////////////////////////////
                            ABSTRACT HOOKS
    //////////////////////////////////////////////////////////////*/

    /// @dev Called after guardian verification succeeds to apply the main account change
    function _executeAppRecovery(address account, address newMainAccount) internal virtual;

    /*//////////////////////////////////////////////////////////////
                              MODIFIERS
    //////////////////////////////////////////////////////////////*/

    modifier validAppRecovery(address account, uint256 chainId, uint256 nonce, uint48 expiry) {
        if (block.timestamp > expiry) revert RecoveryExpired();
        if (_appRecoveryConfig[account].nonceUsed[nonce]) revert NonceAlreadyUsed();
        if (chainId != 0 && chainId != block.chainid) revert InvalidChainId();
        _appRecoveryConfig[account].nonceUsed[nonce] = true;
        _;
    }

    /*//////////////////////////////////////////////////////////////
                              CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Internal immediate guardian config set — used by onInstall
    function _setAppGuardianConfigImmediate(
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

        GuardianVerifierLib.GuardianConfig storage gc = _appRecoveryConfig[account].guardian;
        gc.userGuardian = _userGuardian;
        gc.externalGuardian = _externalGuardian;
        gc.threshold = _threshold;

        emit AppGuardianConfigSet(account, _userGuardian, _externalGuardian, _threshold);
    }

    /// @notice Set or change the guardian configuration for the caller's app account
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

        GuardianVerifierLib.GuardianConfig storage gc = _appRecoveryConfig[msg.sender].guardian;
        gc.userGuardian = _userGuardian;
        gc.externalGuardian = _externalGuardian;
        gc.threshold = _threshold;

        emit AppGuardianConfigSet(msg.sender, _userGuardian, _externalGuardian, _threshold);
    }

    /*//////////////////////////////////////////////////////////////
                                RECOVERY
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Recovers an app account by changing which main account it delegates to
     * @dev Callable by anyone (permissionless). Signature format depends on the account's threshold:
     *      - threshold=1: `[type_byte][sig]` where type_byte is `0x00` (user) or `0x01` (external)
     *      - threshold=2: `[user_sig_len: uint16][user_sig][external_sig]` (both must sign)
     */
    function recoverWithGuardian(
        address account,
        uint256 chainId,
        address newMainAccount,
        uint256 nonce,
        uint48 expiry,
        bytes calldata guardianSig
    )
        external
        validAppRecovery(account, chainId, nonce, expiry)
    {
        if (newMainAccount == address(0)) revert InvalidNewMainAccount();

        bytes32 digest = getRecoverDigest(account, chainId, newMainAccount, nonce, expiry);
        GuardianVerifierLib.GuardianConfig storage gc = _appRecoveryConfig[account].guardian;

        address guardian = GuardianVerifierLib.verifyGuardian(gc, digest, guardianSig);

        _executeAppRecovery(account, newMainAccount);

        emit AppRecoveryExecuted(account, guardian, newMainAccount, nonce);
    }

    /*//////////////////////////////////////////////////////////////
                              VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Returns the full guardian configuration for an app account
    function guardianConfig(address account)
        external
        view
        returns (address userGuardian, address externalGuardian, uint8 threshold)
    {
        GuardianVerifierLib.GuardianConfig storage gc = _appRecoveryConfig[account].guardian;
        return (gc.userGuardian, gc.externalGuardian, gc.threshold);
    }

    /// @notice Returns the effective guardian threshold for an app account (defaults to 1 if unset)
    function guardianThreshold(address account) external view returns (uint8) {
        uint8 t = _appRecoveryConfig[account].guardian.threshold;
        return t == 0 ? 1 : t;
    }

    /// @notice Checks whether a specific recovery nonce has been consumed for an app account
    function nonceUsed(address account, uint256 nonce) external view returns (bool) {
        return _appRecoveryConfig[account].nonceUsed[nonce];
    }

    /**
     * @notice Computes the EIP-712 recovery digest for off-chain or on-chain verification
     * @dev Uses `_hashTypedDataSansChainId` (chain-agnostic domain separator) so the domain
     *      does NOT include chainId. Instead, chainId is embedded in the struct hash.
     */
    function getRecoverDigest(
        address account,
        uint256 chainId,
        address newMainAccount,
        uint256 nonce,
        uint48 expiry
    )
        public
        view
        returns (bytes32)
    {
        return _hashTypedDataSansChainId(
            EIP712Lib.recoverAppValidatorHash(account, chainId, newMainAccount, nonce, expiry)
        );
    }
}
