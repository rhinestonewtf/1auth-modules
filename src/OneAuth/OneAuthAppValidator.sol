// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.28;

import { ERC7579ValidatorBase } from "modulekit/Modules.sol";
import { ERC7579ExecutorBase } from "modulekit/module-bases/ERC7579ExecutorBase.sol";
import { Execution } from "modulekit/accounts/common/interfaces/IERC7579Account.sol";
import { PackedUserOperation } from "modulekit/external/ERC4337.sol";
import { OneAuthValidator } from "./OneAuthValidator.sol";
import { OneAuthAppRecoveryBase } from "./OneAuthAppRecoveryBase.sol";
import { IOneAuthAppValidator } from "./IOneAuthAppValidator.sol";

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
}

/**
 * @title OneAuthAppValidator
 * @notice Delegated ERC-7579 validator + executor that reuses passkey credentials from a main OneAuthValidator.
 * @dev Each "app account" that installs this module specifies a "main account" whose passkey
 *      credentials (stored in the main OneAuthValidator) are used for signature verification.
 *
 *      This module stores no credentials. Validation is delegated to the main OneAuthValidator's
 *      validateSignatureForAccount(), which computes the EIP-712 domain (verifyingContract =
 *      address of main validator) and performs WebAuthn P-256 verification.
 *
 *      As an executor, exposes functions that let the main account pull assets (ERC20 tokens
 *      and native ETH) from the app account via executeFromExecutor.
 *
 *      Supports guardian-based recovery to change the main account pointer. Each app account
 *      has its own guardian configuration, independent of the main account's guardians.
 */
contract OneAuthAppValidator is
    ERC7579ValidatorBase,
    ERC7579ExecutorBase,
    OneAuthAppRecoveryBase,
    IOneAuthAppValidator
{
    /*//////////////////////////////////////////////////////////////
                            IMMUTABLE STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice The main OneAuthValidator that holds credentials and computes EIP-712 domains
    OneAuthValidator public immutable mainValidator;

    /*//////////////////////////////////////////////////////////////
                              STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Maps each app account to the main account whose credentials it delegates to
    mapping(address appAccount => address mainAccount) internal _mainAccounts;

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address _mainValidator) {
        if (_mainValidator == address(0)) revert InvalidMainValidator();
        mainValidator = OneAuthValidator(_mainValidator);
    }

    /*//////////////////////////////////////////////////////////////
                                CONFIG
    //////////////////////////////////////////////////////////////*/

    /// @notice Install the app validator for the caller's account
    /// @dev data format: abi.encode(address mainAccount, address userGuardian, address externalGuardian, uint8 guardianThreshold)
    ///      Idempotent — silently returns if already initialized (supports multi-type install: validator + executor).
    function onInstall(bytes calldata data) external override {
        address appAccount = msg.sender;
        if (_mainAccounts[appAccount] != address(0)) return;

        (address mainAccount, address userGuardian, address externalGuardian, uint8 guardianThreshold) =
            abi.decode(data, (address, address, address, uint8));
        if (mainAccount == address(0)) revert InvalidMainAccount();

        _mainAccounts[appAccount] = mainAccount;
        _setAppGuardianConfigImmediate(appAccount, userGuardian, externalGuardian, guardianThreshold);

        emit AppValidatorInstalled(appAccount, mainAccount);
    }

    /// @dev Idempotent — silently returns if already cleared (supports multi-type uninstall).
    function onUninstall(bytes calldata) external override {
        address appAccount = msg.sender;
        if (_mainAccounts[appAccount] == address(0)) return;

        delete _mainAccounts[appAccount];
        _setAppGuardianConfigImmediate(appAccount, address(0), address(0), 0);

        emit AppValidatorUninstalled(appAccount);
    }

    function isInitialized(address smartAccount) public view returns (bool) {
        return _mainAccounts[smartAccount] != address(0);
    }

    /// @notice Returns the main account linked to an app account (address(0) if not installed)
    function getMainAccount(address appAccount) external view returns (address) {
        return _mainAccounts[appAccount];
    }

    /*//////////////////////////////////////////////////////////////
                         RECOVERY HOOK
    //////////////////////////////////////////////////////////////*/

    /// @dev Called by OneAuthAppRecoveryBase after guardian verification succeeds
    function _executeAppRecovery(address account, address newMainAccount) internal override {
        address oldMainAccount = _mainAccounts[account];
        _mainAccounts[account] = newMainAccount;

        emit AppMainAccountRecovered(account, oldMainAccount, newMainAccount);
    }

    /*//////////////////////////////////////////////////////////////
                              VALIDATE
    //////////////////////////////////////////////////////////////*/

    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    )
        external
        view
        override
        returns (ValidationData)
    {
        address mainAccount = _mainAccounts[userOp.sender];
        if (mainAccount == address(0)) return VALIDATION_FAILED;

        // Bind the app account into the digest before delegating to the main validator.
        // This prevents cross-account replay: a signature for this app account cannot be
        // reused on another app account or the main account.
        bytes32 boundHash = keccak256(abi.encode(userOp.sender, userOpHash));

        if (mainValidator.validateSignatureForAccount(mainAccount, boundHash, userOp.signature)) {
            return VALIDATION_SUCCESS;
        }
        return VALIDATION_FAILED;
    }

    function isValidSignatureWithSender(
        address, /* sender -- ignored */
        bytes32 hash,
        bytes calldata data
    )
        external
        view
        override
        returns (bytes4)
    {
        address mainAccount = _mainAccounts[msg.sender];
        if (mainAccount == address(0)) return EIP1271_FAILED;

        // Bind the app account into the digest before delegating to the main validator.
        bytes32 boundHash = keccak256(abi.encode(msg.sender, hash));

        if (mainValidator.validateSignatureForAccount(mainAccount, boundHash, data)) {
            return EIP1271_SUCCESS;
        }
        return EIP1271_FAILED;
    }

    /*//////////////////////////////////////////////////////////////
                              EXECUTOR
    //////////////////////////////////////////////////////////////*/

    function setApprovalToMainAccount(address appAccount, address token, uint256 amount) external {
        address mainAccount = _mainAccounts[appAccount];
        if (msg.sender != mainAccount) revert OnlyMainAccount();

        _execute(appAccount, token, 0, abi.encodeCall(IERC20.approve, (mainAccount, amount)));
    }

    function transferToMainAccount(address appAccount, address token, uint256 amount) external {
        address mainAccount = _mainAccounts[appAccount];
        if (msg.sender != mainAccount) revert OnlyMainAccount();

        if (token == address(0)) {
            _execute(appAccount, mainAccount, amount, "");
        } else {
            _execute(appAccount, token, 0, abi.encodeCall(IERC20.transfer, (mainAccount, amount)));
        }
    }

    function batchSetApprovalToMainAccount(
        address appAccount,
        TokenAmount[] calldata tokens
    )
        external
    {
        address mainAccount = _mainAccounts[appAccount];
        if (msg.sender != mainAccount) revert OnlyMainAccount();

        Execution[] memory execs = new Execution[](tokens.length);
        for (uint256 i; i < tokens.length; i++) {
            execs[i] = Execution({
                target: tokens[i].token,
                value: 0,
                callData: abi.encodeCall(IERC20.approve, (mainAccount, tokens[i].amount))
            });
        }
        _execute(appAccount, execs);
    }

    function batchTransferToMainAccount(
        address appAccount,
        TokenAmount[] calldata tokens
    )
        external
    {
        address mainAccount = _mainAccounts[appAccount];
        if (msg.sender != mainAccount) revert OnlyMainAccount();

        Execution[] memory execs = new Execution[](tokens.length);
        for (uint256 i; i < tokens.length; i++) {
            if (tokens[i].token == address(0)) {
                execs[i] = Execution({ target: mainAccount, value: tokens[i].amount, callData: "" });
            } else {
                execs[i] = Execution({
                    target: tokens[i].token,
                    value: 0,
                    callData: abi.encodeCall(IERC20.transfer, (mainAccount, tokens[i].amount))
                });
            }
        }
        _execute(appAccount, execs);
    }

    /*//////////////////////////////////////////////////////////////
                              METADATA
    //////////////////////////////////////////////////////////////*/

    function isModuleType(uint256 typeID) external pure override returns (bool) {
        return typeID == TYPE_VALIDATOR || typeID == TYPE_EXECUTOR;
    }

    function name() external pure returns (string memory) {
        return "OneAuthAppValidator";
    }

    function version() external pure returns (string memory) {
        return "1.0.0";
    }
}
