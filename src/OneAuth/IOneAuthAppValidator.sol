// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.28;

/**
 * @title IOneAuthAppValidator
 * @notice Events and errors for the OneAuthAppValidator module
 */
interface IOneAuthAppValidator {
    /*//////////////////////////////////////////////////////////////
                                 STRUCTS
    //////////////////////////////////////////////////////////////*/

    struct TokenAmount {
        address token;
        uint256 amount;
    }

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Emitted when an app account links to a main account's credentials
    event AppValidatorInstalled(address indexed appAccount, address indexed mainAccount);
    /// @notice Emitted when an app account unlinks from its main account
    event AppValidatorUninstalled(address indexed appAccount);
    /// @notice Emitted when recovery changes the main account an app account delegates to
    event AppMainAccountRecovered(
        address indexed appAccount, address indexed oldMainAccount, address indexed newMainAccount
    );

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Thrown when the constructor receives address(0) as the main validator
    error InvalidMainValidator();
    /// @notice Thrown when onInstall receives address(0) as the main account
    error InvalidMainAccount();
    /// @notice Thrown when msg.sender is not the main account for the given app account
    error OnlyMainAccount();

    // NOTE: ModuleAlreadyInitialized(address) and NotInitialized(address) are inherited from IERC7579Module
}
