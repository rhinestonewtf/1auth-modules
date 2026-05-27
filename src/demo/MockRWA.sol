// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import { ERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";

/// @title MockRWA — Mock tokenized real-world asset
/// @notice ERC20 used only in interactive 1Auth demos. Name and symbol are set at
///         deploy time so the same bytecode can stand in for an NVIDIA share
///         (NVDAnon), an S&P 500 tracker, gold, etc.
/// @dev Owner-mintable. There is no burn, no transfer hook, no allowance quirk —
///      the goal is to render as a plain ERC20 on a block explorer.
contract MockRWA is ERC20, Ownable {
    /// @param name_   ERC20 display name, e.g. "NVDAnon Tokenized Share"
    /// @param symbol_ ERC20 ticker, e.g. "NVDAnon"
    /// @param owner_  Address allowed to mint. The deployer typically passes its own EOA.
    constructor(
        string memory name_,
        string memory symbol_,
        address owner_
    )
        ERC20(name_, symbol_)
        Ownable(owner_)
    { }

    /// @notice Mint `amount` tokens to `to`. Used to seed swap-contract liquidity
    ///         between demo runs.
    /// @dev Restricted to the owner. Demo-only: there is no supply cap.
    function mint(address to, uint256 amount) external onlyOwner {
        _mint(to, amount);
    }
}
