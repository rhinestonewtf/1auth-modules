// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";

import { MockRWA } from "./MockRWA.sol";

/// @title MockSwap — Fixed-price USDC → RWA swap for live demos
/// @notice One-directional swap used in the 1Auth interactive demo. The user
///         pays USDC (real Base Sepolia Circle USDC, 6 decimals) and receives a
///         mock RWA token (18 decimals) at an owner-controlled price.
/// @dev This is not a real AMM. There is no curve, no fee, no slippage from
///      depth — just a flat quoted price the demo operator can adjust between
///      runs. The contract is deliberately small so the demo audience can read
///      it on a block explorer.
contract MockSwap is Ownable {
    using SafeERC20 for IERC20;

    /// @notice USDC accepted for swaps. Expected to be Circle's Base Sepolia
    ///         USDC at 0x036CbD53842c5426634e7929541eC2318f3dCF7e (6 decimals).
    IERC20 public immutable USDC;

    /// @notice The mocked RWA token paid out. 18 decimals.
    MockRWA public immutable RWA_TOKEN;

    /// @notice Price quoted in USDC's smallest unit (6 decimals) for one whole
    ///         RWA token (1e18). e.g. `120 * 1e6` = 120 USDC per share.
    uint256 public pricePerShare;

    /// @notice Emitted on every successful swap so the demo UI and the explorer
    ///         have a single event to render.
    /// @param user      The caller paying USDC.
    /// @param recipient The address that received the RWA tokens.
    /// @param usdcIn    USDC pulled from `user` (6-decimal units).
    /// @param rwaOut    RWA paid to `recipient` (18-decimal units).
    /// @param price     `pricePerShare` at the time of swap (6-decimal USDC).
    event Swapped(
        address indexed user,
        address indexed recipient,
        uint256 usdcIn,
        uint256 rwaOut,
        uint256 price
    );

    /// @notice Emitted when the owner changes the quoted price.
    event PriceUpdated(uint256 oldPrice, uint256 newPrice);

    /// @notice `pricePerShare` was set to zero — would cause a division-by-zero.
    error InvalidPrice();

    /// @notice The contract does not hold enough RWA to fulfil this swap.
    error InsufficientLiquidity(uint256 requested, uint256 available);

    /// @notice Swap output is below the caller's `minRwaOut`.
    error SlippageExceeded(uint256 rwaOut, uint256 minRwaOut);

    /// @notice `usdcIn` was zero — refuse to emit a no-op event.
    error ZeroAmount();

    /// @notice `recipient` was the zero address.
    error ZeroRecipient();

    /// @param usdc            Base Sepolia USDC (6 decimals).
    /// @param rwaToken        RWA-style 18-decimal demo token.
    /// @param initialPrice    Initial price in USDC's smallest unit per whole
    ///                        RWA token (e.g. `120 * 1e6` for 120 USDC/share).
    /// @param owner_          Address that may call `setPrice` / `withdraw`.
    constructor(
        IERC20 usdc,
        MockRWA rwaToken,
        uint256 initialPrice,
        address owner_
    )
        Ownable(owner_)
    {
        if (initialPrice == 0) revert InvalidPrice();
        USDC = usdc;
        RWA_TOKEN = rwaToken;
        pricePerShare = initialPrice;
    }

    /// @notice Swap `usdcIn` USDC for RWA tokens at the current `pricePerShare`.
    /// @dev Caller must `approve(this, usdcIn)` on USDC first. Follows
    ///      checks-effects-interactions: pulls USDC, then sends RWA last.
    /// @param usdcIn     USDC amount to spend (6 decimals).
    /// @param minRwaOut  Revert if the resulting RWA output is less than this.
    /// @param recipient  Address that receives the RWA tokens.
    /// @return rwaOut    RWA paid out (18 decimals).
    function swap(
        uint256 usdcIn,
        uint256 minRwaOut,
        address recipient
    )
        external
        returns (uint256 rwaOut)
    {
        if (usdcIn == 0) revert ZeroAmount();
        if (recipient == address(0)) revert ZeroRecipient();

        uint256 price = pricePerShare;

        // Why: USDC has 6 decimals and is priced in `price` per WHOLE RWA token
        // (1e18 base units). To get RWA in its native 18-decimal base units
        // from a 6-decimal USDC input, scale the numerator by 1e18 (the RWA
        // unit) and divide by `price * 1` — but `price` is itself 6-decimal,
        // so we end up with: rwa = usdcIn * 1e18 / price. Working it out:
        //   rwa_whole  = usdcIn_whole / price_whole
        //   rwa_base   = usdcIn_base / 1e6 / (price_base / 1e6) * 1e18
        //              = usdcIn_base * 1e18 / price_base
        rwaOut = (usdcIn * 1e18) / price;

        if (rwaOut < minRwaOut) revert SlippageExceeded(rwaOut, minRwaOut);

        uint256 available = RWA_TOKEN.balanceOf(address(this));
        if (rwaOut > available) revert InsufficientLiquidity(rwaOut, available);

        USDC.safeTransferFrom(msg.sender, address(this), usdcIn);
        IERC20(address(RWA_TOKEN)).safeTransfer(recipient, rwaOut);

        emit Swapped(msg.sender, recipient, usdcIn, rwaOut, price);
    }

    /// @notice View helper: how much RWA you would receive for `usdcIn` USDC
    ///         right now. Cheap to call from a frontend before quoting the user.
    function quote(uint256 usdcIn) external view returns (uint256 rwaOut) {
        rwaOut = (usdcIn * 1e18) / pricePerShare;
    }

    /// @notice Update the quoted price.
    /// @dev Owner-only. Used between demo runs to reflect a "new" market price.
    function setPrice(uint256 newPrice) external onlyOwner {
        if (newPrice == 0) revert InvalidPrice();
        emit PriceUpdated(pricePerShare, newPrice);
        pricePerShare = newPrice;
    }

    /// @notice Pull any ERC20 out of the contract — used to refund collected
    ///         USDC or to drain RWA liquidity between demos.
    /// @dev Owner-only. Intentionally unrestricted on which token can be
    ///      withdrawn; this is a demo, not a treasury.
    function withdraw(IERC20 token, uint256 amount, address to) external onlyOwner {
        token.safeTransfer(to, amount);
    }
}
