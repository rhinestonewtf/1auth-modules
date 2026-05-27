// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import { ERC1155 } from "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";

/// @title MockNFT — Demo ERC1155 sold for USDC
/// @notice Companion contract to MockSwap. Used in a separate 1Auth live-demo
///         scene where the user pays USDC and receives an ERC1155 NFT (a
///         collectible / ticket / badge).
/// @dev ERC1155 is chosen over ERC721 so the same contract can list multiple
///      collectibles (`id` = collectible kind) and so a single deploy covers
///      the whole demo. USDC payments flow straight to an immutable
///      beneficiary, matching MockSwap's pattern.
contract MockNFT is ERC1155, Ownable {
    using SafeERC20 for IERC20;

    /// @notice USDC accepted for purchases. Same Base Sepolia Circle USDC
    ///         (`0x036CbD53842c5426634e7929541eC2318f3dCF7e`, 6 decimals) used
    ///         elsewhere in the demo.
    IERC20 public immutable USDC;

    /// @notice Recipient of every USDC payment. Immutable — collected funds
    ///         skip this contract and land in the demo treasury directly.
    address public immutable BENEFICIARY;

    /// @notice Per-token price in USDC's smallest unit (6 decimals). A price
    ///         of zero means the token is not for sale via `buy()`; the owner
    ///         can still gift it via `mint()`.
    mapping(uint256 id => uint256 priceUsdc) public priceOf;

    /// @notice Emitted on each successful purchase. The demo UI / explorer
    ///         shows this alongside the standard ERC1155 `TransferSingle`.
    /// @param buyer       msg.sender, the address that paid USDC.
    /// @param recipient   Address that received the NFT (often == buyer).
    /// @param id          ERC1155 token id purchased.
    /// @param amount      Number of copies minted in this purchase.
    /// @param totalPrice  Total USDC charged (6-decimal units).
    event Purchased(
        address indexed buyer,
        address indexed recipient,
        uint256 indexed id,
        uint256 amount,
        uint256 totalPrice
    );

    /// @notice Emitted when the owner changes the per-id price.
    event PriceUpdated(uint256 indexed id, uint256 oldPrice, uint256 newPrice);

    /// @notice `id` has no listed price — purchase via `buy()` is disabled.
    error NotForSale(uint256 id);

    /// @notice `amount` was zero — refuse to emit a no-op purchase.
    error ZeroAmount();

    /// @notice `recipient` or `beneficiary` was the zero address.
    error ZeroRecipient();

    /// @param usdc         Base Sepolia USDC (6 decimals).
    /// @param beneficiary  Address that receives every USDC payment. Must be
    ///                     non-zero. Immutable — pick the right address at
    ///                     deploy time.
    /// @param baseUri      ERC1155 base URI string. Convention: include the
    ///                     `{id}` placeholder, e.g.
    ///                     `https://demo.example.com/nft/{id}.json`. Clients
    ///                     substitute it with the hex-padded id.
    /// @param owner_       Address allowed to set prices, mint giveaways, and
    ///                     update the URI.
    constructor(
        IERC20 usdc,
        address beneficiary,
        string memory baseUri,
        address owner_
    )
        ERC1155(baseUri)
        Ownable(owner_)
    {
        if (beneficiary == address(0)) revert ZeroRecipient();
        USDC = usdc;
        BENEFICIARY = beneficiary;
    }

    /// @notice Buy `amount` copies of token `id`, paying `priceOf[id] * amount`
    ///         USDC to `BENEFICIARY`. Reverts if the token is not listed.
    /// @dev Caller must `approve(this, totalPrice)` on USDC first.
    /// @return totalPrice USDC charged (6-decimal units).
    function buy(
        uint256 id,
        uint256 amount,
        address recipient
    )
        external
        returns (uint256 totalPrice)
    {
        if (amount == 0) revert ZeroAmount();
        if (recipient == address(0)) revert ZeroRecipient();

        uint256 unitPrice = priceOf[id];
        if (unitPrice == 0) revert NotForSale(id);

        totalPrice = unitPrice * amount;

        USDC.safeTransferFrom(msg.sender, BENEFICIARY, totalPrice);
        _mint(recipient, id, amount, "");

        emit Purchased(msg.sender, recipient, id, amount, totalPrice);
    }

    /// @notice List token `id` for sale at `priceUsdc` per copy. Pass `0` to
    ///         delist (then `buy()` reverts with `NotForSale`).
    function setPrice(uint256 id, uint256 priceUsdc) external onlyOwner {
        emit PriceUpdated(id, priceOf[id], priceUsdc);
        priceOf[id] = priceUsdc;
    }

    /// @notice Owner-only free mint. Useful for demo giveaways or pre-seeding
    ///         the operator's wallet with collectibles.
    function mint(address to, uint256 id, uint256 amount) external onlyOwner {
        _mint(to, id, amount, "");
    }

    /// @notice Update the ERC1155 base URI (e.g. swap CDN between demo runs).
    function setURI(string calldata newUri) external onlyOwner {
        _setURI(newUri);
    }
}
