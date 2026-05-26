// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";

import { MockRWA } from "./MockRWA.sol";

/// @title MockSwap — Baseline + jitter USDC → RWA swap for live demos
/// @notice One-directional swap used in the 1Auth interactive demo. The user
///         pays USDC (real Base Sepolia Circle USDC, 6 decimals) and receives a
///         mock RWA token (18 decimals) at a price that wobbles around an
///         owner-controlled baseline so the demo feels alive on screen.
/// @dev This is not a real AMM. There is no curve, no fee, no slippage from
///      depth. The "live" price is `basePrice + jitter(block.timestamp)` where
///      jitter is a deterministic value in `[-jitterRange, +jitterRange]`
///      derived from a 5-second timestamp bucket. Because jitter is fully
///      deterministic and visible on-chain, a bot could time txs to land in
///      the cheapest bucket — fine for a live demo, NOT acceptable for real
///      money. Use only in demos.
contract MockSwap is Ownable {
    using SafeERC20 for IERC20;

    /// @notice Width of each timestamp bucket in seconds. The jitter value is
    ///         constant within a bucket so `quote()` agrees with the next
    ///         `swap()` happening in the same window, and the displayed price
    ///         doesn't strobe every block.
    uint256 public constant JITTER_BUCKET_SECONDS = 5;

    /// @notice How many fast buckets share the same slow "drift" sample. With
    ///         `JITTER_BUCKET_SECONDS = 5` and a multiplier of 12, the drift
    ///         component changes every 60 seconds — giving the ticker a
    ///         visible macro trend on top of which the per-bucket noise wiggles.
    uint256 public constant DRIFT_BUCKET_MULTIPLIER = 12;

    /// @notice Share of the jitter band consumed by the slow drift (in
    ///         basis points). 7000 = 70% drift, 30% per-bucket noise. The
    ///         split is chosen so the sum still fits in `[-jitterRange,
    ///         +jitterRange]`, while a clear majority of the visible movement
    ///         comes from the slower trend (the noise is the small wiggle on
    ///         top, not the dominant signal).
    uint256 public constant DRIFT_BPS = 7000;

    /// @notice USDC accepted for swaps. Expected to be Circle's Base Sepolia
    ///         USDC at 0x036CbD53842c5426634e7929541eC2318f3dCF7e (6 decimals).
    IERC20 public immutable USDC;

    /// @notice The mocked RWA token paid out. 18 decimals.
    MockRWA public immutable RWA_TOKEN;

    /// @notice Recipient of every USDC payment. Set once at deployment so
    ///         collected funds skip this contract entirely and land directly
    ///         in the demo treasury / payout address. Cannot be the zero
    ///         address.
    address public immutable BENEFICIARY;

    /// @notice Baseline price in USDC's smallest unit (6 decimals) for one
    ///         whole RWA token (1e18). e.g. `200_000` = 0.20 USDC per share.
    /// @dev Public name kept as `pricePerShare` so existing frontends keep
    ///      working — but it is the BASELINE, not the live quote. Use
    ///      `getPrice()` to see what the next swap will actually charge.
    uint256 public pricePerShare;

    /// @notice Maximum deviation the live price can take above or below the
    ///         baseline, in USDC's smallest unit (6 decimals). e.g. `20_000`
    ///         means the live price walks within ±0.02 USDC of `pricePerShare`.
    ///         Set to zero to disable jitter (price always equals baseline).
    uint256 public jitterRange;

    /// @notice Emitted on every successful swap so the demo UI and the explorer
    ///         have a single event to render.
    /// @param user      The caller paying USDC.
    /// @param recipient The address that received the RWA tokens.
    /// @param usdcIn    USDC pulled from `user` (6-decimal units).
    /// @param rwaOut    RWA paid to `recipient` (18-decimal units).
    /// @param price     Live price used for this swap (6-decimal USDC).
    event Swapped(
        address indexed user,
        address indexed recipient,
        uint256 usdcIn,
        uint256 rwaOut,
        uint256 price
    );

    /// @notice Emitted when the owner changes the baseline price.
    event PriceUpdated(uint256 oldPrice, uint256 newPrice);

    /// @notice Emitted when the owner changes the jitter range.
    event JitterRangeUpdated(uint256 oldRange, uint256 newRange);

    /// @notice Baseline price was set to zero — would cause a div-by-zero in
    ///         `swap()`. We also reject configurations where `jitterRange`
    ///         could drive the live price to zero or below.
    error InvalidPrice();

    /// @notice `jitterRange` would allow the live price to reach zero (or
    ///         underflow it). Must satisfy `jitterRange < basePrice`.
    error InvalidJitter();

    /// @notice The contract does not hold enough RWA to fulfil this swap.
    error InsufficientLiquidity(uint256 requested, uint256 available);

    /// @notice Swap output is below the caller's `minRwaOut`.
    error SlippageExceeded(uint256 rwaOut, uint256 minRwaOut);

    /// @notice `usdcIn` was zero — refuse to emit a no-op event.
    error ZeroAmount();

    /// @notice `recipient` or `beneficiary` was the zero address.
    error ZeroRecipient();

    /// @param usdc           Base Sepolia USDC (6 decimals).
    /// @param rwaToken       RWA-style 18-decimal demo token.
    /// @param beneficiary    Address that receives every USDC payment. Must be
    ///                       non-zero. Immutable — pick the right address at
    ///                       deploy time.
    /// @param initialPrice   Initial BASELINE price in USDC's smallest unit per
    ///                       whole RWA token (e.g. `200_000` = 0.20 USDC/share).
    /// @param initialJitter  Initial jitter range in USDC's smallest unit.
    ///                       Pass `0` to disable jitter. Must be strictly less
    ///                       than `initialPrice` so the live price stays > 0.
    /// @param owner_         Address that may call `setPrice` / `setJitter` /
    ///                       `withdraw`.
    constructor(
        IERC20 usdc,
        MockRWA rwaToken,
        address beneficiary,
        uint256 initialPrice,
        uint256 initialJitter,
        address owner_
    )
        Ownable(owner_)
    {
        if (beneficiary == address(0)) revert ZeroRecipient();
        if (initialPrice == 0) revert InvalidPrice();
        if (initialJitter >= initialPrice) revert InvalidJitter();
        USDC = usdc;
        RWA_TOKEN = rwaToken;
        BENEFICIARY = beneficiary;
        pricePerShare = initialPrice;
        jitterRange = initialJitter;
    }

    /// @notice Live quoted price for the current timestamp bucket. This is
    ///         what the next swap (executed in the same 5-second window) will
    ///         use. UIs should poll this for the ticker display.
    /// @return price Live price in USDC's smallest unit (6 decimals).
    function getPrice() public view returns (uint256 price) {
        uint256 base = pricePerShare;
        uint256 range = jitterRange;
        if (range == 0) return base;

        // Why: bucket the timestamp so the displayed price doesn't change every
        // block — it'd flicker and `quote()` would disagree with the next
        // `swap()` in the same UI tick. 5s gives a visible heartbeat without
        // strobing. Determinism is intentional (demo only — see contract NatSpec).
        uint256 bucket = block.timestamp / JITTER_BUCKET_SECONDS;

        // Two deterministic components per the contract NatSpec:
        //   1. Slow drift: changes every DRIFT_BUCKET_MULTIPLIER fast buckets
        //      (default ~60s). Provides the macro trend that makes the ticker
        //      read as a price chart instead of white noise.
        //   2. Per-bucket noise: small wiggle on top of the drift, refreshed
        //      every fast bucket (5s).
        // Splits the band 70/30 by basis points so `|drift| + |noise| <= range`
        // strictly, keeping the price inside [base - range, base + range].
        uint256 driftRange = (range * DRIFT_BPS) / 10_000;
        uint256 noiseRange = range - driftRange;

        uint256 driftBucket = bucket / DRIFT_BUCKET_MULTIPLIER;
        int256 drift = _signedOffset(
            uint256(keccak256(abi.encode("drift", driftBucket, address(this)))),
            driftRange
        );
        int256 noise = _signedOffset(
            uint256(keccak256(abi.encode("noise", bucket, address(this)))),
            noiseRange
        );

        // base fits easily in int256 (it's a 6-decimal USDC amount, < 2^96 in
        // any sane configuration). drift + noise is bounded by ±range, which
        // is < base (enforced by setJitter / constructor), so the result is
        // always > 0.
        price = uint256(int256(base) + drift + noise);
    }

    /// @dev Map an arbitrary 256-bit hash into the signed range [-r, +r].
    function _signedOffset(uint256 hashWord, uint256 r) private pure returns (int256) {
        if (r == 0) return 0;
        uint256 offset = hashWord % (2 * r + 1);
        return int256(offset) - int256(r);
    }

    /// @notice Swap `usdcIn` USDC for RWA tokens at the live `getPrice()`.
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

        uint256 price = getPrice();

        // Why: USDC has 6 decimals and is priced in `price` per WHOLE RWA token
        // (1e18 base units). To get RWA in its native 18-decimal base units
        // from a 6-decimal USDC input, scale the numerator by 1e18 (the RWA
        // unit) and divide by `price * 1` — but `price` is itself 6-decimal,
        // so we end up with: rwa = usdcIn * 1e18 / price.
        rwaOut = (usdcIn * 1e18) / price;

        if (rwaOut < minRwaOut) revert SlippageExceeded(rwaOut, minRwaOut);

        uint256 available = RWA_TOKEN.balanceOf(address(this));
        if (rwaOut > available) revert InsufficientLiquidity(rwaOut, available);

        USDC.safeTransferFrom(msg.sender, BENEFICIARY, usdcIn);
        IERC20(address(RWA_TOKEN)).safeTransfer(recipient, rwaOut);

        emit Swapped(msg.sender, recipient, usdcIn, rwaOut, price);
    }

    /// @notice View helper: how much RWA you would receive for `usdcIn` USDC
    ///         right now, at the live `getPrice()`. Cheap to call from a
    ///         frontend before quoting the user.
    function quote(uint256 usdcIn) external view returns (uint256 rwaOut) {
        rwaOut = (usdcIn * 1e18) / getPrice();
    }

    /// @notice Update the baseline price.
    /// @dev Owner-only. Reverts if the existing `jitterRange` would no longer
    ///      fit under the new baseline.
    function setPrice(uint256 newPrice) external onlyOwner {
        if (newPrice == 0) revert InvalidPrice();
        if (jitterRange >= newPrice) revert InvalidJitter();
        emit PriceUpdated(pricePerShare, newPrice);
        pricePerShare = newPrice;
    }

    /// @notice Update the jitter range.
    /// @dev Owner-only. Must be strictly less than `pricePerShare` so the
    ///      live price stays positive. Pass `0` to disable jitter entirely.
    function setJitter(uint256 newRange) external onlyOwner {
        if (newRange >= pricePerShare) revert InvalidJitter();
        emit JitterRangeUpdated(jitterRange, newRange);
        jitterRange = newRange;
    }

    /// @notice Pull any ERC20 out of the contract — primarily used to drain
    ///         RWA liquidity between demos. USDC never accrues here (it goes
    ///         straight to `BENEFICIARY`) but `withdraw` still works for any
    ///         token that happens to land in the contract.
    /// @dev Owner-only. Intentionally unrestricted on which token can be
    ///      withdrawn; this is a demo, not a treasury.
    function withdraw(IERC20 token, uint256 amount, address to) external onlyOwner {
        token.safeTransfer(to, amount);
    }
}
