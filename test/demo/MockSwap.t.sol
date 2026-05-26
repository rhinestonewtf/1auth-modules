// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import { Test } from "forge-std/Test.sol";
import { ERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";

import { MockRWA } from "src/demo/MockRWA.sol";
import { MockSwap } from "src/demo/MockSwap.sol";

/// @dev Minimal stand-in for Circle's USDC. 6 decimals, freely mintable for tests.
contract USDCMock is ERC20 {
    constructor() ERC20("USD Coin", "USDC") { }

    function decimals() public pure override returns (uint8) {
        return 6;
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

/// @dev Most tests set jitter=0 in setUp so price math is deterministic
///      (live price == baseline). Jitter behaviour has dedicated tests below.
contract MockSwapTest is Test {
    USDCMock internal usdc;
    MockRWA internal rwa;
    MockSwap internal swap;

    address internal owner = makeAddr("owner");
    address internal beneficiary = makeAddr("beneficiary");
    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");

    uint256 internal constant INITIAL_PRICE = 120 * 1e6; // 120 USDC per RWA
    uint256 internal constant LIQUIDITY = 1_000_000e18;

    function setUp() public {
        usdc = new USDCMock();
        rwa = new MockRWA("NVDAnon Tokenized Share", "NVDAnon", owner);
        // jitter = 0 -> getPrice() == baseline, keeps existing assertions stable.
        swap = new MockSwap(
            IERC20(address(usdc)), rwa, beneficiary, INITIAL_PRICE, 0, owner
        );

        vm.prank(owner);
        rwa.mint(address(swap), LIQUIDITY);
    }

    function _fundAndApprove(address user, uint256 usdcAmount) internal {
        usdc.mint(user, usdcAmount);
        vm.prank(user);
        usdc.approve(address(swap), usdcAmount);
    }

    function test_constructor_zeroPriceReverts() public {
        vm.expectRevert(MockSwap.InvalidPrice.selector);
        new MockSwap(IERC20(address(usdc)), rwa, beneficiary, 0, 0, owner);
    }

    function test_constructor_zeroBeneficiaryReverts() public {
        vm.expectRevert(MockSwap.ZeroRecipient.selector);
        new MockSwap(IERC20(address(usdc)), rwa, address(0), 1, 0, owner);
    }

    function test_constructor_jitterAtOrAboveBaseReverts() public {
        vm.expectRevert(MockSwap.InvalidJitter.selector);
        new MockSwap(IERC20(address(usdc)), rwa, beneficiary, 100, 100, owner);

        vm.expectRevert(MockSwap.InvalidJitter.selector);
        new MockSwap(IERC20(address(usdc)), rwa, beneficiary, 100, 101, owner);
    }

    function test_constructor_setsBeneficiary() public view {
        assertEq(swap.BENEFICIARY(), beneficiary);
    }

    function test_swap_happyPath() public {
        // Buy 1 whole RWA share at 120 USDC.
        uint256 usdcIn = 120 * 1e6;
        _fundAndApprove(alice, usdcIn);

        vm.prank(alice);
        uint256 rwaOut = swap.swap(usdcIn, 0, alice);

        assertEq(rwaOut, 1e18, "expected exactly 1 whole RWA");
        assertEq(rwa.balanceOf(alice), 1e18);
        assertEq(usdc.balanceOf(beneficiary), usdcIn, "USDC must flow to beneficiary");
        assertEq(usdc.balanceOf(address(swap)), 0, "swap must not hold USDC");
        assertEq(usdc.balanceOf(alice), 0);
    }

    function test_swap_routesToDifferentRecipient() public {
        uint256 usdcIn = 60 * 1e6;
        _fundAndApprove(alice, usdcIn);

        vm.prank(alice);
        uint256 rwaOut = swap.swap(usdcIn, 0, bob);

        assertEq(rwaOut, 0.5e18);
        assertEq(rwa.balanceOf(bob), 0.5e18);
        assertEq(rwa.balanceOf(alice), 0);
    }

    function test_swap_emitsEvent() public {
        uint256 usdcIn = 12 * 1e6;
        _fundAndApprove(alice, usdcIn);

        vm.expectEmit(true, true, false, true, address(swap));
        emit MockSwap.Swapped(alice, alice, usdcIn, 0.1e18, INITIAL_PRICE);

        vm.prank(alice);
        swap.swap(usdcIn, 0, alice);
    }

    function test_swap_zeroAmountReverts() public {
        vm.prank(alice);
        vm.expectRevert(MockSwap.ZeroAmount.selector);
        swap.swap(0, 0, alice);
    }

    function test_swap_zeroRecipientReverts() public {
        _fundAndApprove(alice, 1e6);
        vm.prank(alice);
        vm.expectRevert(MockSwap.ZeroRecipient.selector);
        swap.swap(1e6, 0, address(0));
    }

    function test_swap_slippageReverts() public {
        uint256 usdcIn = 120 * 1e6;
        _fundAndApprove(alice, usdcIn);

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(MockSwap.SlippageExceeded.selector, 1e18, 1e18 + 1)
        );
        swap.swap(usdcIn, 1e18 + 1, alice);
    }

    function test_swap_insufficientLiquidityReverts() public {
        vm.prank(owner);
        swap.withdraw(IERC20(address(rwa)), LIQUIDITY, owner);

        uint256 usdcIn = 1 * 1e6;
        _fundAndApprove(alice, usdcIn);

        uint256 expectedOut = (uint256(1e6) * 1e18) / INITIAL_PRICE;
        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(MockSwap.InsufficientLiquidity.selector, expectedOut, 0)
        );
        swap.swap(usdcIn, 0, alice);
    }

    function test_setPrice_takesEffectImmediately() public {
        uint256 newPrice = 200 * 1e6;

        vm.expectEmit(false, false, false, true, address(swap));
        emit MockSwap.PriceUpdated(INITIAL_PRICE, newPrice);
        vm.prank(owner);
        swap.setPrice(newPrice);

        assertEq(swap.pricePerShare(), newPrice);

        uint256 usdcIn = 200 * 1e6;
        _fundAndApprove(alice, usdcIn);

        vm.prank(alice);
        uint256 rwaOut = swap.swap(usdcIn, 0, alice);
        assertEq(rwaOut, 1e18, "price change must affect next swap");
    }

    function test_setPrice_zeroReverts() public {
        vm.prank(owner);
        vm.expectRevert(MockSwap.InvalidPrice.selector);
        swap.setPrice(0);
    }

    function test_setPrice_revertsIfJitterNoLongerFits() public {
        // Set a real jitter, then try to lower baseline below it.
        vm.startPrank(owner);
        swap.setJitter(50 * 1e6); // ±50 USDC jitter
        vm.expectRevert(MockSwap.InvalidJitter.selector);
        swap.setPrice(50 * 1e6); // would make jitter >= base
        vm.stopPrank();
    }

    function test_setPrice_onlyOwner() public {
        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, alice)
        );
        swap.setPrice(1);
    }

    function test_withdraw_onlyOwner() public {
        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, alice)
        );
        swap.withdraw(IERC20(address(rwa)), 1, alice);
    }

    function test_withdraw_movesTokens() public {
        // USDC goes straight to beneficiary on swap, so to exercise `withdraw`
        // we drain RWA liquidity (the main reason `withdraw` still exists).
        vm.prank(owner);
        swap.withdraw(IERC20(address(rwa)), LIQUIDITY, bob);
        assertEq(rwa.balanceOf(bob), LIQUIDITY);
        assertEq(rwa.balanceOf(address(swap)), 0);
    }

    function test_quote_matchesSwap() public {
        uint256 usdcIn = 37 * 1e6;
        uint256 quoted = swap.quote(usdcIn);

        _fundAndApprove(alice, usdcIn);
        vm.prank(alice);
        uint256 rwaOut = swap.swap(usdcIn, 0, alice);
        assertEq(rwaOut, quoted, "quote must equal actual swap output");
    }

    function testFuzz_swapMath(uint256 usdcIn, uint256 price) public {
        price = bound(price, 1, 1_000_000_000 * 1e6); // up to $1B / share
        usdcIn = bound(usdcIn, 1, 1e36);

        vm.prank(owner);
        swap.setPrice(price);

        uint256 expected = (usdcIn * 1e18) / price;
        vm.assume(expected > 0 && expected <= LIQUIDITY);

        _fundAndApprove(alice, usdcIn);
        vm.prank(alice);
        uint256 rwaOut = swap.swap(usdcIn, 0, alice);
        assertEq(rwaOut, expected);
    }

    function testFuzz_quoteAndSwapAgree(uint256 usdcIn) public {
        usdcIn = bound(usdcIn, 1, 1_000_000 * 1e6); // up to 1M USDC
        uint256 quoted = swap.quote(usdcIn);
        vm.assume(quoted > 0 && quoted <= LIQUIDITY);

        _fundAndApprove(alice, usdcIn);
        vm.prank(alice);
        uint256 rwaOut = swap.swap(usdcIn, 0, alice);
        assertEq(rwaOut, quoted);
    }

    function test_swap_roundsDownToZero() public {
        vm.prank(owner);
        swap.setPrice(1e36);
        _fundAndApprove(alice, 1);

        vm.prank(alice);
        uint256 rwaOut = swap.swap(1, 0, alice);
        assertEq(rwaOut, 0, "rounds down to zero when price >> usdcIn*1e18");
    }

    // ---------------------------------------------------------------------
    // Jitter behaviour
    // ---------------------------------------------------------------------

    function test_getPrice_equalsBaselineWhenJitterZero() public view {
        assertEq(swap.getPrice(), INITIAL_PRICE);
    }

    function test_setJitter_onlyOwner() public {
        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, alice)
        );
        swap.setJitter(1);
    }

    function test_setJitter_atOrAboveBaseReverts() public {
        vm.startPrank(owner);
        vm.expectRevert(MockSwap.InvalidJitter.selector);
        swap.setJitter(INITIAL_PRICE);

        vm.expectRevert(MockSwap.InvalidJitter.selector);
        swap.setJitter(INITIAL_PRICE + 1);
        vm.stopPrank();
    }

    function test_setJitter_emitsEvent() public {
        vm.expectEmit(false, false, false, true, address(swap));
        emit MockSwap.JitterRangeUpdated(0, 1e6);
        vm.prank(owner);
        swap.setJitter(1e6);
        assertEq(swap.jitterRange(), 1e6);
    }

    function test_getPrice_constantWithinBucket() public {
        uint256 jitter = 5 * 1e6;
        vm.prank(owner);
        swap.setJitter(jitter);

        vm.warp(1_000_000); // bucket = 1_000_000 / 5 = 200_000
        uint256 p1 = swap.getPrice();
        vm.warp(1_000_001);
        vm.warp(1_000_004);
        uint256 p2 = swap.getPrice();
        assertEq(p1, p2, "price must not change inside a 5-second bucket");

        // Bucket boundary: 1_000_005 is the start of bucket 200_001.
        vm.warp(1_000_005);
        uint256 p3 = swap.getPrice();
        // p3 might equal p1 by collision; we can't strictly require inequality
        // without a tuned timestamp. Just assert it's still within range below.
        _assertWithinBand(p3, INITIAL_PRICE, jitter);
    }

    function test_getPrice_staysWithinBand() public {
        uint256 jitter = 2 * 1e6;
        vm.prank(owner);
        swap.setJitter(jitter);

        // Walk timestamps across many buckets and assert the price is always
        // within [base - jitter, base + jitter]. 200 samples covers ~1000s.
        for (uint256 i = 0; i < 200; i++) {
            vm.warp(1_700_000_000 + i * 5);
            _assertWithinBand(swap.getPrice(), INITIAL_PRICE, jitter);
        }
    }

    function test_getPrice_actuallyMovesAcrossBuckets() public {
        uint256 jitter = 5 * 1e6;
        vm.prank(owner);
        swap.setJitter(jitter);

        // Over many buckets, we should observe at least one price different
        // from the baseline — otherwise jitter is silently no-op.
        bool sawAbove;
        bool sawBelow;
        for (uint256 i = 0; i < 200; i++) {
            vm.warp(1_700_000_000 + i * 5);
            uint256 p = swap.getPrice();
            if (p > INITIAL_PRICE) sawAbove = true;
            if (p < INITIAL_PRICE) sawBelow = true;
            if (sawAbove && sawBelow) break;
        }
        assertTrue(sawAbove, "jitter should produce prices above baseline");
        assertTrue(sawBelow, "jitter should produce prices below baseline");
    }

    function test_swap_usesLivePriceNotBaseline() public {
        // Walk to a bucket where the live price strictly differs from baseline.
        uint256 jitter = 5 * 1e6;
        vm.prank(owner);
        swap.setJitter(jitter);

        uint256 livePrice = INITIAL_PRICE;
        for (uint256 i = 0; i < 200; i++) {
            vm.warp(1_700_000_000 + i * 5);
            livePrice = swap.getPrice();
            if (livePrice != INITIAL_PRICE) break;
        }
        require(livePrice != INITIAL_PRICE, "couldn't find bucket with nonzero jitter");

        uint256 usdcIn = 120 * 1e6;
        _fundAndApprove(alice, usdcIn);

        vm.expectEmit(true, true, false, true, address(swap));
        emit MockSwap.Swapped(alice, alice, usdcIn, (usdcIn * 1e18) / livePrice, livePrice);

        vm.prank(alice);
        uint256 rwaOut = swap.swap(usdcIn, 0, alice);
        assertEq(rwaOut, (usdcIn * 1e18) / livePrice, "swap must use live price");
    }

    function _assertWithinBand(uint256 price, uint256 base, uint256 jitter) internal pure {
        assertGe(price, base - jitter, "price below jitter band");
        assertLe(price, base + jitter, "price above jitter band");
    }
}
