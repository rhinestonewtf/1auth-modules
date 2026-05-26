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

contract MockSwapTest is Test {
    USDCMock internal usdc;
    MockRWA internal rwa;
    MockSwap internal swap;

    address internal owner = makeAddr("owner");
    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");

    uint256 internal constant INITIAL_PRICE = 120 * 1e6; // 120 USDC per RWA
    uint256 internal constant LIQUIDITY = 1_000_000e18;

    function setUp() public {
        usdc = new USDCMock();
        rwa = new MockRWA("NVDAnon Tokenized Share", "NVDAnon", owner);
        swap = new MockSwap(IERC20(address(usdc)), rwa, INITIAL_PRICE, owner);

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
        new MockSwap(IERC20(address(usdc)), rwa, 0, owner);
    }

    function test_swap_happyPath() public {
        // Buy 1 whole RWA share at 120 USDC.
        uint256 usdcIn = 120 * 1e6;
        _fundAndApprove(alice, usdcIn);

        vm.prank(alice);
        uint256 rwaOut = swap.swap(usdcIn, 0, alice);

        assertEq(rwaOut, 1e18, "expected exactly 1 whole RWA");
        assertEq(rwa.balanceOf(alice), 1e18);
        assertEq(usdc.balanceOf(address(swap)), usdcIn);
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
        // Drain RWA liquidity, then attempt swap.
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
        // Owner can pull collected USDC after a swap.
        uint256 usdcIn = 12 * 1e6;
        _fundAndApprove(alice, usdcIn);
        vm.prank(alice);
        swap.swap(usdcIn, 0, alice);

        vm.prank(owner);
        swap.withdraw(IERC20(address(usdc)), usdcIn, bob);
        assertEq(usdc.balanceOf(bob), usdcIn);
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
        // Bound to ranges representative of a demo. `price` is 6-decimal USDC
        // per RWA share; cap inputs to avoid overflow in `usdcIn * 1e18`.
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

    /// @dev Rounds-down semantics: tiny `usdcIn` against a large price returns
    ///      zero RWA. The contract should not silently emit a no-op swap — but
    ///      it also doesn't reject zero output today. Document the behaviour.
    function test_swap_roundsDownToZero() public {
        // 1 wei of USDC against a 120 USDC/share price yields 1e18/120e6 ~ 8.3e9,
        // which is > 0, so pick a more aggressive price.
        vm.prank(owner);
        swap.setPrice(1e36); // absurdly high
        _fundAndApprove(alice, 1);

        vm.prank(alice);
        uint256 rwaOut = swap.swap(1, 0, alice);
        assertEq(rwaOut, 0, "rounds down to zero when price >> usdcIn*1e18");
    }
}
