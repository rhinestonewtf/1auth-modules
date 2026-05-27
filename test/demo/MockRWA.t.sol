// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import { Test } from "forge-std/Test.sol";
import { IERC20Errors } from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";

import { MockRWA } from "src/demo/MockRWA.sol";

contract MockRWATest is Test {
    MockRWA internal rwa;
    address internal owner = makeAddr("owner");
    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");

    function setUp() public {
        rwa = new MockRWA("NVDAnon Tokenized Share", "NVDAnon", owner);
    }

    function test_metadata() public view {
        assertEq(rwa.name(), "NVDAnon Tokenized Share");
        assertEq(rwa.symbol(), "NVDAnon");
        assertEq(rwa.decimals(), 18);
        assertEq(rwa.owner(), owner);
    }

    function test_mint_onlyOwner() public {
        vm.prank(owner);
        rwa.mint(alice, 1_000e18);
        assertEq(rwa.balanceOf(alice), 1_000e18);
    }

    function test_mint_revertsForNonOwner() public {
        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, alice)
        );
        rwa.mint(alice, 1);
    }

    function test_mint_zeroAmountIsNoop() public {
        vm.prank(owner);
        rwa.mint(alice, 0);
        assertEq(rwa.balanceOf(alice), 0);
        assertEq(rwa.totalSupply(), 0);
    }

    function test_mint_toZeroReverts() public {
        // OZ ERC20 disallows minting to the zero address.
        vm.prank(owner);
        vm.expectRevert(
            abi.encodeWithSelector(IERC20Errors.ERC20InvalidReceiver.selector, address(0))
        );
        rwa.mint(address(0), 1);
    }

    function test_transfer_toZeroReverts() public {
        vm.prank(owner);
        rwa.mint(alice, 100);
        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(IERC20Errors.ERC20InvalidReceiver.selector, address(0))
        );
        rwa.transfer(address(0), 1);
    }

    function test_transfer_insufficientBalanceReverts() public {
        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(IERC20Errors.ERC20InsufficientBalance.selector, alice, 0, 1)
        );
        rwa.transfer(bob, 1);
    }

    function test_selfTransferLeavesBalanceUnchanged() public {
        vm.prank(owner);
        rwa.mint(alice, 100);
        vm.prank(alice);
        rwa.transfer(alice, 100);
        assertEq(rwa.balanceOf(alice), 100);
    }

    function test_approveAndTransferFrom() public {
        vm.prank(owner);
        rwa.mint(alice, 100);
        vm.prank(alice);
        rwa.approve(bob, 100);
        vm.prank(bob);
        rwa.transferFrom(alice, bob, 100);
        assertEq(rwa.balanceOf(bob), 100);
        assertEq(rwa.allowance(alice, bob), 0);
    }

    function testFuzz_mintAccumulates(uint128 a, uint128 b) public {
        vm.startPrank(owner);
        rwa.mint(alice, a);
        rwa.mint(alice, b);
        vm.stopPrank();
        assertEq(rwa.balanceOf(alice), uint256(a) + uint256(b));
        assertEq(rwa.totalSupply(), uint256(a) + uint256(b));
    }
}
