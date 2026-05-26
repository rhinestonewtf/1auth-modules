// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import { Test } from "forge-std/Test.sol";
import { ERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { IERC20Errors } from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { IERC1155Receiver } from "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";

import { MockNFT } from "src/demo/MockNFT.sol";

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

/// @dev Contract that REJECTS ERC1155 receipts. Used to assert `_mint`'s
///      safeguard fires when the recipient is a non-acceptor contract.
contract NonReceiver { }

/// @dev Contract that ACCEPTS ERC1155 transfers. Used to confirm contracts
///      with proper hooks can receive purchased NFTs.
contract AcceptingReceiver is IERC1155Receiver {
    function onERC1155Received(address, address, uint256, uint256, bytes calldata)
        external
        pure
        returns (bytes4)
    {
        return IERC1155Receiver.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(
        address,
        address,
        uint256[] calldata,
        uint256[] calldata,
        bytes calldata
    )
        external
        pure
        returns (bytes4)
    {
        return IERC1155Receiver.onERC1155BatchReceived.selector;
    }

    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == type(IERC1155Receiver).interfaceId;
    }
}

contract MockNFTTest is Test {
    USDCMock internal usdc;
    MockNFT internal nft;

    address internal owner = makeAddr("owner");
    address internal beneficiary = makeAddr("beneficiary");
    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");

    string internal constant BASE_URI = "https://demo.example.com/nft/{id}.json";
    uint256 internal constant PRICE = 5 * 1e6; // 5 USDC per copy
    uint256 internal constant ID = 42;

    function setUp() public {
        usdc = new USDCMock();
        nft = new MockNFT(IERC20(address(usdc)), beneficiary, BASE_URI, owner);
        vm.prank(owner);
        nft.setPrice(ID, PRICE);
    }

    function _fundAndApprove(address user, uint256 usdcAmount) internal {
        usdc.mint(user, usdcAmount);
        vm.prank(user);
        usdc.approve(address(nft), usdcAmount);
    }

    // ---------------------------------------------------------------------
    // Constructor / metadata
    // ---------------------------------------------------------------------

    function test_constructor_setsImmutables() public view {
        assertEq(address(nft.USDC()), address(usdc));
        assertEq(nft.BENEFICIARY(), beneficiary);
        assertEq(nft.owner(), owner);
        assertEq(nft.uri(0), BASE_URI);
        assertEq(nft.uri(ID), BASE_URI, "OZ uri() returns the stored string for any id");
    }

    function test_constructor_zeroBeneficiaryReverts() public {
        vm.expectRevert(MockNFT.ZeroRecipient.selector);
        new MockNFT(IERC20(address(usdc)), address(0), BASE_URI, owner);
    }

    // ---------------------------------------------------------------------
    // buy()
    // ---------------------------------------------------------------------

    function test_buy_happyPath() public {
        _fundAndApprove(alice, PRICE);

        vm.expectEmit(true, true, true, true, address(nft));
        emit MockNFT.Purchased(alice, alice, ID, 1, PRICE);

        vm.prank(alice);
        uint256 total = nft.buy(ID, 1, alice);

        assertEq(total, PRICE);
        assertEq(nft.balanceOf(alice, ID), 1);
        assertEq(usdc.balanceOf(beneficiary), PRICE, "USDC must flow to beneficiary");
        assertEq(usdc.balanceOf(address(nft)), 0, "NFT contract must not hold USDC");
        assertEq(usdc.balanceOf(alice), 0);
    }

    function test_buy_multipleCopies() public {
        uint256 amount = 7;
        uint256 total = PRICE * amount;
        _fundAndApprove(alice, total);

        vm.prank(alice);
        uint256 paid = nft.buy(ID, amount, alice);

        assertEq(paid, total);
        assertEq(nft.balanceOf(alice, ID), amount);
        assertEq(usdc.balanceOf(beneficiary), total);
    }

    function test_buy_routesToDifferentRecipient() public {
        _fundAndApprove(alice, PRICE);

        vm.prank(alice);
        nft.buy(ID, 1, bob);

        assertEq(nft.balanceOf(alice, ID), 0);
        assertEq(nft.balanceOf(bob, ID), 1);
    }

    function test_buy_zeroAmountReverts() public {
        vm.prank(alice);
        vm.expectRevert(MockNFT.ZeroAmount.selector);
        nft.buy(ID, 0, alice);
    }

    function test_buy_zeroRecipientReverts() public {
        _fundAndApprove(alice, PRICE);
        vm.prank(alice);
        vm.expectRevert(MockNFT.ZeroRecipient.selector);
        nft.buy(ID, 1, address(0));
    }

    function test_buy_notForSaleReverts() public {
        // id 7 was never listed.
        _fundAndApprove(alice, PRICE);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(MockNFT.NotForSale.selector, uint256(7)));
        nft.buy(7, 1, alice);
    }

    function test_buy_revertsAfterDelist() public {
        vm.prank(owner);
        nft.setPrice(ID, 0); // delist

        _fundAndApprove(alice, PRICE);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(MockNFT.NotForSale.selector, ID));
        nft.buy(ID, 1, alice);
    }

    function test_buy_revertsOnInsufficientAllowance() public {
        usdc.mint(alice, PRICE);
        // No approve() — should bubble up the OZ ERC20 allowance revert.
        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(
                IERC20Errors.ERC20InsufficientAllowance.selector, address(nft), 0, PRICE
            )
        );
        nft.buy(ID, 1, alice);
    }

    function test_buy_revertsToNonReceiverContract() public {
        NonReceiver target = new NonReceiver();
        _fundAndApprove(alice, PRICE);
        vm.prank(alice);
        // OZ ERC1155 reverts with ERC1155InvalidReceiver when the recipient is
        // a contract without the hook.
        vm.expectRevert();
        nft.buy(ID, 1, address(target));
    }

    function test_buy_succeedsToAcceptingReceiver() public {
        AcceptingReceiver target = new AcceptingReceiver();
        _fundAndApprove(alice, PRICE);
        vm.prank(alice);
        nft.buy(ID, 1, address(target));
        assertEq(nft.balanceOf(address(target), ID), 1);
    }

    function testFuzz_buy_costScalesLinearly(uint256 amount) public {
        amount = bound(amount, 1, 1_000);
        uint256 total = PRICE * amount;
        _fundAndApprove(alice, total);

        vm.prank(alice);
        uint256 paid = nft.buy(ID, amount, alice);
        assertEq(paid, total);
        assertEq(nft.balanceOf(alice, ID), amount);
    }

    // ---------------------------------------------------------------------
    // setPrice / mint / setURI access control
    // ---------------------------------------------------------------------

    function test_setPrice_emitsAndStores() public {
        vm.expectEmit(true, false, false, true, address(nft));
        emit MockNFT.PriceUpdated(99, 0, 123);
        vm.prank(owner);
        nft.setPrice(99, 123);
        assertEq(nft.priceOf(99), 123);
    }

    function test_setPrice_onlyOwner() public {
        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, alice)
        );
        nft.setPrice(1, 1);
    }

    function test_mint_onlyOwner() public {
        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, alice)
        );
        nft.mint(alice, ID, 1);
    }

    function test_mint_ownerCanGiveaway() public {
        vm.prank(owner);
        nft.mint(bob, 1234, 3);
        assertEq(nft.balanceOf(bob, 1234), 3);
        // No USDC was charged.
        assertEq(usdc.balanceOf(beneficiary), 0);
    }

    function test_setURI_onlyOwner() public {
        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, alice)
        );
        nft.setURI("https://x");
    }

    function test_setURI_updatesUri() public {
        string memory newUri = "https://new.example.com/{id}.json";
        vm.prank(owner);
        nft.setURI(newUri);
        assertEq(nft.uri(ID), newUri);
    }
}
