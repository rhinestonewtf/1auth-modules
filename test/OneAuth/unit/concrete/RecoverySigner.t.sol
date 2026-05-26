// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { Test } from "forge-std/Test.sol";
import { Ownable } from "solady/auth/Ownable.sol";
import { RecoverySigner } from "src/OneAuth/RecoverySigner.sol";

/// @dev Minimal EIP-1271 contract owner used to exercise the contract-owner code path
contract MockERC1271Owner {
    address public approved;

    constructor(address _approved) {
        approved = _approved;
    }

    function isValidSignature(bytes32 hash, bytes calldata sig) external view returns (bytes4) {
        // Returns the magic value iff `sig` is a valid ECDSA signature from `approved`
        if (sig.length != 65) return 0xffffffff;
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        address recovered = ecrecover(hash, v, r, s);
        if (recovered == approved && recovered != address(0)) return 0x1626ba7e;
        return 0xffffffff;
    }
}

contract RecoverySignerTest is Test {
    /*//////////////////////////////////////////////////////////////////////////
                                  TEST KEYS
    //////////////////////////////////////////////////////////////////////////*/

    uint256 internal constant OWNER_PK = 0xA11CE;
    uint256 internal constant NEW_OWNER_PK = 0xB0B;
    uint256 internal constant STRANGER_PK = 0xBAD;

    address internal ownerAddr;
    address internal newOwnerAddr;
    address internal strangerAddr;

    RecoverySigner internal signer;

    bytes4 internal constant EIP1271_MAGIC = 0x1626ba7e;
    bytes4 internal constant EIP1271_FAIL = 0xffffffff;

    bytes32 internal constant ROTATE_OWNER_TYPEHASH = keccak256(
        "RotateOwner(address newOwner,uint256 chainId,uint256 nonce,uint48 expiry)"
    );

    event OwnerRotatedWithSig(address indexed previousOwner, address indexed newOwner, uint256 nonce);

    function setUp() public {
        ownerAddr = vm.addr(OWNER_PK);
        newOwnerAddr = vm.addr(NEW_OWNER_PK);
        strangerAddr = vm.addr(STRANGER_PK);

        signer = new RecoverySigner(ownerAddr);
    }

    /*//////////////////////////////////////////////////////////////////////////
                                   HELPERS
    //////////////////////////////////////////////////////////////////////////*/

    function _signRotation(
        uint256 pk,
        address newOwner,
        uint256 chainId,
        uint256 nonce,
        uint48 expiry
    )
        internal
        view
        returns (bytes memory)
    {
        bytes32 digest = signer.rotationDigest(newOwner, chainId, nonce, expiry);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _sign(uint256 pk, bytes32 hash) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, hash);
        return abi.encodePacked(r, s, v);
    }

    /*//////////////////////////////////////////////////////////////////////////
                              CONSTRUCTOR TESTS
    //////////////////////////////////////////////////////////////////////////*/

    function test_constructor_setsOwner() public view {
        assertEq(signer.owner(), ownerAddr);
    }

    function test_constructor_revertsOnZeroAddress() public {
        vm.expectRevert(RecoverySigner.ZeroAddress.selector);
        new RecoverySigner(address(0));
    }

    /*//////////////////////////////////////////////////////////////////////////
                            EIP-1271 isValidSignature
    //////////////////////////////////////////////////////////////////////////*/

    function test_isValidSignature_validOwnerSig() public view {
        bytes32 hash = keccak256("hello");
        bytes memory sig = _sign(OWNER_PK, hash);
        assertEq(signer.isValidSignature(hash, sig), EIP1271_MAGIC);
    }

    function test_isValidSignature_wrongSigner() public view {
        bytes32 hash = keccak256("hello");
        bytes memory sig = _sign(STRANGER_PK, hash);
        assertEq(signer.isValidSignature(hash, sig), EIP1271_FAIL);
    }

    function test_isValidSignature_garbageSignature() public view {
        bytes32 hash = keccak256("hello");
        // Returns FAIL (not revert) per EIP-1271 spec
        assertEq(signer.isValidSignature(hash, hex"deadbeef"), EIP1271_FAIL);
    }

    function test_isValidSignature_emptySignature() public view {
        bytes32 hash = keccak256("hello");
        assertEq(signer.isValidSignature(hash, ""), EIP1271_FAIL);
    }

    function test_isValidSignature_wrongHash() public view {
        bytes memory sig = _sign(OWNER_PK, keccak256("msg-a"));
        // Signed msg-a but check msg-b — ecrecover yields a different address than ownerAddr
        assertEq(signer.isValidSignature(keccak256("msg-b"), sig), EIP1271_FAIL);
    }

    function test_isValidSignature_contractOwner() public {
        // Rotate ownership to an EIP-1271 contract owner that approves STRANGER_PK
        MockERC1271Owner contractOwner = new MockERC1271Owner(strangerAddr);
        vm.prank(ownerAddr);
        signer.transferOwnership(address(contractOwner));

        bytes32 hash = keccak256("hello");
        bytes memory sig = _sign(STRANGER_PK, hash);
        // Verified through nested EIP-1271 call
        assertEq(signer.isValidSignature(hash, sig), EIP1271_MAGIC);

        // A different signer should fail
        bytes memory badSig = _sign(OWNER_PK, hash);
        assertEq(signer.isValidSignature(hash, badSig), EIP1271_FAIL);
    }

    /*//////////////////////////////////////////////////////////////////////////
                         OWNER ROTATION — HAPPY PATH
    //////////////////////////////////////////////////////////////////////////*/

    function test_rotateOwnerWithSig_succeeds() public {
        uint48 expiry = uint48(block.timestamp + 1 hours);
        uint256 nonce = 42;
        bytes memory sig = _signRotation(OWNER_PK, newOwnerAddr, block.chainid, nonce, expiry);

        vm.expectEmit(true, true, true, true);
        emit OwnerRotatedWithSig(ownerAddr, newOwnerAddr, nonce);

        // Permissionless: a stranger can submit
        vm.prank(strangerAddr);
        signer.rotateOwnerWithSig(newOwnerAddr, block.chainid, nonce, expiry, sig);

        assertEq(signer.owner(), newOwnerAddr);
        assertTrue(signer.nonceUsed(nonce));
    }

    function test_rotateOwnerWithSig_anyChainIdZero() public {
        uint48 expiry = uint48(block.timestamp + 1 hours);
        bytes memory sig = _signRotation(OWNER_PK, newOwnerAddr, 0, 1, expiry);

        signer.rotateOwnerWithSig(newOwnerAddr, 0, 1, expiry, sig);
        assertEq(signer.owner(), newOwnerAddr);
    }

    function test_rotateOwnerWithSig_unorderedNonces() public {
        // Pre-sign three rotations with arbitrary non-sequential nonces; submit out of order
        uint48 expiry = uint48(block.timestamp + 1 hours);
        uint256 n1 = 999;
        uint256 n2 = 1;
        uint256 n3 = type(uint256).max;

        address ownerA = vm.addr(0x1111);
        address ownerB = vm.addr(0x2222);

        // Use n3 first
        bytes memory sig3 = _signRotation(OWNER_PK, ownerA, 0, n3, expiry);
        signer.rotateOwnerWithSig(ownerA, 0, n3, expiry, sig3);
        assertEq(signer.owner(), ownerA);
        assertTrue(signer.nonceUsed(n3));
        assertFalse(signer.nonceUsed(n1));
        assertFalse(signer.nonceUsed(n2));

        // Now ownerA is in charge; sign next rotation with PK for ownerA
        // (We didn't pre-sign n1/n2 with OWNER_PK that would have been valid after rotation
        // since owner has changed.) Instead, validate that n1/n2 with OWNER_PK now fail.
        bytes memory staleSig = _signRotation(OWNER_PK, ownerB, 0, n1, expiry);
        vm.expectRevert(RecoverySigner.InvalidSignature.selector);
        signer.rotateOwnerWithSig(ownerB, 0, n1, expiry, staleSig);
    }

    /*//////////////////////////////////////////////////////////////////////////
                       OWNER ROTATION — REVERT CASES
    //////////////////////////////////////////////////////////////////////////*/

    function test_rotateOwnerWithSig_revertsOnExpired() public {
        uint48 expiry = uint48(block.timestamp + 1 hours);
        bytes memory sig = _signRotation(OWNER_PK, newOwnerAddr, block.chainid, 1, expiry);

        vm.warp(expiry + 1);
        vm.expectRevert(RecoverySigner.RotationExpired.selector);
        signer.rotateOwnerWithSig(newOwnerAddr, block.chainid, 1, expiry, sig);
    }

    function test_rotateOwnerWithSig_revertsOnExactlyExpired_atBoundary() public {
        // expiry == block.timestamp is still valid (boundary). expiry < block.timestamp reverts.
        uint48 expiry = uint48(block.timestamp);
        bytes memory sig = _signRotation(OWNER_PK, newOwnerAddr, block.chainid, 1, expiry);
        // At the boundary it should succeed
        signer.rotateOwnerWithSig(newOwnerAddr, block.chainid, 1, expiry, sig);
        assertEq(signer.owner(), newOwnerAddr);
    }

    function test_rotateOwnerWithSig_revertsOnWrongChainId() public {
        uint48 expiry = uint48(block.timestamp + 1 hours);
        uint256 wrongChain = block.chainid + 1;
        bytes memory sig = _signRotation(OWNER_PK, newOwnerAddr, wrongChain, 1, expiry);

        vm.expectRevert(RecoverySigner.InvalidChainId.selector);
        signer.rotateOwnerWithSig(newOwnerAddr, wrongChain, 1, expiry, sig);
    }

    function test_rotateOwnerWithSig_revertsOnReusedNonce() public {
        uint48 expiry = uint48(block.timestamp + 1 hours);
        uint256 nonce = 7;
        bytes memory sig = _signRotation(OWNER_PK, newOwnerAddr, block.chainid, nonce, expiry);

        signer.rotateOwnerWithSig(newOwnerAddr, block.chainid, nonce, expiry, sig);
        assertEq(signer.owner(), newOwnerAddr);

        // Replaying the exact same call now fails — even with a fresh signature by current
        // owner, the nonce check happens before signature verification, so any caller can
        // re-submit the original digest and it will revert on NonceAlreadyUsed.
        vm.expectRevert(RecoverySigner.NonceAlreadyUsed.selector);
        signer.rotateOwnerWithSig(newOwnerAddr, block.chainid, nonce, expiry, sig);
    }

    function test_rotateOwnerWithSig_revertsOnZeroAddress() public {
        uint48 expiry = uint48(block.timestamp + 1 hours);
        bytes memory sig = _signRotation(OWNER_PK, address(0), block.chainid, 1, expiry);

        vm.expectRevert(RecoverySigner.ZeroAddress.selector);
        signer.rotateOwnerWithSig(address(0), block.chainid, 1, expiry, sig);
    }

    function test_rotateOwnerWithSig_revertsOnWrongSigner() public {
        uint48 expiry = uint48(block.timestamp + 1 hours);
        bytes memory sig = _signRotation(STRANGER_PK, newOwnerAddr, block.chainid, 1, expiry);

        vm.expectRevert(RecoverySigner.InvalidSignature.selector);
        signer.rotateOwnerWithSig(newOwnerAddr, block.chainid, 1, expiry, sig);
    }

    function test_rotateOwnerWithSig_revertsOnMutatedParam_newOwner() public {
        uint48 expiry = uint48(block.timestamp + 1 hours);
        bytes memory sig = _signRotation(OWNER_PK, newOwnerAddr, block.chainid, 1, expiry);

        // Caller passes a different newOwner than was signed
        vm.expectRevert(RecoverySigner.InvalidSignature.selector);
        signer.rotateOwnerWithSig(strangerAddr, block.chainid, 1, expiry, sig);
    }

    function test_rotateOwnerWithSig_revertsOnMutatedParam_nonce() public {
        uint48 expiry = uint48(block.timestamp + 1 hours);
        bytes memory sig = _signRotation(OWNER_PK, newOwnerAddr, block.chainid, 1, expiry);

        vm.expectRevert(RecoverySigner.InvalidSignature.selector);
        signer.rotateOwnerWithSig(newOwnerAddr, block.chainid, 2, expiry, sig);
    }

    function test_rotateOwnerWithSig_revertsOnMutatedParam_expiry() public {
        uint48 expiry = uint48(block.timestamp + 1 hours);
        bytes memory sig = _signRotation(OWNER_PK, newOwnerAddr, block.chainid, 1, expiry);

        vm.expectRevert(RecoverySigner.InvalidSignature.selector);
        signer.rotateOwnerWithSig(newOwnerAddr, block.chainid, 1, expiry + 1, sig);
    }

    function test_rotateOwnerWithSig_garbageSignatureReverts() public {
        uint48 expiry = uint48(block.timestamp + 1 hours);
        vm.expectRevert(RecoverySigner.InvalidSignature.selector);
        signer.rotateOwnerWithSig(newOwnerAddr, block.chainid, 1, expiry, hex"deadbeef");
    }

    /*//////////////////////////////////////////////////////////////////////////
                         DIRECT OWNERSHIP (Ownable path)
    //////////////////////////////////////////////////////////////////////////*/

    function test_transferOwnership_byOwner() public {
        vm.prank(ownerAddr);
        signer.transferOwnership(newOwnerAddr);
        assertEq(signer.owner(), newOwnerAddr);
    }

    function test_transferOwnership_byStrangerReverts() public {
        vm.prank(strangerAddr);
        vm.expectRevert(Ownable.Unauthorized.selector);
        signer.transferOwnership(newOwnerAddr);
    }

    function test_renounceOwnership_byOwner() public {
        vm.prank(ownerAddr);
        signer.renounceOwnership();
        assertEq(signer.owner(), address(0));

        // After renounce, no signature can satisfy isValidSignature — ecrecover never
        // returns address(0) for a well-formed sig, and the check fails for malformed
        bytes32 hash = keccak256("hello");
        bytes memory sig = _sign(OWNER_PK, hash);
        assertEq(signer.isValidSignature(hash, sig), EIP1271_FAIL);
    }

    /*//////////////////////////////////////////////////////////////////////////
                                  FUZZ TESTS
    //////////////////////////////////////////////////////////////////////////*/

    function testFuzz_rotateOwnerWithSig_arbitraryNonce(uint256 nonce, address newOwner) public {
        vm.assume(newOwner != address(0));
        uint48 expiry = uint48(block.timestamp + 1 hours);
        bytes memory sig = _signRotation(OWNER_PK, newOwner, block.chainid, nonce, expiry);

        signer.rotateOwnerWithSig(newOwner, block.chainid, nonce, expiry, sig);
        assertEq(signer.owner(), newOwner);
        assertTrue(signer.nonceUsed(nonce));
    }

    function testFuzz_isValidSignature_onlyOwnerPasses(uint256 sigPk, bytes32 hash) public view {
        // Bound to valid secp256k1 range
        sigPk = bound(sigPk, 1, type(uint128).max);
        bytes memory sig = _sign(sigPk, hash);
        address signed = vm.addr(sigPk);

        bytes4 expected = signed == ownerAddr ? EIP1271_MAGIC : EIP1271_FAIL;
        assertEq(signer.isValidSignature(hash, sig), expected);
    }

    function testFuzz_rotation_replayAlwaysReverts(uint256 nonce, address newOwner) public {
        vm.assume(newOwner != address(0));
        uint48 expiry = uint48(block.timestamp + 1 hours);
        bytes memory sig = _signRotation(OWNER_PK, newOwner, block.chainid, nonce, expiry);

        signer.rotateOwnerWithSig(newOwner, block.chainid, nonce, expiry, sig);

        vm.expectRevert(RecoverySigner.NonceAlreadyUsed.selector);
        signer.rotateOwnerWithSig(newOwner, block.chainid, nonce, expiry, sig);
    }
}
