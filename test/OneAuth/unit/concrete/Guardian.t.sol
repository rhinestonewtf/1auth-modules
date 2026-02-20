// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { Test } from "forge-std/Test.sol";
import { Guardian } from "src/OneAuth/Guardian.sol";
import { OneAuthValidator } from "src/OneAuth/OneAuthValidator.sol";
import { OneAuthRecoveryBase } from "src/OneAuth/OneAuthRecoveryBase.sol";
import { SignatureCheckerLib } from "solady/utils/SignatureCheckerLib.sol";

contract GuardianTest is Test {
    // Private keys for test guardians
    uint256 internal constant PK_0 = 0xA11CE;
    uint256 internal constant PK_1 = 0xB0B;
    uint256 internal constant PK_2 = 0xCA501;

    // Non-guardian private key
    uint256 internal constant PK_STRANGER = 0xBAD;

    Guardian internal guardian;

    // Guardian addresses in constructor order (slot 0, 1, 2)
    address internal addr0;
    address internal addr1;
    address internal addr2;

    bytes32 internal constant TEST_HASH = keccak256("test message");

    function setUp() public {
        addr0 = vm.addr(PK_0);
        addr1 = vm.addr(PK_1);
        addr2 = vm.addr(PK_2);

        address[] memory addrs = new address[](3);
        addrs[0] = addr0;
        addrs[1] = addr1;
        addrs[2] = addr2;

        // Default: 2-of-3
        guardian = new Guardian(addrs, 2);
    }

    /*//////////////////////////////////////////////////////////////////////////
                                  HELPERS
    //////////////////////////////////////////////////////////////////////////*/

    /// @dev Build a single EOA signature entry: packed(uint8 id, uint16 sigLen, bytes65 sig)
    function _signEntry(uint8 id, uint256 pk, bytes32 hash) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, hash);
        return abi.encodePacked(id, uint16(65), r, s, v);
    }

    /*//////////////////////////////////////////////////////////////////////////
                              CONSTRUCTOR TESTS
    //////////////////////////////////////////////////////////////////////////*/

    function test_constructor_setsImmutables() public view {
        assertEq(guardian.guardian0(), addr0);
        assertEq(guardian.guardian1(), addr1);
        assertEq(guardian.guardian2(), addr2);
        assertEq(guardian.guardianCount(), 3);
        assertEq(guardian.threshold(), 2);
    }

    function test_constructor_singleGuardian() public {
        address[] memory addrs = new address[](1);
        addrs[0] = addr0;

        Guardian g = new Guardian(addrs, 1);
        assertEq(g.guardian0(), addr0);
        assertEq(g.guardian1(), address(0));
        assertEq(g.guardian2(), address(0));
        assertEq(g.guardianCount(), 1);
        assertEq(g.threshold(), 1);
    }

    function test_constructor_twoGuardians() public {
        address[] memory addrs = new address[](2);
        addrs[0] = addr0;
        addrs[1] = addr1;

        Guardian g = new Guardian(addrs, 2);
        assertEq(g.guardianCount(), 2);
        assertEq(g.threshold(), 2);
    }

    function test_constructor_revertsOnZeroGuardians() public {
        address[] memory addrs = new address[](0);
        vm.expectRevert(Guardian.InvalidGuardianCount.selector);
        new Guardian(addrs, 1);
    }

    function test_constructor_revertsOnFourGuardians() public {
        address[] memory addrs = new address[](4);
        for (uint256 i; i < 4; i++) {
            addrs[i] = vm.addr(i + 100);
        }
        vm.expectRevert(Guardian.InvalidGuardianCount.selector);
        new Guardian(addrs, 1);
    }

    function test_constructor_revertsOnZeroThreshold() public {
        address[] memory addrs = new address[](1);
        addrs[0] = addr0;
        vm.expectRevert(Guardian.InvalidThreshold.selector);
        new Guardian(addrs, 0);
    }

    function test_constructor_revertsOnThresholdExceedsCount() public {
        address[] memory addrs = new address[](2);
        addrs[0] = addr0;
        addrs[1] = addr1;
        vm.expectRevert(Guardian.InvalidThreshold.selector);
        new Guardian(addrs, 3);
    }

    function test_constructor_revertsOnZeroAddress() public {
        address[] memory addrs = new address[](2);
        addrs[0] = addr0;
        addrs[1] = address(0);
        vm.expectRevert(Guardian.ZeroAddress.selector);
        new Guardian(addrs, 1);
    }

    function test_constructor_revertsOnDuplicateGuardians() public {
        address[] memory addrs = new address[](3);
        addrs[0] = addr0;
        addrs[1] = addr1;
        addrs[2] = addr0; // duplicate
        vm.expectRevert(Guardian.DuplicateGuardian.selector);
        new Guardian(addrs, 2);
    }

    /*//////////////////////////////////////////////////////////////////////////
                           isValidSignature TESTS
    //////////////////////////////////////////////////////////////////////////*/

    function test_isValidSignature_valid2of3_ids01() public view {
        bytes memory sigs = abi.encodePacked(
            _signEntry(0, PK_0, TEST_HASH),
            _signEntry(1, PK_1, TEST_HASH)
        );
        assertEq(guardian.isValidSignature(TEST_HASH, sigs), bytes4(0x1626ba7e));
    }

    function test_isValidSignature_valid2of3_ids02() public view {
        bytes memory sigs = abi.encodePacked(
            _signEntry(0, PK_0, TEST_HASH),
            _signEntry(2, PK_2, TEST_HASH)
        );
        assertEq(guardian.isValidSignature(TEST_HASH, sigs), bytes4(0x1626ba7e));
    }

    function test_isValidSignature_valid2of3_ids12() public view {
        bytes memory sigs = abi.encodePacked(
            _signEntry(1, PK_1, TEST_HASH),
            _signEntry(2, PK_2, TEST_HASH)
        );
        assertEq(guardian.isValidSignature(TEST_HASH, sigs), bytes4(0x1626ba7e));
    }

    function test_isValidSignature_valid2of3_reverseOrder() public view {
        // IDs don't need to be in ascending order — just unique
        bytes memory sigs = abi.encodePacked(
            _signEntry(2, PK_2, TEST_HASH),
            _signEntry(0, PK_0, TEST_HASH)
        );
        assertEq(guardian.isValidSignature(TEST_HASH, sigs), bytes4(0x1626ba7e));
    }

    function test_isValidSignature_valid1of1() public {
        address[] memory addrs = new address[](1);
        addrs[0] = addr0;
        Guardian g = new Guardian(addrs, 1);

        bytes memory sig = _signEntry(0, PK_0, TEST_HASH);
        assertEq(g.isValidSignature(TEST_HASH, sig), bytes4(0x1626ba7e));
    }

    function test_isValidSignature_valid3of3() public {
        address[] memory addrs = new address[](3);
        addrs[0] = addr0;
        addrs[1] = addr1;
        addrs[2] = addr2;
        Guardian g = new Guardian(addrs, 3);

        bytes memory sigs = abi.encodePacked(
            _signEntry(0, PK_0, TEST_HASH),
            _signEntry(1, PK_1, TEST_HASH),
            _signEntry(2, PK_2, TEST_HASH)
        );
        assertEq(g.isValidSignature(TEST_HASH, sigs), bytes4(0x1626ba7e));
    }

    function test_isValidSignature_failsOnWrongLength() public view {
        // Too short
        assertEq(guardian.isValidSignature(TEST_HASH, hex"aabbcc"), bytes4(0xffffffff));

        // Too long (3 entries instead of 2)
        bytes memory sigs = abi.encodePacked(
            _signEntry(0, PK_0, TEST_HASH),
            _signEntry(1, PK_1, TEST_HASH),
            _signEntry(2, PK_2, TEST_HASH)
        );
        assertEq(guardian.isValidSignature(TEST_HASH, sigs), bytes4(0xffffffff));
    }

    function test_isValidSignature_failsOnEmptySigs() public view {
        assertEq(guardian.isValidSignature(TEST_HASH, ""), bytes4(0xffffffff));
    }

    function test_isValidSignature_failsOnDuplicateId() public view {
        // Same ID used twice — threshold bypass attempt
        bytes memory sigs = abi.encodePacked(
            _signEntry(0, PK_0, TEST_HASH),
            _signEntry(0, PK_0, TEST_HASH)
        );
        assertEq(guardian.isValidSignature(TEST_HASH, sigs), bytes4(0xffffffff));
    }

    function test_isValidSignature_failsOnIdOutOfRange() public view {
        // ID 3 is out of range for a 3-guardian setup (valid: 0, 1, 2)
        bytes memory sigs = abi.encodePacked(
            _signEntry(0, PK_0, TEST_HASH),
            _signEntry(3, PK_1, TEST_HASH) // invalid ID
        );
        assertEq(guardian.isValidSignature(TEST_HASH, sigs), bytes4(0xffffffff));
    }

    function test_isValidSignature_failsOnWrongSignerForId() public view {
        // Guardian 1's key signing with ID 0 — mismatch
        bytes memory sigs = abi.encodePacked(
            _signEntry(0, PK_1, TEST_HASH), // PK_1 is guardian1, but claims ID 0
            _signEntry(1, PK_0, TEST_HASH)  // PK_0 is guardian0, but claims ID 1
        );
        assertEq(guardian.isValidSignature(TEST_HASH, sigs), bytes4(0xffffffff));
    }

    function test_isValidSignature_failsOnNonGuardianSigner() public view {
        bytes memory sigs = abi.encodePacked(
            _signEntry(0, PK_0, TEST_HASH),
            _signEntry(1, PK_STRANGER, TEST_HASH) // stranger can't be guardian1
        );
        assertEq(guardian.isValidSignature(TEST_HASH, sigs), bytes4(0xffffffff));
    }

    function test_isValidSignature_failsOnWrongHash() public view {
        bytes32 wrongHash = keccak256("wrong message");

        bytes memory sigs = abi.encodePacked(
            _signEntry(0, PK_0, wrongHash),
            _signEntry(1, PK_1, wrongHash)
        );
        assertEq(guardian.isValidSignature(TEST_HASH, sigs), bytes4(0xffffffff));
    }

    function test_isValidSignature_failsOnGarbageSignature() public view {
        // Two entries with correct headers but garbage ECDSA data
        bytes memory garbage = abi.encodePacked(
            uint8(0), uint16(65), new bytes(65),
            uint8(1), uint16(65), new bytes(65)
        );
        assertEq(guardian.isValidSignature(TEST_HASH, garbage), bytes4(0xffffffff));
    }

    function test_isValidSignature_differentHashes() public view {
        bytes32 hash1 = keccak256("message 1");
        bytes32 hash2 = keccak256("message 2");

        bytes memory sigs1 = abi.encodePacked(
            _signEntry(0, PK_0, hash1),
            _signEntry(1, PK_1, hash1)
        );

        // Valid for hash1
        assertEq(guardian.isValidSignature(hash1, sigs1), bytes4(0x1626ba7e));
        // Invalid for hash2
        assertEq(guardian.isValidSignature(hash2, sigs1), bytes4(0xffffffff));
    }

    function test_isValidSignature_allCombinations2of3() public view {
        // All 3 valid 2-of-3 combinations, each in both orderings (6 total)
        uint8[2][6] memory combos = [
            [uint8(0), 1],
            [uint8(0), 2],
            [uint8(1), 0],
            [uint8(1), 2],
            [uint8(2), 0],
            [uint8(2), 1]
        ];

        uint256[3] memory pks = [PK_0, PK_1, PK_2];

        for (uint256 c; c < 6; c++) {
            uint8 id0 = combos[c][0];
            uint8 id1 = combos[c][1];

            bytes memory sigs = abi.encodePacked(
                _signEntry(id0, pks[id0], TEST_HASH),
                _signEntry(id1, pks[id1], TEST_HASH)
            );
            assertEq(guardian.isValidSignature(TEST_HASH, sigs), bytes4(0x1626ba7e));
        }
    }

    function test_isValidSignature_failsOnIdOutOfRange_singleGuardian() public {
        address[] memory addrs = new address[](1);
        addrs[0] = addr0;
        Guardian g = new Guardian(addrs, 1);

        // ID 1 is out of range for a 1-guardian setup
        bytes memory sig = _signEntry(1, PK_1, TEST_HASH);
        assertEq(g.isValidSignature(TEST_HASH, sig), bytes4(0xffffffff));
    }

    /*//////////////////////////////////////////////////////////////////////////
                              EDGE CASE TESTS
    //////////////////////////////////////////////////////////////////////////*/

    function test_isValidSignature_invalidV() public view {
        // Craft a signature entry with v=0 (invalid recovery ID)
        (,bytes32 r, bytes32 s) = vm.sign(PK_0, TEST_HASH);
        bytes memory invalidEntry = abi.encodePacked(uint8(0), uint16(65), r, s, uint8(0)); // v=0
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(PK_1, TEST_HASH);
        bytes memory validEntry = abi.encodePacked(uint8(1), uint16(65), r1, s1, v1);

        bytes memory sigs = abi.encodePacked(invalidEntry, validEntry);
        assertEq(guardian.isValidSignature(TEST_HASH, sigs), bytes4(0xffffffff));
    }

    function test_isValidSignature_truncatedHeader() public view {
        // Only 2 bytes — not enough for a full header (id + sigLen)
        bytes memory tooShort = new bytes(2);
        assertEq(guardian.isValidSignature(TEST_HASH, tooShort), bytes4(0xffffffff));
    }

    function test_isValidSignature_trailingBytes() public view {
        // Valid 2-of-3 entries followed by an extra byte — rejected as trailing data
        bytes memory sigs = abi.encodePacked(
            _signEntry(0, PK_0, TEST_HASH),
            _signEntry(1, PK_1, TEST_HASH),
            hex"ff"
        );
        assertEq(guardian.isValidSignature(TEST_HASH, sigs), bytes4(0xffffffff));
    }

    function test_isValidSignature_truncatedSignatureData() public view {
        // Header claims 65-byte sig but only 10 bytes follow
        bytes memory truncated = abi.encodePacked(
            uint8(0), uint16(65), new bytes(10)
        );
        assertEq(guardian.isValidSignature(TEST_HASH, truncated), bytes4(0xffffffff));
    }

    function test_isValidSignature_stateless() public view {
        // Guardian is stateless — same set validates multiple different hashes
        bytes32 hash1 = keccak256("alpha");
        bytes32 hash2 = keccak256("beta");
        bytes32 hash3 = keccak256("gamma");

        bytes32[3] memory hashes = [hash1, hash2, hash3];

        for (uint256 i; i < 3; i++) {
            bytes memory sigs = abi.encodePacked(
                _signEntry(0, PK_0, hashes[i]),
                _signEntry(1, PK_1, hashes[i])
            );
            assertEq(guardian.isValidSignature(hashes[i], sigs), bytes4(0x1626ba7e));
        }
    }
}

/// @notice Integration test: Guardian contract used as the guardian on OneAuthValidator recovery
contract GuardianRecoveryIntegrationTest is Test {
    uint256 internal constant PK_0 = 0xA11CE;
    uint256 internal constant PK_1 = 0xB0B;
    uint256 internal constant PK_2 = 0xCA501;

    OneAuthValidator internal validator;
    Guardian internal guardianContract;

    // P-256 test public keys (same as OneAuthRecovery tests)
    bytes32 internal _pubKeyX0 =
        bytes32(uint256(66_296_829_923_831_658_891_499_717_579_803_548_012_279_830_557_731_564_719_736_971_029_660_387_468_805));
    bytes32 internal _pubKeyY0 =
        bytes32(uint256(46_098_569_798_045_992_993_621_049_610_647_226_011_837_333_919_273_603_402_527_314_962_291_506_652_186));
    bytes32 internal _pubKeyX1 =
        bytes32(uint256(77_427_310_596_034_628_445_756_159_459_159_056_108_500_819_865_614_675_054_701_790_516_611_205_123_311));
    bytes32 internal _pubKeyY1 =
        bytes32(uint256(20_591_151_874_462_689_689_754_215_152_304_668_244_192_265_896_034_279_288_204_806_249_532_173_935_644));

    function setUp() public {
        validator = new OneAuthValidator();

        address[] memory guardians = new address[](3);
        guardians[0] = vm.addr(PK_0);
        guardians[1] = vm.addr(PK_1);
        guardians[2] = vm.addr(PK_2);
        guardianContract = new Guardian(guardians, 2);
    }

    function _signEntry(uint8 id, uint256 pk, bytes32 hash) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, hash);
        return abi.encodePacked(id, uint16(65), r, s, v);
    }

    function _installWithGuardian() internal {
        uint16[] memory keyIds = new uint16[](1);
        keyIds[0] = 0;
        OneAuthValidator.WebAuthnCredential[] memory creds =
            new OneAuthValidator.WebAuthnCredential[](1);
        creds[0] = OneAuthValidator.WebAuthnCredential({ pubKeyX: _pubKeyX0, pubKeyY: _pubKeyY0 });
        validator.onInstall(abi.encode(keyIds, creds, address(0), address(guardianContract), uint8(0)));
    }

    function test_recoverWithGuardian_2of3() public {
        _installWithGuardian();

        // Verify external guardian is set
        (, address eg,) = validator.guardianConfig(address(this));
        assertEq(eg, address(guardianContract));

        uint48 expiry = uint48(block.timestamp + 1000);
        uint256 nonce = 0;
        OneAuthRecoveryBase.NewCredential memory cred = OneAuthRecoveryBase.NewCredential({
            keyId: 1,
            pubKeyX: _pubKeyX1,
            pubKeyY: _pubKeyY1,
            replace: false
        });

        // Compute the recovery digest
        bytes32 digest = validator.getRecoverDigest(address(this), block.chainid, cred, nonce, expiry);

        // Guardians 0 and 2 sign the digest (2-of-3 threshold)
        // Prepend 0x01 type byte for external guardian path
        bytes memory guardianSig = abi.encodePacked(
            uint8(0x01),
            _signEntry(0, PK_0, digest),
            _signEntry(2, PK_2, digest)
        );

        // Execute recovery through the real Guardian contract
        validator.recoverWithGuardian(address(this), block.chainid, cred, nonce, expiry, guardianSig);

        // Verify credential was added
        (bytes32 px, bytes32 py) = validator.getCredential(1, address(this));
        assertEq(px, _pubKeyX1, "Recovered credential pubKeyX");
        assertEq(py, _pubKeyY1, "Recovered credential pubKeyY");
        assertEq(validator.credentialCount(address(this)), 2, "Should have 2 credentials");
        assertTrue(validator.nonceUsed(address(this), nonce), "Nonce should be consumed");
    }

    function test_recoverWithGuardian_replaceCredential() public {
        _installWithGuardian();

        uint48 expiry = uint48(block.timestamp + 1000);
        uint256 nonce = 1;
        // Replace keyId 0 in-place with new public key
        OneAuthRecoveryBase.NewCredential memory cred = OneAuthRecoveryBase.NewCredential({
            keyId: 0,
            pubKeyX: _pubKeyX1,
            pubKeyY: _pubKeyY1,
            replace: true
        });

        bytes32 digest = validator.getRecoverDigest(address(this), block.chainid, cred, nonce, expiry);

        // Guardians 1 and 2 sign — prepend 0x01 for external guardian
        bytes memory guardianSig = abi.encodePacked(
            uint8(0x01),
            _signEntry(1, PK_1, digest),
            _signEntry(2, PK_2, digest)
        );

        validator.recoverWithGuardian(address(this), block.chainid, cred, nonce, expiry, guardianSig);

        // Verify credential was rotated
        (bytes32 px, bytes32 py) = validator.getCredential(0, address(this));
        assertEq(px, _pubKeyX1, "Credential should be rotated");
        assertEq(py, _pubKeyY1);
        assertEq(validator.credentialCount(address(this)), 1, "Count should stay 1");
    }

    function test_recoverWithGuardian_failsWithInsufficientSigners() public {
        _installWithGuardian();

        uint48 expiry = uint48(block.timestamp + 1000);
        OneAuthRecoveryBase.NewCredential memory cred = OneAuthRecoveryBase.NewCredential({
            keyId: 1,
            pubKeyX: _pubKeyX1,
            pubKeyY: _pubKeyY1,
            replace: false
        });

        bytes32 digest = validator.getRecoverDigest(address(this), block.chainid, cred, 0, expiry);

        // Only 1 signature — threshold is 2. Prepend 0x01 for external guardian.
        bytes memory guardianSig = abi.encodePacked(uint8(0x01), _signEntry(0, PK_0, digest));

        vm.expectRevert(OneAuthRecoveryBase.InvalidGuardianSignature.selector);
        validator.recoverWithGuardian(address(this), block.chainid, cred, 0, expiry, guardianSig);
    }

    function test_recoverWithGuardian_failsWithWrongSigner() public {
        _installWithGuardian();

        uint48 expiry = uint48(block.timestamp + 1000);
        OneAuthRecoveryBase.NewCredential memory cred = OneAuthRecoveryBase.NewCredential({
            keyId: 1,
            pubKeyX: _pubKeyX1,
            pubKeyY: _pubKeyY1,
            replace: false
        });

        bytes32 digest = validator.getRecoverDigest(address(this), block.chainid, cred, 0, expiry);

        // Stranger signs with ID 1 instead of actual guardian1
        uint256 PK_STRANGER = 0xBAD;
        bytes memory guardianSig = abi.encodePacked(
            uint8(0x01),
            _signEntry(0, PK_0, digest),
            _signEntry(1, PK_STRANGER, digest)
        );

        vm.expectRevert(OneAuthRecoveryBase.InvalidGuardianSignature.selector);
        validator.recoverWithGuardian(address(this), block.chainid, cred, 0, expiry, guardianSig);
    }

    function test_signatureCheckerLib_delegatesToGuardian() public view {
        // Verify the exact code path used in OneAuthRecoveryBase.recoverWithGuardian:
        // SignatureCheckerLib calls Guardian.isValidSignature via staticcall
        bytes32 digest = keccak256("test digest for checker lib");

        bytes memory guardianSig = abi.encodePacked(
            _signEntry(0, PK_0, digest),
            _signEntry(2, PK_2, digest)
        );

        bool isValid = SignatureCheckerLib.isValidSignatureNow(
            address(guardianContract), digest, guardianSig
        );
        assertTrue(isValid, "SignatureCheckerLib should delegate to Guardian.isValidSignature");

        // Invalid signatures should return false (not revert)
        bytes memory badSig = abi.encodePacked(
            _signEntry(0, PK_0, digest),
            _signEntry(1, 0xBAD, digest) // stranger
        );
        bool isInvalid = SignatureCheckerLib.isValidSignatureNow(
            address(guardianContract), digest, badSig
        );
        assertFalse(isInvalid, "Should return false for invalid guardian sigs");
    }

    function test_recoverWithGuardian_chainIdZero() public {
        _installWithGuardian();

        uint48 expiry = uint48(block.timestamp + 1000);
        OneAuthRecoveryBase.NewCredential memory cred = OneAuthRecoveryBase.NewCredential({
            keyId: 1,
            pubKeyX: _pubKeyX1,
            pubKeyY: _pubKeyY1,
            replace: false
        });

        // chainId=0 means valid on any chain
        bytes32 digest = validator.getRecoverDigest(address(this), 0, cred, 0, expiry);

        bytes memory guardianSig = abi.encodePacked(
            uint8(0x01),
            _signEntry(0, PK_0, digest),
            _signEntry(1, PK_1, digest)
        );

        validator.recoverWithGuardian(address(this), 0, cred, 0, expiry, guardianSig);

        (bytes32 px, bytes32 py) = validator.getCredential(1, address(this));
        assertEq(px, _pubKeyX1);
        assertEq(py, _pubKeyY1);
    }
}

/// @notice Tests for chaining Guardian contracts (contract guardian as a slot)
contract GuardianChainingTest is Test {
    uint256 internal constant PK_0 = 0xA11CE;
    uint256 internal constant PK_1 = 0xB0B;
    uint256 internal constant PK_2 = 0xCA501;

    address internal addr0;
    address internal addr1;
    address internal addr2;

    bytes32 internal constant TEST_HASH = keccak256("chaining test");

    function setUp() public {
        addr0 = vm.addr(PK_0);
        addr1 = vm.addr(PK_1);
        addr2 = vm.addr(PK_2);
    }

    function _signEntry(uint8 id, uint256 pk, bytes32 hash) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, hash);
        return abi.encodePacked(id, uint16(65), r, s, v);
    }

    function test_chainedGuardian_innerContractAsSlot() public {
        // Inner guardian: 1-of-1 controlled by addr0
        address[] memory innerAddrs = new address[](1);
        innerAddrs[0] = addr0;
        Guardian inner = new Guardian(innerAddrs, 1);

        // Outer guardian: 2-of-3 where slot 0 is the inner Guardian contract
        address[] memory outerAddrs = new address[](3);
        outerAddrs[0] = address(inner);
        outerAddrs[1] = addr1;
        outerAddrs[2] = addr2;
        Guardian outer = new Guardian(outerAddrs, 2);

        // Build the inner signature (what inner.isValidSignature expects)
        bytes memory innerSig = _signEntry(0, PK_0, TEST_HASH);

        // Build outer entries: slot 0 is contract guardian (variable-length inner sig),
        // slot 2 is EOA guardian
        bytes memory outerSigs = abi.encodePacked(
            uint8(0), uint16(innerSig.length), innerSig,
            _signEntry(2, PK_2, TEST_HASH)
        );

        assertEq(outer.isValidSignature(TEST_HASH, outerSigs), bytes4(0x1626ba7e));
    }

    function test_chainedGuardian_twoLevelNesting() public {
        // Level 0: 1-of-1 controlled by addr0
        address[] memory l0Addrs = new address[](1);
        l0Addrs[0] = addr0;
        Guardian level0 = new Guardian(l0Addrs, 1);

        // Level 1: 1-of-1 controlled by level0 contract
        address[] memory l1Addrs = new address[](1);
        l1Addrs[0] = address(level0);
        Guardian level1 = new Guardian(l1Addrs, 1);

        // Outer: 2-of-2 where slot 0 is level1 (doubly-nested), slot 1 is EOA
        address[] memory outerAddrs = new address[](2);
        outerAddrs[0] = address(level1);
        outerAddrs[1] = addr1;
        Guardian outer = new Guardian(outerAddrs, 2);

        // Build signatures from inside out
        bytes memory l0Sig = _signEntry(0, PK_0, TEST_HASH);
        bytes memory l1Sig = abi.encodePacked(uint8(0), uint16(l0Sig.length), l0Sig);

        bytes memory outerSigs = abi.encodePacked(
            uint8(0), uint16(l1Sig.length), l1Sig,
            _signEntry(1, PK_1, TEST_HASH)
        );

        assertEq(outer.isValidSignature(TEST_HASH, outerSigs), bytes4(0x1626ba7e));
    }

    function test_chainedGuardian_failsWithWrongInnerSigner() public {
        // Inner guardian: 1-of-1 controlled by addr0
        address[] memory innerAddrs = new address[](1);
        innerAddrs[0] = addr0;
        Guardian inner = new Guardian(innerAddrs, 1);

        // Outer: 2-of-2 where slot 0 is the inner Guardian contract
        address[] memory outerAddrs = new address[](2);
        outerAddrs[0] = address(inner);
        outerAddrs[1] = addr1;
        Guardian outer = new Guardian(outerAddrs, 2);

        // Sign with PK_2 (stranger to inner guardian) instead of PK_0
        bytes memory badInnerSig = _signEntry(0, PK_2, TEST_HASH);

        bytes memory outerSigs = abi.encodePacked(
            uint8(0), uint16(badInnerSig.length), badInnerSig,
            _signEntry(1, PK_1, TEST_HASH)
        );

        assertEq(outer.isValidSignature(TEST_HASH, outerSigs), bytes4(0xffffffff));
    }
}

/// @notice Fuzz tests: verify Guardian never reverts on arbitrary input
contract GuardianFuzzTest is Test {
    uint256 internal constant PK_0 = 0xA11CE;
    uint256 internal constant PK_1 = 0xB0B;
    uint256 internal constant PK_2 = 0xCA501;

    Guardian internal guardian;

    function setUp() public {
        address[] memory addrs = new address[](3);
        addrs[0] = vm.addr(PK_0);
        addrs[1] = vm.addr(PK_1);
        addrs[2] = vm.addr(PK_2);
        guardian = new Guardian(addrs, 2);
    }

    function _signEntry(uint8 id, uint256 pk, bytes32 hash) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, hash);
        return abi.encodePacked(id, uint16(65), r, s, v);
    }

    /// @dev isValidSignature must never revert — always returns a valid bytes4
    function testFuzz_isValidSignature_neverReverts(bytes32 hash, bytes calldata randomSigs) public view {
        bytes4 result = guardian.isValidSignature(hash, randomSigs);
        assertTrue(
            result == bytes4(0x1626ba7e) || result == bytes4(0xffffffff),
            "Must return valid EIP-1271 bytes4"
        );
    }

    /// @dev Valid guardian signatures should succeed for any hash
    function testFuzz_isValidSignature_validForAnyHash(bytes32 hash) public view {
        bytes memory sigs = abi.encodePacked(
            _signEntry(0, PK_0, hash),
            _signEntry(1, PK_1, hash)
        );
        assertEq(guardian.isValidSignature(hash, sigs), bytes4(0x1626ba7e));
    }
}

/// @notice Gas benchmarks for Guardian signature validation
contract GuardianGasTest is Test {
    uint256 internal constant PK_0 = 0xA11CE;
    uint256 internal constant PK_1 = 0xB0B;
    uint256 internal constant PK_2 = 0xCA501;

    address internal addr0;
    address internal addr1;
    address internal addr2;

    bytes32 internal constant BENCH_HASH = keccak256("gas benchmark");

    function setUp() public {
        addr0 = vm.addr(PK_0);
        addr1 = vm.addr(PK_1);
        addr2 = vm.addr(PK_2);
    }

    function _signEntry(uint8 id, uint256 pk, bytes32 hash) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, hash);
        return abi.encodePacked(id, uint16(65), r, s, v);
    }

    function test_gas_1of1() public {
        address[] memory addrs = new address[](1);
        addrs[0] = addr0;
        Guardian g = new Guardian(addrs, 1);

        bytes memory sig = _signEntry(0, PK_0, BENCH_HASH);

        uint256 gasBefore = gasleft();
        bytes4 result = g.isValidSignature(BENCH_HASH, sig);
        uint256 gasUsed = gasBefore - gasleft();

        assertEq(result, bytes4(0x1626ba7e));
        emit log_named_uint("Guardian 1-of-1 gas", gasUsed);
    }

    function test_gas_2of3() public {
        address[] memory addrs = new address[](3);
        addrs[0] = addr0;
        addrs[1] = addr1;
        addrs[2] = addr2;
        Guardian g = new Guardian(addrs, 2);

        bytes memory sigs = abi.encodePacked(
            _signEntry(0, PK_0, BENCH_HASH),
            _signEntry(1, PK_1, BENCH_HASH)
        );

        uint256 gasBefore = gasleft();
        bytes4 result = g.isValidSignature(BENCH_HASH, sigs);
        uint256 gasUsed = gasBefore - gasleft();

        assertEq(result, bytes4(0x1626ba7e));
        emit log_named_uint("Guardian 2-of-3 gas", gasUsed);
    }

    function test_gas_3of3() public {
        address[] memory addrs = new address[](3);
        addrs[0] = addr0;
        addrs[1] = addr1;
        addrs[2] = addr2;
        Guardian g = new Guardian(addrs, 3);

        bytes memory sigs = abi.encodePacked(
            _signEntry(0, PK_0, BENCH_HASH),
            _signEntry(1, PK_1, BENCH_HASH),
            _signEntry(2, PK_2, BENCH_HASH)
        );

        uint256 gasBefore = gasleft();
        bytes4 result = g.isValidSignature(BENCH_HASH, sigs);
        uint256 gasUsed = gasBefore - gasleft();

        assertEq(result, bytes4(0x1626ba7e));
        emit log_named_uint("Guardian 3-of-3 gas", gasUsed);
    }

    function test_gas_invalidSignature() public {
        address[] memory addrs = new address[](3);
        addrs[0] = addr0;
        addrs[1] = addr1;
        addrs[2] = addr2;
        Guardian g = new Guardian(addrs, 2);

        // Two entries with correct headers but garbage ECDSA data
        bytes memory garbage = abi.encodePacked(
            uint8(0), uint16(65), new bytes(65),
            uint8(1), uint16(65), new bytes(65)
        );

        uint256 gasBefore = gasleft();
        bytes4 result = g.isValidSignature(BENCH_HASH, garbage);
        uint256 gasUsed = gasBefore - gasleft();

        assertEq(result, bytes4(0xffffffff));
        emit log_named_uint("Guardian invalid sig gas", gasUsed);
    }
}
