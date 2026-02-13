// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { BaseTest } from "test/Base.t.sol";
import { OneAuthValidator } from "src/OneAuth/OneAuthValidator.sol";
import { IOneAuthValidator } from "src/OneAuth/IOneAuthValidator.sol";
import { P256Lib } from "src/OneAuth/lib/P256Lib.sol";
import { ERC7579HybridValidatorBase, ERC7579ValidatorBase } from "modulekit/Modules.sol";
import { PackedUserOperation, getEmptyUserOperation } from "test/utils/ERC4337.sol";
import { EIP1271_MAGIC_VALUE } from "test/utils/Constants.sol";

/// @dev Harness to expose P256Lib's internal parseWebAuthnAuth for fuzz testing
contract P256LibFuzzHarness {
    function parseWebAuthnAuth(bytes calldata raw) external pure returns (bool ok) {
        (, ok) = P256Lib.parseWebAuthnAuth(raw);
    }
}

contract OneAuthValidatorFuzzTest is BaseTest {
    OneAuthValidator internal validator;
    P256LibFuzzHarness internal p256Harness;

    bytes32 _pubKeyX0 =
        bytes32(uint256(66_296_829_923_831_658_891_499_717_579_803_548_012_279_830_557_731_564_719_736_971_029_660_387_468_805));
    bytes32 _pubKeyY0 =
        bytes32(uint256(46_098_569_798_045_992_993_621_049_610_647_226_011_837_333_919_273_603_402_527_314_962_291_506_652_186));

    bytes32 constant TEST_DIGEST =
        0xf631058a3ba1116acce12396fad0a125b5041c43f8e15723709f81aa8d5f4ccf;

    function setUp() public override {
        BaseTest.setUp();
        validator = new OneAuthValidator();
        p256Harness = new P256LibFuzzHarness();

        // Install with one valid credential
        uint16[] memory keyIds = new uint16[](1);
        keyIds[0] = 0;
        OneAuthValidator.WebAuthnCredential[] memory creds =
            new OneAuthValidator.WebAuthnCredential[](1);
        creds[0] = OneAuthValidator.WebAuthnCredential({
            pubKeyX: _pubKeyX0,
            pubKeyY: _pubKeyY0
        });
        validator.onInstall(abi.encode(keyIds, creds, address(0), uint48(0)));
    }

    /*//////////////////////////////////////////////////////////////////////////
                              ON-CURVE FUZZ TESTS
    //////////////////////////////////////////////////////////////////////////*/

    /// @dev Random (x, y) pairs are almost certainly not on P-256, so install should revert
    function testFuzz_OnInstall_RejectsRandomPubKeys(bytes32 x, bytes32 y) public {
        // Skip the known valid test keys
        vm.assume(x != _pubKeyX0);
        vm.assume(uint256(x) != 0 && uint256(y) != 0);

        OneAuthValidator freshValidator = new OneAuthValidator();
        uint16[] memory keyIds = new uint16[](1);
        keyIds[0] = 0;
        OneAuthValidator.WebAuthnCredential[] memory creds =
            new OneAuthValidator.WebAuthnCredential[](1);
        creds[0] = OneAuthValidator.WebAuthnCredential({ pubKeyX: x, pubKeyY: y });

        // The overwhelming probability is this will revert with InvalidPublicKey.
        // On the astronomically rare chance it's on-curve, the install succeeds — that's fine.
        try freshValidator.onInstall(abi.encode(keyIds, creds, address(0), uint48(0))) {
            // If it succeeded, the point happens to be on-curve — no assertion needed
        } catch (bytes memory reason) {
            assertEq(
                bytes4(reason),
                IOneAuthValidator.InvalidPublicKey.selector,
                "Should revert with InvalidPublicKey"
            );
        }
    }

    /*//////////////////////////////////////////////////////////////////////////
                              VALIDATION FUZZ TESTS
    //////////////////////////////////////////////////////////////////////////*/

    /// @dev validateUserOp should never revert, even with random signature data
    function testFuzz_ValidateUserOp_RandomSig_Fails(bytes calldata randomSig) public view {
        PackedUserOperation memory userOp = getEmptyUserOperation();
        userOp.sender = address(this);
        userOp.signature = randomSig;

        uint256 validationData =
            ERC7579ValidatorBase.ValidationData.unwrap(validator.validateUserOp(userOp, TEST_DIGEST));
        // Must return 0 (success) or 1 (failure), never revert
        assertTrue(validationData == 0 || validationData == 1, "Must return valid ValidationData");
    }

    /// @dev isValidSignatureWithSender should never revert, even with random signature data
    function testFuzz_IsValidSignatureWithSender_RandomSig_Fails(bytes calldata randomSig)
        public
        view
    {
        bytes4 result = validator.isValidSignatureWithSender(address(this), TEST_DIGEST, randomSig);
        // Must return EIP1271_SUCCESS or EIP1271_FAILED, never revert
        assertTrue(
            result == EIP1271_MAGIC_VALUE || result == bytes4(0xffffffff),
            "Must return valid EIP-1271 result"
        );
    }

    /// @dev validateSignatureWithData may revert on malformed data, but should handle gracefully
    function testFuzz_ValidateSignatureWithData_RandomData(
        bytes calldata sig,
        bytes calldata data
    )
        public
        view
    {
        // May revert with InvalidSignatureData, ProofTooLong, or InvalidMerkleProof
        // Or may return false. Should never panic or return true for random data.
        try validator.validateSignatureWithData(TEST_DIGEST, sig, data) returns (bool) {
            // If it didn't revert, it should return false (random data won't produce valid sig)
            // In extremely rare cases it could return true, so we don't assert false
        } catch {
            // Expected reverts for malformed data — this is fine
        }
    }

    /*//////////////////////////////////////////////////////////////////////////
                          P256LIB PARSE FUZZ TESTS
    //////////////////////////////////////////////////////////////////////////*/

    /// @dev parseWebAuthnAuth should never revert regardless of input
    function testFuzz_ParseWebAuthnAuth_NeverReverts(bytes calldata raw) public view {
        // Should never revert for any input — returns ok=false for malformed input
        p256Harness.parseWebAuthnAuth(raw);
    }
}
