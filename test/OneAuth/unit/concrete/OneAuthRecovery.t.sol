// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { BaseTest } from "test/Base.t.sol";
import { OneAuthValidator } from "src/OneAuth/OneAuthValidator.sol";
import { IOneAuthValidator } from "src/OneAuth/IOneAuthValidator.sol";
import { OneAuthRecoveryBase } from "src/OneAuth/OneAuthRecoveryBase.sol";
import { ERC7579HybridValidatorBase, ERC7579ValidatorBase } from "modulekit/Modules.sol";
import { WebAuthn } from "solady/utils/WebAuthn.sol";
import { PackedUserOperation, getEmptyUserOperation } from "test/utils/ERC4337.sol";
import { Base64Url } from "FreshCryptoLib/utils/Base64Url.sol";

/// @dev Mock guardian that implements ERC-1271
contract MockGuardian {
    mapping(bytes32 => bool) public approvedDigests;

    function approveDigest(bytes32 digest) external {
        approvedDigests[digest] = true;
    }

    function isValidSignature(bytes32 hash, bytes calldata) external view returns (bytes4) {
        if (approvedDigests[hash]) return 0x1626ba7e;
        return 0xffffffff;
    }
}

/// @dev Mock guardian that always rejects
contract RejectingGuardian {
    function isValidSignature(bytes32, bytes calldata) external pure returns (bytes4) {
        return 0xffffffff;
    }
}

contract OneAuthRecoveryTest is BaseTest {
    OneAuthValidator internal validator;
    MockGuardian internal mockGuardian;
    RejectingGuardian internal rejectingGuardian;

    // Test public keys (same as v2 test vectors)
    bytes32 _pubKeyX0 =
        bytes32(uint256(66_296_829_923_831_658_891_499_717_579_803_548_012_279_830_557_731_564_719_736_971_029_660_387_468_805));
    bytes32 _pubKeyY0 =
        bytes32(uint256(46_098_569_798_045_992_993_621_049_610_647_226_011_837_333_919_273_603_402_527_314_962_291_506_652_186));

    bytes32 _pubKeyX1 =
        bytes32(uint256(77_427_310_596_034_628_445_756_159_459_159_056_108_500_819_865_614_675_054_701_790_516_611_205_123_311));
    bytes32 _pubKeyY1 =
        bytes32(uint256(20_591_151_874_462_689_689_754_215_152_304_668_244_192_265_896_034_279_288_204_806_249_532_173_935_644));

    // The digest that the test WebAuthn signatures were created for
    bytes32 constant TEST_DIGEST =
        0xf631058a3ba1116acce12396fad0a125b5041c43f8e15723709f81aa8d5f4ccf;

    // Real WebAuthn auth data for pubKey0 signing abi.encode(TEST_DIGEST)
    bytes constant AUTH_DATA =
        hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630100000001";
    uint256 constant SIG_R =
        23_510_924_181_331_275_540_501_876_269_042_668_160_690_304_423_490_805_737_085_519_687_669_896_593_880;
    uint256 constant SIG_S =
        36_590_747_517_247_563_381_084_733_394_442_750_806_324_326_036_343_798_276_847_517_765_557_371_045_088;
    uint256 constant CHALLENGE_INDEX = 23;
    uint256 constant TYPE_INDEX = 1;

    function setUp() public virtual override {
        BaseTest.setUp();
        validator = new OneAuthValidator();
        mockGuardian = new MockGuardian();
        rejectingGuardian = new RejectingGuardian();
    }

    /*//////////////////////////////////////////////////////////////////////////
                              HELPERS
    //////////////////////////////////////////////////////////////////////////*/

    function _buildClientDataJSON(bytes32 challengeHash) internal pure returns (string memory) {
        bytes memory challenge = abi.encode(challengeHash);
        return string.concat(
            '{"type":"webauthn.get","challenge":"',
            Base64Url.encode(challenge),
            '","origin":"http://localhost:8080","crossOrigin":false}'
        );
    }

    function _buildRegularSignature(
        uint16 keyId,
        uint256 r,
        uint256 s,
        bytes memory authenticatorData,
        string memory clientDataJSON
    )
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
            uint8(0), // proofLength = 0
            keyId,
            r,
            s,
            uint16(CHALLENGE_INDEX),
            uint16(TYPE_INDEX),
            uint16(authenticatorData.length),
            authenticatorData,
            clientDataJSON
        );
    }

    function _installData1() internal view returns (bytes memory) {
        uint16[] memory keyIds = new uint16[](1);
        keyIds[0] = 0;
        OneAuthValidator.WebAuthnCredential[] memory creds =
            new OneAuthValidator.WebAuthnCredential[](1);
        creds[0] = OneAuthValidator.WebAuthnCredential({ pubKeyX: _pubKeyX0, pubKeyY: _pubKeyY0 });
        return abi.encode(keyIds, creds, address(0), uint48(0));
    }

    function _install1() internal {
        validator.onInstall(_installData1());
    }

    function _newCred(
        uint16 keyId,
        bytes32 pubKeyX,
        bytes32 pubKeyY
    )
        internal
        pure
        returns (OneAuthRecoveryBase.NewCredential memory)
    {
        return OneAuthRecoveryBase.NewCredential({
            keyId: keyId,
            pubKeyX: pubKeyX,
            pubKeyY: pubKeyY,
            replace: false
        });
    }

    function _newCredReplace(
        uint16 keyId,
        bytes32 pubKeyX,
        bytes32 pubKeyY
    )
        internal
        pure
        returns (OneAuthRecoveryBase.NewCredential memory)
    {
        return OneAuthRecoveryBase.NewCredential({
            keyId: keyId,
            pubKeyX: pubKeyX,
            pubKeyY: pubKeyY,
            replace: true
        });
    }

    /*//////////////////////////////////////////////////////////////////////////
                              GUARDIAN CONFIG TESTS
    //////////////////////////////////////////////////////////////////////////*/

    function test_ProposeGuardian_ImmediateWhenNoTimelock() public {
        validator.proposeGuardian(address(mockGuardian));
        assertEq(validator.guardian(address(this)), address(mockGuardian));
    }

    function test_ProposeGuardian_ToZero() public {
        validator.proposeGuardian(address(mockGuardian));
        validator.proposeGuardian(address(0));
        assertEq(validator.guardian(address(this)), address(0));
    }

    function test_OnInstall_SetsGuardian() public {
        uint16[] memory keyIds = new uint16[](1);
        keyIds[0] = 0;
        OneAuthValidator.WebAuthnCredential[] memory creds =
            new OneAuthValidator.WebAuthnCredential[](1);
        creds[0] = OneAuthValidator.WebAuthnCredential({ pubKeyX: _pubKeyX0, pubKeyY: _pubKeyY0 });
        validator.onInstall(abi.encode(keyIds, creds, address(mockGuardian), uint48(0)));

        assertEq(validator.guardian(address(this)), address(mockGuardian));
    }

    function test_OnUninstall_ClearsGuardian() public {
        _install1();
        validator.proposeGuardian(address(mockGuardian));
        assertEq(validator.guardian(address(this)), address(mockGuardian));

        validator.onUninstall("");
        assertEq(validator.guardian(address(this)), address(0));
    }

    /*//////////////////////////////////////////////////////////////////////////
                              EIP-712 DIGEST TESTS
    //////////////////////////////////////////////////////////////////////////*/

    function test_GetRecoverDigest_Deterministic() public view {
        OneAuthRecoveryBase.NewCredential memory cred = _newCred(1, _pubKeyX1, _pubKeyY1);
        bytes32 d1 = validator.getRecoverDigest(address(this), block.chainid, cred, 0, 1000);
        bytes32 d2 = validator.getRecoverDigest(address(this), block.chainid, cred, 0, 1000);
        assertEq(d1, d2, "Same inputs should produce same digest");
    }

    function test_GetRecoverDigest_DifferentNonce() public view {
        OneAuthRecoveryBase.NewCredential memory cred = _newCred(1, _pubKeyX1, _pubKeyY1);
        bytes32 d1 = validator.getRecoverDigest(address(this), block.chainid, cred, 0, 1000);
        bytes32 d2 = validator.getRecoverDigest(address(this), block.chainid, cred, 1, 1000);
        assertTrue(d1 != d2, "Different nonce should produce different digest");
    }

    function test_GetRecoverDigest_DifferentExpiry() public view {
        OneAuthRecoveryBase.NewCredential memory cred = _newCred(1, _pubKeyX1, _pubKeyY1);
        bytes32 d1 = validator.getRecoverDigest(address(this), block.chainid, cred, 0, 1000);
        bytes32 d2 = validator.getRecoverDigest(address(this), block.chainid, cred, 0, 2000);
        assertTrue(d1 != d2, "Different expiry should produce different digest");
    }

    function test_GetRecoverDigest_DifferentKeyId() public view {
        OneAuthRecoveryBase.NewCredential memory cred1 = _newCred(1, _pubKeyX1, _pubKeyY1);
        OneAuthRecoveryBase.NewCredential memory cred2 = _newCred(2, _pubKeyX1, _pubKeyY1);
        bytes32 d1 = validator.getRecoverDigest(address(this), block.chainid, cred1, 0, 1000);
        bytes32 d2 = validator.getRecoverDigest(address(this), block.chainid, cred2, 0, 1000);
        assertTrue(d1 != d2, "Different keyId should produce different digest");
    }

    function test_GetRecoverDigest_DifferentAccount() public view {
        OneAuthRecoveryBase.NewCredential memory cred = _newCred(1, _pubKeyX1, _pubKeyY1);
        bytes32 d1 = validator.getRecoverDigest(address(this), block.chainid, cred, 0, 1000);
        bytes32 d2 = validator.getRecoverDigest(address(1), block.chainid, cred, 0, 1000);
        assertTrue(d1 != d2, "Different account should produce different digest");
    }

    function test_GetRecoverDigest_DifferentChainId() public view {
        OneAuthRecoveryBase.NewCredential memory cred = _newCred(1, _pubKeyX1, _pubKeyY1);
        bytes32 d1 = validator.getRecoverDigest(address(this), 1, cred, 0, 1000);
        bytes32 d2 = validator.getRecoverDigest(address(this), 2, cred, 0, 1000);
        assertTrue(d1 != d2, "Different chainId should produce different digest");
    }

    function test_GetRecoverDigest_MatchesEIP712() public view {
        bytes32 typehash = keccak256(
            "RecoverPasskey(address account,uint256 chainId,uint16 newKeyId,bytes32 newPubKeyX,bytes32 newPubKeyY,bool replace,uint256 nonce,uint48 expiry)"
        );
        bytes32 structHash = keccak256(
            abi.encode(
                typehash,
                address(this),
                block.chainid, // chainId in struct
                uint256(1), // newKeyId cast to uint256
                _pubKeyX1,
                _pubKeyY1,
                uint256(0), // replace = false
                uint256(42), // nonce
                uint256(uint48(9999)) // expiry cast to uint256
            )
        );

        // Sans-chainId domain separator: EIP712Domain(string name,string version,address verifyingContract)
        bytes32 domainSep = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,address verifyingContract)"),
                keccak256(bytes("OneAuthValidator")),
                keccak256(bytes("1.0.0")),
                address(validator)
            )
        );

        // EIP-712: "\x19\x01" || domainSeparator || structHash
        bytes32 expected = keccak256(abi.encodePacked("\x19\x01", domainSep, structHash));

        OneAuthRecoveryBase.NewCredential memory cred = _newCred(1, _pubKeyX1, _pubKeyY1);
        bytes32 actual = validator.getRecoverDigest(address(this), block.chainid, cred, 42, 9999);
        assertEq(actual, expected, "Digest should match manual EIP-712 computation");
    }

    /*//////////////////////////////////////////////////////////////////////////
                              PASSKEY RECOVERY TESTS
    //////////////////////////////////////////////////////////////////////////*/

    function test_RecoverWithPasskey_RevertWhen_Expired() public {
        _install1();

        OneAuthRecoveryBase.NewCredential memory cred = _newCred(1, _pubKeyX1, _pubKeyY1);
        vm.warp(2000);
        vm.expectRevert(OneAuthRecoveryBase.RecoveryExpired.selector);
        validator.recoverWithPasskey(address(this), block.chainid, cred, 0, 1000, "");
    }

    function test_RecoverWithPasskey_RevertWhen_NonceAlreadyUsed() public {
        _install1();

        // Mark nonce 42 as used by doing a guardian recovery first
        validator.proposeGuardian(address(mockGuardian));
        uint48 expiry = uint48(block.timestamp + 1000);
        OneAuthRecoveryBase.NewCredential memory cred = _newCred(5, _pubKeyX1, _pubKeyY1);
        bytes32 digest = validator.getRecoverDigest(address(this), block.chainid, cred, 42, expiry);
        mockGuardian.approveDigest(digest);
        validator.recoverWithGuardian(address(this), block.chainid, cred, 42, expiry, "");

        // Now try to use nonce 42 again with passkey recovery
        OneAuthRecoveryBase.NewCredential memory cred2 = _newCred(6, _pubKeyX1, _pubKeyY1);
        vm.expectRevert(OneAuthRecoveryBase.NonceAlreadyUsed.selector);
        validator.recoverWithPasskey(address(this), block.chainid, cred2, 42, expiry, "");
    }

    function test_RecoverWithPasskey_RevertWhen_InvalidSignature() public {
        _install1();

        uint48 expiry = uint48(block.timestamp + 1000);
        OneAuthRecoveryBase.NewCredential memory cred = _newCred(1, _pubKeyX1, _pubKeyY1);
        // Sign over wrong digest (TEST_DIGEST, not recovery digest)
        string memory clientDataJSON = _buildClientDataJSON(TEST_DIGEST);
        bytes memory sig = _buildRegularSignature(0, SIG_R, SIG_S, AUTH_DATA, clientDataJSON);

        vm.expectRevert(OneAuthRecoveryBase.InvalidRecoverySignature.selector);
        validator.recoverWithPasskey(address(this), block.chainid, cred, 0, expiry, sig);
    }

    function test_RecoverWithPasskey_RevertWhen_NotInitialized() public {
        uint48 expiry = uint48(block.timestamp + 1000);
        OneAuthRecoveryBase.NewCredential memory cred = _newCred(1, _pubKeyX1, _pubKeyY1);

        // _validateSignatureWithConfig returns false for uninitialized
        vm.expectRevert(OneAuthRecoveryBase.InvalidRecoverySignature.selector);
        validator.recoverWithPasskey(
            address(this), block.chainid, cred, 0, expiry,
            _buildRegularSignature(0, SIG_R, SIG_S, AUTH_DATA, _buildClientDataJSON(TEST_DIGEST))
        );
    }

    function test_RecoverWithPasskey_RevertWhen_ZeroPubKey() public {
        _install1();

        uint48 expiry = uint48(block.timestamp + 1000);
        OneAuthRecoveryBase.NewCredential memory cred = _newCred(1, bytes32(0), bytes32(0));
        string memory clientDataJSON = _buildClientDataJSON(TEST_DIGEST);
        bytes memory sig = _buildRegularSignature(0, SIG_R, SIG_S, AUTH_DATA, clientDataJSON);
        vm.expectRevert(OneAuthRecoveryBase.InvalidRecoverySignature.selector);
        validator.recoverWithPasskey(address(this), block.chainid, cred, 0, expiry, sig);
    }

    function test_RecoverWithPasskey_RevertWhen_InvalidChainId() public {
        _install1();

        uint48 expiry = uint48(block.timestamp + 1000);
        OneAuthRecoveryBase.NewCredential memory cred = _newCred(1, _pubKeyX1, _pubKeyY1);
        vm.expectRevert(OneAuthRecoveryBase.InvalidChainId.selector);
        validator.recoverWithPasskey(address(this), 999, cred, 0, expiry, "");
    }

    function test_RecoverWithPasskey_ChainIdZero_AnyChain() public {
        _install1();
        validator.proposeGuardian(address(mockGuardian));

        uint48 expiry = uint48(block.timestamp + 1000);
        OneAuthRecoveryBase.NewCredential memory cred = _newCred(1, _pubKeyX1, _pubKeyY1);

        // chainId=0 means any chain — should not revert with InvalidChainId
        // (will revert with InvalidRecoverySignature since sig is empty, which proves chainId check passed)
        vm.expectRevert(OneAuthRecoveryBase.InvalidRecoverySignature.selector);
        validator.recoverWithPasskey(address(this), 0, cred, 0, expiry, "");
    }

    /*//////////////////////////////////////////////////////////////////////////
                              GUARDIAN RECOVERY TESTS
    //////////////////////////////////////////////////////////////////////////*/

    function test_RecoverWithGuardian_Success() public {
        _install1();
        validator.proposeGuardian(address(mockGuardian));

        uint48 expiry = uint48(block.timestamp + 1000);
        uint256 nonce = 0;
        OneAuthRecoveryBase.NewCredential memory cred = _newCred(1, _pubKeyX1, _pubKeyY1);

        bytes32 digest = validator.getRecoverDigest(address(this), block.chainid, cred, nonce, expiry);
        mockGuardian.approveDigest(digest);

        validator.recoverWithGuardian(address(this), block.chainid, cred, nonce, expiry, "");

        // Verify credential was added
        (bytes32 px, bytes32 py) = validator.getCredential(1, address(this));
        assertEq(px, _pubKeyX1, "New credential pubKeyX should be set");
        assertEq(py, _pubKeyY1, "New credential pubKeyY should be set");
        assertEq(validator.credentialCount(address(this)), 2, "Should now have 2 credentials");
    }

    function test_RecoverWithGuardian_NonceMarkedUsed() public {
        _install1();
        validator.proposeGuardian(address(mockGuardian));

        uint48 expiry = uint48(block.timestamp + 1000);
        uint256 nonce = 7;
        OneAuthRecoveryBase.NewCredential memory cred = _newCred(1, _pubKeyX1, _pubKeyY1);

        assertFalse(validator.nonceUsed(address(this), nonce), "Nonce should not be used initially");

        bytes32 digest = validator.getRecoverDigest(address(this), block.chainid, cred, nonce, expiry);
        mockGuardian.approveDigest(digest);

        validator.recoverWithGuardian(address(this), block.chainid, cred, nonce, expiry, "");

        assertTrue(validator.nonceUsed(address(this), nonce), "Nonce should be marked as used");
    }

    function test_RecoverWithGuardian_RevertWhen_Expired() public {
        _install1();
        validator.proposeGuardian(address(mockGuardian));

        OneAuthRecoveryBase.NewCredential memory cred = _newCred(1, _pubKeyX1, _pubKeyY1);
        vm.warp(2000);
        vm.expectRevert(OneAuthRecoveryBase.RecoveryExpired.selector);
        validator.recoverWithGuardian(address(this), block.chainid, cred, 0, 1000, "");
    }

    function test_RecoverWithGuardian_RevertWhen_NonceAlreadyUsed() public {
        _install1();
        validator.proposeGuardian(address(mockGuardian));

        uint48 expiry = uint48(block.timestamp + 1000);
        uint256 nonce = 0;
        OneAuthRecoveryBase.NewCredential memory cred = _newCred(1, _pubKeyX1, _pubKeyY1);

        // First recovery succeeds
        bytes32 digest = validator.getRecoverDigest(address(this), block.chainid, cred, nonce, expiry);
        mockGuardian.approveDigest(digest);
        validator.recoverWithGuardian(address(this), block.chainid, cred, nonce, expiry, "");

        // Second recovery with same nonce fails
        OneAuthRecoveryBase.NewCredential memory cred2 = _newCred(2, _pubKeyX1, _pubKeyY1);
        vm.expectRevert(OneAuthRecoveryBase.NonceAlreadyUsed.selector);
        validator.recoverWithGuardian(address(this), block.chainid, cred2, nonce, expiry, "");
    }

    function test_RecoverWithGuardian_RevertWhen_GuardianNotConfigured() public {
        _install1();
        // No guardian set

        uint48 expiry = uint48(block.timestamp + 1000);
        OneAuthRecoveryBase.NewCredential memory cred = _newCred(1, _pubKeyX1, _pubKeyY1);
        vm.expectRevert(OneAuthRecoveryBase.GuardianNotConfigured.selector);
        validator.recoverWithGuardian(address(this), block.chainid, cred, 0, expiry, "");
    }

    function test_RecoverWithGuardian_RevertWhen_InvalidGuardianSignature() public {
        _install1();
        validator.proposeGuardian(address(rejectingGuardian));

        uint48 expiry = uint48(block.timestamp + 1000);
        OneAuthRecoveryBase.NewCredential memory cred = _newCred(1, _pubKeyX1, _pubKeyY1);
        vm.expectRevert(OneAuthRecoveryBase.InvalidGuardianSignature.selector);
        validator.recoverWithGuardian(address(this), block.chainid, cred, 0, expiry, "");
    }

    function test_RecoverWithGuardian_RevertWhen_ZeroPubKey() public {
        _install1();
        validator.proposeGuardian(address(mockGuardian));

        uint48 expiry = uint48(block.timestamp + 1000);
        OneAuthRecoveryBase.NewCredential memory cred = _newCred(1, bytes32(0), bytes32(0));
        bytes32 digest = validator.getRecoverDigest(address(this), block.chainid, cred, 0, expiry);
        mockGuardian.approveDigest(digest);

        vm.expectRevert(IOneAuthValidator.InvalidPublicKey.selector);
        validator.recoverWithGuardian(address(this), block.chainid, cred, 0, expiry, "");
    }

    function test_RecoverWithGuardian_RevertWhen_DuplicateCredKey() public {
        _install1(); // keyId 0
        validator.proposeGuardian(address(mockGuardian));

        uint48 expiry = uint48(block.timestamp + 1000);
        OneAuthRecoveryBase.NewCredential memory cred = _newCred(0, _pubKeyX1, _pubKeyY1);
        // Try to add keyId 0 again (duplicate credKey)
        bytes32 digest = validator.getRecoverDigest(address(this), block.chainid, cred, 0, expiry);
        mockGuardian.approveDigest(digest);

        vm.expectRevert(abi.encodeWithSelector(IOneAuthValidator.KeyIdAlreadyExists.selector, 0));
        validator.recoverWithGuardian(address(this), block.chainid, cred, 0, expiry, "");
    }

    function test_RecoverWithGuardian_RevertWhen_NotInitialized() public {
        validator.proposeGuardian(address(mockGuardian));

        uint48 expiry = uint48(block.timestamp + 1000);
        OneAuthRecoveryBase.NewCredential memory cred = _newCred(1, _pubKeyX1, _pubKeyY1);
        bytes32 digest = validator.getRecoverDigest(address(this), block.chainid, cred, 0, expiry);
        mockGuardian.approveDigest(digest);

        // _addCredentialRecovery checks isInitialized
        vm.expectRevert();
        validator.recoverWithGuardian(address(this), block.chainid, cred, 0, expiry, "");
    }

    function test_RecoverWithGuardian_RevertWhen_InvalidChainId() public {
        _install1();
        validator.proposeGuardian(address(mockGuardian));

        uint48 expiry = uint48(block.timestamp + 1000);
        OneAuthRecoveryBase.NewCredential memory cred = _newCred(1, _pubKeyX1, _pubKeyY1);
        vm.expectRevert(OneAuthRecoveryBase.InvalidChainId.selector);
        validator.recoverWithGuardian(address(this), 999, cred, 0, expiry, "");
    }

    function test_RecoverWithGuardian_ChainIdZero_AnyChain() public {
        _install1();
        validator.proposeGuardian(address(mockGuardian));

        uint48 expiry = uint48(block.timestamp + 1000);
        OneAuthRecoveryBase.NewCredential memory cred = _newCred(1, _pubKeyX1, _pubKeyY1);

        // chainId=0 means any chain
        bytes32 digest = validator.getRecoverDigest(address(this), 0, cred, 0, expiry);
        mockGuardian.approveDigest(digest);

        validator.recoverWithGuardian(address(this), 0, cred, 0, expiry, "");

        // Verify credential was added
        (bytes32 px, bytes32 py) = validator.getCredential(1, address(this));
        assertEq(px, _pubKeyX1);
        assertEq(py, _pubKeyY1);
    }

    function test_RecoverWithGuardian_MultipleDifferentNonces() public {
        _install1();
        validator.proposeGuardian(address(mockGuardian));

        uint48 expiry = uint48(block.timestamp + 1000);

        // Recovery with nonce 10
        OneAuthRecoveryBase.NewCredential memory cred1 = _newCred(1, _pubKeyX1, _pubKeyY1);
        bytes32 digest1 = validator.getRecoverDigest(address(this), block.chainid, cred1, 10, expiry);
        mockGuardian.approveDigest(digest1);
        validator.recoverWithGuardian(address(this), block.chainid, cred1, 10, expiry, "");

        // Recovery with nonce 20 (different keyId)
        OneAuthRecoveryBase.NewCredential memory cred2 = _newCred(2, _pubKeyX1, _pubKeyY1);
        bytes32 digest2 = validator.getRecoverDigest(address(this), block.chainid, cred2, 20, expiry);
        mockGuardian.approveDigest(digest2);
        validator.recoverWithGuardian(address(this), block.chainid, cred2, 20, expiry, "");

        // Both nonces used
        assertTrue(validator.nonceUsed(address(this), 10));
        assertTrue(validator.nonceUsed(address(this), 20));
        assertFalse(validator.nonceUsed(address(this), 15)); // unused nonce

        // 3 credentials total now (original + 2 recovered)
        assertEq(validator.credentialCount(address(this)), 3);
    }

    /*//////////////////////////////////////////////////////////////////////////
                      CREDENTIAL REPLACEMENT RECOVERY TESTS
    //////////////////////////////////////////////////////////////////////////*/

    function test_RecoverWithGuardian_ReplaceCredential() public {
        _install1(); // keyId 0
        validator.addCredential(5, _pubKeyX1, _pubKeyY1); // keyId 5
        validator.proposeGuardian(address(mockGuardian));

        uint48 expiry = uint48(block.timestamp + 1000);
        // Replace keyId 5 in-place with new pubkey (replace=true)
        OneAuthRecoveryBase.NewCredential memory cred = _newCredReplace(5, _pubKeyX0, _pubKeyY0);

        bytes32 digest = validator.getRecoverDigest(address(this), block.chainid, cred, 0, expiry);
        mockGuardian.approveDigest(digest);

        validator.recoverWithGuardian(address(this), block.chainid, cred, 0, expiry, "");

        // Credential at keyId 5 should now have the new pubkey
        (bytes32 px, bytes32 py) = validator.getCredential(5, address(this));
        assertEq(px, _pubKeyX0, "Credential should be rotated in-place");
        assertEq(py, _pubKeyY0);

        // Count should stay the same (original 2, replaced 1 → still 2)
        assertEq(validator.credentialCount(address(this)), 2);
    }

    function test_RecoverWithGuardian_ReplaceCredential_KeyIdZero() public {
        _install1(); // keyId 0
        validator.proposeGuardian(address(mockGuardian));

        uint48 expiry = uint48(block.timestamp + 1000);
        // Replace keyId 0 in-place (verifies bool replace works for keyId 0)
        OneAuthRecoveryBase.NewCredential memory cred = _newCredReplace(0, _pubKeyX1, _pubKeyY1);

        bytes32 digest = validator.getRecoverDigest(address(this), block.chainid, cred, 0, expiry);
        mockGuardian.approveDigest(digest);

        validator.recoverWithGuardian(address(this), block.chainid, cred, 0, expiry, "");

        // Credential at keyId 0 should now have the new pubkey
        (bytes32 px, bytes32 py) = validator.getCredential(0, address(this));
        assertEq(px, _pubKeyX1, "Credential should be rotated in-place");
        assertEq(py, _pubKeyY1);

        // Count should stay the same
        assertEq(validator.credentialCount(address(this)), 1);
    }

    function test_RecoverWithGuardian_ReplaceCredential_RevertWhen_NotFound() public {
        _install1(); // only keyId 0
        validator.proposeGuardian(address(mockGuardian));

        uint48 expiry = uint48(block.timestamp + 1000);
        // Try to replace non-existent keyId 99
        OneAuthRecoveryBase.NewCredential memory cred = _newCredReplace(99, _pubKeyX1, _pubKeyY1);

        bytes32 digest = validator.getRecoverDigest(address(this), block.chainid, cred, 0, expiry);
        mockGuardian.approveDigest(digest);

        vm.expectRevert(abi.encodeWithSelector(IOneAuthValidator.CredentialNotFound.selector, 99));
        validator.recoverWithGuardian(address(this), block.chainid, cred, 0, expiry, "");
    }

    function test_GetRecoverDigest_DifferentReplace() public view {
        OneAuthRecoveryBase.NewCredential memory cred1 = _newCred(1, _pubKeyX1, _pubKeyY1);
        OneAuthRecoveryBase.NewCredential memory cred2 = _newCredReplace(1, _pubKeyX1, _pubKeyY1);
        bytes32 d1 = validator.getRecoverDigest(address(this), block.chainid, cred1, 0, 1000);
        bytes32 d2 = validator.getRecoverDigest(address(this), block.chainid, cred2, 0, 1000);
        assertTrue(d1 != d2, "Different replace flag should produce different digest");
    }

    /*//////////////////////////////////////////////////////////////////////////
                          NONCE PERSISTENCE ACROSS REINSTALL
    //////////////////////////////////////////////////////////////////////////*/

    function test_RecoveryNonce_PersistsAcrossReinstall() public {
        _install1();
        validator.proposeGuardian(address(mockGuardian));

        uint48 expiry = uint48(block.timestamp + 1000);
        uint256 nonce = 42;
        OneAuthRecoveryBase.NewCredential memory cred = _newCred(1, _pubKeyX1, _pubKeyY1);

        // Execute a recovery to consume nonce 42
        bytes32 digest = validator.getRecoverDigest(address(this), block.chainid, cred, nonce, expiry);
        mockGuardian.approveDigest(digest);
        validator.recoverWithGuardian(address(this), block.chainid, cred, nonce, expiry, "");

        assertTrue(validator.nonceUsed(address(this), nonce), "Nonce should be used after recovery");

        // Uninstall
        validator.onUninstall("");

        // Verify nonce is still used after uninstall
        assertTrue(validator.nonceUsed(address(this), nonce), "Nonce should persist after uninstall");

        // Reinstall
        _install1();

        // Verify nonce is STILL used after reinstall
        assertTrue(validator.nonceUsed(address(this), nonce), "Nonce should persist after reinstall");
    }

    /*//////////////////////////////////////////////////////////////////////////
                              EVENT TESTS
    //////////////////////////////////////////////////////////////////////////*/

    function test_RecoverWithGuardian_EmitsEvent() public {
        _install1();
        validator.proposeGuardian(address(mockGuardian));

        uint48 expiry = uint48(block.timestamp + 1000);
        uint256 nonce = 5;
        OneAuthRecoveryBase.NewCredential memory cred = _newCred(1, _pubKeyX1, _pubKeyY1);

        bytes32 digest = validator.getRecoverDigest(address(this), block.chainid, cred, nonce, expiry);
        mockGuardian.approveDigest(digest);

        vm.expectEmit(true, true, true, true);
        emit OneAuthRecoveryBase.GuardianRecoveryExecuted(
            address(this), address(mockGuardian), 1, nonce
        );

        validator.recoverWithGuardian(address(this), block.chainid, cred, nonce, expiry, "");
    }

    function test_ProposeGuardian_EmitsEvent() public {
        vm.expectEmit(true, true, false, false);
        emit OneAuthRecoveryBase.GuardianSet(address(this), address(mockGuardian));

        validator.proposeGuardian(address(mockGuardian));
    }

    /*//////////////////////////////////////////////////////////////////////////
                          GUARDIAN TIMELOCK TESTS
    //////////////////////////////////////////////////////////////////////////*/

    function test_SetGuardianTimelock() public {
        uint48 duration = 1 days;
        vm.expectEmit(true, false, false, true);
        emit OneAuthRecoveryBase.GuardianTimelockSet(address(this), duration);
        validator.setGuardianTimelock(duration);

        assertEq(validator.guardianTimelock(address(this)), duration);
    }

    function test_ProposeGuardian_PendingWhen_TimelockSet() public {
        validator.setGuardianTimelock(1 days);

        vm.expectEmit(true, true, false, true);
        emit OneAuthRecoveryBase.GuardianChangeProposed(
            address(this), address(mockGuardian), uint48(block.timestamp + 1 days)
        );
        validator.proposeGuardian(address(mockGuardian));

        // Guardian should NOT be set yet
        assertEq(validator.guardian(address(this)), address(0));

        // Pending info should be populated
        (address pending, uint48 activatesAt) = validator.pendingGuardianInfo(address(this));
        assertEq(pending, address(mockGuardian));
        assertEq(activatesAt, uint48(block.timestamp + 1 days));
    }

    function test_ConfirmGuardian_RevertWhen_TimelockNotElapsed() public {
        validator.setGuardianTimelock(1 days);
        validator.proposeGuardian(address(mockGuardian));

        // Try to confirm before timelock elapses
        vm.expectRevert(OneAuthRecoveryBase.GuardianTimelockNotElapsed.selector);
        validator.confirmGuardian();
    }

    function test_ConfirmGuardian_Success_AfterTimelock() public {
        validator.setGuardianTimelock(1 days);
        validator.proposeGuardian(address(mockGuardian));

        // Warp past the timelock
        vm.warp(block.timestamp + 1 days);

        vm.expectEmit(true, true, false, false);
        emit OneAuthRecoveryBase.GuardianSet(address(this), address(mockGuardian));
        validator.confirmGuardian();

        // Guardian should now be set
        assertEq(validator.guardian(address(this)), address(mockGuardian));

        // Pending info should be cleared
        (address pending, uint48 activatesAt) = validator.pendingGuardianInfo(address(this));
        assertEq(pending, address(0));
        assertEq(activatesAt, 0);
    }

    function test_CancelGuardianChange() public {
        validator.setGuardianTimelock(1 days);
        validator.proposeGuardian(address(mockGuardian));

        vm.expectEmit(true, false, false, false);
        emit OneAuthRecoveryBase.GuardianChangeCancelled(address(this));
        validator.cancelGuardianChange();

        // Pending should be cleared
        (address pending, uint48 activatesAt) = validator.pendingGuardianInfo(address(this));
        assertEq(pending, address(0));
        assertEq(activatesAt, 0);

        // Guardian should still be address(0)
        assertEq(validator.guardian(address(this)), address(0));
    }

    function test_CancelGuardianChange_RevertWhen_NoPending() public {
        vm.expectRevert(OneAuthRecoveryBase.NoPendingGuardianChange.selector);
        validator.cancelGuardianChange();
    }

    function test_ConfirmGuardian_RevertWhen_NoPending() public {
        vm.expectRevert(OneAuthRecoveryBase.NoPendingGuardianChange.selector);
        validator.confirmGuardian();
    }

    function test_OnUninstall_ClearsPendingGuardian() public {
        _install1();
        validator.setGuardianTimelock(1 days);
        validator.proposeGuardian(address(mockGuardian));

        validator.onUninstall("");

        // Pending should be cleared
        (address pending, uint48 activatesAt) = validator.pendingGuardianInfo(address(this));
        assertEq(pending, address(0));
        assertEq(activatesAt, 0);
    }

    function test_GuardianTimelock_PersistsFromPreInstall() public {
        // Set timelock BEFORE installing the module
        validator.setGuardianTimelock(1 days);

        // Install with guardianTimelock=0 (which means "don't override")
        // _install1 passes guardianTimelock=0 in the encoded data
        _install1();

        // The pre-install timelock should persist because onInstall only
        // sets guardianTimelock when the provided value is non-zero
        assertEq(
            validator.guardianTimelock(address(this)),
            1 days,
            "Pre-install timelock should persist when onInstall passes 0"
        );
    }

    function test_SetGuardianTimelock_RemoveTimelock() public {
        _install1();

        // Set a timelock
        validator.setGuardianTimelock(1 days);
        assertEq(validator.guardianTimelock(address(this)), 1 days);

        // Remove timelock by setting to 0
        validator.setGuardianTimelock(0);
        assertEq(validator.guardianTimelock(address(this)), 0);

        // Now proposeGuardian should take effect immediately
        address newGuardian = makeAddr("newGuardian");
        validator.proposeGuardian(newGuardian);
        assertEq(
            validator.guardian(address(this)),
            newGuardian,
            "Guardian should change immediately with zero timelock"
        );
    }

    function test_OnInstall_SetsGuardianTimelock() public {
        uint16[] memory keyIds = new uint16[](1);
        keyIds[0] = 0;
        OneAuthValidator.WebAuthnCredential[] memory creds =
            new OneAuthValidator.WebAuthnCredential[](1);
        creds[0] = OneAuthValidator.WebAuthnCredential({ pubKeyX: _pubKeyX0, pubKeyY: _pubKeyY0 });
        validator.onInstall(abi.encode(keyIds, creds, address(mockGuardian), uint48(1 days)));

        assertEq(validator.guardian(address(this)), address(mockGuardian));
        assertEq(validator.guardianTimelock(address(this)), uint48(1 days));

        // With timelock set via onInstall, proposeGuardian should queue (not immediate)
        validator.proposeGuardian(address(rejectingGuardian));
        assertEq(validator.guardian(address(this)), address(mockGuardian));
    }
}
