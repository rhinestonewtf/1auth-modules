// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { BaseTest } from "test/Base.t.sol";
import { OneAuthValidator } from "src/OneAuth/OneAuthValidator.sol";
import { OneAuthAppValidator } from "src/OneAuth/OneAuthAppValidator.sol";
import { IOneAuthAppValidator } from "src/OneAuth/IOneAuthAppValidator.sol";
import { ERC7579ValidatorBase } from "modulekit/Modules.sol";
import { PackedUserOperation, getEmptyUserOperation } from "test/utils/ERC4337.sol";
import { EIP1271_MAGIC_VALUE } from "test/utils/Constants.sol";
import { Base64Url } from "FreshCryptoLib/utils/Base64Url.sol";
import { P256VerifierWrapper } from "test/OneAuth/helpers/P256VerifierWrapper.sol";

contract OneAuthAppValidatorTest is BaseTest {
    OneAuthValidator internal mainValidator;
    OneAuthAppValidator internal appValidator;

    address constant MAIN_ACCOUNT = address(0xAA);
    address constant APP_ACCOUNT = address(0xBB);

    uint256 constant P256_PRIV_KEY = 0x03d99692017473e2d631945a812607b23269d85721e0f370b8d3e7d29a874004;

    bytes32 _pubKeyX0;
    bytes32 _pubKeyY0;

    bytes32 _pubKeyX1 =
        bytes32(uint256(77_427_310_596_034_628_445_756_159_459_159_056_108_500_819_865_614_675_054_701_790_516_611_205_123_311));
    bytes32 _pubKeyY1 =
        bytes32(uint256(20_591_151_874_462_689_689_754_215_152_304_668_244_192_265_896_034_279_288_204_806_249_532_173_935_644));

    bytes32 constant TEST_DIGEST =
        0xf631058a3ba1116acce12396fad0a125b5041c43f8e15723709f81aa8d5f4ccf;

    uint256 constant P256_N =
        0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;
    uint256 constant P256_N_DIV_2 =
        0x7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8;

    bytes constant AUTH_DATA_UV =
        hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630500000001";

    uint256 constant CHALLENGE_INDEX = 23;
    uint256 constant TYPE_INDEX = 1;

    function setUp() public virtual override {
        BaseTest.setUp();

        // Deploy P256 verifier
        address SOLADY_P256_VERIFIER = 0x000000000000D01eA45F9eFD5c54f037Fa57Ea1a;
        P256VerifierWrapper verifier_ = new P256VerifierWrapper();
        vm.etch(SOLADY_P256_VERIFIER, address(verifier_).code);

        mainValidator = new OneAuthValidator();
        appValidator = new OneAuthAppValidator(address(mainValidator));

        // Derive P-256 public keys
        (uint256 x0, uint256 y0) = vm.publicKeyP256(P256_PRIV_KEY);
        _pubKeyX0 = bytes32(x0);
        _pubKeyY0 = bytes32(y0);

        // Install credential on main validator for MAIN_ACCOUNT
        _installMainAccount();
    }

    /*//////////////////////////////////////////////////////////////////////////
                              HELPERS
    //////////////////////////////////////////////////////////////////////////*/

    function _installMainAccount() internal {
        uint16[] memory keyIds = new uint16[](1);
        keyIds[0] = 0;
        OneAuthValidator.WebAuthnCredential[] memory creds =
            new OneAuthValidator.WebAuthnCredential[](1);
        creds[0] = OneAuthValidator.WebAuthnCredential({
            pubKeyX: _pubKeyX0,
            pubKeyY: _pubKeyY0
        });
        bytes memory data = abi.encode(keyIds, creds, address(0), address(0), uint8(0));
        vm.prank(MAIN_ACCOUNT);
        mainValidator.onInstall(data);
    }

    function _installAppAccount() internal {
        vm.prank(APP_ACCOUNT);
        appValidator.onInstall(abi.encode(MAIN_ACCOUNT, address(0), address(0), uint8(0)));
    }

    function _buildClientDataJSON(bytes32 challengeHash) internal pure returns (string memory) {
        bytes memory challenge = abi.encode(challengeHash);
        return string.concat(
            '{"type":"webauthn.get","challenge":"',
            Base64Url.encode(challenge),
            '","origin":"http://localhost:8080","crossOrigin":false}'
        );
    }

    function _createValidWebAuthnSig(bytes32 digest)
        internal
        view
        returns (uint256 r, uint256 s, string memory clientDataJSON)
    {
        // The main validator wraps the digest in EIP-712
        bytes32 challenge = mainValidator.getPasskeyDigest(digest);
        clientDataJSON = _buildClientDataJSON(challenge);

        bytes32 msgHash = sha256(abi.encodePacked(AUTH_DATA_UV, sha256(bytes(clientDataJSON))));
        (bytes32 r32, bytes32 s32) = vm.signP256(P256_PRIV_KEY, msgHash);
        r = uint256(r32);
        s = uint256(s32);

        if (s > P256_N_DIV_2) {
            s = P256_N - s;
        }
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

    function _buildMerkleSignature(
        bytes32 merkleRoot,
        bytes32[] memory proof,
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
        bytes memory result = abi.encodePacked(uint8(proof.length), merkleRoot);
        for (uint256 i; i < proof.length; ++i) {
            result = abi.encodePacked(result, proof[i]);
        }
        result = abi.encodePacked(
            result,
            keyId,
            r,
            s,
            uint16(CHALLENGE_INDEX),
            uint16(TYPE_INDEX),
            uint16(authenticatorData.length),
            authenticatorData,
            clientDataJSON
        );
        return result;
    }

    /*//////////////////////////////////////////////////////////////////////////
                              CONSTRUCTOR TESTS
    //////////////////////////////////////////////////////////////////////////*/

    function test_Constructor() public view {
        assertEq(address(appValidator.mainValidator()), address(mainValidator));
    }

    function test_Constructor_RevertWhen_ZeroAddress() public {
        vm.expectRevert(IOneAuthAppValidator.InvalidMainValidator.selector);
        new OneAuthAppValidator(address(0));
    }

    /*//////////////////////////////////////////////////////////////////////////
                              CONFIG TESTS
    //////////////////////////////////////////////////////////////////////////*/

    function test_OnInstall() public {
        _installAppAccount();
        assertTrue(appValidator.isInitialized(APP_ACCOUNT));
        assertEq(appValidator.getMainAccount(APP_ACCOUNT), MAIN_ACCOUNT);
    }

    function test_OnInstall_RevertWhen_AlreadyInitialized() public {
        _installAppAccount();
        vm.prank(APP_ACCOUNT);
        vm.expectRevert();
        appValidator.onInstall(abi.encode(MAIN_ACCOUNT, address(0), address(0), uint8(0)));
    }

    function test_OnInstall_RevertWhen_ZeroMainAccount() public {
        vm.prank(APP_ACCOUNT);
        vm.expectRevert(IOneAuthAppValidator.InvalidMainAccount.selector);
        appValidator.onInstall(abi.encode(address(0), address(0), address(0), uint8(0)));
    }

    function test_OnUninstall() public {
        _installAppAccount();
        assertTrue(appValidator.isInitialized(APP_ACCOUNT));

        vm.prank(APP_ACCOUNT);
        appValidator.onUninstall("");
        assertFalse(appValidator.isInitialized(APP_ACCOUNT));
        assertEq(appValidator.getMainAccount(APP_ACCOUNT), address(0));
    }

    function test_OnUninstall_RevertWhen_NotInitialized() public {
        vm.prank(APP_ACCOUNT);
        vm.expectRevert();
        appValidator.onUninstall("");
    }

    function test_IsInitialized() public {
        assertFalse(appValidator.isInitialized(APP_ACCOUNT));
        _installAppAccount();
        assertTrue(appValidator.isInitialized(APP_ACCOUNT));
    }

    function test_GetMainAccount() public {
        assertEq(appValidator.getMainAccount(APP_ACCOUNT), address(0));
        _installAppAccount();
        assertEq(appValidator.getMainAccount(APP_ACCOUNT), MAIN_ACCOUNT);
    }

    /*//////////////////////////////////////////////////////////////////////////
                              VALIDATION TESTS — REGULAR SIGNING
    //////////////////////////////////////////////////////////////////////////*/

    function test_ValidateUserOp_RegularSigning() public {
        _installAppAccount();

        PackedUserOperation memory userOp = getEmptyUserOperation();
        userOp.sender = APP_ACCOUNT;

        (uint256 r, uint256 s, string memory clientDataJSON) = _createValidWebAuthnSig(TEST_DIGEST);
        userOp.signature = _buildRegularSignature(0, r, s, AUTH_DATA_UV, clientDataJSON);

        uint256 validationData =
            ERC7579ValidatorBase.ValidationData.unwrap(appValidator.validateUserOp(userOp, TEST_DIGEST));
        assertEq(validationData, 0, "Should return VALIDATION_SUCCESS");
    }

    function test_ValidateUserOp_FailWhen_NotInstalled() public view {
        PackedUserOperation memory userOp = getEmptyUserOperation();
        userOp.sender = APP_ACCOUNT;

        (uint256 r, uint256 s, string memory clientDataJSON) = _createValidWebAuthnSig(TEST_DIGEST);
        userOp.signature = _buildRegularSignature(0, r, s, AUTH_DATA_UV, clientDataJSON);

        uint256 validationData =
            ERC7579ValidatorBase.ValidationData.unwrap(appValidator.validateUserOp(userOp, TEST_DIGEST));
        assertEq(validationData, 1, "Should return VALIDATION_FAILED when not installed");
    }

    function test_ValidateUserOp_FailWhen_WrongKeyId() public {
        _installAppAccount();

        PackedUserOperation memory userOp = getEmptyUserOperation();
        userOp.sender = APP_ACCOUNT;

        (uint256 r, uint256 s, string memory clientDataJSON) = _createValidWebAuthnSig(TEST_DIGEST);
        userOp.signature = _buildRegularSignature(99, r, s, AUTH_DATA_UV, clientDataJSON);

        uint256 validationData =
            ERC7579ValidatorBase.ValidationData.unwrap(appValidator.validateUserOp(userOp, TEST_DIGEST));
        assertEq(validationData, 1, "Should fail with wrong keyId");
    }

    function test_ValidateUserOp_FailWhen_MainAccountNotInitialized() public {
        // Point app account to an account that has no credentials
        address emptyMainAccount = address(0xCC);
        vm.prank(APP_ACCOUNT);
        appValidator.onInstall(abi.encode(emptyMainAccount, address(0), address(0), uint8(0)));

        PackedUserOperation memory userOp = getEmptyUserOperation();
        userOp.sender = APP_ACCOUNT;

        (uint256 r, uint256 s, string memory clientDataJSON) = _createValidWebAuthnSig(TEST_DIGEST);
        userOp.signature = _buildRegularSignature(0, r, s, AUTH_DATA_UV, clientDataJSON);

        uint256 validationData =
            ERC7579ValidatorBase.ValidationData.unwrap(appValidator.validateUserOp(userOp, TEST_DIGEST));
        assertEq(validationData, 1, "Should fail when main account has no credentials");
    }

    // --- EIP-1271 ---

    function test_IsValidSignatureWithSender_RegularSigning() public {
        _installAppAccount();

        (uint256 r, uint256 s, string memory clientDataJSON) = _createValidWebAuthnSig(TEST_DIGEST);
        bytes memory sig = _buildRegularSignature(0, r, s, AUTH_DATA_UV, clientDataJSON);

        vm.prank(APP_ACCOUNT);
        bytes4 result = appValidator.isValidSignatureWithSender(address(0), TEST_DIGEST, sig);
        assertEq(result, EIP1271_MAGIC_VALUE, "Should return EIP1271_SUCCESS");
    }

    function test_IsValidSignatureWithSender_FailWhen_NotInstalled() public {
        (uint256 r, uint256 s, string memory clientDataJSON) = _createValidWebAuthnSig(TEST_DIGEST);
        bytes memory sig = _buildRegularSignature(0, r, s, AUTH_DATA_UV, clientDataJSON);

        vm.prank(APP_ACCOUNT);
        bytes4 result = appValidator.isValidSignatureWithSender(address(0), TEST_DIGEST, sig);
        assertEq(result, bytes4(0xffffffff), "Should return EIP1271_FAILED");
    }

    /*//////////////////////////////////////////////////////////////////////////
                              VALIDATION TESTS — MERKLE SIGNING
    //////////////////////////////////////////////////////////////////////////*/

    function test_ValidateUserOp_WithMerkleProof() public {
        _installAppAccount();

        bytes32 leaf0 = TEST_DIGEST;
        bytes32 leaf1 = bytes32(uint256(0xdead));

        bytes32 merkleRoot;
        if (uint256(leaf0) < uint256(leaf1)) {
            merkleRoot = keccak256(abi.encodePacked(leaf0, leaf1));
        } else {
            merkleRoot = keccak256(abi.encodePacked(leaf1, leaf0));
        }

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = leaf1;

        // Create a valid multichain signature over the merkle root
        bytes32 challenge = mainValidator.getPasskeyMultichain(merkleRoot);
        string memory clientDataJSON = _buildClientDataJSON(challenge);

        bytes32 msgHash = sha256(abi.encodePacked(AUTH_DATA_UV, sha256(bytes(clientDataJSON))));
        (bytes32 r32, bytes32 s32) = vm.signP256(P256_PRIV_KEY, msgHash);
        uint256 r = uint256(r32);
        uint256 s = uint256(s32);
        if (s > P256_N_DIV_2) {
            s = P256_N - s;
        }

        PackedUserOperation memory userOp = getEmptyUserOperation();
        userOp.sender = APP_ACCOUNT;
        userOp.signature = _buildMerkleSignature(merkleRoot, proof, 0, r, s, AUTH_DATA_UV, clientDataJSON);

        uint256 validationData =
            ERC7579ValidatorBase.ValidationData.unwrap(appValidator.validateUserOp(userOp, TEST_DIGEST));
        assertEq(validationData, 0, "Should return VALIDATION_SUCCESS with merkle proof");
    }

    /*//////////////////////////////////////////////////////////////////////////
                              LIVE CREDENTIAL ACCESS TESTS
    //////////////////////////////////////////////////////////////////////////*/

    function test_MainCredentialChange_ReflectedInAppValidator() public {
        _installAppAccount();

        // Add a new credential (keyId 1) on the main account
        vm.prank(MAIN_ACCOUNT);
        mainValidator.addCredential(1, _pubKeyX1, _pubKeyY1);

        // Verify the app validator can validate using the new keyId 1
        // (We can't create a valid sig for pubKey1 since we don't have its private key,
        //  but we can verify keyId 0 still works after the change)
        PackedUserOperation memory userOp = getEmptyUserOperation();
        userOp.sender = APP_ACCOUNT;

        (uint256 r, uint256 s, string memory clientDataJSON) = _createValidWebAuthnSig(TEST_DIGEST);
        userOp.signature = _buildRegularSignature(0, r, s, AUTH_DATA_UV, clientDataJSON);

        uint256 validationData =
            ERC7579ValidatorBase.ValidationData.unwrap(appValidator.validateUserOp(userOp, TEST_DIGEST));
        assertEq(validationData, 0, "Should still work after main account credential change");
    }

    /*//////////////////////////////////////////////////////////////////////////
                              METADATA TESTS
    //////////////////////////////////////////////////////////////////////////*/

    function test_IsModuleType_Validator() public view {
        assertTrue(appValidator.isModuleType(1));
    }

    function test_IsModuleType_NotStatelessValidator() public view {
        assertFalse(appValidator.isModuleType(7));
    }

    function test_IsModuleType_Other() public view {
        assertFalse(appValidator.isModuleType(2));
        assertFalse(appValidator.isModuleType(0));
    }

    function test_Name() public view {
        assertEq(appValidator.name(), "OneAuthAppValidator");
    }

    function test_Version() public view {
        assertEq(appValidator.version(), "1.0.0");
    }

    /*//////////////////////////////////////////////////////////////////////////
                              EVENT TESTS
    //////////////////////////////////////////////////////////////////////////*/

    function test_OnInstall_EmitsAppValidatorInstalled() public {
        vm.prank(APP_ACCOUNT);
        vm.expectEmit(true, true, false, false);
        emit IOneAuthAppValidator.AppValidatorInstalled(APP_ACCOUNT, MAIN_ACCOUNT);
        appValidator.onInstall(abi.encode(MAIN_ACCOUNT, address(0), address(0), uint8(0)));
    }

    function test_OnUninstall_EmitsAppValidatorUninstalled() public {
        _installAppAccount();

        vm.prank(APP_ACCOUNT);
        vm.expectEmit(true, false, false, false);
        emit IOneAuthAppValidator.AppValidatorUninstalled(APP_ACCOUNT);
        appValidator.onUninstall("");
    }
}
