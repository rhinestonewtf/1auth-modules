// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { BaseTest } from "test/Base.t.sol";
import { OneAuthValidator } from "src/OneAuth/OneAuthValidator.sol";
import { IOneAuthValidator } from "src/OneAuth/IOneAuthValidator.sol";
import { ERC7579HybridValidatorBase, ERC7579ValidatorBase } from "modulekit/Modules.sol";
import { WebAuthn } from "solady/utils/WebAuthn.sol";
import { PackedUserOperation, getEmptyUserOperation } from "test/utils/ERC4337.sol";
import { EIP1271_MAGIC_VALUE } from "test/utils/Constants.sol";
import { Base64Url } from "FreshCryptoLib/utils/Base64Url.sol";
import { console2 } from "forge-std/console2.sol";
import { P256VerifierWrapper } from "test/OneAuth/helpers/P256VerifierWrapper.sol";

contract OneAuthValidatorTest is BaseTest {
    OneAuthValidator internal validator;

    uint256 constant P256_PRIV_KEY = 0x03d99692017473e2d631945a812607b23269d85721e0f370b8d3e7d29a874004;

    // Test public keys — pubKey0 is derived from P256_PRIV_KEY in setUp()
    bytes32 _pubKeyX0;
    bytes32 _pubKeyY0;

    bytes32 _pubKeyX1 =
        bytes32(uint256(77_427_310_596_034_628_445_756_159_459_159_056_108_500_819_865_614_675_054_701_790_516_611_205_123_311));
    bytes32 _pubKeyY1 =
        bytes32(uint256(20_591_151_874_462_689_689_754_215_152_304_668_244_192_265_896_034_279_288_204_806_249_532_173_935_644));

    // The digest that the test WebAuthn signatures were created for
    bytes32 constant TEST_DIGEST =
        0xf631058a3ba1116acce12396fad0a125b5041c43f8e15723709f81aa8d5f4ccf;

    // P-256 field prime (for on-curve edge case tests)
    uint256 constant P256_P =
        0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF;

    // P-256 curve order N and N/2 (for s-malleability normalization)
    uint256 constant P256_N =
        0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;
    uint256 constant P256_N_DIV_2 =
        0x7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8;

    // Real WebAuthn auth data (UP flag only, no UV)
    bytes constant AUTH_DATA =
        hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630100000001";

    // Auth data with both UP and UV flags set (flags byte = 0x05)
    bytes constant AUTH_DATA_UV =
        hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630500000001";
    uint256 constant SIG_R =
        23_510_924_181_331_275_540_501_876_269_042_668_160_690_304_423_490_805_737_085_519_687_669_896_593_880;
    uint256 constant SIG_S =
        36_590_747_517_247_563_381_084_733_394_442_750_806_324_326_036_343_798_276_847_517_765_557_371_045_088;
    uint256 constant CHALLENGE_INDEX = 23;
    uint256 constant TYPE_INDEX = 1;

    function setUp() public virtual override {
        BaseTest.setUp();

        // Deploy P256 verifier at the Solady VERIFIER address so Solady's P256.sol can verify signatures
        address SOLADY_P256_VERIFIER = 0x000000000000D01eA45F9eFD5c54f037Fa57Ea1a;
        P256VerifierWrapper verifier_ = new P256VerifierWrapper();
        vm.etch(SOLADY_P256_VERIFIER, address(verifier_).code);

        validator = new OneAuthValidator();

        // Derive P-256 public keys from private key
        (uint256 x0, uint256 y0) = vm.publicKeyP256(P256_PRIV_KEY);
        _pubKeyX0 = bytes32(x0);
        _pubKeyY0 = bytes32(y0);
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

    function _packWebAuthnAuth(
        uint256 r,
        uint256 s,
        uint16 challengeIdx,
        uint16 typeIdx,
        bytes memory authenticatorData,
        string memory clientDataJSON
    )
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
            r, s, challengeIdx, typeIdx, uint16(authenticatorData.length), authenticatorData, clientDataJSON
        );
    }

    /// @dev Regular signing (proofLength=0): challenge = digest
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

    /// @dev Merkle signing (proofLength>0): challenge = merkleRoot
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

    /// @dev Create a valid WebAuthn signature at runtime using vm.signP256
    /// Uses AUTH_DATA_UV (with UV flag set) since the contract defaults to requireUV=true
    function _createValidWebAuthnSig(bytes32 digest)
        internal
        view
        returns (uint256 r, uint256 s, string memory clientDataJSON)
    {
        // The contract wraps the digest in EIP-712
        bytes32 challenge = validator.getPasskeyDigest(digest);
        clientDataJSON = _buildClientDataJSON(challenge);

        // WebAuthn message = sha256(authenticatorData || sha256(clientDataJSON))
        bytes32 msgHash = sha256(abi.encodePacked(AUTH_DATA_UV, sha256(bytes(clientDataJSON))));

        // Sign with P-256
        (bytes32 r32, bytes32 s32) = vm.signP256(P256_PRIV_KEY, msgHash);
        r = uint256(r32);
        s = uint256(s32);

        // Normalize s to low-half per Solady's malleability check (s must be <= N/2)
        if (s > P256_N_DIV_2) {
            s = P256_N - s;
        }
    }

    function _installData1() internal view returns (bytes memory) {
        uint16[] memory keyIds = new uint16[](1);
        keyIds[0] = 0;
        OneAuthValidator.WebAuthnCredential[] memory creds =
            new OneAuthValidator.WebAuthnCredential[](1);
        creds[0] = OneAuthValidator.WebAuthnCredential({
            pubKeyX: _pubKeyX0,
            pubKeyY: _pubKeyY0
        });
        return abi.encode(keyIds, creds, address(0), uint48(0));
    }

    function _installData2() internal view returns (bytes memory) {
        uint16[] memory keyIds = new uint16[](2);
        keyIds[0] = 10;
        keyIds[1] = 42;
        OneAuthValidator.WebAuthnCredential[] memory creds =
            new OneAuthValidator.WebAuthnCredential[](2);
        creds[0] = OneAuthValidator.WebAuthnCredential({
            pubKeyX: _pubKeyX0,
            pubKeyY: _pubKeyY0
        });
        creds[1] = OneAuthValidator.WebAuthnCredential({
            pubKeyX: _pubKeyX1,
            pubKeyY: _pubKeyY1
        });
        return abi.encode(keyIds, creds, address(0), uint48(0));
    }

    function _install1() internal {
        validator.onInstall(_installData1());
    }

    function _install2() internal {
        validator.onInstall(_installData2());
    }

    /*//////////////////////////////////////////////////////////////////////////
                                  CONFIG TESTS
    //////////////////////////////////////////////////////////////////////////*/

    function test_OnInstall() public {
        _install2();
        assertTrue(validator.isInitialized(address(this)));
        assertEq(validator.credentialCount(address(this)), 2);

        // keyId 10 → pubKey0
        (bytes32 px0, bytes32 py0) = validator.getCredential(10, address(this));
        assertEq(px0, _pubKeyX0);
        assertEq(py0, _pubKeyY0);

        // keyId 42 → pubKey1
        (bytes32 px1, bytes32 py1) = validator.getCredential(42, address(this));
        assertEq(px1, _pubKeyX1);
        assertEq(py1, _pubKeyY1);
    }

    function test_OnInstall_RevertWhen_AlreadyInitialized() public {
        _install1();
        vm.expectRevert();
        _install1();
    }

    function test_OnInstall_RevertWhen_EmptyCredentials() public {
        uint16[] memory keyIds = new uint16[](0);
        OneAuthValidator.WebAuthnCredential[] memory creds =
            new OneAuthValidator.WebAuthnCredential[](0);
        vm.expectRevert(IOneAuthValidator.InvalidPublicKey.selector);
        validator.onInstall(abi.encode(keyIds, creds, address(0), uint48(0)));
    }

    function test_OnInstall_RevertWhen_ZeroPubKey() public {
        uint16[] memory keyIds = new uint16[](1);
        keyIds[0] = 0;
        OneAuthValidator.WebAuthnCredential[] memory creds =
            new OneAuthValidator.WebAuthnCredential[](1);
        creds[0] = OneAuthValidator.WebAuthnCredential({ pubKeyX: bytes32(0), pubKeyY: bytes32(0) });
        vm.expectRevert(IOneAuthValidator.InvalidPublicKey.selector);
        validator.onInstall(abi.encode(keyIds, creds, address(0), uint48(0)));
    }

    function test_OnInstall_RevertWhen_DuplicateKeyId() public {
        uint16[] memory keyIds = new uint16[](2);
        keyIds[0] = 5;
        keyIds[1] = 5;
        OneAuthValidator.WebAuthnCredential[] memory creds =
            new OneAuthValidator.WebAuthnCredential[](2);
        creds[0] = OneAuthValidator.WebAuthnCredential({ pubKeyX: _pubKeyX0, pubKeyY: _pubKeyY0 });
        creds[1] = OneAuthValidator.WebAuthnCredential({ pubKeyX: _pubKeyX1, pubKeyY: _pubKeyY1 });
        vm.expectRevert(abi.encodeWithSelector(IOneAuthValidator.KeyIdAlreadyExists.selector, 5));
        validator.onInstall(abi.encode(keyIds, creds, address(0), uint48(0)));
    }

    function test_OnUninstall() public {
        _install2();
        assertTrue(validator.isInitialized(address(this)));

        validator.onUninstall("");
        assertFalse(validator.isInitialized(address(this)));
        assertEq(validator.credentialCount(address(this)), 0);
    }

    function test_IsInitialized() public {
        assertFalse(validator.isInitialized(address(this)));
        _install1();
        assertTrue(validator.isInitialized(address(this)));
    }

    function test_AddCredential() public {
        _install1();
        assertEq(validator.credentialCount(address(this)), 1);

        validator.addCredential(99, _pubKeyX1, _pubKeyY1);
        assertEq(validator.credentialCount(address(this)), 2);

        (bytes32 px, bytes32 py) = validator.getCredential(99, address(this));
        assertEq(px, _pubKeyX1);
        assertEq(py, _pubKeyY1);
    }

    function test_AddCredential_RevertWhen_NotInitialized() public {
        vm.expectRevert();
        validator.addCredential(0, _pubKeyX0, _pubKeyY0);
    }

    function test_AddCredential_RevertWhen_ZeroPubKey() public {
        _install1();
        vm.expectRevert(IOneAuthValidator.InvalidPublicKey.selector);
        validator.addCredential(1, bytes32(0), bytes32(0));
    }

    function test_AddCredential_RevertWhen_DuplicateKeyId() public {
        _install1(); // keyId 0
        vm.expectRevert(abi.encodeWithSelector(IOneAuthValidator.KeyIdAlreadyExists.selector, 0));
        validator.addCredential(0, _pubKeyX1, _pubKeyY1);
    }

    function test_RemoveCredential() public {
        _install2(); // keyIds 10 and 42
        assertEq(validator.credentialCount(address(this)), 2);

        validator.removeCredential(10);
        assertEq(validator.credentialCount(address(this)), 1);

        // keyId 10 credential should be cleared
        (bytes32 px,) = validator.getCredential(10, address(this));
        assertEq(px, bytes32(0), "Removed credential should be zeroed");

        // keyId 42 should still exist
        (bytes32 px42, bytes32 py42) = validator.getCredential(42, address(this));
        assertEq(px42, _pubKeyX1);
        assertEq(py42, _pubKeyY1);
    }

    function test_RemoveCredential_RevertWhen_LastCredential() public {
        _install1();
        vm.expectRevert(IOneAuthValidator.CannotRemoveLastCredential.selector);
        validator.removeCredential(0);
    }

    function test_RemoveCredential_RevertWhen_NotFound() public {
        _install2();
        vm.expectRevert(abi.encodeWithSelector(IOneAuthValidator.CredentialNotFound.selector, 999));
        validator.removeCredential(999);
    }

    function test_GetCredKeys() public {
        _install2();
        uint256[] memory credKeys = validator.getCredKeys(address(this));
        assertEq(credKeys.length, 2);
    }

    /*//////////////////////////////////////////////////////////////////////////
                              VALIDATION TESTS — REGULAR SIGNING (proofLength=0)
    //////////////////////////////////////////////////////////////////////////*/

    function test_ValidateUserOp_RegularSigning() public {
        _install1(); // keyId 0

        PackedUserOperation memory userOp = getEmptyUserOperation();
        userOp.sender = address(this);

        (uint256 r, uint256 s, string memory clientDataJSON) = _createValidWebAuthnSig(TEST_DIGEST);
        userOp.signature = _buildRegularSignature(0, r, s, AUTH_DATA_UV, clientDataJSON);

        uint256 validationData =
            ERC7579ValidatorBase.ValidationData.unwrap(validator.validateUserOp(userOp, TEST_DIGEST));
        assertEq(validationData, 0, "Should return VALIDATION_SUCCESS");
    }

    function test_ValidateUserOp_RevertWhen_NotInitialized() public view {
        PackedUserOperation memory userOp = getEmptyUserOperation();
        userOp.sender = address(this);

        userOp.signature =
            _buildRegularSignature(0, SIG_R, SIG_S, AUTH_DATA, _buildClientDataJSON(TEST_DIGEST));

        uint256 validationData =
            ERC7579ValidatorBase.ValidationData.unwrap(validator.validateUserOp(userOp, TEST_DIGEST));
        assertEq(validationData, 1, "Should return VALIDATION_FAILED when not initialized");
    }

    function test_ValidateUserOp_FailWhen_WrongKeyId() public {
        _install1(); // only keyId 0

        PackedUserOperation memory userOp = getEmptyUserOperation();
        userOp.sender = address(this);

        userOp.signature =
            _buildRegularSignature(1, SIG_R, SIG_S, AUTH_DATA, _buildClientDataJSON(TEST_DIGEST));

        uint256 validationData =
            ERC7579ValidatorBase.ValidationData.unwrap(validator.validateUserOp(userOp, TEST_DIGEST));
        assertEq(validationData, 1, "Should fail with wrong keyId");
    }

    function test_ValidateUserOp_WithArbitraryKeyId() public {
        _install2(); // keyIds 10 and 42, pubKey0 at keyId 10

        PackedUserOperation memory userOp = getEmptyUserOperation();
        userOp.sender = address(this);

        (uint256 r, uint256 s, string memory clientDataJSON) = _createValidWebAuthnSig(TEST_DIGEST);
        // Use keyId 10 which has pubKey0 (matches the test vectors)
        userOp.signature = _buildRegularSignature(10, r, s, AUTH_DATA_UV, clientDataJSON);

        uint256 validationData =
            ERC7579ValidatorBase.ValidationData.unwrap(validator.validateUserOp(userOp, TEST_DIGEST));
        assertEq(validationData, 0, "Should succeed with arbitrary keyId");
    }

    // --- EIP-1271 ---

    function test_IsValidSignatureWithSender_RegularSigning() public {
        _install1();

        (uint256 r, uint256 s, string memory clientDataJSON) = _createValidWebAuthnSig(TEST_DIGEST);
        bytes memory sig = _buildRegularSignature(0, r, s, AUTH_DATA_UV, clientDataJSON);

        bytes4 result = validator.isValidSignatureWithSender(address(this), TEST_DIGEST, sig);
        assertEq(result, EIP1271_MAGIC_VALUE, "Should return EIP1271_SUCCESS");
    }

    function test_IsValidSignatureWithSender_FailWhen_NotInitialized() public view {
        bytes memory sig =
            _buildRegularSignature(0, SIG_R, SIG_S, AUTH_DATA, _buildClientDataJSON(TEST_DIGEST));

        bytes4 result = validator.isValidSignatureWithSender(address(this), TEST_DIGEST, sig);
        assertEq(result, bytes4(0xffffffff), "Should return EIP1271_FAILED");
    }

    /*//////////////////////////////////////////////////////////////////////////
                              VALIDATION TESTS — MERKLE SIGNING (proofLength>0)
    //////////////////////////////////////////////////////////////////////////*/

    function test_ValidateUserOp_WithMerkleProof() public {
        _install1();

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

        // WebAuthn signature signs over merkleRoot, but test vectors were signed over TEST_DIGEST.
        // So WebAuthn.verify will fail — we're testing merkle proof parsing works correctly.
        string memory clientDataJSON = _buildClientDataJSON(merkleRoot);

        PackedUserOperation memory userOp = getEmptyUserOperation();
        userOp.sender = address(this);
        userOp.signature =
            _buildMerkleSignature(merkleRoot, proof, 0, SIG_R, SIG_S, AUTH_DATA, clientDataJSON);

        uint256 validationData =
            ERC7579ValidatorBase.ValidationData.unwrap(validator.validateUserOp(userOp, TEST_DIGEST));
        assertEq(validationData, 1, "Should fail WebAuthn verification (wrong challenge)");
    }

    function test_ValidateUserOp_MerkleProof_FailWhen_InvalidProof() public {
        _install1();

        bytes32 leaf0 = TEST_DIGEST;
        bytes32 leaf1 = bytes32(uint256(0xdead));

        bytes32 merkleRoot;
        if (uint256(leaf0) < uint256(leaf1)) {
            merkleRoot = keccak256(abi.encodePacked(leaf0, leaf1));
        } else {
            merkleRoot = keccak256(abi.encodePacked(leaf1, leaf0));
        }

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = bytes32(uint256(0xbad)); // wrong proof

        string memory clientDataJSON = _buildClientDataJSON(merkleRoot);

        PackedUserOperation memory userOp = getEmptyUserOperation();
        userOp.sender = address(this);
        userOp.signature =
            _buildMerkleSignature(merkleRoot, proof, 0, SIG_R, SIG_S, AUTH_DATA, clientDataJSON);

        uint256 validationData =
            ERC7579ValidatorBase.ValidationData.unwrap(validator.validateUserOp(userOp, TEST_DIGEST));
        assertEq(validationData, 1, "Should fail with invalid merkle proof");
    }

    /*//////////////////////////////////////////////////////////////////////////
                              STATELESS VALIDATION TESTS
    //////////////////////////////////////////////////////////////////////////*/

    function test_ValidateSignatureWithData_RegularSigning() public view {
        // proofLength=0: regular signing, challenge = _passkeyDigest(hash)
        bytes memory data = abi.encodePacked(
            uint8(0), // proofLength = 0
            _pubKeyX0,
            _pubKeyY0
        );

        // Compute the EIP-712 challenge
        bytes32 challenge = validator.getPasskeyDigest(TEST_DIGEST);
        string memory clientDataJSON = _buildClientDataJSON(challenge);

        // Sign the WebAuthn message
        bytes32 msgHash = sha256(abi.encodePacked(AUTH_DATA_UV, sha256(bytes(clientDataJSON))));
        (bytes32 r32, bytes32 s32) = vm.signP256(P256_PRIV_KEY, msgHash);

        // Normalize s to low-half per Solady's malleability check
        uint256 sNorm = uint256(s32);
        if (sNorm > P256_N_DIV_2) {
            sNorm = P256_N - sNorm;
        }

        bytes memory sig = _packWebAuthnAuth(
            uint256(r32), sNorm, uint16(CHALLENGE_INDEX), uint16(TYPE_INDEX), AUTH_DATA_UV, clientDataJSON
        );

        bool result = validator.validateSignatureWithData(TEST_DIGEST, sig, data);
        assertTrue(result, "Stateless regular validation should succeed");
    }

    function test_ValidateSignatureWithData_FailWhen_DataTooShort() public {
        vm.expectRevert(IOneAuthValidator.InvalidSignatureData.selector);
        validator.validateSignatureWithData(TEST_DIGEST, "", "");
    }

    function test_ValidateSignatureWithData_FailWhen_ProofTooLong() public {
        bytes memory data = abi.encodePacked(
            uint8(33), // proofLength = 33 > MAX_MERKLE_DEPTH
            bytes32(0), // merkleRoot placeholder
            _pubKeyX0,
            _pubKeyY0
        );

        vm.expectRevert(IOneAuthValidator.ProofTooLong.selector);
        validator.validateSignatureWithData(TEST_DIGEST, "", data);
    }

    function test_ValidateSignatureWithData_MerkleProof_FailWhen_InvalidProof() public {
        bytes32 fakeRoot = bytes32(uint256(0x1234));

        // proofLength=1 but wrong proof — layout matches stateful: proof before credential
        bytes memory data = abi.encodePacked(
            uint8(1), // proofLength
            fakeRoot, // merkleRoot
            bytes32(uint256(0xbad)), // wrong proof element
            _pubKeyX0,
            _pubKeyY0
        );

        string memory clientDataJSON = _buildClientDataJSON(fakeRoot);
        bytes memory sig = _packWebAuthnAuth(
            SIG_R, SIG_S, uint16(CHALLENGE_INDEX), uint16(TYPE_INDEX), AUTH_DATA, clientDataJSON
        );

        vm.expectRevert(IOneAuthValidator.InvalidMerkleProof.selector);
        validator.validateSignatureWithData(TEST_DIGEST, sig, data);
    }

    /*//////////////////////////////////////////////////////////////////////////
                              METADATA TESTS
    //////////////////////////////////////////////////////////////////////////*/

    function test_Name() public view {
        assertEq(validator.name(), "OneAuthValidator");
    }

    function test_Version() public view {
        assertEq(validator.version(), "1.0.0");
    }

    function test_IsModuleType_Validator() public view {
        assertTrue(validator.isModuleType(1));
    }

    function test_IsModuleType_StatelessValidator() public view {
        assertTrue(validator.isModuleType(7));
    }

    function test_IsModuleType_Other() public view {
        assertFalse(validator.isModuleType(2));
        assertFalse(validator.isModuleType(0));
    }

    /*//////////////////////////////////////////////////////////////////////////
                              EIP-712 PASSKEY DIGEST TESTS
    //////////////////////////////////////////////////////////////////////////*/

    function test_GetPasskeyDigest_MatchesEIP712() public view {
        bytes32 typehash = keccak256("PasskeyDigest(bytes32 digest)");

        bytes32 structHash = keccak256(abi.encode(typehash, TEST_DIGEST));

        bytes32 domainSep = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("OneAuthValidator")),
                keccak256(bytes("1.0.0")),
                block.chainid,
                address(validator)
            )
        );

        bytes32 expected = keccak256(abi.encodePacked("\x19\x01", domainSep, structHash));
        bytes32 actual = validator.getPasskeyDigest(TEST_DIGEST);
        assertEq(actual, expected, "PasskeyDigest should match manual EIP-712 computation");
    }

    function test_GetPasskeyDigest_ChainSpecific() public {
        bytes32 digest1 = validator.getPasskeyDigest(TEST_DIGEST);

        vm.chainId(999);
        bytes32 digest2 = validator.getPasskeyDigest(TEST_DIGEST);

        assertTrue(digest1 != digest2, "Different chainIds should produce different digests");
    }

    function test_GetPasskeyMultichain_MatchesEIP712() public view {
        bytes32 typehash = keccak256("PasskeyMultichain(bytes32 root)");

        bytes32 structHash = keccak256(abi.encode(typehash, TEST_DIGEST));

        // Sans-chainId domain: no chainId field
        bytes32 domainSep = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,address verifyingContract)"),
                keccak256(bytes("OneAuthValidator")),
                keccak256(bytes("1.0.0")),
                address(validator)
            )
        );

        bytes32 expected = keccak256(abi.encodePacked("\x19\x01", domainSep, structHash));
        bytes32 actual = validator.getPasskeyMultichain(TEST_DIGEST);
        assertEq(actual, expected, "PasskeyMultichain should match manual EIP-712 computation");
    }

    function test_GetPasskeyMultichain_ChainAgnostic() public {
        bytes32 digest1 = validator.getPasskeyMultichain(TEST_DIGEST);

        vm.chainId(999);
        bytes32 digest2 = validator.getPasskeyMultichain(TEST_DIGEST);

        assertEq(digest1, digest2, "Different chainIds should produce the same multichain digest");
    }

    function test_GetPasskeyDigest_DifferentDigests() public view {
        bytes32 d1 = validator.getPasskeyDigest(TEST_DIGEST);
        bytes32 d2 = validator.getPasskeyDigest(bytes32(uint256(0xdead)));
        assertTrue(d1 != d2, "Different input digests should produce different passkey digests");
    }

    /*//////////////////////////////////////////////////////////////////////////
                              P-256 ON-CURVE EDGE CASE TESTS
    //////////////////////////////////////////////////////////////////////////*/

    function test_OnInstall_RevertWhen_PubKeyXEqualsPrime() public {
        uint16[] memory keyIds = new uint16[](1);
        keyIds[0] = 0;
        OneAuthValidator.WebAuthnCredential[] memory creds =
            new OneAuthValidator.WebAuthnCredential[](1);
        creds[0] = OneAuthValidator.WebAuthnCredential({
            pubKeyX: bytes32(P256_P),
            pubKeyY: _pubKeyY0
        });
        vm.expectRevert(IOneAuthValidator.InvalidPublicKey.selector);
        validator.onInstall(abi.encode(keyIds, creds, address(0), uint48(0)));
    }

    function test_OnInstall_RevertWhen_PubKeyYEqualsPrime() public {
        uint16[] memory keyIds = new uint16[](1);
        keyIds[0] = 0;
        OneAuthValidator.WebAuthnCredential[] memory creds =
            new OneAuthValidator.WebAuthnCredential[](1);
        creds[0] = OneAuthValidator.WebAuthnCredential({
            pubKeyX: _pubKeyX0,
            pubKeyY: bytes32(P256_P)
        });
        vm.expectRevert(IOneAuthValidator.InvalidPublicKey.selector);
        validator.onInstall(abi.encode(keyIds, creds, address(0), uint48(0)));
    }

    function test_OnInstall_RevertWhen_PubKeyExceedsPrime() public {
        uint16[] memory keyIds = new uint16[](1);
        keyIds[0] = 0;
        OneAuthValidator.WebAuthnCredential[] memory creds =
            new OneAuthValidator.WebAuthnCredential[](1);
        creds[0] = OneAuthValidator.WebAuthnCredential({
            pubKeyX: bytes32(P256_P + 1),
            pubKeyY: _pubKeyY0
        });
        vm.expectRevert(IOneAuthValidator.InvalidPublicKey.selector);
        validator.onInstall(abi.encode(keyIds, creds, address(0), uint48(0)));
    }

    function test_OnInstall_RevertWhen_NotOnCurve() public {
        uint16[] memory keyIds = new uint16[](1);
        keyIds[0] = 0;
        OneAuthValidator.WebAuthnCredential[] memory creds =
            new OneAuthValidator.WebAuthnCredential[](1);
        // (1, 1) is not on the P-256 curve
        creds[0] = OneAuthValidator.WebAuthnCredential({
            pubKeyX: bytes32(uint256(1)),
            pubKeyY: bytes32(uint256(1))
        });
        vm.expectRevert(IOneAuthValidator.InvalidPublicKey.selector);
        validator.onInstall(abi.encode(keyIds, creds, address(0), uint48(0)));
    }

    function test_AddCredential_RevertWhen_NotOnCurve() public {
        _install1();
        vm.expectRevert(IOneAuthValidator.InvalidPublicKey.selector);
        validator.addCredential(99, bytes32(uint256(1)), bytes32(uint256(1)));
    }

    /*//////////////////////////////////////////////////////////////////////////
                              TOO MANY CREDENTIALS + MISMATCHED ARRAYS
    //////////////////////////////////////////////////////////////////////////*/

    function test_AddCredential_RevertWhen_TooManyCredentials() public {
        _install1(); // keyId 0 installed, count = 1

        // Add credentials for keyIds 1..63 (total = 64 = MAX_CREDENTIALS)
        for (uint16 i = 1; i < 64; i++) {
            validator.addCredential(i, _pubKeyX0, _pubKeyY0);
        }
        assertEq(validator.credentialCount(address(this)), 64);

        // The 65th should revert
        vm.expectRevert(IOneAuthValidator.TooManyCredentials.selector);
        validator.addCredential(64, _pubKeyX0, _pubKeyY0);
    }

    function test_OnInstall_RevertWhen_TooManyCredentials() public {
        uint256 count = 65; // exceeds MAX_CREDENTIALS = 64
        uint16[] memory keyIds = new uint16[](count);
        OneAuthValidator.WebAuthnCredential[] memory creds =
            new OneAuthValidator.WebAuthnCredential[](count);
        for (uint256 i; i < count; i++) {
            keyIds[i] = uint16(i);
            creds[i] = OneAuthValidator.WebAuthnCredential({
                pubKeyX: _pubKeyX0,
                pubKeyY: _pubKeyY0
            });
        }
        vm.expectRevert(IOneAuthValidator.TooManyCredentials.selector);
        validator.onInstall(abi.encode(keyIds, creds, address(0), uint48(0)));
    }

    function test_OnInstall_RevertWhen_MismatchedArrayLengths() public {
        uint16[] memory keyIds = new uint16[](2);
        keyIds[0] = 0;
        keyIds[1] = 1;
        OneAuthValidator.WebAuthnCredential[] memory creds =
            new OneAuthValidator.WebAuthnCredential[](1);
        creds[0] = OneAuthValidator.WebAuthnCredential({
            pubKeyX: _pubKeyX0,
            pubKeyY: _pubKeyY0
        });
        vm.expectRevert(IOneAuthValidator.InvalidPublicKey.selector);
        validator.onInstall(abi.encode(keyIds, creds, address(0), uint48(0)));
    }

    /*//////////////////////////////////////////////////////////////////////////
                              EVENT EMISSION TESTS
    //////////////////////////////////////////////////////////////////////////*/

    function test_OnInstall_EmitsCredentialAdded() public {
        uint16[] memory keyIds = new uint16[](2);
        keyIds[0] = 10;
        keyIds[1] = 42;
        OneAuthValidator.WebAuthnCredential[] memory creds =
            new OneAuthValidator.WebAuthnCredential[](2);
        creds[0] = OneAuthValidator.WebAuthnCredential({
            pubKeyX: _pubKeyX0,
            pubKeyY: _pubKeyY0
        });
        creds[1] = OneAuthValidator.WebAuthnCredential({
            pubKeyX: _pubKeyX1,
            pubKeyY: _pubKeyY1
        });

        vm.expectEmit(true, true, false, true);
        emit IOneAuthValidator.CredentialAdded(address(this), 10, _pubKeyX0, _pubKeyY0);
        vm.expectEmit(true, true, false, true);
        emit IOneAuthValidator.CredentialAdded(address(this), 42, _pubKeyX1, _pubKeyY1);
        validator.onInstall(abi.encode(keyIds, creds, address(0), uint48(0)));
    }

    function test_OnInstall_EmitsModuleInitialized() public {
        vm.expectEmit(true, false, false, false);
        emit IOneAuthValidator.ModuleInitialized(address(this));
        _install1();
    }

    function test_OnUninstall_EmitsModuleUninitialized() public {
        _install2();

        vm.expectEmit(true, false, false, false);
        emit IOneAuthValidator.ModuleUninitialized(address(this));
        validator.onUninstall("");
    }

    function test_AddCredential_EmitsCredentialAdded() public {
        _install1();

        vm.expectEmit(true, true, false, true);
        emit IOneAuthValidator.CredentialAdded(address(this), 99, _pubKeyX1, _pubKeyY1);
        validator.addCredential(99, _pubKeyX1, _pubKeyY1);
    }

    function test_RemoveCredential_EmitsCredentialRemoved() public {
        _install2(); // keyIds 10, 42

        vm.expectEmit(true, true, false, false);
        emit IOneAuthValidator.CredentialRemoved(address(this), 10);
        validator.removeCredential(10);
    }
}
