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

/// @title CrossAccountReplayTest
/// @notice Multi-actor tests proving cross-chain and cross-account signature replay is impossible.
///
/// Actors:
///   - ALICE: main account owner (has passkey credentials on mainValidator)
///   - APP_1: app account #1 linked to ALICE via appValidator
///   - APP_2: app account #2 linked to ALICE via appValidator
///   - BOB:   separate main account (also has credentials — same key for testing)
///
/// Attack vectors tested:
///   1. Same digest, different main accounts → different challenges
///   2. Signature for ALICE replayed on BOB's main account
///   3. Signature for APP_1 replayed on APP_2 (both point to ALICE)
///   4. Signature for ALICE (main) replayed on APP_1 (app)
///   5. Signature for APP_1 (app) replayed on ALICE (main)
///   6. Cross-chain replay: chain-specific signature replayed on different chainId
///   7. Merkle cross-account: merkle proof for one account used on another
///   8. Merkle cross-app: merkle proof for APP_1 used on APP_2
contract CrossAccountReplayTest is BaseTest {
    OneAuthValidator internal mainValidator;
    OneAuthAppValidator internal appValidator;

    address constant ALICE = address(0xA11CE);
    address constant BOB = address(0xB0B);
    address constant APP_1 = address(0xAA01);
    address constant APP_2 = address(0xAA02);

    uint256 constant P256_PRIV_KEY = 0x03d99692017473e2d631945a812607b23269d85721e0f370b8d3e7d29a874004;

    bytes32 _pubKeyX;
    bytes32 _pubKeyY;

    bytes32 constant TEST_DIGEST = 0xf631058a3ba1116acce12396fad0a125b5041c43f8e15723709f81aa8d5f4ccf;

    uint256 constant P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;
    uint256 constant P256_N_DIV_2 = 0x7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8;

    bytes constant AUTH_DATA_UV =
        hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630500000001";
    uint256 constant CHALLENGE_INDEX = 23;
    uint256 constant TYPE_INDEX = 1;

    function setUp() public virtual override {
        BaseTest.setUp();

        address SOLADY_P256_VERIFIER = 0x000000000000D01eA45F9eFD5c54f037Fa57Ea1a;
        P256VerifierWrapper verifier_ = new P256VerifierWrapper();
        vm.etch(SOLADY_P256_VERIFIER, address(verifier_).code);

        mainValidator = new OneAuthValidator();
        appValidator = new OneAuthAppValidator(address(mainValidator));

        (uint256 x, uint256 y) = vm.publicKeyP256(P256_PRIV_KEY);
        _pubKeyX = bytes32(x);
        _pubKeyY = bytes32(y);

        // Install same credential on both ALICE and BOB (simulates same user or key reuse)
        _installMainAccount(ALICE);
        _installMainAccount(BOB);

        // Install two app accounts both pointing to ALICE
        _installAppAccount(APP_1, ALICE);
        _installAppAccount(APP_2, ALICE);
    }

    /*//////////////////////////////////////////////////////////////////////////
                                    HELPERS
    //////////////////////////////////////////////////////////////////////////*/

    function _installMainAccount(address account) internal {
        uint16[] memory keyIds = new uint16[](1);
        keyIds[0] = 0;
        OneAuthValidator.WebAuthnCredential[] memory creds = new OneAuthValidator.WebAuthnCredential[](1);
        creds[0] = OneAuthValidator.WebAuthnCredential({ pubKeyX: _pubKeyX, pubKeyY: _pubKeyY });
        vm.prank(account);
        mainValidator.onInstall(abi.encode(keyIds, creds, address(0), address(0), uint8(0)));
    }

    function _installAppAccount(address appAccount, address mainAccount) internal {
        vm.prank(appAccount);
        appValidator.onInstall(abi.encode(mainAccount, address(0), address(0), uint8(0)));
    }

    function _buildClientDataJSON(bytes32 challengeHash) internal pure returns (string memory) {
        bytes memory challenge = abi.encode(challengeHash);
        return string.concat(
            '{"type":"webauthn.get","challenge":"',
            Base64Url.encode(challenge),
            '","origin":"http://localhost:8080","crossOrigin":false}'
        );
    }

    function _signChallenge(bytes32 challenge)
        internal
        view
        returns (uint256 r, uint256 s, string memory clientDataJSON)
    {
        clientDataJSON = _buildClientDataJSON(challenge);
        bytes32 msgHash = sha256(abi.encodePacked(AUTH_DATA_UV, sha256(bytes(clientDataJSON))));
        (bytes32 r32, bytes32 s32) = vm.signP256(P256_PRIV_KEY, msgHash);
        r = uint256(r32);
        s = uint256(s32);
        if (s > P256_N_DIV_2) s = P256_N - s;
    }

    function _buildRegularSig(uint16 keyId, uint256 r, uint256 s, string memory clientDataJSON)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
            uint8(0), keyId, r, s,
            uint16(CHALLENGE_INDEX), uint16(TYPE_INDEX),
            uint16(AUTH_DATA_UV.length), AUTH_DATA_UV, clientDataJSON
        );
    }

    function _buildMerkleSig(
        bytes32 merkleRoot,
        bytes32[] memory proof,
        uint16 keyId,
        uint256 r,
        uint256 s,
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
            result, keyId, r, s,
            uint16(CHALLENGE_INDEX), uint16(TYPE_INDEX),
            uint16(AUTH_DATA_UV.length), AUTH_DATA_UV, clientDataJSON
        );
        return result;
    }

    function _hashPair(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return a < b ? keccak256(abi.encodePacked(a, b)) : keccak256(abi.encodePacked(b, a));
    }

    /*//////////////////////////////////////////////////////////////////////////
        1. SAME DIGEST, DIFFERENT ACCOUNTS → DIFFERENT CHALLENGES (unit check)
    //////////////////////////////////////////////////////////////////////////*/

    function test_SameDigest_DifferentAccounts_DifferentChallenges() public view {
        bytes32 challengeAlice = mainValidator.getPasskeyDigest(ALICE, TEST_DIGEST);
        bytes32 challengeBob = mainValidator.getPasskeyDigest(BOB, TEST_DIGEST);
        bytes32 challengeApp1 = mainValidator.getPasskeyDigest(ALICE, keccak256(abi.encode(APP_1, TEST_DIGEST)));
        bytes32 challengeApp2 = mainValidator.getPasskeyDigest(ALICE, keccak256(abi.encode(APP_2, TEST_DIGEST)));

        // All four must be distinct
        assertTrue(challengeAlice != challengeBob, "ALICE != BOB");
        assertTrue(challengeAlice != challengeApp1, "ALICE != APP_1");
        assertTrue(challengeAlice != challengeApp2, "ALICE != APP_2");
        assertTrue(challengeApp1 != challengeApp2, "APP_1 != APP_2");
        assertTrue(challengeBob != challengeApp1, "BOB != APP_1");
    }

    /*//////////////////////////////////////////////////////////////////////////
        2. MAIN→MAIN REPLAY: signature for ALICE fails on BOB
    //////////////////////////////////////////////////////////////////////////*/

    function test_MainToMain_ReplayFails() public {
        // Create valid signature for ALICE
        bytes32 aliceChallenge = mainValidator.getPasskeyDigest(ALICE, TEST_DIGEST);
        (uint256 r, uint256 s, string memory cdj) = _signChallenge(aliceChallenge);
        bytes memory sig = _buildRegularSig(0, r, s, cdj);

        // Verify it works for ALICE
        PackedUserOperation memory userOp = getEmptyUserOperation();
        userOp.sender = ALICE;
        userOp.signature = sig;
        uint256 result = ERC7579ValidatorBase.ValidationData.unwrap(mainValidator.validateUserOp(userOp, TEST_DIGEST));
        assertEq(result, 0, "should succeed for ALICE");

        // Replay on BOB — must fail
        userOp.sender = BOB;
        result = ERC7579ValidatorBase.ValidationData.unwrap(mainValidator.validateUserOp(userOp, TEST_DIGEST));
        assertEq(result, 1, "REPLAY: ALICE sig must fail on BOB");
    }

    /*//////////////////////////////////////////////////////////////////////////
        3. APP→APP REPLAY: signature for APP_1 fails on APP_2
    //////////////////////////////////////////////////////////////////////////*/

    function test_AppToApp_ReplayFails() public {
        // Create valid signature for APP_1
        bytes32 boundHash1 = keccak256(abi.encode(APP_1, TEST_DIGEST));
        bytes32 challenge1 = mainValidator.getPasskeyDigest(ALICE, boundHash1);
        (uint256 r, uint256 s, string memory cdj) = _signChallenge(challenge1);
        bytes memory sig = _buildRegularSig(0, r, s, cdj);

        // Works for APP_1
        PackedUserOperation memory userOp = getEmptyUserOperation();
        userOp.sender = APP_1;
        userOp.signature = sig;
        uint256 result =
            ERC7579ValidatorBase.ValidationData.unwrap(appValidator.validateUserOp(userOp, TEST_DIGEST));
        assertEq(result, 0, "should succeed for APP_1");

        // Replay on APP_2 — must fail (different boundHash)
        userOp.sender = APP_2;
        result = ERC7579ValidatorBase.ValidationData.unwrap(appValidator.validateUserOp(userOp, TEST_DIGEST));
        assertEq(result, 1, "REPLAY: APP_1 sig must fail on APP_2");
    }

    /*//////////////////////////////////////////////////////////////////////////
        4. MAIN→APP REPLAY: signature for ALICE fails on APP_1
    //////////////////////////////////////////////////////////////////////////*/

    function test_MainToApp_ReplayFails() public {
        // Create valid signature for ALICE (main account)
        bytes32 aliceChallenge = mainValidator.getPasskeyDigest(ALICE, TEST_DIGEST);
        (uint256 r, uint256 s, string memory cdj) = _signChallenge(aliceChallenge);
        bytes memory sig = _buildRegularSig(0, r, s, cdj);

        // Works for ALICE
        PackedUserOperation memory userOp = getEmptyUserOperation();
        userOp.sender = ALICE;
        userOp.signature = sig;
        uint256 result = ERC7579ValidatorBase.ValidationData.unwrap(mainValidator.validateUserOp(userOp, TEST_DIGEST));
        assertEq(result, 0, "should succeed for ALICE");

        // Replay on APP_1 via appValidator — must fail
        // The app validator pre-hashes: keccak256(abi.encode(APP_1, TEST_DIGEST))
        // But the sig was made for _passkeyDigest(ALICE, TEST_DIGEST) — no pre-hash
        userOp.sender = APP_1;
        result = ERC7579ValidatorBase.ValidationData.unwrap(appValidator.validateUserOp(userOp, TEST_DIGEST));
        assertEq(result, 1, "REPLAY: ALICE main sig must fail on APP_1");
    }

    /*//////////////////////////////////////////////////////////////////////////
        5. APP→MAIN REPLAY: signature for APP_1 fails on ALICE
    //////////////////////////////////////////////////////////////////////////*/

    function test_AppToMain_ReplayFails() public {
        // Create valid signature for APP_1
        bytes32 boundHash1 = keccak256(abi.encode(APP_1, TEST_DIGEST));
        bytes32 challenge1 = mainValidator.getPasskeyDigest(ALICE, boundHash1);
        (uint256 r, uint256 s, string memory cdj) = _signChallenge(challenge1);
        bytes memory sig = _buildRegularSig(0, r, s, cdj);

        // Works for APP_1 via appValidator
        PackedUserOperation memory userOp = getEmptyUserOperation();
        userOp.sender = APP_1;
        userOp.signature = sig;
        uint256 result =
            ERC7579ValidatorBase.ValidationData.unwrap(appValidator.validateUserOp(userOp, TEST_DIGEST));
        assertEq(result, 0, "should succeed for APP_1");

        // Replay on ALICE via mainValidator — must fail
        // The sig was made for _passkeyDigest(ALICE, keccak256(abi.encode(APP_1, TEST_DIGEST)))
        // but main validator computes _passkeyDigest(ALICE, TEST_DIGEST) — different
        userOp.sender = ALICE;
        result = ERC7579ValidatorBase.ValidationData.unwrap(mainValidator.validateUserOp(userOp, TEST_DIGEST));
        assertEq(result, 1, "REPLAY: APP_1 sig must fail on ALICE main");
    }

    /*//////////////////////////////////////////////////////////////////////////
        6. CROSS-CHAIN REPLAY: chain-specific signature fails on different chain
    //////////////////////////////////////////////////////////////////////////*/

    function test_CrossChain_RegularReplayFails() public {
        // Sign for ALICE on current chainId
        bytes32 aliceChallenge = mainValidator.getPasskeyDigest(ALICE, TEST_DIGEST);
        (uint256 r, uint256 s, string memory cdj) = _signChallenge(aliceChallenge);
        bytes memory sig = _buildRegularSig(0, r, s, cdj);

        // Works on current chain
        PackedUserOperation memory userOp = getEmptyUserOperation();
        userOp.sender = ALICE;
        userOp.signature = sig;
        uint256 result = ERC7579ValidatorBase.ValidationData.unwrap(mainValidator.validateUserOp(userOp, TEST_DIGEST));
        assertEq(result, 0, "should succeed on current chain");

        // Fork to a different chainId — deploy fresh validator (same address won't have same domain separator)
        vm.chainId(999);
        OneAuthValidator otherChainValidator = new OneAuthValidator();
        _installOnValidator(otherChainValidator, ALICE);

        // Replay on different chain — must fail (chainId is in the EIP-712 domain for PasskeyDigest)
        result = ERC7579ValidatorBase.ValidationData.unwrap(otherChainValidator.validateUserOp(userOp, TEST_DIGEST));
        assertEq(result, 1, "REPLAY: chain-specific sig must fail on different chainId");
    }

    function _installOnValidator(OneAuthValidator v, address account) internal {
        uint16[] memory keyIds = new uint16[](1);
        keyIds[0] = 0;
        OneAuthValidator.WebAuthnCredential[] memory creds = new OneAuthValidator.WebAuthnCredential[](1);
        creds[0] = OneAuthValidator.WebAuthnCredential({ pubKeyX: _pubKeyX, pubKeyY: _pubKeyY });
        vm.prank(account);
        v.onInstall(abi.encode(keyIds, creds, address(0), address(0), uint8(0)));
    }

    /*//////////////////////////////////////////////////////////////////////////
        7. MERKLE CROSS-ACCOUNT: merkle proof for ALICE fails for BOB
    //////////////////////////////////////////////////////////////////////////*/

    function test_Merkle_MainToMain_ReplayFails() public {
        // Build a merkle tree with account-bound leaves for ALICE
        bytes32 aliceLeaf = keccak256(abi.encode(ALICE, TEST_DIGEST));
        bytes32 dummyLeaf = bytes32(uint256(0xdead));
        bytes32 merkleRoot = _hashPair(aliceLeaf, dummyLeaf);

        bytes32[] memory aliceProof = new bytes32[](1);
        aliceProof[0] = dummyLeaf;

        // Sign the merkle root (chain-agnostic PasskeyMultichain)
        bytes32 challenge = mainValidator.getPasskeyMultichain(merkleRoot);
        (uint256 r, uint256 s, string memory cdj) = _signChallenge(challenge);
        bytes memory sig = _buildMerkleSig(merkleRoot, aliceProof, 0, r, s, cdj);

        // Works for ALICE
        PackedUserOperation memory userOp = getEmptyUserOperation();
        userOp.sender = ALICE;
        userOp.signature = sig;
        uint256 result = ERC7579ValidatorBase.ValidationData.unwrap(mainValidator.validateUserOp(userOp, TEST_DIGEST));
        assertEq(result, 0, "merkle should succeed for ALICE");

        // Replay on BOB — must fail (BOB's leaf = keccak256(abi.encode(BOB, TEST_DIGEST)) != aliceLeaf)
        userOp.sender = BOB;
        result = ERC7579ValidatorBase.ValidationData.unwrap(mainValidator.validateUserOp(userOp, TEST_DIGEST));
        assertEq(result, 1, "REPLAY: ALICE merkle sig must fail on BOB");
    }

    /*//////////////////////////////////////////////////////////////////////////
        8. MERKLE CROSS-APP: merkle proof for APP_1 fails for APP_2
    //////////////////////////////////////////////////////////////////////////*/

    function test_Merkle_AppToApp_ReplayFails() public {
        // For APP_1: app validator pre-hashes, then main validator computes leaf
        bytes32 boundHash1 = keccak256(abi.encode(APP_1, TEST_DIGEST));
        bytes32 app1Leaf = keccak256(abi.encode(ALICE, boundHash1));
        bytes32 dummyLeaf = bytes32(uint256(0xbeef));
        bytes32 merkleRoot = _hashPair(app1Leaf, dummyLeaf);

        bytes32[] memory app1Proof = new bytes32[](1);
        app1Proof[0] = dummyLeaf;

        // Sign the merkle root
        bytes32 challenge = mainValidator.getPasskeyMultichain(merkleRoot);
        (uint256 r, uint256 s, string memory cdj) = _signChallenge(challenge);
        bytes memory sig = _buildMerkleSig(merkleRoot, app1Proof, 0, r, s, cdj);

        // Works for APP_1
        PackedUserOperation memory userOp = getEmptyUserOperation();
        userOp.sender = APP_1;
        userOp.signature = sig;
        uint256 result =
            ERC7579ValidatorBase.ValidationData.unwrap(appValidator.validateUserOp(userOp, TEST_DIGEST));
        assertEq(result, 0, "merkle should succeed for APP_1");

        // Replay on APP_2 — must fail (APP_2's leaf uses keccak256(abi.encode(APP_2, TEST_DIGEST)))
        userOp.sender = APP_2;
        result = ERC7579ValidatorBase.ValidationData.unwrap(appValidator.validateUserOp(userOp, TEST_DIGEST));
        assertEq(result, 1, "REPLAY: APP_1 merkle sig must fail on APP_2");
    }

    /*//////////////////////////////////////////////////////////////////////////
        9. MERKLE MAIN↔APP: merkle proof for main account fails for app account
    //////////////////////////////////////////////////////////////////////////*/

    function test_Merkle_MainToApp_ReplayFails() public {
        // Build merkle tree with ALICE's main-account leaf
        bytes32 aliceLeaf = keccak256(abi.encode(ALICE, TEST_DIGEST));
        bytes32 dummyLeaf = bytes32(uint256(0xcafe));
        bytes32 merkleRoot = _hashPair(aliceLeaf, dummyLeaf);

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = dummyLeaf;

        bytes32 challenge = mainValidator.getPasskeyMultichain(merkleRoot);
        (uint256 r, uint256 s, string memory cdj) = _signChallenge(challenge);
        bytes memory sig = _buildMerkleSig(merkleRoot, proof, 0, r, s, cdj);

        // Works for ALICE (main)
        PackedUserOperation memory userOp = getEmptyUserOperation();
        userOp.sender = ALICE;
        userOp.signature = sig;
        uint256 result = ERC7579ValidatorBase.ValidationData.unwrap(mainValidator.validateUserOp(userOp, TEST_DIGEST));
        assertEq(result, 0, "merkle should succeed for ALICE main");

        // Replay on APP_1 via appValidator — must fail
        userOp.sender = APP_1;
        result = ERC7579ValidatorBase.ValidationData.unwrap(appValidator.validateUserOp(userOp, TEST_DIGEST));
        assertEq(result, 1, "REPLAY: ALICE main merkle sig must fail on APP_1");
    }

    function test_Merkle_AppToMain_ReplayFails() public {
        // Build merkle tree with APP_1's leaf
        bytes32 boundHash1 = keccak256(abi.encode(APP_1, TEST_DIGEST));
        bytes32 app1Leaf = keccak256(abi.encode(ALICE, boundHash1));
        bytes32 dummyLeaf = bytes32(uint256(0xfeed));
        bytes32 merkleRoot = _hashPair(app1Leaf, dummyLeaf);

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = dummyLeaf;

        bytes32 challenge = mainValidator.getPasskeyMultichain(merkleRoot);
        (uint256 r, uint256 s, string memory cdj) = _signChallenge(challenge);
        bytes memory sig = _buildMerkleSig(merkleRoot, proof, 0, r, s, cdj);

        // Works for APP_1 via appValidator
        PackedUserOperation memory userOp = getEmptyUserOperation();
        userOp.sender = APP_1;
        userOp.signature = sig;
        uint256 result =
            ERC7579ValidatorBase.ValidationData.unwrap(appValidator.validateUserOp(userOp, TEST_DIGEST));
        assertEq(result, 0, "merkle should succeed for APP_1");

        // Replay on ALICE via mainValidator — must fail
        userOp.sender = ALICE;
        result = ERC7579ValidatorBase.ValidationData.unwrap(mainValidator.validateUserOp(userOp, TEST_DIGEST));
        assertEq(result, 1, "REPLAY: APP_1 merkle sig must fail on ALICE main");
    }

    /*//////////////////////////////////////////////////////////////////////////
        10. ERC-1271 CROSS-ACCOUNT REPLAY
    //////////////////////////////////////////////////////////////////////////*/

    function test_ERC1271_MainToMain_ReplayFails() public {
        // Sign for ALICE via ERC-1271
        bytes32 aliceChallenge = mainValidator.getPasskeyDigest(ALICE, TEST_DIGEST);
        (uint256 r, uint256 s, string memory cdj) = _signChallenge(aliceChallenge);
        bytes memory sig = _buildRegularSig(0, r, s, cdj);

        // Works for ALICE
        vm.prank(ALICE);
        bytes4 result = mainValidator.isValidSignatureWithSender(address(0), TEST_DIGEST, sig);
        assertEq(result, EIP1271_MAGIC_VALUE, "ERC-1271 should succeed for ALICE");

        // Replay on BOB — must fail
        vm.prank(BOB);
        result = mainValidator.isValidSignatureWithSender(address(0), TEST_DIGEST, sig);
        assertEq(result, bytes4(0xffffffff), "REPLAY: ALICE ERC-1271 sig must fail on BOB");
    }

    function test_ERC1271_AppToApp_ReplayFails() public {
        // Sign for APP_1 via ERC-1271
        bytes32 boundHash1 = keccak256(abi.encode(APP_1, TEST_DIGEST));
        bytes32 challenge1 = mainValidator.getPasskeyDigest(ALICE, boundHash1);
        (uint256 r, uint256 s, string memory cdj) = _signChallenge(challenge1);
        bytes memory sig = _buildRegularSig(0, r, s, cdj);

        // Works for APP_1
        vm.prank(APP_1);
        bytes4 result = appValidator.isValidSignatureWithSender(address(0), TEST_DIGEST, sig);
        assertEq(result, EIP1271_MAGIC_VALUE, "ERC-1271 should succeed for APP_1");

        // Replay on APP_2 — must fail
        vm.prank(APP_2);
        result = appValidator.isValidSignatureWithSender(address(0), TEST_DIGEST, sig);
        assertEq(result, bytes4(0xffffffff), "REPLAY: APP_1 ERC-1271 sig must fail on APP_2");
    }

    /*//////////////////////////////////////////////////////////////////////////
        11. MULTI-ACCOUNT MERKLE: valid tree spanning main + app works correctly
    //////////////////////////////////////////////////////////////////////////*/

    function test_MultiAccountMerkle_ValidTree() public {
        // Build a merkle tree with leaves for ALICE (main) and APP_1 (app)
        // ALICE leaf: keccak256(abi.encode(ALICE, TEST_DIGEST))
        // APP_1 leaf: keccak256(abi.encode(ALICE, keccak256(abi.encode(APP_1, TEST_DIGEST))))
        bytes32 aliceLeaf = keccak256(abi.encode(ALICE, TEST_DIGEST));
        bytes32 boundHash1 = keccak256(abi.encode(APP_1, TEST_DIGEST));
        bytes32 app1Leaf = keccak256(abi.encode(ALICE, boundHash1));
        bytes32 merkleRoot = _hashPair(aliceLeaf, app1Leaf);

        // Sign the merkle root once
        bytes32 challenge = mainValidator.getPasskeyMultichain(merkleRoot);
        (uint256 r, uint256 s, string memory cdj) = _signChallenge(challenge);

        // Build proof for ALICE (sibling = app1Leaf)
        bytes32[] memory aliceProof = new bytes32[](1);
        aliceProof[0] = app1Leaf;
        bytes memory aliceSig = _buildMerkleSig(merkleRoot, aliceProof, 0, r, s, cdj);

        // Build proof for APP_1 (sibling = aliceLeaf)
        bytes32[] memory app1Proof = new bytes32[](1);
        app1Proof[0] = aliceLeaf;
        bytes memory app1Sig = _buildMerkleSig(merkleRoot, app1Proof, 0, r, s, cdj);

        // Both should work for their respective accounts
        PackedUserOperation memory userOp = getEmptyUserOperation();

        userOp.sender = ALICE;
        userOp.signature = aliceSig;
        uint256 result = ERC7579ValidatorBase.ValidationData.unwrap(mainValidator.validateUserOp(userOp, TEST_DIGEST));
        assertEq(result, 0, "multi-account merkle should succeed for ALICE");

        userOp.sender = APP_1;
        userOp.signature = app1Sig;
        result = ERC7579ValidatorBase.ValidationData.unwrap(appValidator.validateUserOp(userOp, TEST_DIGEST));
        assertEq(result, 0, "multi-account merkle should succeed for APP_1");

        // Cross-replay: ALICE's proof on APP_2 must fail
        userOp.sender = APP_2;
        userOp.signature = aliceSig;
        result = ERC7579ValidatorBase.ValidationData.unwrap(appValidator.validateUserOp(userOp, TEST_DIGEST));
        assertEq(result, 1, "REPLAY: ALICE proof must fail on APP_2");

        // Cross-replay: APP_1's proof on ALICE (wrong leaf structure) must fail
        userOp.sender = ALICE;
        userOp.signature = app1Sig;
        result = ERC7579ValidatorBase.ValidationData.unwrap(mainValidator.validateUserOp(userOp, TEST_DIGEST));
        assertEq(result, 1, "REPLAY: APP_1 proof must fail on ALICE main");

        // Cross-replay: APP_1's proof on BOB must fail
        userOp.sender = BOB;
        userOp.signature = app1Sig;
        result = ERC7579ValidatorBase.ValidationData.unwrap(mainValidator.validateUserOp(userOp, TEST_DIGEST));
        assertEq(result, 1, "REPLAY: APP_1 proof must fail on BOB");
    }
}
