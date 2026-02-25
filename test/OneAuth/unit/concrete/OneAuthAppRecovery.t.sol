// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { BaseTest } from "test/Base.t.sol";
import { OneAuthValidator } from "src/OneAuth/OneAuthValidator.sol";
import { OneAuthAppValidator } from "src/OneAuth/OneAuthAppValidator.sol";
import { OneAuthAppRecoveryBase } from "src/OneAuth/OneAuthAppRecoveryBase.sol";
import { IOneAuthAppValidator } from "src/OneAuth/IOneAuthAppValidator.sol";
import { GuardianVerifierLib } from "src/OneAuth/lib/GuardianVerifierLib.sol";
import { ERC7579ValidatorBase } from "modulekit/Modules.sol";
import { PackedUserOperation, getEmptyUserOperation } from "test/utils/ERC4337.sol";
import { Base64Url } from "FreshCryptoLib/utils/Base64Url.sol";
import { P256VerifierWrapper } from "test/OneAuth/helpers/P256VerifierWrapper.sol";

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

contract OneAuthAppRecoveryTest is BaseTest {
    OneAuthValidator internal mainValidator;
    OneAuthAppValidator internal appValidator;
    MockGuardian internal mockGuardian;
    MockGuardian internal mockGuardian2;
    RejectingGuardian internal rejectingGuardian;

    address constant MAIN_ACCOUNT = address(0xAA);
    address constant MAIN_ACCOUNT_2 = address(0xDD);
    address constant APP_ACCOUNT = address(0xBB);

    uint256 constant P256_PRIV_KEY = 0x03d99692017473e2d631945a812607b23269d85721e0f370b8d3e7d29a874004;

    bytes32 _pubKeyX0;
    bytes32 _pubKeyY0;

    bytes32 constant TEST_DIGEST =
        0xf631058a3ba1116acce12396fad0a125b5041c43f8e15723709f81aa8d5f4ccf;

    bytes constant AUTH_DATA_UV =
        hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630500000001";

    uint256 constant CHALLENGE_INDEX = 23;
    uint256 constant TYPE_INDEX = 1;
    uint256 constant P256_N =
        0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;
    uint256 constant P256_N_DIV_2 =
        0x7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8;

    function setUp() public virtual override {
        BaseTest.setUp();

        // Deploy P256 verifier
        address SOLADY_P256_VERIFIER = 0x000000000000D01eA45F9eFD5c54f037Fa57Ea1a;
        P256VerifierWrapper verifier_ = new P256VerifierWrapper();
        vm.etch(SOLADY_P256_VERIFIER, address(verifier_).code);

        mainValidator = new OneAuthValidator();
        appValidator = new OneAuthAppValidator(address(mainValidator));

        mockGuardian = new MockGuardian();
        mockGuardian2 = new MockGuardian();
        rejectingGuardian = new RejectingGuardian();

        // Derive P-256 public keys
        (uint256 x0, uint256 y0) = vm.publicKeyP256(P256_PRIV_KEY);
        _pubKeyX0 = bytes32(x0);
        _pubKeyY0 = bytes32(y0);

        // Install credential on main validator for MAIN_ACCOUNT
        _installMainAccount(MAIN_ACCOUNT);

        // Install credential on main validator for MAIN_ACCOUNT_2
        _installMainAccount(MAIN_ACCOUNT_2);
    }

    /*//////////////////////////////////////////////////////////////////////////
                              HELPERS
    //////////////////////////////////////////////////////////////////////////*/

    function _installMainAccount(address account) internal {
        uint16[] memory keyIds = new uint16[](1);
        keyIds[0] = 0;
        OneAuthValidator.WebAuthnCredential[] memory creds =
            new OneAuthValidator.WebAuthnCredential[](1);
        creds[0] = OneAuthValidator.WebAuthnCredential({ pubKeyX: _pubKeyX0, pubKeyY: _pubKeyY0 });
        bytes memory data = abi.encode(keyIds, creds, address(0), address(0), uint8(0));
        vm.prank(account);
        mainValidator.onInstall(data);
    }

    function _installAppAccount() internal {
        vm.prank(APP_ACCOUNT);
        appValidator.onInstall(
            abi.encode(MAIN_ACCOUNT, address(mockGuardian), address(0), uint8(1))
        );
    }

    function _installAppAccountNoGuardian() internal {
        vm.prank(APP_ACCOUNT);
        appValidator.onInstall(
            abi.encode(MAIN_ACCOUNT, address(0), address(0), uint8(0))
        );
    }

    function _installAppAccountDualGuardian() internal {
        vm.prank(APP_ACCOUNT);
        appValidator.onInstall(
            abi.encode(MAIN_ACCOUNT, address(mockGuardian), address(mockGuardian2), uint8(2))
        );
    }

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

    /// @dev Create a valid WebAuthn signature for the app validator flow.
    /// The app validator pre-hashes: keccak256(abi.encode(appAccount, digest))
    /// Then the main validator wraps it: _passkeyDigest(mainAccount, boundHash)
    function _createValidWebAuthnSig(address mainAccount, bytes32 digest)
        internal
        view
        returns (uint256 r, uint256 s, string memory clientDataJSON)
    {
        bytes32 boundHash = keccak256(abi.encode(APP_ACCOUNT, digest));
        bytes32 challenge = mainValidator.getPasskeyDigest(mainAccount, boundHash);
        clientDataJSON = _buildClientDataJSON(challenge);

        bytes32 msgHash = sha256(abi.encodePacked(AUTH_DATA_UV, sha256(bytes(clientDataJSON))));
        (bytes32 r32, bytes32 s32) = vm.signP256(P256_PRIV_KEY, msgHash);
        r = uint256(r32);
        s = uint256(s32);

        if (s > P256_N_DIV_2) {
            s = P256_N - s;
        }
    }

    /*//////////////////////////////////////////////////////////////////////////
                              GUARDIAN CONFIG TESTS
    //////////////////////////////////////////////////////////////////////////*/

    function test_OnInstall_SetsGuardianConfig() public {
        _installAppAccount();
        (address ug, address eg, uint8 t) = appValidator.guardianConfig(APP_ACCOUNT);
        assertEq(ug, address(mockGuardian));
        assertEq(eg, address(0));
        assertEq(t, 1);
    }

    function test_OnInstall_NoGuardian() public {
        _installAppAccountNoGuardian();
        (address ug, address eg, uint8 t) = appValidator.guardianConfig(APP_ACCOUNT);
        assertEq(ug, address(0));
        assertEq(eg, address(0));
        assertEq(t, 0);
    }

    function test_OnInstall_DualGuardian() public {
        _installAppAccountDualGuardian();
        (address ug, address eg, uint8 t) = appValidator.guardianConfig(APP_ACCOUNT);
        assertEq(ug, address(mockGuardian));
        assertEq(eg, address(mockGuardian2));
        assertEq(t, 2);
    }

    function test_SetGuardianConfig() public {
        _installAppAccountNoGuardian();

        vm.prank(APP_ACCOUNT);
        appValidator.setGuardianConfig(address(mockGuardian), address(0), 1);

        (address ug,,) = appValidator.guardianConfig(APP_ACCOUNT);
        assertEq(ug, address(mockGuardian));
    }

    function test_OnUninstall_ClearsGuardianConfig() public {
        _installAppAccount();
        (address ug,,) = appValidator.guardianConfig(APP_ACCOUNT);
        assertEq(ug, address(mockGuardian));

        vm.prank(APP_ACCOUNT);
        appValidator.onUninstall("");

        (address ug2, address eg2, uint8 t2) = appValidator.guardianConfig(APP_ACCOUNT);
        assertEq(ug2, address(0));
        assertEq(eg2, address(0));
        assertEq(t2, 0);
    }

    /*//////////////////////////////////////////////////////////////////////////
                              EIP-712 DIGEST TESTS
    //////////////////////////////////////////////////////////////////////////*/

    function test_GetRecoverDigest_Deterministic() public view {
        bytes32 d1 = appValidator.getRecoverDigest(APP_ACCOUNT, block.chainid, MAIN_ACCOUNT_2, 0, 1000);
        bytes32 d2 = appValidator.getRecoverDigest(APP_ACCOUNT, block.chainid, MAIN_ACCOUNT_2, 0, 1000);
        assertEq(d1, d2, "Same inputs should produce same digest");
    }

    function test_GetRecoverDigest_DifferentNonce() public view {
        bytes32 d1 = appValidator.getRecoverDigest(APP_ACCOUNT, block.chainid, MAIN_ACCOUNT_2, 0, 1000);
        bytes32 d2 = appValidator.getRecoverDigest(APP_ACCOUNT, block.chainid, MAIN_ACCOUNT_2, 1, 1000);
        assertTrue(d1 != d2, "Different nonce should produce different digest");
    }

    function test_GetRecoverDigest_DifferentChainId() public view {
        bytes32 d1 = appValidator.getRecoverDigest(APP_ACCOUNT, 1, MAIN_ACCOUNT_2, 0, 1000);
        bytes32 d2 = appValidator.getRecoverDigest(APP_ACCOUNT, 2, MAIN_ACCOUNT_2, 0, 1000);
        assertTrue(d1 != d2, "Different chainId should produce different digest");
    }

    function test_GetRecoverDigest_DifferentAccount() public view {
        bytes32 d1 = appValidator.getRecoverDigest(APP_ACCOUNT, block.chainid, MAIN_ACCOUNT_2, 0, 1000);
        bytes32 d2 = appValidator.getRecoverDigest(address(1), block.chainid, MAIN_ACCOUNT_2, 0, 1000);
        assertTrue(d1 != d2, "Different account should produce different digest");
    }

    function test_GetRecoverDigest_DifferentNewMainAccount() public view {
        bytes32 d1 = appValidator.getRecoverDigest(APP_ACCOUNT, block.chainid, MAIN_ACCOUNT_2, 0, 1000);
        bytes32 d2 = appValidator.getRecoverDigest(APP_ACCOUNT, block.chainid, address(0xEE), 0, 1000);
        assertTrue(d1 != d2, "Different newMainAccount should produce different digest");
    }

    function test_GetRecoverDigest_MatchesEIP712() public view {
        bytes32 typehash = keccak256(
            "RecoverAppValidator(address account,uint256 chainId,address newMainAccount,uint256 nonce,uint48 expiry)"
        );
        bytes32 structHash = keccak256(
            abi.encode(
                typehash,
                APP_ACCOUNT,
                block.chainid,
                MAIN_ACCOUNT_2,
                uint256(42),
                uint256(uint48(9999))
            )
        );

        // Sans-chainId domain separator: EIP712Domain(string name,string version,address verifyingContract)
        bytes32 domainSep = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,address verifyingContract)"),
                keccak256(bytes("OneAuthAppValidator")),
                keccak256(bytes("1.0.0")),
                address(appValidator)
            )
        );

        bytes32 expected = keccak256(abi.encodePacked("\x19\x01", domainSep, structHash));

        bytes32 actual = appValidator.getRecoverDigest(APP_ACCOUNT, block.chainid, MAIN_ACCOUNT_2, 42, 9999);
        assertEq(actual, expected, "Digest should match manual EIP-712 computation");
    }

    /*//////////////////////////////////////////////////////////////////////////
                              GUARDIAN RECOVERY TESTS
    //////////////////////////////////////////////////////////////////////////*/

    function test_RecoverWithGuardian_Success() public {
        _installAppAccount();

        uint48 expiry = uint48(block.timestamp + 1000);
        uint256 nonce = 0;

        bytes32 digest = appValidator.getRecoverDigest(APP_ACCOUNT, block.chainid, MAIN_ACCOUNT_2, nonce, expiry);
        mockGuardian.approveDigest(digest);

        appValidator.recoverWithGuardian(APP_ACCOUNT, block.chainid, MAIN_ACCOUNT_2, nonce, expiry, hex"00");

        // Verify main account was updated
        assertEq(appValidator.getMainAccount(APP_ACCOUNT), MAIN_ACCOUNT_2, "Main account should be updated");
    }

    function test_RecoverWithGuardian_NonceMarkedUsed() public {
        _installAppAccount();

        uint48 expiry = uint48(block.timestamp + 1000);
        uint256 nonce = 7;

        assertFalse(appValidator.nonceUsed(APP_ACCOUNT, nonce), "Nonce should not be used initially");

        bytes32 digest = appValidator.getRecoverDigest(APP_ACCOUNT, block.chainid, MAIN_ACCOUNT_2, nonce, expiry);
        mockGuardian.approveDigest(digest);

        appValidator.recoverWithGuardian(APP_ACCOUNT, block.chainid, MAIN_ACCOUNT_2, nonce, expiry, hex"00");

        assertTrue(appValidator.nonceUsed(APP_ACCOUNT, nonce), "Nonce should be marked as used");
    }

    function test_RecoverWithGuardian_RevertWhen_Expired() public {
        _installAppAccount();

        vm.warp(2000);
        vm.expectRevert(OneAuthAppRecoveryBase.RecoveryExpired.selector);
        appValidator.recoverWithGuardian(APP_ACCOUNT, block.chainid, MAIN_ACCOUNT_2, 0, 1000, hex"00");
    }

    function test_RecoverWithGuardian_RevertWhen_NonceAlreadyUsed() public {
        _installAppAccount();

        uint48 expiry = uint48(block.timestamp + 1000);
        uint256 nonce = 0;

        // First recovery succeeds
        bytes32 digest = appValidator.getRecoverDigest(APP_ACCOUNT, block.chainid, MAIN_ACCOUNT_2, nonce, expiry);
        mockGuardian.approveDigest(digest);
        appValidator.recoverWithGuardian(APP_ACCOUNT, block.chainid, MAIN_ACCOUNT_2, nonce, expiry, hex"00");

        // Second recovery with same nonce fails
        vm.expectRevert(OneAuthAppRecoveryBase.NonceAlreadyUsed.selector);
        appValidator.recoverWithGuardian(APP_ACCOUNT, block.chainid, address(0xEE), nonce, expiry, hex"00");
    }

    function test_RecoverWithGuardian_RevertWhen_GuardianNotConfigured() public {
        _installAppAccountNoGuardian();

        uint48 expiry = uint48(block.timestamp + 1000);
        vm.expectRevert(GuardianVerifierLib.GuardianNotConfigured.selector);
        appValidator.recoverWithGuardian(APP_ACCOUNT, block.chainid, MAIN_ACCOUNT_2, 0, expiry, hex"00");
    }

    function test_RecoverWithGuardian_RevertWhen_InvalidGuardianSignature() public {
        // Install with a rejecting guardian
        vm.prank(APP_ACCOUNT);
        appValidator.onInstall(
            abi.encode(MAIN_ACCOUNT, address(rejectingGuardian), address(0), uint8(1))
        );

        uint48 expiry = uint48(block.timestamp + 1000);
        vm.expectRevert(GuardianVerifierLib.InvalidGuardianSignature.selector);
        appValidator.recoverWithGuardian(APP_ACCOUNT, block.chainid, MAIN_ACCOUNT_2, 0, expiry, hex"00");
    }

    function test_RecoverWithGuardian_RevertWhen_InvalidChainId() public {
        _installAppAccount();

        uint48 expiry = uint48(block.timestamp + 1000);
        vm.expectRevert(OneAuthAppRecoveryBase.InvalidChainId.selector);
        appValidator.recoverWithGuardian(APP_ACCOUNT, 999, MAIN_ACCOUNT_2, 0, expiry, hex"00");
    }

    function test_RecoverWithGuardian_RevertWhen_ZeroNewMainAccount() public {
        _installAppAccount();

        uint48 expiry = uint48(block.timestamp + 1000);
        bytes32 digest = appValidator.getRecoverDigest(APP_ACCOUNT, block.chainid, address(0), 0, expiry);
        mockGuardian.approveDigest(digest);

        vm.expectRevert(OneAuthAppRecoveryBase.InvalidNewMainAccount.selector);
        appValidator.recoverWithGuardian(APP_ACCOUNT, block.chainid, address(0), 0, expiry, hex"00");
    }

    function test_RecoverWithGuardian_ChainIdZero_AnyChain() public {
        _installAppAccount();

        uint48 expiry = uint48(block.timestamp + 1000);

        // chainId=0 means any chain
        bytes32 digest = appValidator.getRecoverDigest(APP_ACCOUNT, 0, MAIN_ACCOUNT_2, 0, expiry);
        mockGuardian.approveDigest(digest);

        appValidator.recoverWithGuardian(APP_ACCOUNT, 0, MAIN_ACCOUNT_2, 0, expiry, hex"00");

        assertEq(appValidator.getMainAccount(APP_ACCOUNT), MAIN_ACCOUNT_2);
    }

    function test_RecoverWithGuardian_DualGuardian_Success() public {
        _installAppAccountDualGuardian();

        uint48 expiry = uint48(block.timestamp + 1000);
        uint256 nonce = 0;

        bytes32 digest = appValidator.getRecoverDigest(APP_ACCOUNT, block.chainid, MAIN_ACCOUNT_2, nonce, expiry);
        mockGuardian.approveDigest(digest);
        mockGuardian2.approveDigest(digest);

        // Dual guardian sig format: [user_sig_len:uint16][user_sig][external_sig]
        // For ERC-1271 mock guardians, the sig content is empty (just type byte matters for single,
        // but for dual we need the length prefix)
        bytes memory dualSig = abi.encodePacked(uint16(0), bytes(""));

        appValidator.recoverWithGuardian(APP_ACCOUNT, block.chainid, MAIN_ACCOUNT_2, nonce, expiry, dualSig);

        assertEq(appValidator.getMainAccount(APP_ACCOUNT), MAIN_ACCOUNT_2, "Main account should be updated");
    }

    /*//////////////////////////////////////////////////////////////////////////
                              NONCE PERSISTENCE ACROSS REINSTALL
    //////////////////////////////////////////////////////////////////////////*/

    function test_RecoveryNonce_PersistsAcrossReinstall() public {
        _installAppAccount();

        uint48 expiry = uint48(block.timestamp + 1000);
        uint256 nonce = 42;

        // Execute a recovery to consume nonce 42
        bytes32 digest = appValidator.getRecoverDigest(APP_ACCOUNT, block.chainid, MAIN_ACCOUNT_2, nonce, expiry);
        mockGuardian.approveDigest(digest);
        appValidator.recoverWithGuardian(APP_ACCOUNT, block.chainid, MAIN_ACCOUNT_2, nonce, expiry, hex"00");

        assertTrue(appValidator.nonceUsed(APP_ACCOUNT, nonce), "Nonce should be used after recovery");

        // Uninstall
        vm.prank(APP_ACCOUNT);
        appValidator.onUninstall("");

        // Verify nonce persists after uninstall
        assertTrue(appValidator.nonceUsed(APP_ACCOUNT, nonce), "Nonce should persist after uninstall");

        // Reinstall
        vm.prank(APP_ACCOUNT);
        appValidator.onInstall(
            abi.encode(MAIN_ACCOUNT, address(mockGuardian), address(0), uint8(1))
        );

        // Verify nonce still used after reinstall
        assertTrue(appValidator.nonceUsed(APP_ACCOUNT, nonce), "Nonce should persist after reinstall");
    }

    /*//////////////////////////////////////////////////////////////////////////
                              EVENT TESTS
    //////////////////////////////////////////////////////////////////////////*/

    function test_RecoverWithGuardian_EmitsEvent() public {
        _installAppAccount();

        uint48 expiry = uint48(block.timestamp + 1000);
        uint256 nonce = 5;

        bytes32 digest = appValidator.getRecoverDigest(APP_ACCOUNT, block.chainid, MAIN_ACCOUNT_2, nonce, expiry);
        mockGuardian.approveDigest(digest);

        vm.expectEmit(true, true, true, true);
        emit OneAuthAppRecoveryBase.AppRecoveryExecuted(
            APP_ACCOUNT, address(mockGuardian), MAIN_ACCOUNT_2, nonce
        );

        appValidator.recoverWithGuardian(APP_ACCOUNT, block.chainid, MAIN_ACCOUNT_2, nonce, expiry, hex"00");
    }

    function test_RecoverWithGuardian_EmitsAppMainAccountRecovered() public {
        _installAppAccount();

        uint48 expiry = uint48(block.timestamp + 1000);
        uint256 nonce = 0;

        bytes32 digest = appValidator.getRecoverDigest(APP_ACCOUNT, block.chainid, MAIN_ACCOUNT_2, nonce, expiry);
        mockGuardian.approveDigest(digest);

        vm.expectEmit(true, true, true, false);
        emit IOneAuthAppValidator.AppMainAccountRecovered(APP_ACCOUNT, MAIN_ACCOUNT, MAIN_ACCOUNT_2);

        appValidator.recoverWithGuardian(APP_ACCOUNT, block.chainid, MAIN_ACCOUNT_2, nonce, expiry, hex"00");
    }

    function test_SetGuardianConfig_EmitsEvent() public {
        _installAppAccountNoGuardian();

        vm.prank(APP_ACCOUNT);
        vm.expectEmit(true, true, false, false);
        emit OneAuthAppRecoveryBase.AppGuardianConfigSet(APP_ACCOUNT, address(mockGuardian), address(0), 1);

        appValidator.setGuardianConfig(address(mockGuardian), address(0), 1);
    }

    /*//////////////////////////////////////////////////////////////////////////
                              VALIDATION AFTER RECOVERY
    //////////////////////////////////////////////////////////////////////////*/

    function test_ValidateUserOp_AfterRecovery_UsesNewMainAccount() public {
        _installAppAccount();

        // Recover to MAIN_ACCOUNT_2
        uint48 expiry = uint48(block.timestamp + 1000);
        bytes32 digest = appValidator.getRecoverDigest(APP_ACCOUNT, block.chainid, MAIN_ACCOUNT_2, 0, expiry);
        mockGuardian.approveDigest(digest);
        appValidator.recoverWithGuardian(APP_ACCOUNT, block.chainid, MAIN_ACCOUNT_2, 0, expiry, hex"00");

        // Now validate using the new main account's credentials
        // Both MAIN_ACCOUNT and MAIN_ACCOUNT_2 have the same pubKey so this still works
        PackedUserOperation memory userOp = getEmptyUserOperation();
        userOp.sender = APP_ACCOUNT;

        // After recovery, APP_ACCOUNT points to MAIN_ACCOUNT_2, so use that for signing
        (uint256 r, uint256 s, string memory clientDataJSON) = _createValidWebAuthnSig(MAIN_ACCOUNT_2, TEST_DIGEST);
        userOp.signature = _buildRegularSignature(0, r, s, AUTH_DATA_UV, clientDataJSON);

        uint256 validationData =
            ERC7579ValidatorBase.ValidationData.unwrap(appValidator.validateUserOp(userOp, TEST_DIGEST));
        assertEq(validationData, 0, "Should validate against new main account after recovery");
    }

    /*//////////////////////////////////////////////////////////////////////////
                              GUARDIAN THRESHOLD TESTS
    //////////////////////////////////////////////////////////////////////////*/

    function test_GuardianThreshold_DefaultsTo1() public {
        _installAppAccountNoGuardian();
        assertEq(appValidator.guardianThreshold(APP_ACCOUNT), 1);
    }

    function test_GuardianThreshold_Returns2() public {
        _installAppAccountDualGuardian();
        assertEq(appValidator.guardianThreshold(APP_ACCOUNT), 2);
    }
}
