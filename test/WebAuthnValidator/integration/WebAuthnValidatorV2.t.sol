// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { BaseIntegrationTest, ModuleKitHelpers } from "test/BaseIntegration.t.sol";
import { WebAuthnValidatorV2 } from "src/WebAuthnValidator/WebAuthnValidatorV2.sol";
import { MODULE_TYPE_VALIDATOR } from "modulekit/accounts/common/interfaces/IERC7579Module.sol";
import { UserOpData } from "modulekit/ModuleKit.sol";

contract WebAuthnValidatorV2IntegrationTest is BaseIntegrationTest {
    using ModuleKitHelpers for *;

    /*//////////////////////////////////////////////////////////////////////////
                                    CONTRACTS
    //////////////////////////////////////////////////////////////////////////*/

    WebAuthnValidatorV2 internal validator;

    /*//////////////////////////////////////////////////////////////////////////
                                    VARIABLES
    //////////////////////////////////////////////////////////////////////////*/

    // Test public keys for WebAuthn credentials
    bytes32 _pubKeyX0 = bytes32(uint256(66_296_829_923_831_658_891_499_717_579_803_548_012_279_830_557_731_564_719_736_971_029_660_387_468_805));
    bytes32 _pubKeyY0 = bytes32(uint256(46_098_569_798_045_992_993_621_049_610_647_226_011_837_333_919_273_603_402_527_314_962_291_506_652_186));
    bytes32 _pubKeyX1 = bytes32(uint256(77_427_310_596_034_628_445_756_159_459_159_056_108_500_819_865_614_675_054_701_790_516_611_205_123_311));
    bytes32 _pubKeyY1 = bytes32(uint256(20_591_151_874_462_689_689_754_215_152_304_668_244_192_265_896_034_279_288_204_806_249_532_173_935_644));

    /*//////////////////////////////////////////////////////////////////////////
                                      SETUP
    //////////////////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        super.setUp();
        validator = new WebAuthnValidatorV2();

        // Setup two credentials with keyIds 0 and 1, no guardian, no timelock
        uint16[] memory keyIds = new uint16[](2);
        keyIds[0] = 0;
        keyIds[1] = 1;

        WebAuthnValidatorV2.WebAuthnCredential[] memory creds = new WebAuthnValidatorV2.WebAuthnCredential[](2);
        creds[0] = WebAuthnValidatorV2.WebAuthnCredential({
            pubKeyX: _pubKeyX0,
            pubKeyY: _pubKeyY0
        });
        creds[1] = WebAuthnValidatorV2.WebAuthnCredential({
            pubKeyX: _pubKeyX1,
            pubKeyY: _pubKeyY1
        });

        address guardian = address(0);
        uint48 guardianTimelock = 0;

        // Install the validator module on the account
        instance.installModule({
            moduleTypeId: MODULE_TYPE_VALIDATOR,
            module: address(validator),
            data: abi.encode(keyIds, creds, guardian, guardianTimelock)
        });
    }

    /*//////////////////////////////////////////////////////////////////////////
                                      TESTS
    //////////////////////////////////////////////////////////////////////////*/

    function test_OnInstall_SetsCredentials() public view {
        // It should set the credentials and credential count
        assertTrue(validator.isInitialized(address(instance.account)), "Validator should be initialized");

        uint256 credentialCount = validator.credentialCount(address(instance.account));
        assertEq(credentialCount, 2, "Credential count should be 2");

        // Verify first credential
        (bytes32 pubKeyX0, bytes32 pubKeyY0) = validator.getCredential(0, address(instance.account));
        assertEq(pubKeyX0, _pubKeyX0, "First credential pubKeyX should match");
        assertEq(pubKeyY0, _pubKeyY0, "First credential pubKeyY should match");

        // Verify second credential
        (bytes32 pubKeyX1, bytes32 pubKeyY1) = validator.getCredential(1, address(instance.account));
        assertEq(pubKeyX1, _pubKeyX1, "Second credential pubKeyX should match");
        assertEq(pubKeyY1, _pubKeyY1, "Second credential pubKeyY should match");
    }

    function test_OnUninstall_ClearsCredentials() public {
        // It should remove all credentials and clear initialization state
        instance.uninstallModule({
            moduleTypeId: MODULE_TYPE_VALIDATOR,
            module: address(validator),
            data: ""
        });

        assertFalse(validator.isInitialized(address(instance.account)), "Validator should not be initialized");

        uint256 credentialCount = validator.credentialCount(address(instance.account));
        assertEq(credentialCount, 0, "Credential count should be 0");
    }

    function test_AddCredential_ViaAccount() public {
        // It should add a new credential
        uint16 newKeyId = 99;

        instance.getExecOps({
            target: address(validator),
            value: 0,
            callData: abi.encodeWithSelector(
                WebAuthnValidatorV2.addCredential.selector,
                newKeyId,
                _pubKeyX0,
                _pubKeyY0
            ),
            txValidator: address(instance.defaultValidator)
        }).execUserOps();

        // Verify credential was added
        uint256 credentialCount = validator.credentialCount(address(instance.account));
        assertEq(credentialCount, 3, "Credential count should be incremented to 3");

        (bytes32 pubKeyX, bytes32 pubKeyY) = validator.getCredential(newKeyId, address(instance.account));
        assertEq(pubKeyX, _pubKeyX0, "New credential pubKeyX should match");
        assertEq(pubKeyY, _pubKeyY0, "New credential pubKeyY should match");
    }

    function test_RemoveCredential_ViaAccount() public {
        // It should remove a credential
        uint16 keyIdToRemove = 0;

        instance.getExecOps({
            target: address(validator),
            value: 0,
            callData: abi.encodeWithSelector(
                WebAuthnValidatorV2.removeCredential.selector,
                keyIdToRemove
            ),
            txValidator: address(instance.defaultValidator)
        }).execUserOps();

        // Verify credential was removed
        uint256 credentialCount = validator.credentialCount(address(instance.account));
        assertEq(credentialCount, 1, "Credential count should be decremented to 1");

        (bytes32 pubKeyX, bytes32 pubKeyY) = validator.getCredential(keyIdToRemove, address(instance.account));
        assertEq(pubKeyX, bytes32(0), "Removed credential pubKeyX should be zero");
        assertEq(pubKeyY, bytes32(0), "Removed credential pubKeyY should be zero");
    }

    function test_ProposeGuardian_ViaAccount() public {
        // It should propose a guardian
        address guardianAddress = address(0xBEEF);

        instance.getExecOps({
            target: address(validator),
            value: 0,
            callData: abi.encodeWithSelector(
                bytes4(keccak256("proposeGuardian(address)")),
                guardianAddress
            ),
            txValidator: address(instance.defaultValidator)
        }).execUserOps();

        // Verify guardian was set (with zero timelock it should be immediate)
        address setGuardian = validator.guardian(address(instance.account));
        assertEq(setGuardian, guardianAddress, "Guardian should be set");
    }

    function test_ERC1271_FailWhen_NotInstalled() public {
        // After uninstalling, the account reverts with InvalidModule when calling
        // isValidSignature on a non-installed validator module.
        instance.uninstallModule({
            moduleTypeId: MODULE_TYPE_VALIDATOR,
            module: address(validator),
            data: ""
        });

        bytes32 hash = bytes32(uint256(0x1234567890abcdef));
        bytes memory signature = hex"00112233445566778899aabbccddeeff";

        // The account itself rejects calls to uninstalled validator modules
        vm.expectRevert();
        instance.isValidSignature(address(validator), hash, signature);
    }
}
