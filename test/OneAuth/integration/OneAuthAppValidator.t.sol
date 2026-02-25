// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { BaseIntegrationTest, ModuleKitHelpers, AccountInstance } from "test/BaseIntegration.t.sol";
import { OneAuthValidator } from "src/OneAuth/OneAuthValidator.sol";
import { OneAuthAppValidator } from "src/OneAuth/OneAuthAppValidator.sol";
import { MODULE_TYPE_VALIDATOR } from "modulekit/accounts/common/interfaces/IERC7579Module.sol";

contract OneAuthAppValidatorIntegrationTest is BaseIntegrationTest {
    using ModuleKitHelpers for *;

    OneAuthValidator internal mainValidatorModule;
    OneAuthAppValidator internal appValidatorModule;

    /// @dev Second smart account instance that acts as the "app account"
    AccountInstance internal appInstance;

    // Test public keys (same as OneAuthValidator integration test)
    bytes32 _pubKeyX0 = bytes32(uint256(66_296_829_923_831_658_891_499_717_579_803_548_012_279_830_557_731_564_719_736_971_029_660_387_468_805));
    bytes32 _pubKeyY0 = bytes32(uint256(46_098_569_798_045_992_993_621_049_610_647_226_011_837_333_919_273_603_402_527_314_962_291_506_652_186));

    function setUp() public virtual override {
        super.setUp();

        // Create the second smart account for the app
        appInstance = makeAccountInstance("appInstance");
        vm.deal(address(appInstance.account), 10 ether);

        // Deploy modules
        mainValidatorModule = new OneAuthValidator();
        appValidatorModule = new OneAuthAppValidator(address(mainValidatorModule));

        // Install OneAuthValidator on the main account (instance) with one credential
        uint16[] memory keyIds = new uint16[](1);
        keyIds[0] = 0;
        OneAuthValidator.WebAuthnCredential[] memory creds =
            new OneAuthValidator.WebAuthnCredential[](1);
        creds[0] = OneAuthValidator.WebAuthnCredential({
            pubKeyX: _pubKeyX0,
            pubKeyY: _pubKeyY0
        });
        instance.installModule({
            moduleTypeId: MODULE_TYPE_VALIDATOR,
            module: address(mainValidatorModule),
            data: abi.encode(keyIds, creds, address(0), address(0), uint8(0))
        });

        // Install OneAuthAppValidator on the app account, pointing to the main account
        appInstance.installModule({
            moduleTypeId: MODULE_TYPE_VALIDATOR,
            module: address(appValidatorModule),
            data: abi.encode(address(instance.account), address(0), address(0), uint8(0))
        });
    }

    function test_OnInstall_SetsMainAccount() public view {
        assertTrue(appValidatorModule.isInitialized(address(appInstance.account)));
        assertEq(
            appValidatorModule.getMainAccount(address(appInstance.account)),
            address(instance.account)
        );
    }

    function test_OnUninstall_ClearsMainAccount() public {
        appInstance.uninstallModule({
            moduleTypeId: MODULE_TYPE_VALIDATOR,
            module: address(appValidatorModule),
            data: ""
        });

        assertFalse(appValidatorModule.isInitialized(address(appInstance.account)));
        assertEq(appValidatorModule.getMainAccount(address(appInstance.account)), address(0));
    }

    function test_MainAccountCredentials_Accessible() public view {
        // Verify the main account has credentials installed
        assertTrue(mainValidatorModule.isInitialized(address(instance.account)));
        assertEq(mainValidatorModule.credentialCount(address(instance.account)), 1);

        (bytes32 px, bytes32 py) = mainValidatorModule.getCredential(0, address(instance.account));
        assertEq(px, _pubKeyX0);
        assertEq(py, _pubKeyY0);
    }
}
