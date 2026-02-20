// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";
import { OneAuthValidator } from "src/OneAuth/OneAuthValidator.sol";
import { P256Lib } from "src/OneAuth/lib/P256Lib.sol";
import { P256VerifierWrapper } from "test/OneAuth/helpers/P256VerifierWrapper.sol";
import { PackedUserOperation, getEmptyUserOperation } from "test/utils/ERC4337.sol";
import { ERC7579ValidatorBase } from "modulekit/Modules.sol";
import { CredentialHandler } from "./handlers/CredentialHandler.sol";
import { RecoveryHandler } from "./handlers/RecoveryHandler.sol";

/// @dev Thin wrapper to expose P256Lib.isOnCurve for invariant assertions
contract P256CurveChecker {
    function isOnCurve(uint256 x, uint256 y) external pure returns (bool) {
        return P256Lib.isOnCurve(x, y);
    }
}

contract OneAuthInvariantTest is Test {
    OneAuthValidator internal validator;
    CredentialHandler internal credentialHandler;
    RecoveryHandler internal recoveryHandler;
    P256CurveChecker internal curveChecker;

    address[] internal actors;
    uint256 constant NUM_ACTORS = 3;

    function setUp() public {
        // Deploy P256 verifier at the Solady address
        P256VerifierWrapper verifier_ = new P256VerifierWrapper();
        vm.etch(0x000000000000D01eA45F9eFD5c54f037Fa57Ea1a, address(verifier_).code);

        validator = new OneAuthValidator();
        curveChecker = new P256CurveChecker();

        // Create actor addresses
        for (uint256 i; i < NUM_ACTORS; i++) {
            actors.push(makeAddr(string.concat("actor", vm.toString(i))));
        }

        // Deploy handlers (late-bind recovery handler to avoid circular dep)
        credentialHandler = new CredentialHandler(validator, actors);
        recoveryHandler = new RecoveryHandler(validator, actors, credentialHandler);
        credentialHandler.setRecoveryHandler(address(recoveryHandler));

        // Restrict fuzzer to only the handler contracts
        targetContract(address(credentialHandler));
        targetContract(address(recoveryHandler));

        // Further restrict to only handler_* functions
        bytes4[] memory credSelectors = new bytes4[](4);
        credSelectors[0] = CredentialHandler.handler_install.selector;
        credSelectors[1] = CredentialHandler.handler_uninstall.selector;
        credSelectors[2] = CredentialHandler.handler_addCredential.selector;
        credSelectors[3] = CredentialHandler.handler_removeCredential.selector;
        targetSelector(
            FuzzSelector({
                addr: address(credentialHandler),
                selectors: credSelectors
            })
        );

        bytes4[] memory recoverySelectors = new bytes4[](3);
        recoverySelectors[0] = RecoveryHandler.handler_setUserGuardian.selector;
        recoverySelectors[1] = RecoveryHandler.handler_recoverWithGuardian.selector;
        recoverySelectors[2] = RecoveryHandler.handler_warpTime.selector;
        targetSelector(
            FuzzSelector({
                addr: address(recoveryHandler),
                selectors: recoverySelectors
            })
        );
    }

    /*//////////////////////////////////////////////////////////////////////////
                              INVARIANT 1: CREDENTIAL LIVENESS
    //////////////////////////////////////////////////////////////////////////*/

    /// @dev Installed accounts must always have >= 1 credential
    function invariant_credentialLiveness() public view {
        for (uint256 i; i < actors.length; i++) {
            if (credentialHandler.ghost_isInstalled(actors[i])) {
                assertGt(
                    validator.credentialCount(actors[i]),
                    0,
                    "Installed account must have >= 1 credential"
                );
            }
        }
    }

    /*//////////////////////////////////////////////////////////////////////////
                              INVARIANT 2: CREDENTIAL COUNT CAP
    //////////////////////////////////////////////////////////////////////////*/

    /// @dev No account can exceed MAX_CREDENTIALS (64)
    function invariant_credentialCountCapped() public view {
        for (uint256 i; i < actors.length; i++) {
            assertLe(
                validator.credentialCount(actors[i]),
                64,
                "Credential count must not exceed MAX_CREDENTIALS"
            );
        }
    }

    /*//////////////////////////////////////////////////////////////////////////
                              INVARIANT 3: PUBKEYS ON CURVE
    //////////////////////////////////////////////////////////////////////////*/

    /// @dev All stored public keys must be valid P-256 curve points
    function invariant_pubkeysOnCurve() public view {
        for (uint256 i; i < actors.length; i++) {
            uint256[] memory credKeys = validator.getCredKeys(actors[i]);
            for (uint256 j; j < credKeys.length; j++) {
                (bytes32 px, bytes32 py) =
                    validator.getCredential(uint16(credKeys[j]), actors[i]);
                assertTrue(
                    curveChecker.isOnCurve(uint256(px), uint256(py)),
                    "Stored pubkey must be on P-256 curve"
                );
            }
        }
    }

    /*//////////////////////////////////////////////////////////////////////////
                              INVARIANT 4: NONCE NON-REUSABILITY
    //////////////////////////////////////////////////////////////////////////*/

    /// @dev Every nonce the handler consumed must be marked used on-chain
    function invariant_nonceNonReusable() public view {
        for (uint256 i; i < actors.length; i++) {
            address actor = actors[i];
            uint256 maxNonce = recoveryHandler.ghost_nextNonce(actor);
            for (uint256 n; n < maxNonce; n++) {
                if (recoveryHandler.ghost_nonceUsed(actor, n)) {
                    assertTrue(
                        validator.nonceUsed(actor, n),
                        "Ghost-used nonce must be marked used on-chain"
                    );
                }
            }
        }
    }

    /*//////////////////////////////////////////////////////////////////////////
                      INVARIANT 5: GUARDIAN GHOST-STATE CONSISTENCY
    //////////////////////////////////////////////////////////////////////////*/

    /// @dev Guardian ghost state must match on-chain state for installed accounts
    function invariant_guardianGhostConsistency() public view {
        for (uint256 i; i < actors.length; i++) {
            address actor = actors[i];
            if (!credentialHandler.ghost_isInstalled(actor)) continue;

            (address onChainUserGuardian, address onChainExternalGuardian,) = validator.guardianConfig(actor);
            assertEq(
                recoveryHandler.ghost_userGuardian(actor),
                onChainUserGuardian,
                "Ghost user guardian must match on-chain"
            );
            assertEq(
                recoveryHandler.ghost_externalGuardian(actor),
                onChainExternalGuardian,
                "Ghost external guardian must match on-chain"
            );
        }
    }

    /*//////////////////////////////////////////////////////////////////////////
                          INVARIANT 6: GHOST-STATE CONSISTENCY
    //////////////////////////////////////////////////////////////////////////*/

    /// @dev Handler ghost state must match on-chain contract state
    function invariant_ghostStateConsistency() public view {
        for (uint256 i; i < actors.length; i++) {
            address actor = actors[i];
            assertEq(
                credentialHandler.ghost_isInstalled(actor),
                validator.isInitialized(actor),
                "Ghost install state must match on-chain"
            );
            if (validator.isInitialized(actor)) {
                assertEq(
                    credentialHandler.ghost_credentialCount(actor),
                    validator.credentialCount(actor),
                    "Ghost credential count must match on-chain"
                );
            }
        }
    }

    /*//////////////////////////////////////////////////////////////////////////
                      INVARIANT 7: validateUserOp NEVER REVERTS
    //////////////////////////////////////////////////////////////////////////*/

    /// @dev validateUserOp must return 0 or 1 for installed accounts, never revert
    function invariant_validateUserOpNeverReverts() public view {
        for (uint256 i; i < actors.length; i++) {
            if (!validator.isInitialized(actors[i])) continue;

            PackedUserOperation memory userOp = getEmptyUserOperation();
            userOp.sender = actors[i];
            userOp.signature = "";

            uint256 result = ERC7579ValidatorBase.ValidationData.unwrap(
                validator.validateUserOp(userOp, bytes32(0))
            );
            assertTrue(
                result == 0 || result == 1,
                "validateUserOp must return 0 or 1"
            );
        }
    }
}
