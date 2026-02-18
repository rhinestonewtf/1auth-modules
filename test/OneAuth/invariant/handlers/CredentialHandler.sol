// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";
import { OneAuthValidator } from "src/OneAuth/OneAuthValidator.sol";

interface IRecoveryHandlerGhost {
    function ghostClearGuardianState(address actor) external;
}

contract CredentialHandler is Test {
    OneAuthValidator public validator;
    address[] public actors;
    IRecoveryHandlerGhost public recoveryHandler;

    uint256 constant NUM_KEYS = 8;
    bytes32[] public pubKeysX;
    bytes32[] public pubKeysY;

    // Ghost state
    mapping(address => bool) public ghost_isInstalled;
    mapping(address => uint256) public ghost_credentialCount;
    mapping(address => mapping(uint16 => bool)) public ghost_credKeyExists;

    // Call counters
    uint256 public ghost_installCalls;
    uint256 public ghost_uninstallCalls;
    uint256 public ghost_addCredCalls;
    uint256 public ghost_removeCredCalls;

    constructor(OneAuthValidator _validator, address[] memory _actors) {
        validator = _validator;
        actors = _actors;

        // Generate P-256 key pool from deterministic private keys
        for (uint256 i; i < NUM_KEYS; i++) {
            uint256 privKey = uint256(keccak256(abi.encodePacked("invariant-key", i)));
            (uint256 x, uint256 y) = vm.publicKeyP256(privKey);
            pubKeysX.push(bytes32(x));
            pubKeysY.push(bytes32(y));
        }
    }

    function _pickActor(uint8 seed) internal view returns (address) {
        return actors[seed % actors.length];
    }

    function _pickKey(uint8 seed) public view returns (bytes32 px, bytes32 py) {
        uint256 idx = seed % NUM_KEYS;
        return (pubKeysX[idx], pubKeysY[idx]);
    }

    function handler_install(uint8 actorSeed, uint8 credCount, uint8 keySeed) external {
        address actor = _pickActor(actorSeed);
        if (ghost_isInstalled[actor]) return;

        uint256 count = bound(credCount, 1, 4);

        uint16[] memory keyIds = new uint16[](count);
        OneAuthValidator.WebAuthnCredential[] memory creds =
            new OneAuthValidator.WebAuthnCredential[](count);

        for (uint256 i; i < count; i++) {
            uint256 keyIdx = (uint256(keySeed) + i) % NUM_KEYS;
            keyIds[i] = uint16(i);
            creds[i] = OneAuthValidator.WebAuthnCredential({
                pubKeyX: pubKeysX[keyIdx],
                pubKeyY: pubKeysY[keyIdx]
            });
        }

        vm.prank(actor);
        try validator.onInstall(abi.encode(keyIds, creds, address(0), address(0), uint48(0))) {
            ghost_isInstalled[actor] = true;
            ghost_credentialCount[actor] = count;
            for (uint256 i; i < count; i++) {
                ghost_credKeyExists[actor][uint16(i)] = true;
            }
            ghost_installCalls++;
        } catch { }
    }

    function handler_uninstall(uint8 actorSeed) external {
        address actor = _pickActor(actorSeed);
        if (!ghost_isInstalled[actor]) return;

        vm.prank(actor);
        try validator.onUninstall("") {
            ghost_isInstalled[actor] = false;
            ghost_credentialCount[actor] = 0;
            // onUninstall clears guardian/pending/timelock on-chain, sync ghost state
            if (address(recoveryHandler) != address(0)) {
                recoveryHandler.ghostClearGuardianState(actor);
            }
            ghost_uninstallCalls++;
        } catch { }
    }

    function handler_addCredential(uint8 actorSeed, uint16 keyId, uint8 keySeed) external {
        address actor = _pickActor(actorSeed);
        if (!ghost_isInstalled[actor]) return;
        if (ghost_credentialCount[actor] >= 64) return;

        (bytes32 px, bytes32 py) = _pickKey(keySeed);

        vm.prank(actor);
        try validator.addCredential(keyId, px, py) {
            ghost_credentialCount[actor]++;
            ghost_credKeyExists[actor][keyId] = true;
            ghost_addCredCalls++;
        } catch { }
    }

    function handler_removeCredential(uint8 actorSeed, uint16 keyId) external {
        address actor = _pickActor(actorSeed);
        if (!ghost_isInstalled[actor]) return;
        if (ghost_credentialCount[actor] <= 1) return;

        vm.prank(actor);
        try validator.removeCredential(keyId) {
            ghost_credentialCount[actor]--;
            ghost_credKeyExists[actor][keyId] = false;
            ghost_removeCredCalls++;
        } catch { }
    }

    /// @dev Set after construction to avoid circular dependency
    function setRecoveryHandler(address _recoveryHandler) external {
        recoveryHandler = IRecoveryHandlerGhost(_recoveryHandler);
    }

    /// @dev Called by RecoveryHandler when a recovery adds a credential (replace=false)
    function ghostIncrementCredCount(address actor) external {
        ghost_credentialCount[actor]++;
    }

    function actorCount() external view returns (uint256) {
        return actors.length;
    }

    function getActor(uint256 i) external view returns (address) {
        return actors[i];
    }
}
