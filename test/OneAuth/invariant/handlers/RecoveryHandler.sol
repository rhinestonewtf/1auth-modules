// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";
import { OneAuthValidator } from "src/OneAuth/OneAuthValidator.sol";
import { OneAuthRecoveryBase } from "src/OneAuth/OneAuthRecoveryBase.sol";
import { SignatureCheckerLib } from "solady/utils/SignatureCheckerLib.sol";
import { CredentialHandler } from "./CredentialHandler.sol";

/// @dev ERC-1271 mock guardian that pre-approves digests
contract InvariantMockGuardian {
    mapping(bytes32 => bool) public approvedDigests;

    function approveDigest(bytes32 digest) external {
        approvedDigests[digest] = true;
    }

    function isValidSignature(bytes32 hash, bytes calldata) external view returns (bytes4) {
        if (approvedDigests[hash]) return 0x1626ba7e;
        return 0xffffffff;
    }
}

contract RecoveryHandler is Test {
    OneAuthValidator public validator;
    CredentialHandler public credHandler;
    address[] public actors;

    InvariantMockGuardian public mockGuardian1;
    InvariantMockGuardian public mockGuardian2;

    // Ghost state — nonces
    mapping(address => mapping(uint256 => bool)) public ghost_nonceUsed;
    mapping(address => uint256) public ghost_nextNonce;

    // Ghost state — guardian
    mapping(address => address) public ghost_userGuardian;
    mapping(address => address) public ghost_externalGuardian;

    /// @dev Called by CredentialHandler on uninstall to clear guardian ghost state
    function ghostClearGuardianState(address actor) external {
        ghost_userGuardian[actor] = address(0);
        ghost_externalGuardian[actor] = address(0);
    }

    // Call counters
    uint256 public ghost_setUserGuardianCalls;
    uint256 public ghost_recoveryCalls;
    uint256 public ghost_warpCalls;

    constructor(
        OneAuthValidator _validator,
        address[] memory _actors,
        CredentialHandler _credHandler
    ) {
        validator = _validator;
        actors = _actors;
        credHandler = _credHandler;

        mockGuardian1 = new InvariantMockGuardian();
        mockGuardian2 = new InvariantMockGuardian();
    }

    function _pickActor(uint8 seed) internal view returns (address) {
        return actors[seed % actors.length];
    }

    function _pickGuardian(uint8 seed) internal view returns (address) {
        return seed % 2 == 0 ? address(mockGuardian1) : address(mockGuardian2);
    }

    function handler_setUserGuardian(uint8 actorSeed, uint8 guardianSeed) external {
        address actor = _pickActor(actorSeed);
        if (!credHandler.ghost_isInstalled(actor)) return;

        address newGuardian = _pickGuardian(guardianSeed);

        vm.prank(actor);
        try validator.setGuardianConfig(newGuardian, address(0), 1) {
            ghost_userGuardian[actor] = newGuardian;
            ghost_setUserGuardianCalls++;
        } catch { }
    }

    function handler_recoverWithGuardian(
        uint8 actorSeed,
        uint16 newKeyId,
        uint8 keySeed,
        bool replace
    )
        external
    {
        address actor = _pickActor(actorSeed);
        if (!credHandler.ghost_isInstalled(actor)) return;
        if (ghost_userGuardian[actor] == address(0)) return;

        uint256 nonce = ghost_nextNonce[actor]++;
        uint48 expiry = uint48(block.timestamp + 1 hours);

        (bytes32 px, bytes32 py) = credHandler._pickKey(keySeed);

        OneAuthRecoveryBase.NewCredential memory cred = OneAuthRecoveryBase.NewCredential({
            keyId: newKeyId,
            pubKeyX: px,
            pubKeyY: py,
            replace: replace
        });

        bytes32 digest = validator.getRecoverDigest(actor, block.chainid, cred, nonce, expiry);

        // Pre-approve the digest on the correct user guardian
        InvariantMockGuardian g = InvariantMockGuardian(ghost_userGuardian[actor]);
        g.approveDigest(digest);

        // 0x00 type byte = user guardian
        try validator.recoverWithGuardian(actor, block.chainid, cred, nonce, expiry, hex"00") {
            ghost_nonceUsed[actor][nonce] = true;
            // Update credential ghost state: replace keeps count, add increments
            if (!replace) {
                credHandler.ghostIncrementCredCount(actor);
            }
            ghost_recoveryCalls++;
        } catch {
            // Recovery can fail (e.g., keyId collision with replace=false,
            // invalid key, etc.) — don't update ghost state
        }
    }

    function handler_warpTime(uint32 delta) external {
        uint256 warpDelta = bound(delta, 0, 7 days);
        vm.warp(block.timestamp + warpDelta);
        ghost_warpCalls++;
    }

    function actorCount() external view returns (uint256) {
        return actors.length;
    }
}
