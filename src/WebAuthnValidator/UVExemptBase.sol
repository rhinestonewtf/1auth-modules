// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.28;

import { EnumerableSetLib } from "solady/utils/EnumerableSetLib.sol";
import { OriginLib } from "./lib/OriginLib.sol";
import { P256Lib } from "./lib/P256Lib.sol";

/// @title UVExemptBase
/// @notice Abstract mixin for origin-based user verification (UV) exemptions in WebAuthn
/// @dev When a third-party app (e.g., game.xyz) embeds a passkey RP via iframe, the WebAuthn
///      clientDataJSON contains both topOrigin (the embedding app) and origin (the RP).
///      This mixin allows accounts to exempt specific (topOrigin, origin) pairs from requiring
///      user verification (biometric/PIN), enabling smoother UX for trusted iframe scenarios.
///
///      UV exemptions are stored per-account in an EnumerableSet of composite keys. On uninstall,
///      all entries are iterated and removed, performing actual storage cleanup.
abstract contract UVExemptBase {
    using EnumerableSetLib for EnumerableSetLib.Bytes32Set;

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Emitted when a UV exemption is set or cleared for an (topOrigin, origin) pair
    event UVExemptOriginSet(
        address indexed account, bytes32 topOriginHash, bytes32 originHash, bool exempt
    );

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Per-account set of UV-exempt origin pair keys (keccak256(topOriginHash, originHash))
    mapping(address account => EnumerableSetLib.Bytes32Set) internal _uvExemptKeys;

    /*//////////////////////////////////////////////////////////////
                            EXTERNAL / PUBLIC
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Configure a (topOrigin, origin) pair as UV-exempt for the caller's account
     * @param topOriginHash keccak256 of the topOrigin string (e.g., keccak256("https://game.xyz"))
     * @param originHash keccak256 of the origin string (e.g., keccak256("https://passkey.1auth.box"))
     * @param exempt True to allow UV-less signing from this origin pair, false to revoke
     */
    function setUVExemptOrigin(bytes32 topOriginHash, bytes32 originHash, bool exempt) external {
        bytes32 key = keccak256(abi.encodePacked(topOriginHash, originHash));
        if (exempt) {
            _uvExemptKeys[msg.sender].add(key);
        } else {
            _uvExemptKeys[msg.sender].remove(key);
        }
        emit UVExemptOriginSet(msg.sender, topOriginHash, originHash, exempt);
    }

    /**
     * @notice Check if a (topOrigin, origin) pair is UV-exempt for an account
     * @param account The smart account to query
     * @param topOriginHash keccak256 of the topOrigin string
     * @param originHash keccak256 of the origin string
     * @return True if the pair is UV-exempt
     */
    function isUVExemptOrigin(
        address account,
        bytes32 topOriginHash,
        bytes32 originHash
    )
        external
        view
        returns (bool)
    {
        bytes32 key = keccak256(abi.encodePacked(topOriginHash, originHash));
        return _uvExemptKeys[account].contains(key);
    }

    /*//////////////////////////////////////////////////////////////
                                INTERNAL
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Remove all UV exemptions for an account (actual storage cleanup)
     * @dev Called by onUninstall. Iterates the set and removes each entry.
     */
    function _invalidateUVExemptions(address account) internal {
        EnumerableSetLib.Bytes32Set storage keys = _uvExemptKeys[account];
        bytes32[] memory allKeys = keys.values();
        for (uint256 i; i < allKeys.length; ++i) {
            keys.remove(allKeys[i]);
        }
    }

    /**
     * @notice Resolve UV skip request against origin-based UV exemption policy
     * @dev Extracts clientDataJSON from the packed WebAuthnAuth calldata, then uses
     *      OriginLib to scan for topOrigin/origin directly from calldata (no memory copy).
     *      Called only when requestSkipUV=true.
     * @param account The smart account for exemption lookup
     * @param packedAuth The packed WebAuthnAuth calldata (r, s, indices, authData, clientDataJSON)
     * @return requireUV The effective requireUV to pass to WebAuthn.verify
     * @return allowed False if the UV exemption claim is denied (topOrigin present but not exempt)
     */
    function _resolveSkipUV(
        address account,
        bytes calldata packedAuth
    )
        internal
        view
        returns (bool requireUV, bool allowed)
    {
        // Packed format: [0:32] r, [32:64] s, [64:66] challengeIdx, [66:68] typeIdx,
        //                [68:70] adLen, [70:70+adLen] authData, [70+adLen:] clientDataJSON
        if (packedAuth.length < P256Lib.WEBAUTHN_AUTH_HEADER_SIZE) return (true, true);
        uint256 adLen = uint16(bytes2(packedAuth[68:70]));
        if (packedAuth.length < P256Lib.WEBAUTHN_AUTH_HEADER_SIZE + adLen) return (true, true);

        bytes calldata clientDataJSON = packedAuth[P256Lib.WEBAUTHN_AUTH_HEADER_SIZE + adLen:];
        (bytes32 originHash, bytes32 topOriginHash) = OriginLib.extractOriginHashes(clientDataJSON);

        // No topOrigin (direct access or old browser) — fallback to requireUV=true
        if (topOriginHash == bytes32(0)) return (true, true);

        // topOrigin present — check exemption
        bytes32 key = keccak256(abi.encodePacked(topOriginHash, originHash));
        if (!_uvExemptKeys[account].contains(key)) {
            return (false, false);
        }

        // Exempt — verify with requireUV=false
        return (false, true);
    }
}
