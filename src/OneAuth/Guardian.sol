// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.28;

import { SignatureCheckerLib } from "solady/utils/SignatureCheckerLib.sol";

/**
 * @title Guardian
 * @notice Multisig guardian implementing EIP-1271 for use with OneAuth recovery
 * @dev Holds up to 3 immutable guardian addresses with a configurable M-of-N threshold.
 *      Each signature entry is length-prefixed: `(uint8 id, uint16 sigLen, bytes[sigLen] sig)`.
 *      The `id` identifies the guardian slot (0, 1, or 2). IDs cannot be reused within a
 *      single validation, preventing the same guardian from signing twice.
 *      Guardians can be EOAs (65-byte ECDSA signatures) or EIP-1271 contracts
 *      (variable-length signatures), enabling composable guardian trees.
 *      Intended to be set as the guardian address on OneAuthValidator via `proposeGuardian`.
 */
contract Guardian {
    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @dev EIP-1271 magic value returned on successful signature validation
    bytes4 internal constant _EIP1271_MAGIC = 0x1626ba7e;

    /// @dev Value returned when signature validation fails
    bytes4 internal constant _EIP1271_FAIL = 0xffffffff;

    /// @dev Maximum number of guardians
    uint256 internal constant MAX_GUARDIANS = 3;

    /// @dev Length of the per-entry header: 1 byte id + 2 bytes sigLen
    uint256 internal constant HEADER_LENGTH = 3;

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Thrown when threshold is 0 or exceeds the number of guardians
    error InvalidThreshold();

    /// @notice Thrown when guardian count is 0 or exceeds MAX_GUARDIANS
    error InvalidGuardianCount();

    /// @notice Thrown when duplicate guardian addresses are provided
    error DuplicateGuardian();

    /// @notice Thrown when a guardian address is address(0)
    error ZeroAddress();

    /*//////////////////////////////////////////////////////////////
                           IMMUTABLE STATE
    //////////////////////////////////////////////////////////////*/

    address public immutable guardian0;
    address public immutable guardian1;
    address public immutable guardian2;

    /// @notice Number of active guardians (1-3)
    uint8 public immutable guardianCount;

    /// @notice Number of signatures required for valid authorization
    uint8 public immutable threshold;

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /**
     * @param _guardians Array of guardian addresses (1-3, no duplicates, no zero addresses)
     * @param _threshold Minimum number of signatures required (1 <= threshold <= guardians.length)
     */
    constructor(address[] memory _guardians, uint8 _threshold) {
        uint256 len = _guardians.length;
        if (len == 0 || len > MAX_GUARDIANS) revert InvalidGuardianCount();
        if (_threshold == 0 || _threshold > len) revert InvalidThreshold();

        // Validate: no zero addresses, no duplicates
        for (uint256 i; i < len; i++) {
            if (_guardians[i] == address(0)) revert ZeroAddress();
            for (uint256 j = i + 1; j < len; j++) {
                if (_guardians[i] == _guardians[j]) revert DuplicateGuardian();
            }
        }

        guardian0 = _guardians[0];
        guardian1 = len > 1 ? _guardians[1] : address(0);
        guardian2 = len > 2 ? _guardians[2] : address(0);

        guardianCount = uint8(len);
        threshold = _threshold;
    }

    /*//////////////////////////////////////////////////////////////
                             EIP-1271
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Validates a multisig signature against the guardian set
     * @dev Expects `threshold` length-prefixed entries: `(uint8 id, uint16 sigLen, bytes[sigLen] sig)`.
     *      The `id` (0-2) identifies which guardian slot the signature is for.
     *      Each ID can only appear once — reuse is rejected to prevent threshold bypass.
     *      Signatures are validated via SignatureCheckerLib, supporting both EOA (ECDSA)
     *      and EIP-1271 contract guardians (e.g. nested Guardian multisigs).
     * @param hash The digest that was signed
     * @param signatures Concatenated length-prefixed entries from threshold-many guardians
     * @return bytes4 `0x1626ba7e` on success, `0xffffffff` on failure
     */
    function isValidSignature(bytes32 hash, bytes calldata signatures) external view returns (bytes4) {
        uint256 t = threshold;
        uint256 len = signatures.length;
        uint256 usedIds; // bitmask tracking which guardian IDs have been used
        uint256 offset;

        for (uint256 i; i < t; i++) {
            // Need at least HEADER_LENGTH bytes for (id, sigLen)
            if (offset + HEADER_LENGTH > len) return _EIP1271_FAIL;

            // First byte is the guardian ID
            uint8 id = uint8(signatures[offset]);

            // Next 2 bytes are the signature length (big-endian)
            uint256 sigLen = uint16(bytes2(signatures[offset + 1:offset + 3]));
            uint256 entryEnd = offset + HEADER_LENGTH + sigLen;
            if (entryEnd > len) return _EIP1271_FAIL;

            // ID must be within range of active guardians
            if (id >= guardianCount) return _EIP1271_FAIL;

            // Each ID can only be used once (bitmask check)
            uint256 idBit = 1 << id;
            if (usedIds & idBit != 0) return _EIP1271_FAIL;
            usedIds |= idBit;

            // Validate signature via SignatureCheckerLib. For EOAs this performs ECDSA
            // recovery; for contracts it calls isValidSignature (EIP-1271). Failures
            // return false rather than reverting, letting us return _EIP1271_FAIL per spec.
            if (
                !SignatureCheckerLib.isValidSignatureNowCalldata(
                    _guardianAt(id), hash, signatures[offset + HEADER_LENGTH:entryEnd]
                )
            ) {
                return _EIP1271_FAIL;
            }

            offset = entryEnd;
        }

        // Reject trailing data
        if (offset != len) return _EIP1271_FAIL;

        return _EIP1271_MAGIC;
    }

    /*//////////////////////////////////////////////////////////////
                           INTERNAL HELPERS
    //////////////////////////////////////////////////////////////*/

    /**
     * @dev Returns the guardian address at the given slot index (0-2)
     */
    function _guardianAt(uint8 id) internal view returns (address) {
        if (id == 0) return guardian0;
        if (id == 1) return guardian1;
        return guardian2;
    }
}
