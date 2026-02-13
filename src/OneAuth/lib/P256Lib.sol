// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.28;

import { WebAuthn } from "solady/utils/WebAuthn.sol";

/**
 * @title P256Lib
 * @notice P-256 (secp256r1) curve validation and WebAuthn auth parsing utilities
 * @dev Provides on-curve validation for P-256 public keys and packed WebAuthnAuth
 *      parsing used by the OneAuth validator modules.
 */
library P256Lib {
    /*//////////////////////////////////////////////////////////////
                            CURVE PARAMETERS
    //////////////////////////////////////////////////////////////*/

    /// @dev P-256 field prime (modulus)
    uint256 internal constant P =
        0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF;

    /// @dev P-256 curve parameter a (coefficient of x in the Weierstrass equation)
    uint256 internal constant A =
        0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC;

    /// @dev P-256 curve parameter b (constant term in the Weierstrass equation)
    uint256 internal constant B =
        0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B;

    /*//////////////////////////////////////////////////////////////
                              VALIDATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Validate that (x, y) is a point on the P-256 (secp256r1) curve
     * @dev Verifies the Weierstrass equation: y^2 = x^3 + ax + b (mod p)
     *      where a and b are the P-256 curve parameters. Also rejects the point at infinity
     *      (zero coordinates) and values >= the field prime p.
     * @param x X coordinate of the candidate point
     * @param y Y coordinate of the candidate point
     * @return True if (x, y) lies on the P-256 curve
     */
    function isOnCurve(uint256 x, uint256 y) internal pure returns (bool) {
        // Reject zero coordinates (point at infinity) and values >= field prime
        if (x == 0 || y == 0 || x >= P || y >= P) return false;

        // LHS: y^2 mod p
        uint256 lhs = mulmod(y, y, P);

        // RHS: x^3 + ax + b mod p
        // Computed as: ((x * x mod p) * x mod p) + (x * a mod p) + b, all mod p
        uint256 rhs = addmod(
            addmod(mulmod(mulmod(x, x, P), x, P), mulmod(x, A, P), P),
            B,
            P
        );
        return lhs == rhs;
    }

    /*//////////////////////////////////////////////////////////////
                        WEBAUTHN AUTH CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @dev Packed WebAuthnAuth header size: r (32) + s (32) + challengeIndex (2) + typeIndex (2) + adLen (2) = 70 bytes
    uint256 internal constant WEBAUTHN_AUTH_HEADER_SIZE = 70;

    /*//////////////////////////////////////////////////////////////
                          WEBAUTHN AUTH PARSING
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Parse tightly packed WebAuthnAuth from calldata
     * @dev Returns (auth, ok) tuple -- returns false instead of reverting when the input is
     *      malformed. This is required because callers in the validation path must return false
     *      (not revert) on invalid data per ERC-4337 requirements.
     *
     *      Packed format (avoids ABI encoding overhead for gas savings):
     *        [0:32]              r (uint256) -- ECDSA r component
     *        [32:64]             s (uint256) -- ECDSA s component
     *        [64:66]             challengeIndex (uint16) -- offset of challenge in clientDataJSON
     *        [66:68]             typeIndex (uint16) -- offset of "type" field in clientDataJSON
     *        [68:70]             authenticatorDataLen (uint16) -- length of authenticatorData
     *        [70:70+adLen]       authenticatorData (bytes) -- raw authenticator data
     *        [70+adLen:]         clientDataJSON (bytes) -- remaining bytes are the client data
     *
     *      WebAuthn.WebAuthnAuth memory layout (used by the assembly blocks):
     *        0x00: authenticatorData (bytes pointer)
     *        0x20: clientDataJSON (bytes pointer)
     *        0x40: challengeIndex (uint256)
     *        0x60: typeIndex (uint256)
     *        0x80: r (uint256)
     *        0xa0: s (uint256)
     * @param raw The tightly packed WebAuthnAuth calldata
     * @return auth The parsed WebAuthnAuth struct
     * @return ok True if parsing succeeded, false if the input was too short
     */
    function parseWebAuthnAuth(bytes calldata raw)
        internal
        pure
        returns (WebAuthn.WebAuthnAuth memory auth, bool ok)
    {
        // Minimum header: r (32) + s (32) + challengeIndex (2) + typeIndex (2) + adLen (2)
        if (raw.length < WEBAUTHN_AUTH_HEADER_SIZE) return (auth, false);

        uint256 adLen;
        /// @solidity memory-safe-assembly
        assembly {
            let off := raw.offset

            // First assembly block: reads scalar fields directly from calldata into the
            // auth struct in memory. Uses calldataload for raw 32-byte reads of r and s.
            // For the three 2-byte fields (challengeIndex, typeIndex, adLen), a single
            // calldataload at offset 0x40 reads 32 bytes containing all three packed at the
            // high end. Each is extracted by shifting right to position it and masking to 16 bits.
            mstore(add(auth, 0x80), calldataload(off))           // r
            mstore(add(auth, 0xa0), calldataload(add(off, 0x20))) // s

            // Single calldataload reads 32 bytes starting at the challengeIndex position.
            // The three uint16 fields are packed in the high bytes of this 32-byte word:
            //   bits [240:255] = challengeIndex (shift right 240, implicit 16-bit value)
            //   bits [224:239] = typeIndex (shift right 224, mask to 16 bits)
            //   bits [208:223] = adLen (shift right 208, mask to 16 bits)
            let packed := calldataload(add(off, 0x40))
            mstore(add(auth, 0x40), shr(240, packed))                // challengeIndex
            mstore(add(auth, 0x60), and(shr(224, packed), 0xffff))   // typeIndex
            adLen := and(shr(208, packed), 0xffff)                   // authenticatorDataLen
        }

        // Ensure calldata is long enough to contain the authenticatorData bytes
        if (raw.length < WEBAUTHN_AUTH_HEADER_SIZE + adLen) return (auth, false);

        /// @solidity memory-safe-assembly
        assembly {
            // Second assembly block: allocates memory for the two dynamic byte arrays
            // (authenticatorData and clientDataJSON) and sets the struct pointers.

            let off := raw.offset
            // clientDataJSON is everything after the fixed header and authenticatorData
            let cdLen := sub(raw.length, add(WEBAUTHN_AUTH_HEADER_SIZE, adLen))
            let fmp := mload(0x40) // current free memory pointer

            // Allocate authenticatorData: write length prefix then copy bytes from calldata
            mstore(fmp, adLen)
            calldatacopy(add(fmp, 0x20), add(off, WEBAUTHN_AUTH_HEADER_SIZE), adLen)
            mstore(auth, fmp) // auth.authenticatorData = pointer to this bytes array

            // Advance past authenticatorData allocation with 32-byte alignment
            // adAlloc = 32 (length prefix) + ceil(adLen / 32) * 32
            let adAlloc := add(0x20, and(add(adLen, 0x1f), not(0x1f)))
            let cdPtr := add(fmp, adAlloc)

            // Allocate clientDataJSON: write length prefix then copy remaining bytes
            mstore(cdPtr, cdLen)
            calldatacopy(add(cdPtr, 0x20), add(off, add(WEBAUTHN_AUTH_HEADER_SIZE, adLen)), cdLen)
            mstore(add(auth, 0x20), cdPtr) // auth.clientDataJSON = pointer to this bytes array

            // Update free memory pointer past both allocations with 32-byte alignment
            mstore(0x40, add(cdPtr, add(0x20, and(add(cdLen, 0x1f), not(0x1f)))))
        }

        ok = true;
    }
}
