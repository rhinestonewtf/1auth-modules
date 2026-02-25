// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.28;

import { SignatureCheckerLib } from "solady/utils/SignatureCheckerLib.sol";

/// @title GuardianVerifierLib
/// @notice Shared guardian signature verification logic used by both OneAuthRecoveryBase
///         and OneAuthAppRecoveryBase.
library GuardianVerifierLib {
    /*//////////////////////////////////////////////////////////////
                                STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Guardian addresses and signing threshold
    /// @dev threshold=1: either guardian can authorize recovery alone
    ///      threshold=2: both guardians must sign
    ///      threshold=0: treated as 1 (default for zero-initialized storage)
    struct GuardianConfig {
        address userGuardian;
        address externalGuardian;
        uint8 threshold;
    }

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Thrown when the selected guardian type is not configured
    error GuardianNotConfigured();

    /// @notice Thrown when the guardian's signature over the recovery digest is invalid
    error InvalidGuardianSignature();

    /// @notice Thrown when the guardian type byte prefix is not 0x00 or 0x01
    error InvalidGuardianType();

    /// @notice Thrown when guardianSig is empty (no type byte)
    error EmptyGuardianSignature();

    /*//////////////////////////////////////////////////////////////
                           VERIFICATION FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Dispatches to single or dual guardian verification based on threshold
    /// @param gc Guardian configuration for the account
    /// @param digest The EIP-712 digest that guardians must sign
    /// @param guardianSig Packed guardian signature(s)
    /// @return guardian The address of the (first) guardian that verified
    function verifyGuardian(
        GuardianConfig storage gc,
        bytes32 digest,
        bytes calldata guardianSig
    )
        internal
        view
        returns (address guardian)
    {
        uint8 t = gc.threshold;
        if (t <= 1) {
            return verifySingleGuardian(gc, digest, guardianSig);
        } else {
            return verifyDualGuardian(gc, digest, guardianSig);
        }
    }

    /// @notice Single-guardian verification (threshold=1). Format: [type_byte][sig]
    /// @dev type_byte 0x00 = user guardian, 0x01 = external guardian
    function verifySingleGuardian(
        GuardianConfig storage gc,
        bytes32 digest,
        bytes calldata guardianSig
    )
        internal
        view
        returns (address guardian)
    {
        if (guardianSig.length == 0) revert EmptyGuardianSignature();

        uint8 guardianType = uint8(guardianSig[0]);
        bytes calldata sig = guardianSig[1:];

        if (guardianType == 0x00) {
            guardian = gc.userGuardian;
        } else if (guardianType == 0x01) {
            guardian = gc.externalGuardian;
        } else {
            revert InvalidGuardianType();
        }

        if (guardian == address(0)) revert GuardianNotConfigured();

        if (!SignatureCheckerLib.isValidSignatureNowCalldata(guardian, digest, sig)) {
            revert InvalidGuardianSignature();
        }
    }

    /// @notice Dual-guardian verification (threshold=2). Format: [user_sig_len:uint16][user_sig][external_sig]
    /// @dev Both guardians must sign; returns the user guardian address for event emission
    function verifyDualGuardian(
        GuardianConfig storage gc,
        bytes32 digest,
        bytes calldata guardianSig
    )
        internal
        view
        returns (address guardian)
    {
        if (guardianSig.length < 2) revert EmptyGuardianSignature();

        uint256 userSigEnd = 2 + uint256(uint16(bytes2(guardianSig[0:2])));
        if (guardianSig.length < userSigEnd) revert InvalidGuardianSignature();

        if (gc.userGuardian == address(0) || gc.externalGuardian == address(0)) {
            revert GuardianNotConfigured();
        }

        if (!SignatureCheckerLib.isValidSignatureNowCalldata(gc.userGuardian, digest, guardianSig[2:userSigEnd])) {
            revert InvalidGuardianSignature();
        }
        if (
            !SignatureCheckerLib.isValidSignatureNowCalldata(gc.externalGuardian, digest, guardianSig[userSigEnd:])
        ) {
            revert InvalidGuardianSignature();
        }

        guardian = gc.userGuardian;
    }
}
