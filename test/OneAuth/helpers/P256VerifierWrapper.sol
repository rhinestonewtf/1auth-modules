// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { FCL_ecdsa } from "FreshCryptoLib/FCL_ecdsa.sol";

/// @title P256VerifierWrapper
/// @notice Deploys at the Solady P256 VERIFIER address to enable P256 verification in tests.
///         Accepts raw calldata: (bytes32 hash, uint256 r, uint256 s, uint256 x, uint256 y)
///         Returns uint256(1) on valid signature, uint256(0) on invalid.
contract P256VerifierWrapper {
    fallback(bytes calldata input) external returns (bytes memory) {
        if (input.length != 160) return abi.encode(uint256(0));

        bytes32 hash = bytes32(input[0:32]);
        uint256 r = uint256(bytes32(input[32:64]));
        uint256 s = uint256(bytes32(input[64:96]));
        uint256 x = uint256(bytes32(input[96:128]));
        uint256 y = uint256(bytes32(input[128:160]));

        bool valid = FCL_ecdsa.ecdsa_verify(hash, r, s, x, y);
        return abi.encode(valid ? uint256(1) : uint256(0));
    }
}
