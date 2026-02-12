// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.28;

import { EfficientHashLib } from "solady/utils/EfficientHashLib.sol";

/// @title EIP712Lib
/// @notice Centralized EIP-712 typehash constants and gas-efficient struct hashing
///         for the WebAuthn validator module family.
/// @dev Three "sub-envelopes" are defined, each corresponding to a different signing context:
///
///      1. PasskeyDigest — chain-specific single-operation signing.
///         Used with `_hashTypedData` (includes chainId in EIP-712 domain).
///
///      2. PasskeyMultichain — chain-agnostic merkle batch signing.
///         Used with `_hashTypedDataSansChainId` (omits chainId from domain).
///
///      3. RecoverPasskey — chain-agnostic recovery with struct-level chainId.
///         Used with `_hashTypedDataSansChainId`; embeds chainId in the struct
///         so chainId=0 means valid on any chain.
///
///      All hash functions use Solady's EfficientHashLib instead of keccak256(abi.encode(...))
///      for gas-efficient struct hashing via direct memory operations.
library EIP712Lib {
    using EfficientHashLib for bytes32;

    /*//////////////////////////////////////////////////////////////
                             TYPEHASHES
    //////////////////////////////////////////////////////////////*/

    /// @dev EIP-712 typehash for single-operation (chain-specific) passkey signing
    bytes32 internal constant PASSKEY_DIGEST_TYPEHASH =
        keccak256("PasskeyDigest(bytes32 digest)");

    /// @dev EIP-712 typehash for merkle batch (chain-agnostic) passkey signing
    bytes32 internal constant PASSKEY_MULTICHAIN_TYPEHASH =
        keccak256("PasskeyMultichain(bytes32 root)");

    /// @dev EIP-712 typehash for recovery operations
    bytes32 internal constant RECOVER_PASSKEY_TYPEHASH = keccak256(
        "RecoverPasskey(address account,uint256 chainId,uint16 newKeyId,bytes32 newPubKeyX,bytes32 newPubKeyY,uint256 nonce,uint48 expiry)"
    );

    /*//////////////////////////////////////////////////////////////
                         STRUCT HASH FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @dev Struct hash for PasskeyDigest(bytes32 digest)
    function passkeyDigestHash(bytes32 digest) internal pure returns (bytes32) {
        return PASSKEY_DIGEST_TYPEHASH.hash(digest);
    }

    /// @dev Struct hash for PasskeyMultichain(bytes32 root)
    function passkeyMultichainHash(bytes32 root) internal pure returns (bytes32) {
        return PASSKEY_MULTICHAIN_TYPEHASH.hash(root);
    }

    /// @dev Struct hash for RecoverPasskey(...)
    function recoverPasskeyHash(
        address account,
        uint256 chainId,
        uint16 keyId,
        bytes32 pubKeyX,
        bytes32 pubKeyY,
        uint256 nonce,
        uint48 expiry
    )
        internal
        pure
        returns (bytes32)
    {
        return EfficientHashLib.hash(
            RECOVER_PASSKEY_TYPEHASH,
            bytes32(uint256(uint160(account))),
            bytes32(chainId),
            bytes32(uint256(keyId)),
            pubKeyX,
            pubKeyY,
            bytes32(uint256(nonce)),
            bytes32(uint256(expiry))
        );
    }
}
