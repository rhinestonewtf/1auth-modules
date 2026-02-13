// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.28;

import { EfficientHashLib } from "solady/utils/EfficientHashLib.sol";

/**
 * @title EIP712Lib
 * @notice EIP-712 typehash constants and gas-efficient struct hashing for the OneAuth validator.
 * @dev Uses Solady's EfficientHashLib instead of keccak256(abi.encode(...))
 *      for gas-efficient struct hashing via direct memory operations.
 */
library EIP712Lib {
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
    /// @dev replace: false = add new credential, true = in-place rotation of existing credential
    bytes32 internal constant RECOVER_PASSKEY_TYPEHASH = keccak256(
        "RecoverPasskey(address account,uint256 chainId,uint16 newKeyId,bytes32 newPubKeyX,bytes32 newPubKeyY,bool replace,uint256 nonce,uint48 expiry)"
    );

    /*//////////////////////////////////////////////////////////////
                         STRUCT HASH FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @dev Struct hash for RecoverPasskey(...)
    function recoverPasskeyHash(
        address account,
        uint256 chainId,
        uint16 keyId,
        bytes32 pubKeyX,
        bytes32 pubKeyY,
        bool replace,
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
            bytes32(uint256(replace ? 1 : 0)),
            bytes32(uint256(nonce)),
            bytes32(uint256(expiry))
        );
    }
}
