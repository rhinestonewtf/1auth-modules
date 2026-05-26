// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.28;

import { Ownable } from "solady/auth/Ownable.sol";
import { EIP712 } from "solady/utils/EIP712.sol";
import { EfficientHashLib } from "solady/utils/EfficientHashLib.sol";
import { SignatureCheckerLib } from "solady/utils/SignatureCheckerLib.sol";

/**
 * @title RecoverySigner
 * @notice EIP-1271 signer wrapper whose controlling key (the "owner") can be rotated
 *         via an EIP-712 signed authorization from the current owner.
 * @dev Intended to be used as a guardian address on OneAuthValidator / OneAuthAppValidator.
 *      Because the guardian slot is a `bytes32`-stable address but the underlying signing
 *      key may need to rotate (e.g. lost device, key compromise), this contract decouples
 *      the on-chain identity (this contract's address) from the off-chain signing key
 *      (the EOA / EIP-1271 contract stored as `owner`).
 *
 *      Two ways to rotate the owner:
 *      1. {transferOwnership} — direct call from the current owner (Solady Ownable).
 *      2. {rotateOwnerWithSig} — permissionless submission of an EIP-712 signed
 *         authorization from the current owner, enabling meta-transaction-style
 *         rotation without the owner needing to pay gas.
 *
 *      Replay protection: each rotation consumes a nonce, and the signed message
 *      carries an `expiry` (uint48 unix timestamp) past which it cannot be used.
 *
 *      EIP-1271: forwards `isValidSignature` to the current owner via
 *      SignatureCheckerLib, transparently supporting both EOA (ECDSA) and contract
 *      (nested EIP-1271) owners.
 */
contract RecoverySigner is Ownable, EIP712 {
    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @dev EIP-1271 magic value returned on successful signature validation
    bytes4 internal constant _EIP1271_MAGIC = 0x1626ba7e;

    /// @dev Value returned when signature validation fails
    bytes4 internal constant _EIP1271_FAIL = 0xffffffff;

    /**
     * @dev EIP-712 typehash for owner rotation. `chainId == 0` makes the
     *      authorization valid on any chain; a non-zero `chainId` pins it to that chain.
     */
    bytes32 internal constant ROTATE_OWNER_TYPEHASH = keccak256(
        "RotateOwner(address newOwner,uint256 chainId,uint256 nonce,uint48 expiry)"
    );

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Thrown when the rotation authorization has expired
    error RotationExpired();

    /// @notice Thrown when the supplied nonce has already been consumed
    error NonceAlreadyUsed();

    /// @notice Thrown when chainId is non-zero and does not match block.chainid
    error InvalidChainId();

    /// @notice Thrown when the rotation signature is not from the current owner
    error InvalidSignature();

    /// @notice Thrown when attempting to rotate ownership to the zero address
    error ZeroAddress();

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Emitted when ownership is rotated via {rotateOwnerWithSig}
    /// @dev Solady's {Ownable} emits its own OwnershipTransferred event in addition to this
    event OwnerRotatedWithSig(address indexed previousOwner, address indexed newOwner, uint256 nonce);

    /*//////////////////////////////////////////////////////////////
                                STATE
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Unordered nonce tracking for owner rotations.
     * @dev Each rotation authorization carries a caller-chosen nonce; once consumed,
     *      that nonce can never be reused. Unordered (rather than sequential) nonces
     *      let the owner pre-sign multiple independent rotation authorizations that
     *      can be submitted in any order.
     */
    mapping(uint256 nonce => bool used) public nonceUsed;

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @param initialOwner The initial signing key. Must be non-zero.
    constructor(address initialOwner) {
        if (initialOwner == address(0)) revert ZeroAddress();
        _initializeOwner(initialOwner);
    }

    /*//////////////////////////////////////////////////////////////
                          EIP-712 DOMAIN
    //////////////////////////////////////////////////////////////*/

    function _domainNameAndVersion()
        internal
        pure
        override
        returns (string memory name, string memory version)
    {
        name = "RecoverySigner";
        version = "1.0.0";
    }

    /*//////////////////////////////////////////////////////////////
                              EIP-1271
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Validates `signature` against `hash` using the current owner as the signer.
     * @dev Supports both EOA owners (ECDSA) and contract owners (nested EIP-1271)
     *      via {SignatureCheckerLib}. Returns the failure sentinel rather than reverting
     *      on invalid input, per the EIP-1271 spec.
     */
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        if (SignatureCheckerLib.isValidSignatureNowCalldata(owner(), hash, signature)) {
            return _EIP1271_MAGIC;
        }
        return _EIP1271_FAIL;
    }

    /*//////////////////////////////////////////////////////////////
                           OWNER ROTATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Returns the EIP-712 digest for a {rotateOwnerWithSig} authorization.
     * @dev Off-chain signers can use this to compute the digest they need to sign,
     *      or callers can use it to verify a digest matches their parameters.
     */
    function rotationDigest(
        address newOwner,
        uint256 chainId,
        uint256 nonce,
        uint48 expiry
    )
        public
        view
        returns (bytes32)
    {
        bytes32 structHash = EfficientHashLib.hash(
            ROTATE_OWNER_TYPEHASH,
            bytes32(uint256(uint160(newOwner))),
            bytes32(chainId),
            bytes32(nonce),
            bytes32(uint256(expiry))
        );
        return _hashTypedData(structHash);
    }

    /**
     * @notice Rotate the owner using an EIP-712 signature from the current owner.
     * @dev Permissionless: anyone may submit the authorization, paying the gas. This
     *      enables meta-transaction-style rotation flows where the cold/lost-device
     *      owner's signature is relayed by a third party.
     *
     *      Replay protection:
     *      - `nonce` is unordered: any unused value works, and is marked consumed on success.
     *      - `expiry` is a uint48 unix timestamp; the call reverts if `block.timestamp` is past it.
     *      - `chainId == 0` means valid on any chain; non-zero pins to that chain.
     *
     *      The signature is verified against the *current* owner via SignatureCheckerLib,
     *      so contract owners (EIP-1271) can authorize rotations too.
     *
     * @param newOwner The address to transfer ownership to. Must be non-zero.
     * @param chainId The chain this authorization is valid on (0 = any chain).
     * @param nonce Any value not previously consumed; marked used on success.
     * @param expiry Unix timestamp (uint48) past which this authorization is invalid.
     * @param signature Signature from the current owner over the EIP-712 digest.
     */
    function rotateOwnerWithSig(
        address newOwner,
        uint256 chainId,
        uint256 nonce,
        uint48 expiry,
        bytes calldata signature
    )
        external
    {
        if (newOwner == address(0)) revert ZeroAddress();
        if (block.timestamp > expiry) revert RotationExpired();
        if (chainId != 0 && chainId != block.chainid) revert InvalidChainId();
        if (nonceUsed[nonce]) revert NonceAlreadyUsed();

        bytes32 digest = rotationDigest(newOwner, chainId, nonce, expiry);

        address currentOwner = owner();
        if (!SignatureCheckerLib.isValidSignatureNowCalldata(currentOwner, digest, signature)) {
            revert InvalidSignature();
        }

        // Mark nonce consumed before the ownership transfer so any reentrant call
        // observes the post-rotation state — defense in depth even though _setOwner
        // does not call out.
        nonceUsed[nonce] = true;

        _setOwner(newOwner);

        emit OwnerRotatedWithSig(currentOwner, newOwner, nonce);
    }
}
