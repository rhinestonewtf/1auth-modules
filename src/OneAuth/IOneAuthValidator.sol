// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.28;

/**
 * @title IOneAuthValidator
 * @notice Events and errors for the OneAuthValidator module
 */
interface IOneAuthValidator {
    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Emitted when the module is installed for a smart account
    event ModuleInitialized(address indexed account);
    /// @notice Emitted when the module is uninstalled, after all credentials and guardian are cleared
    event ModuleUninitialized(address indexed account);
    /// @notice Emitted when a new passkey credential is registered for an account
    event CredentialAdded(address indexed account, uint16 indexed keyId, bytes32 pubKeyX, bytes32 pubKeyY);
    /// @notice Emitted when a passkey credential is removed from an account
    event CredentialRemoved(address indexed account, uint16 indexed keyId);

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Thrown when signature calldata is malformed or too short to parse
    error InvalidSignatureData();
    /// @notice Thrown when the provided merkle proof does not verify against the merkle root
    error InvalidMerkleProof();
    /// @notice Thrown when proofLength exceeds MAX_MERKLE_DEPTH (DoS prevention)
    error ProofTooLong();
    /// @notice Thrown when a public key is not on the P-256 curve or has zero coordinates
    error InvalidPublicKey();
    /// @notice Thrown when attempting to remove a credential that does not exist
    error CredentialNotFound(uint16 keyId);
    /// @notice Thrown when attempting to remove the last remaining credential (liveness guarantee)
    error CannotRemoveLastCredential();
    /// @notice Thrown when adding a credential with a keyId that already exists
    error KeyIdAlreadyExists(uint16 keyId);
    /// @notice Thrown when the account already has MAX_CREDENTIALS registered
    error TooManyCredentials();

    // NOTE: NotInitialized(address) is also used by this module but is inherited from IERC7579Module
}
