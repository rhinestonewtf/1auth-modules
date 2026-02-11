use crate::types::{EncodeError, ModuleType};

/// Base trait for all ERC-7579 modules.
pub trait IERC7579Module {
    /// The ERC-7579 module type (Validator, Executor, Hook, Fallback, StatelessValidator).
    fn module_type(&self) -> ModuleType;

    /// Human-readable module name (e.g., "WebAuthnValidator").
    fn name(&self) -> &str;

    /// Semantic version string (e.g., "2.0.0").
    fn version(&self) -> &str;
}

/// Trait for ERC-7579 validator modules that store credentials on-chain.
///
/// Maps to the Solidity interface:
/// - `onInstall(bytes)` / `onUninstall(bytes)`
/// - `validateUserOp(PackedUserOperation, bytes32)` (signature encoding)
pub trait IERC7579Validator: IERC7579Module {
    /// The input type for encoding `onInstall` calldata.
    type InstallData;

    /// The configuration type for encoding a stateful signature.
    type SignatureConfig;

    /// ABI-encode the `onInstall` calldata from structured input.
    fn encode_install(&self, data: &Self::InstallData) -> Result<Vec<u8>, EncodeError>;

    /// ABI-encode the `onUninstall` calldata.
    fn encode_uninstall(&self) -> Vec<u8>;

    /// Encode a stateful signature (credentials stored on-chain).
    fn encode_signature(&self, config: &Self::SignatureConfig, auth: &[u8]) -> Vec<u8>;
}

/// Trait for ERC-7579 stateless validators that accept credentials externally.
///
/// Maps to: `isValidSignatureWithData(address, bytes32, bytes, bytes)`
pub trait IERC7579StatelessValidator: IERC7579Validator {
    /// The configuration type for encoding stateless validator data.
    type StatelessConfig;

    /// Encode the external data blob for stateless signature verification.
    fn encode_stateless_data(&self, config: &Self::StatelessConfig) -> Vec<u8>;
}
