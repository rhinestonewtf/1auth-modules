use std::fmt;

/// ERC-7579 module type identifiers.
/// Values match the on-chain constants from the ERC-7579 spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleType {
    Validator = 1,
    Executor = 2,
    Fallback = 3,
    Hook = 4,
    StatelessValidator = 7,
}

/// Errors that can occur during module encoding operations.
#[derive(Debug)]
pub enum EncodeError {
    InvalidInput(String),
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncodeError::InvalidInput(msg) => write!(f, "invalid input: {msg}"),
        }
    }
}

impl std::error::Error for EncodeError {}
