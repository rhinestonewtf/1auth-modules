use encoding_core::{
    EncodeError, IERC7579Module, IERC7579StatelessValidator, IERC7579Validator, ModuleType,
};

/// Zero-sized struct representing the OneAuthValidator module.
/// Implements the ERC-7579 trait hierarchy, delegating to existing free functions.
pub struct OneAuthValidator;

impl IERC7579Module for OneAuthValidator {
    fn module_type(&self) -> ModuleType {
        ModuleType::Validator
    }

    fn name(&self) -> &str {
        "OneAuthValidator"
    }

    fn version(&self) -> &str {
        "1.0.0"
    }
}

impl IERC7579Validator for OneAuthValidator {
    type InstallData = crate::encode::InstallInput;
    type SignatureConfig = crate::signature::StatefulSignatureConfig;

    fn encode_install(&self, data: &Self::InstallData) -> Result<Vec<u8>, EncodeError> {
        crate::encode::encode_install(data)
            .map(|(_, bytes)| bytes)
            .map_err(|e| EncodeError::InvalidInput(e))
    }

    fn encode_uninstall(&self) -> Vec<u8> {
        crate::encode::encode_uninstall()
    }

    fn encode_signature(&self, config: &Self::SignatureConfig, auth: &[u8]) -> Vec<u8> {
        crate::signature::encode_stateful_signature(config, auth)
    }
}

impl IERC7579StatelessValidator for OneAuthValidator {
    type StatelessConfig = crate::signature::StatelessSignatureConfig;

    fn encode_stateless_data(&self, config: &Self::StatelessConfig) -> Vec<u8> {
        crate::signature::encode_stateless_data(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode::{CredentialInput, InstallInput};
    use crate::signature::{StatefulSignatureConfig, StatelessSignatureConfig};

    #[test]
    fn module_metadata() {
        let m = OneAuthValidator;
        assert_eq!(m.module_type(), ModuleType::Validator);
        assert_eq!(m.name(), "OneAuthValidator");
        assert_eq!(m.version(), "1.0.0");
    }

    #[test]
    fn trait_encode_install() {
        let m = OneAuthValidator;
        let input = InstallInput {
            key_ids: vec![0],
            credentials: vec![CredentialInput {
                pub_key_x:
                    "0x580a9af0569ad3905b26a703201b358aa0904236642ebe79b22a19d00d373763"
                        .to_string(),
                pub_key_y:
                    "0x7d46f725a5427ae45a9569259bf67e1e16b187d7b3ad1ed70138c4f0409677d1"
                        .to_string(),
            }],
            guardian: None,
            guardian_timelock: None,
        };
        let bytes = m.encode_install(&input).unwrap();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn trait_encode_uninstall() {
        let m = OneAuthValidator;
        let bytes = m.encode_uninstall();
        assert!(bytes.is_empty());
    }

    #[test]
    fn trait_encode_signature() {
        let m = OneAuthValidator;
        let config = StatefulSignatureConfig {
            key_id: 0,
            merkle: None,
        };
        let auth = vec![0xAA; 64];
        let sig = m.encode_signature(&config, &auth);
        assert_eq!(sig[0], 0); // proofLength = 0
        assert_eq!(&sig[3..], &auth[..]);
    }

    #[test]
    fn trait_encode_stateless_data() {
        let m = OneAuthValidator;
        let config = StatelessSignatureConfig {
            pub_key_x: [0x11; 32],
            pub_key_y: [0x22; 32],
            merkle: None,
        };
        let data = m.encode_stateless_data(&config);
        assert_eq!(data[0], 0);
        assert_eq!(data.len(), 65);
    }
}
