use crate::config::SignatureInfo;
use crate::errors::{Error::NotKnownProvider, Result};
use crate::providers::sign_provider::{Ed25519Provider, SignatureProviderWrap};
#[cfg(feature = "stronghold")]
use crate::providers::sign_provider::StrongholdProvider;

pub fn new_signature_provider(config: &SignatureInfo) -> Result<SignatureProviderWrap> {
    if !check_key_type(config) {
        return Err(NotKnownProvider(config.private_key_info.key_type.0.clone()));
    }

    match config.private_key_info.key_type.0.as_str() {
        "ed25519" => Ok(SignatureProviderWrap::Ed25519(Ed25519Provider::new(
            config,
        )?)),
        #[cfg(feature = "stronghold")]
        "stronghold" => Ok(SignatureProviderWrap::Stronghold(StrongholdProvider::new(
            config,
        )?)),
        _ => Err(NotKnownProvider(config.private_key_info.key_type.0.clone())),
    }
}

// Check if the key type is supported
fn check_key_type(config: &SignatureInfo) -> bool {
    config.private_key_info.key_type.is_base_key_algorithm() ||
        config.private_key_info.key_type.0.eq("stronghold")
}
