use crate::config::SignatureInfo;
use crate::errors::{Error, Result};
use alvarium_annotator::SignProvider;
use crypto::signatures::ed25519::Signature;
use futures::executor::block_on;
use iota_sdk::client::secret::SecretManager;
use iota_stronghold::Location;
use streams::id::did::{StrongholdSecretManager, STREAMS_VAULT};

pub struct StrongholdProvider {
    config: SignatureInfo,
}

impl StrongholdProvider {
    pub fn new(config: &SignatureInfo) -> Result<Self> {
        Ok(StrongholdProvider {
            config: config.clone(),
        })
    }

    fn get_adapter(&self) -> Result<SecretManager> {
        println!("GetAdapter: {}, {}", self.config.private_key_info.stronghold_password, self.config.private_key_info.path);
        let stronghold_adapter = StrongholdSecretManager::builder()
            .password(self.config.private_key_info.stronghold_password.clone())
            .build(self.config.private_key_info.path.clone())?;
        Ok(SecretManager::Stronghold(stronghold_adapter))
    }
}

impl SignProvider for StrongholdProvider {
    type Error = crate::errors::Error;

    fn sign(&self, content: &[u8]) -> Result<String> {
        // Sign using the key stored in Stronghold
        if let SecretManager::Stronghold(adapter) = self.get_adapter()? {
            println!("StrongholdProvider.sign() adapter: {}", self.config.private_key_info.signature_key_path.clone());
            let location = Location::generic(STREAMS_VAULT, self.config.private_key_info.signature_key_path.clone());
            let signature = block_on(adapter.ed25519_sign(location, content)).map_err(
                |err| {
                    println!("StrongholdProvider.sign() error: {}", err);
                    Error::StrongholdAdapterError
                },
            )?;
            return Ok(hex::encode(signature.to_bytes()))
        }
        Err(Error::StrongholdAdapterError)
    }

    fn verify(&self, content: &[u8], signed: &[u8]) -> Result<bool> {
        let sig = get_signature(signed)?;
        // Fetch public key from Stronghold and verify the signature
        if let SecretManager::Stronghold(adapter) = self.get_adapter()? {
            let location = Location::generic(STREAMS_VAULT, self.config.public_key_info.signature_key_path.clone());
            let pub_key = block_on(adapter.ed25519_public_key(location))?;
            return Ok(pub_key.verify(&sig, content));
        }
        Err(Error::StrongholdAdapterError)
    }
}

pub(crate) fn get_signature(signature: &[u8]) -> Result<Signature> {
    match <[u8; Signature::LENGTH]>::try_from(signature) {
        Ok(resized) => Ok(Signature::from_bytes(resized)),
        Err(_) => Err(Error::IncorrectKeySize(signature.len(), Signature::LENGTH)),
    }
}