pub use aws_mls_core::identity::*;

#[cfg(any(test, feature = "benchmark"))]
pub mod test_utils {
    use async_trait::async_trait;
    use aws_mls_core::{
        crypto::{CipherSuite, CipherSuiteProvider, SignatureSecretKey},
        group::{RosterEntry, RosterUpdate},
        identity::{Credential, CredentialType, IdentityProvider, SigningIdentity},
        time::MlsTime,
    };
    use thiserror::Error;

    use crate::provider::{
        crypto::test_utils::test_cipher_suite_provider,
        identity::{BasicCredentialError, BasicIdentityProvider},
    };

    use super::BasicCredential;

    #[derive(Debug, Error)]
    #[error("expected basic or custom credential type 42 found: {0:?}")]
    pub struct BasicWithCustomProviderError(CredentialType);

    impl From<BasicCredentialError> for BasicWithCustomProviderError {
        fn from(value: BasicCredentialError) -> Self {
            BasicWithCustomProviderError(value.credential_type())
        }
    }

    #[derive(Debug, Clone)]
    pub struct BasicWithCustomProvider {
        pub(crate) basic: BasicIdentityProvider,
        pub(crate) allow_any_custom: bool,
    }

    impl BasicWithCustomProvider {
        pub const CUSTOM_CREDENTIAL_TYPE: u16 = 42;

        pub fn new(basic: BasicIdentityProvider) -> BasicWithCustomProvider {
            BasicWithCustomProvider {
                basic,
                allow_any_custom: false,
            }
        }

        async fn resolve_custom_identity(
            &self,
            signing_id: &SigningIdentity,
        ) -> Result<Vec<u8>, BasicWithCustomProviderError> {
            self.basic.identity(signing_id).await.or_else(|_| {
                signing_id
                    .credential
                    .as_custom()
                    .map(|c| {
                        if c.credential_type() == CredentialType::from(Self::CUSTOM_CREDENTIAL_TYPE)
                            || self.allow_any_custom
                        {
                            Ok(c.data().to_vec())
                        } else {
                            Err(BasicWithCustomProviderError(c.credential_type()))
                        }
                    })
                    .transpose()?
                    .ok_or_else(|| {
                        BasicWithCustomProviderError(signing_id.credential.credential_type())
                    })
            })
        }
    }

    #[async_trait]
    impl IdentityProvider for BasicWithCustomProvider {
        type Error = BasicWithCustomProviderError;
        type IdentityEvent = ();

        async fn validate(
            &self,
            _signing_identity: &SigningIdentity,
            _timestamp: Option<MlsTime>,
        ) -> Result<(), Self::Error> {
            //TODO: Is it actually beneficial to check the key, or does that already happen elsewhere before
            //this point?
            Ok(())
        }

        async fn identity(&self, signing_id: &SigningIdentity) -> Result<Vec<u8>, Self::Error> {
            self.resolve_custom_identity(signing_id).await
        }

        async fn valid_successor(
            &self,
            predecessor: &SigningIdentity,
            successor: &SigningIdentity,
        ) -> Result<bool, Self::Error> {
            let predecessor = self.resolve_custom_identity(predecessor).await?;
            let successor = self.resolve_custom_identity(successor).await?;

            Ok(predecessor == successor)
        }

        fn supported_types(&self) -> Vec<CredentialType> {
            vec![
                BasicCredential::credential_type(),
                CredentialType::new(Self::CUSTOM_CREDENTIAL_TYPE),
            ]
        }

        async fn identity_events<T: RosterEntry>(
            &self,
            _update: &RosterUpdate<T>,
            _prior_roster: Vec<T>,
        ) -> Result<Vec<Self::IdentityEvent>, Self::Error> {
            Ok(vec![])
        }
    }

    pub fn get_test_signing_identity(
        cipher_suite: CipherSuite,
        identity: Vec<u8>,
    ) -> (SigningIdentity, SignatureSecretKey) {
        let provider = test_cipher_suite_provider(cipher_suite);
        let (secret_key, public_key) = provider.signature_key_generate().unwrap();

        let basic = get_test_basic_credential(identity);

        (SigningIdentity::new(basic, public_key), secret_key)
    }

    pub fn get_test_basic_credential(identity: Vec<u8>) -> Credential {
        BasicCredential::new(identity).into_credential()
    }
}
