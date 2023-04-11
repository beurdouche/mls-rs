use alloc::boxed::Box;
use thiserror::Error;

#[cfg(feature = "std")]
use std::error::Error;

#[cfg(not(feature = "std"))]
use core::error::Error;

use aws_mls_core::{crypto::CipherSuiteProvider, extension::ExtensionList, group::Capabilities};

use crate::{
    group::{GroupInfo, NewMemberInfo},
    key_package::KeyPackage,
    tree_kem::leaf_node::{LeafNode, LeafNodeError},
};

#[derive(Debug, Error)]
pub enum GreaseError {
    #[error(transparent)]
    RandomGeneratorError(Box<dyn Error + Send + Sync + 'static>),
}

impl LeafNode {
    pub fn ungreased_capabilities(&self) -> Capabilities {
        let mut capabilitites = self.capabilities.clone();
        grease_functions::ungrease(&mut capabilitites.cipher_suites);
        grease_functions::ungrease(&mut capabilitites.extensions);
        grease_functions::ungrease(&mut capabilitites.proposals);
        grease_functions::ungrease(&mut capabilitites.credentials);
        capabilitites
    }

    pub fn ungreased_extensions(&self) -> ExtensionList {
        let mut extensions = self.extensions.clone();
        grease_functions::ungrease_extensions(&mut extensions);
        extensions
    }

    pub fn grease<P: CipherSuiteProvider>(&mut self, cs: &P) -> Result<(), LeafNodeError> {
        grease_functions::grease(&mut self.capabilities.cipher_suites, cs)?;
        grease_functions::grease(&mut self.capabilities.proposals, cs)?;
        grease_functions::grease(&mut self.capabilities.credentials, cs)?;

        let mut new_extensions = grease_functions::grease_extensions(&mut self.extensions, cs)?;
        self.capabilities.extensions.append(&mut new_extensions);

        Ok(())
    }
}

impl KeyPackage {
    pub fn grease<P: CipherSuiteProvider>(&mut self, cs: &P) -> Result<(), GreaseError> {
        grease_functions::grease_extensions(&mut self.extensions, cs).map(|_| ())
    }

    pub fn ungreased_extensions(&self) -> ExtensionList {
        let mut extensions = self.extensions.clone();
        grease_functions::ungrease_extensions(&mut extensions);
        extensions
    }
}

impl GroupInfo {
    pub fn grease<P: CipherSuiteProvider>(&mut self, cs: &P) -> Result<(), GreaseError> {
        grease_functions::grease_extensions(&mut self.extensions, cs).map(|_| ())
    }
}

impl NewMemberInfo {
    pub fn ungrease(&mut self) {
        grease_functions::ungrease_extensions(&mut self.group_info_extensions)
    }
}

#[cfg(feature = "grease")]
mod grease_functions {
    use core::ops::Deref;

    use aws_mls_core::{
        crypto::CipherSuiteProvider,
        extension::{Extension, ExtensionList, ExtensionType},
    };

    use super::GreaseError;

    pub const GREASE_VALUES: &[u16] = &[
        0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA,
        0xBABA, 0xCACA, 0xDADA, 0xEAEA,
    ];

    pub fn grease<T: From<u16>, P: CipherSuiteProvider>(
        array: &mut Vec<T>,
        cs: &P,
    ) -> Result<(), GreaseError> {
        array.push(random_grease_value(cs)?.into());
        Ok(())
    }

    pub fn grease_extensions<P: CipherSuiteProvider>(
        extensions: &mut ExtensionList,
        cs: &P,
    ) -> Result<Vec<ExtensionType>, GreaseError> {
        let grease_value = random_grease_value(cs)?;
        extensions.set(Extension::new(grease_value.into(), vec![]));
        Ok(vec![grease_value.into()])
    }

    fn random_grease_value<P: CipherSuiteProvider>(cs: &P) -> Result<u16, GreaseError> {
        let index = cs
            .random_bytes_vec(1)
            .map_err(|e| GreaseError::RandomGeneratorError(e.into()))?[0];

        Ok(GREASE_VALUES[index as usize % GREASE_VALUES.len()])
    }

    pub fn ungrease<T: Deref<Target = u16>>(array: &mut Vec<T>) {
        array.retain(|x| !GREASE_VALUES.contains(&**x));
    }

    pub fn ungrease_extensions(extensions: &mut ExtensionList) {
        for e in GREASE_VALUES {
            extensions.remove((*e).into())
        }
    }
}

#[cfg(not(feature = "grease"))]
mod grease_functions {
    use core::ops::Deref;

    use alloc::vec::Vec;

    use aws_mls_core::{
        crypto::CipherSuiteProvider,
        extension::{ExtensionList, ExtensionType},
    };

    use super::GreaseError;

    pub fn grease<T: From<u16>, P: CipherSuiteProvider>(
        _array: &mut [T],
        _cs: &P,
    ) -> Result<(), GreaseError> {
        Ok(())
    }

    pub fn grease_extensions<P: CipherSuiteProvider>(
        _extensions: &mut ExtensionList,
        _cs: &P,
    ) -> Result<Vec<ExtensionType>, GreaseError> {
        Ok(Vec::new())
    }

    pub fn ungrease<T: Deref<Target = u16>>(_array: &mut [T]) {}

    pub fn ungrease_extensions(_extensions: &mut ExtensionList) {}
}

#[cfg(all(test, feature = "grease"))]
mod tests {
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[cfg(not(target_arch = "wasm32"))]
    use futures_test::test;

    use std::ops::Deref;

    use aws_mls_core::extension::ExtensionList;

    use crate::{
        client::test_utils::{test_client_with_key_pkg, TEST_CIPHER_SUITE, TEST_PROTOCOL_VERSION},
        group::test_utils::test_group,
    };

    use super::grease_functions::GREASE_VALUES;

    #[test]
    async fn key_package_is_greased() {
        let key_pkg = test_client_with_key_pkg(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "alice")
            .await
            .1
            .into_key_package()
            .unwrap();

        assert!(is_ext_greased(&key_pkg.extensions));
        assert!(is_ext_greased(&key_pkg.leaf_node.extensions));
        assert!(is_greased(&key_pkg.leaf_node.capabilities.cipher_suites));
        assert!(is_greased(&key_pkg.leaf_node.capabilities.extensions));
        assert!(is_greased(&key_pkg.leaf_node.capabilities.proposals));
        assert!(is_greased(&key_pkg.leaf_node.capabilities.credentials));

        assert!(!is_greased(
            &key_pkg.leaf_node.capabilities.protocol_versions
        ));
    }

    #[test]
    async fn group_info_is_greased() {
        let group_info = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE)
            .await
            .group
            .group_info_message(true)
            .await
            .unwrap()
            .into_group_info()
            .unwrap();

        assert!(is_ext_greased(&group_info.extensions));
    }

    #[test]
    async fn public_api_is_not_greased() {
        let member = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE)
            .await
            .group
            .roster()[0]
            .clone();

        assert!(!is_ext_greased(member.extensions()));
        assert!(!is_greased(member.capabilities().protocol_versions()));
        assert!(!is_greased(member.capabilities().cipher_suites()));
        assert!(!is_greased(member.capabilities().extensions()));
        assert!(!is_greased(member.capabilities().proposals()));
        assert!(!is_greased(member.capabilities().credentials()));
    }

    fn is_greased<T: Deref<Target = u16>>(list: &[T]) -> bool {
        list.iter().any(|v| GREASE_VALUES.contains(v))
    }

    fn is_ext_greased(extensions: &ExtensionList) -> bool {
        extensions
            .into_iter()
            .any(|ext| GREASE_VALUES.contains(&*ext.extension_type()))
    }
}
