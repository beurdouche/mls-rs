// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use nss_gk_api::{
    ec::{self},
    nss_prelude::SECSuccess,
    PrivateKey, PublicKey,
};

use nss_gk_api::SECItemMut;

use alloc::vec::Vec;
use mls_rs_crypto_traits::Curve;

#[cfg(feature = "std")]
use std::array::TryFromSliceError;

#[cfg(not(feature = "std"))]
use core::array::TryFromSliceError;
use core::fmt::{self, Debug};

use crate::Hash;

// TODO: do you need Eq/PartialEq?
// #[derive(Debug, Eq, PartialEq, Clone)]
#[derive(Debug, Clone)]
pub enum EcPublicKey {
    X25519(nss_gk_api::PublicKey),
    Ed25519(nss_gk_api::PublicKey),
    P256(nss_gk_api::PublicKey),
}

#[derive(Clone)]
pub enum EcPrivateKey {
    X25519(nss_gk_api::PrivateKey),
    Ed25519(nss_gk_api::PrivateKey),
    P256(nss_gk_api::PrivateKey),
}

#[derive(Debug)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum EcError {
    #[cfg_attr(feature = "std", error("unsupported curve type"))]
    UnsupportedCurve,
    #[cfg_attr(feature = "std", error("invalid public key data"))]
    EcKeyInvalidKeyData,
    #[cfg_attr(feature = "std", error("ec key is not a signature key"))]
    EcKeyNotSignature,
    #[cfg_attr(feature = "std", error(transparent))]
    TryFromSliceError(TryFromSliceError),
    #[cfg_attr(feature = "std", error("rand error: {0:?}"))]
    RandCoreError(rand_core::Error),
    #[cfg_attr(feature = "std", error("ecdh key type mismatch"))]
    EcdhKeyTypeMismatch,
    #[cfg_attr(feature = "std", error("ec key is not an ecdh key"))]
    EcKeyNotEcdh,
}

impl From<rand_core::Error> for EcError {
    fn from(value: rand_core::Error) -> Self {
        EcError::RandCoreError(value)
    }
}

impl From<TryFromSliceError> for EcError {
    fn from(e: TryFromSliceError) -> Self {
        EcError::TryFromSliceError(e)
    }
}

impl core::fmt::Debug for EcPrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::X25519(_) => f.write_str("X25519 Secret Key"),
            Self::Ed25519(_) => f.write_str("Ed25519 Secret Key"),
            Self::P256(_) => f.write_str("P256 Secret Key"),
        }
    }
}

pub fn pub_key_from_uncompressed(bytes: &[u8], curve: Curve) -> Result<EcPublicKey, EcError> {
    match curve {
        Curve::P256 => {
            let pk_test = nss_gk_api::ec::import_ec_public_key_from_raw(bytes, ec::EcCurve::P256);
            match pk_test {
                Ok(keys) => Ok(EcPublicKey::P256(keys)),
                _ => Err(EcError::UnsupportedCurve),
            }
        }
        Curve::Ed25519 => {
            let pk_test =
                nss_gk_api::ec::import_ec_public_key_from_raw(bytes, ec::EcCurve::Ed25519);
            match pk_test {
                Ok(keys) => Ok(EcPublicKey::Ed25519(keys)),
                _ => Err(EcError::UnsupportedCurve),
            }
        }
        Curve::X25519 => {
            let pk_test = nss_gk_api::ec::import_ec_public_key_from_raw(bytes, ec::EcCurve::X25519);
            match pk_test {
                Ok(keys) => Ok(EcPublicKey::X25519(keys)),
                _ => Err(EcError::UnsupportedCurve),
            }
        }
        _ => Err(EcError::UnsupportedCurve),
    }
}

pub fn pub_key_to_uncompressed(key: EcPublicKey) -> Result<Vec<u8>, EcError> {
    match key {
        EcPublicKey::P256(key) | EcPublicKey::Ed25519(key) | EcPublicKey::X25519(key) => {
            let k = nss_gk_api::ec::export_ec_public_key_from_raw(key);
            match k {
                Ok(k) => Ok(k),
                _ => Err(EcError::UnsupportedCurve),
            }
        }
    }
}

pub fn generate_private_key(curve: Curve) -> Result<EcPrivateKey, EcError> {
    match curve {
        Curve::P256 => {
            let key = nss_gk_api::ec::ecdh_keygen(nss_gk_api::ec::EcCurve::P256);
            match key {
                Ok(key) => return Ok(EcPrivateKey::P256(key.private)),
                Err(e) => return Err(EcError::UnsupportedCurve),
            }
        }
        Curve::X25519 => {
            let key = nss_gk_api::ec::ecdh_keygen(nss_gk_api::ec::EcCurve::X25519);
            match key {
                Ok(key) => return Ok(EcPrivateKey::X25519(key.private)),
                Err(e) => return Err(EcError::UnsupportedCurve),
            }
        }
        Curve::Ed25519 => {
            let key = nss_gk_api::ec::ecdh_keygen(nss_gk_api::ec::EcCurve::Ed25519);
            match key {
                Ok(key) => return Ok(EcPrivateKey::Ed25519(key.private)),
                Err(e) => return Err(EcError::UnsupportedCurve),
            }
        }
        _ => Err(EcError::UnsupportedCurve),
    }
}

pub fn private_key_from_pkcs8(bytes: &[u8], curve: Curve) -> Result<EcPrivateKey, EcError> {
    match curve {
        Curve::P256 => match nss_gk_api::ec::import_ec_private_key_pkcs8(bytes) {
            Ok(key) => return Ok(EcPrivateKey::P256(key)),
            Err(e) => return Err(EcError::EcKeyNotEcdh),
        },
        Curve::Ed25519 => match nss_gk_api::ec::import_ec_private_key_pkcs8(bytes) {
            Ok(key) => return Ok(EcPrivateKey::Ed25519(key)),
            Err(e) => return Err(EcError::EcKeyNotEcdh),
        },
        Curve::X25519 => match nss_gk_api::ec::import_ec_private_key_pkcs8(bytes) {
            Ok(key) => return Ok(EcPrivateKey::X25519(key)),
            Err(e) => return Err(EcError::EcKeyNotEcdh),
        },
        _ => Err(EcError::UnsupportedCurve),
    }
}

pub fn private_key_to_pkcs8(key: EcPrivateKey) -> Result<Vec<u8>, EcError> {
    match key {
        EcPrivateKey::P256(key) | EcPrivateKey::Ed25519(key) | EcPrivateKey::X25519(key) => {
            let k = key.key_data();
            match nss_gk_api::ec::export_ec_private_key_pkcs8(key) {
                Ok(key) => return Ok(key),
                Err(e) => return Err(EcError::UnsupportedCurve),
            }
        }
        _ => Err(EcError::UnsupportedCurve),
    }
}

pub fn private_key_from_bytes(bytes: &[u8], curve: Curve) -> Result<EcPrivateKey, EcError> {
    match curve {
        Curve::P256 => {
            // let lh = [
            //     0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce,
            //     0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04,
            //     0x6d, 0x30, 0x6b, 0x02, 0x01, 0x01, 0x04, 0x20,
            // ];
            // let rh = [
            //     0xa1, 0x44, 0x03, 0x42, 0x00, 0x04, 0x08, 0xf1, 0x3f, 0x67, 0x3c, 0xc3, 0xeb, 0x08,
            //     0xc9, 0x9c, 0x21, 0x85, 0x7a, 0x17, 0x3e, 0x24, 0xf1, 0xe9, 0xd1, 0xd0, 0xef, 0x80,
            //     0xa0, 0xac, 0x81, 0x13, 0x70, 0x79, 0x50, 0x7f, 0xd3, 0x93, 0xa8, 0x0d, 0x24, 0x9a,
            //     0xf2, 0x6b, 0xf4, 0x31, 0x3f, 0x2b, 0xdf, 0xbe, 0xfd, 0x03, 0xb4, 0x3a, 0x3d, 0x1f,
            //     0x8d, 0x27, 0xae, 0x9f, 0x85, 0xbf, 0x0a, 0x6f, 0xe1, 0xa5, 0xe2, 0x4e, 0xac, 0x98,
            // ];

            // // Let's hope that the key is 32.
            // let mut z = [0; 36 + 70 + 32];
            // let mut i = 0;

            // while i < lh.len() {
            //     z[i] = lh[i];
            //     i = i + 1;
            // }

            // i = 0;
            // while i < 32 {
            //     z[36 + i] = bytes[i];
            //     i = i + 1;
            // }

            // i = 0;
            // while i < rh.len() {
            //     z[36 + 32 + i] = rh[i];
            //     i = i + 1;
            // }

            let lh = [
                0x30, 0x41, 0x2, 0x1, 0x0, 0x30, 0x13, 0x6, 0x7, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x2,
                0x1, 0x6, 0x8, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x3, 0x1, 0x7, 0x4, 0x27, 0x30, 0x25,
                0x2, 0x1, 0x1, 0x4, 0x20,
            ];

            let mut z = [0; 35 + 32];
            let mut i = 0;

            while i < lh.len() {
                z[i] = lh[i];
                i = i + 1;
            }

            i = 0;
            while i < 32 {
                z[35 + i] = bytes[i];
                i = i + 1;
            }

            match nss_gk_api::ec::import_ec_private_key_pkcs8(&z) {
                Ok(key) => return Ok(EcPrivateKey::P256(key)),
                Err(e) => return Err(EcError::EcKeyNotEcdh),
            }
        }
        Curve::Ed25519 => {
            let lh = [
                0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
                0x04, 0x20,
            ];

            let mut z = [0; 16 + 32];
            let mut i = 0;

            while i < lh.len() {
                z[i] = lh[i];
                i = i + 1;
            }

            i = 0;
            while i < 32 {
                z[16 + i] = bytes[i];
                i = i + 1;
            }

            match nss_gk_api::ec::import_ec_private_key_pkcs8(&z) {
                Ok(key) => return Ok(EcPrivateKey::Ed25519(key)),
                Err(e) => return Err(EcError::EcKeyNotEcdh),
            }
        }
        Curve::X25519 => {
            let lh = [
                0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22,
                0x04, 0x20,
            ];

            let mut z = [0; 16 + 32];
            let mut i = 0;

            while i < lh.len() {
                z[i] = lh[i];
                i = i + 1;
            }

            i = 0;
            while i < 32 {
                z[16 + i] = bytes[i];
                i = i + 1;
            }

            match nss_gk_api::ec::import_ec_private_key_pkcs8(&z) {
                Ok(key) => return Ok(EcPrivateKey::Ed25519(key)),
                Err(e) => return Err(EcError::EcKeyNotEcdh),
            }
        }
        _ => Err(EcError::UnsupportedCurve),
    }
}

pub fn private_key_to_bytes(key: EcPrivateKey) -> Result<Vec<u8>, EcError> {
    match key {
        EcPrivateKey::Ed25519(key) | EcPrivateKey::P256(key) | EcPrivateKey::X25519(key) => {
            let k = key.key_data();
            match nss_gk_api::ec::export_ec_private_key_from_raw(key) {
                Ok(key) => return Ok(key),
                Err(e) => return Err(EcError::UnsupportedCurve),
            }
        }
    }
}

pub fn private_key_to_public(private_key: &EcPrivateKey) -> Result<EcPublicKey, EcError> {
    match private_key {
        EcPrivateKey::X25519(key) => Ok(EcPublicKey::X25519(
            nss_gk_api::ec::convert_to_public(key.clone()).unwrap(),
        )),
        EcPrivateKey::Ed25519(key) => Ok(EcPublicKey::Ed25519(
            nss_gk_api::ec::convert_to_public(key.clone()).unwrap(),
        )),
        EcPrivateKey::P256(key) => Ok(EcPublicKey::P256(
            nss_gk_api::ec::convert_to_public(key.clone()).unwrap(),
        )),
    }
}

pub fn private_key_ecdh(
    private_key: &EcPrivateKey,
    remote_public: &EcPublicKey,
) -> Result<Vec<u8>, EcError> {
    let shared_secret = match private_key {
        EcPrivateKey::X25519(private_key) => match remote_public {
            EcPublicKey::X25519(public) => {
                let r = nss_gk_api::ec::ecdh(private_key.clone(), public.clone()).unwrap();
                Ok(r)
            }
            _ => Err(EcError::EcdhKeyTypeMismatch),
        },
        EcPrivateKey::Ed25519(_) => Err(EcError::EcKeyNotEcdh),
        EcPrivateKey::P256(private_key) => match remote_public {
            EcPublicKey::P256(public) => {
                let r = nss_gk_api::ec::ecdh(private_key.clone(), public.clone()).unwrap();
                Ok(r)
            }
            _ => Err(EcError::EcdhKeyTypeMismatch),
        },
    }?;

    Ok(shared_secret)
}

pub fn sign_p256(private_key: PrivateKey, data: &[u8]) -> Result<Vec<u8>, EcError> {
    let mut signature = SECItemMut::make_empty();
    let hashed_data = Hash::hash(&Hash::Sha256, data);
    let mut data_to_sign = nss_gk_api::SECItemBorrowed::wrap(&hashed_data);

    unsafe {
        let rv = nss_gk_api::p11::PK11_SignWithMechanism(
            private_key.as_mut().unwrap(),
            nss_gk_api::p11::CKM_ECDSA.into(),
            std::ptr::null_mut(),
            signature.as_mut(),
            data_to_sign.as_mut(),
        );
        let signature = signature.as_slice().to_owned();
        Ok(signature)
    }
}

pub fn sign_ed25519(private_key: PrivateKey, data: &[u8]) -> Result<Vec<u8>, EcError> {
    let mut signature = SECItemMut::make_empty();
    let mut data_to_sign = nss_gk_api::SECItemBorrowed::wrap(&data);

    unsafe {
        let rv = nss_gk_api::p11::PK11_SignWithMechanism(
            private_key.as_mut().unwrap(),
            nss_gk_api::p11::CKM_EDDSA.into(),
            std::ptr::null_mut(),
            signature.as_mut(),
            data_to_sign.as_mut(),
        );
        let signature = signature.as_slice().to_owned();
        Ok(signature)
    }
}

// True if success
fn rv_to_bool(rv: i32) -> bool {
    //SECSuccess = 0
    return rv == SECSuccess;
}

pub fn verify_p256(public_key: PublicKey, signature: &[u8], data: &[u8]) -> Result<bool, EcError> {
    let mut signature = nss_gk_api::SECItemBorrowed::wrap(&signature);
    let hashed_data = Hash::hash(&Hash::Sha256, data);
    let mut data_to_verify = nss_gk_api::SECItemBorrowed::wrap(&hashed_data);

    unsafe {
        let rv = nss_gk_api::p11::PK11_VerifyWithMechanism(
            public_key.as_mut().unwrap(),
            nss_gk_api::p11::CKM_ECDSA.into(),
            std::ptr::null_mut(),
            data_to_verify.as_mut(),
            signature.as_mut(),
            std::ptr::null_mut(),
        );
        Ok(rv_to_bool(rv))
    }
}

pub fn verify_ed25519(
    public_key: PublicKey,
    signature: &[u8],
    data: &[u8],
) -> Result<bool, EcError> {
    let mut signature = nss_gk_api::SECItemBorrowed::wrap(&signature);
    let mut data_to_verify = nss_gk_api::SECItemBorrowed::wrap(&data);

    unsafe {
        let rv = nss_gk_api::p11::PK11_VerifyWithMechanism(
            public_key.as_mut().unwrap(),
            nss_gk_api::p11::CKM_EDDSA.into(),
            std::ptr::null_mut(),
            data_to_verify.as_mut(),
            signature.as_mut(),
            std::ptr::null_mut(),
        );
        Ok(rv_to_bool(rv))
    }
}

pub fn generate_keypair(curve: Curve) -> Result<KeyPair, EcError> {
    match curve {
        Curve::P256 => {
            let key = nss_gk_api::ec::ecdh_keygen(nss_gk_api::ec::EcCurve::P256);
            match key {
                Ok(key) => {
                    let secret: Vec<u8> = private_key_to_bytes(EcPrivateKey::P256(key.private))?;
                    let public: Vec<u8> = pub_key_to_uncompressed(EcPublicKey::P256(key.public))?;
                    return Ok(KeyPair { public, secret });
                }
                Err(e) => return Err(EcError::UnsupportedCurve),
            };
        }
        Curve::Ed25519 => {
            let key = nss_gk_api::ec::ecdh_keygen(nss_gk_api::ec::EcCurve::Ed25519);
            match key {
                Ok(key) => {
                    let secret: Vec<u8> = private_key_to_bytes(EcPrivateKey::Ed25519(key.private))?;
                    let public: Vec<u8> =
                        pub_key_to_uncompressed(EcPublicKey::Ed25519(key.public))?;
                    return Ok(KeyPair { public, secret });
                }
                Err(e) => return Err(EcError::UnsupportedCurve),
            };
        }
        Curve::X25519 => {
            let key = nss_gk_api::ec::ecdh_keygen(nss_gk_api::ec::EcCurve::X25519);
            match key {
                Ok(key) => {
                    let secret: Vec<u8> = private_key_to_bytes(EcPrivateKey::X25519(key.private))?;
                    let public: Vec<u8> = pub_key_to_uncompressed(EcPublicKey::X25519(key.public))?;
                    return Ok(KeyPair { public, secret });
                }
                Err(e) => return Err(EcError::UnsupportedCurve),
            };
        }
        _ => {
            let secret = generate_private_key(curve)?;
            let public = private_key_to_public(&secret)?;
            let secret = private_key_to_bytes(secret)?;
            let public = pub_key_to_uncompressed(public)?;
            Ok(KeyPair { public, secret })
        }
    }
}

#[derive(Clone, Default)]
pub struct KeyPair {
    pub public: Vec<u8>,
    pub secret: Vec<u8>,
}

impl Debug for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyPair")
            .field("public", &mls_rs_core::debug::pretty_bytes(&self.public))
            .field("secret", &mls_rs_core::debug::pretty_bytes(&self.secret))
            .finish()
    }
}

pub fn private_key_bytes_to_public(secret_key: &[u8], curve: Curve) -> Result<Vec<u8>, EcError> {
    let secret_key = private_key_from_bytes(secret_key, curve)?;
    let public_key = private_key_to_public(&secret_key)?;
    pub_key_to_uncompressed(public_key)
}

#[cfg(test)]
pub(crate) mod test_utils {
    use serde::Deserialize;

    use super::Curve;

    use alloc::vec::Vec;

    #[derive(Deserialize)]
    pub(crate) struct TestKeys {
        #[serde(with = "hex::serde")]
        p256: Vec<u8>,
        #[serde(with = "hex::serde")]
        x25519: Vec<u8>,
        #[serde(with = "hex::serde")]
        ed25519: Vec<u8>,
    }

    impl TestKeys {
        pub(crate) fn get_key_from_curve(&self, curve: Curve) -> Vec<u8> {
            match curve {
                Curve::P256 => self.p256.clone(),
                Curve::X25519 => self.x25519.clone(),
                Curve::Ed25519 => self.ed25519.clone(),
                _ => Vec::new(),
            }
        }
    }

    pub(crate) fn get_test_public_keys() -> TestKeys {
        let test_case_file = include_str!("../test_data/test_public_keys.json");
        serde_json::from_str(test_case_file).unwrap()
    }

    pub(crate) fn get_test_secret_keys() -> TestKeys {
        let test_case_file = include_str!("../test_data/test_private_keys.json");
        serde_json::from_str(test_case_file).unwrap()
    }

    pub fn is_curve_25519(curve: Curve) -> bool {
        curve == Curve::X25519 || curve == Curve::Ed25519
    }

    pub fn byte_equal(curve: Curve, other: Curve) -> bool {
        if curve == other {
            return true;
        }

        if is_curve_25519(curve) && is_curve_25519(other) {
            return true;
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;

    use super::{
        generate_keypair, generate_private_key, private_key_bytes_to_public,
        private_key_from_bytes, private_key_from_pkcs8, private_key_to_bytes, private_key_to_pkcs8,
        pub_key_from_uncompressed, pub_key_to_uncompressed,
        test_utils::{byte_equal, get_test_public_keys, get_test_secret_keys},
        Curve, EcError,
    };

    use alloc::vec;
    const SUPPORTED_CURVES: [Curve; 3] = [Curve::Ed25519, Curve::P256, Curve::X25519];

    #[test]
    fn private_key_can_be_generated() {
        SUPPORTED_CURVES.iter().copied().for_each(|curve| {
            let one_key = generate_private_key(curve)
                .unwrap_or_else(|e| panic!("Failed to generate private key for {curve:?} : {e:?}"));

            let another_key = generate_private_key(curve)
                .unwrap_or_else(|e| panic!("Failed to generate private key for {curve:?} : {e:?}"));

            assert_ne!(
                private_key_to_bytes(one_key).unwrap(),
                private_key_to_bytes(another_key).unwrap(),
                "Same key generated twice for {curve:?}"
            );
        });
    }

    #[test]
    fn key_pair_can_be_generated() {
        SUPPORTED_CURVES.iter().copied().for_each(|curve| {
            assert_matches!(
                generate_keypair(curve),
                Ok(_),
                "Failed to generate key pair for {curve:?}"
            );
        });
    }

    #[test]
    fn private_key_can_be_imported_and_exported() {
        SUPPORTED_CURVES.iter().copied().for_each(|curve| {
            let key_bytes = get_test_secret_keys().get_key_from_curve(curve);

            let imported_key = private_key_from_bytes(&key_bytes, curve)
                .unwrap_or_else(|e| panic!("Failed to import private key for {curve:?} : {e:?}"));

            let exported_bytes = private_key_to_bytes(imported_key)
                .unwrap_or_else(|e| panic!("Failed to export private key for {curve:?} : {e:?}"));

            assert_eq!(exported_bytes, key_bytes);
        });
    }

    #[test]
    fn private_key_pkcs8_can_be_imported_and_exported() {
        SUPPORTED_CURVES.iter().copied().for_each(|curve| {
            let key = generate_private_key(curve)
                .unwrap_or_else(|e| panic!("Failed to generate private key for {curve:?} : {e:?}"));

            let exported_bytes = private_key_to_pkcs8(key)
                .unwrap_or_else(|e| panic!("Failed to export private key for {curve:?} : {e:?}"));

            let imported_key = private_key_from_pkcs8(&exported_bytes, curve)
                .unwrap_or_else(|e| panic!("Failed to import private key for {curve:?} : {e:?}"));

            let exported_bytes_2 = private_key_to_pkcs8(imported_key)
                .unwrap_or_else(|e| panic!("Failed to export private key for {curve:?} : {e:?}"));

            assert_eq!(exported_bytes_2, exported_bytes);
        });
    }

    #[test]
    fn public_key_can_be_imported_and_exported() {
        SUPPORTED_CURVES.iter().copied().for_each(|curve| {
            let key_bytes = get_test_public_keys().get_key_from_curve(curve);

            let imported_key = pub_key_from_uncompressed(&key_bytes, curve)
                .unwrap_or_else(|e| panic!("Failed to import public key for {curve:?} : {e:?}"));

            let exported_bytes = pub_key_to_uncompressed(imported_key)
                .unwrap_or_else(|e| panic!("Failed to export public key for {curve:?} : {e:?}"));

            assert_eq!(exported_bytes, key_bytes);
        });
    }

    #[test]
    fn secret_to_public() {
        let test_public_keys = get_test_public_keys();
        let test_secret_keys = get_test_secret_keys();

        for curve in SUPPORTED_CURVES.iter().copied() {
            let secret_key = test_secret_keys.get_key_from_curve(curve);
            let public_key = private_key_bytes_to_public(&secret_key, curve).unwrap();
            assert_eq!(public_key, test_public_keys.get_key_from_curve(curve));
        }
    }

    #[test]
    fn mismatched_curve_import() {
        for curve in SUPPORTED_CURVES.iter().copied() {
            for other_curve in SUPPORTED_CURVES
                .iter()
                .copied()
                .filter(|c| !byte_equal(*c, curve))
            {
                let public_key = get_test_public_keys().get_key_from_curve(curve);
                let res = pub_key_from_uncompressed(&public_key, other_curve);

                assert!(res.is_err());
            }
        }
    }

    #[test]
    fn test_order_range_enforcement() {
        let p256_order =
            hex::decode("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")
                .unwrap();

        // Keys must be <= to order
        let p256_res = private_key_from_bytes(&p256_order, Curve::P256);
        assert_matches!(p256_res, Err(EcError::EcKeyInvalidKeyData));

        let nist_curves = [Curve::P256];

        // Keys must not be 0
        for curve in nist_curves {
            assert_matches!(
                private_key_from_bytes(&vec![0u8; curve.secret_key_size()], curve),
                Err(EcError::EcKeyInvalidKeyData)
            );
        }
    }
}
