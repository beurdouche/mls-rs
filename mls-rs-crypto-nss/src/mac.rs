// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use alloc::vec::Vec;
use mls_rs_core::crypto::CipherSuite;
use nss_gk_api::hmac;

#[derive(Debug)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum HashError {
    #[cfg_attr(feature = "std", error("invalid hmac length"))]
    InvalidHmacLength,
    #[cfg_attr(feature = "std", error("unsupported cipher suite"))]
    UnsupportedCipherSuite,
    #[cfg_attr(feature = "std", error("internal error"))]
    InternalError,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum Hash {
    Sha256,
    Sha384,
    Sha512,
}

impl Hash {
    pub fn new(cipher_suite: CipherSuite) -> Result<Self, HashError> {
        match cipher_suite {
            CipherSuite::CURVE25519_AES128
            | CipherSuite::P256_AES128
            | CipherSuite::CURVE25519_CHACHA => Ok(Hash::Sha256),
            CipherSuite::P384_AES256 => Ok(Hash::Sha384),
            CipherSuite::CURVE448_AES256
            | CipherSuite::CURVE448_CHACHA
            | CipherSuite::P521_AES256 => Ok(Hash::Sha512),
            _ => Err(HashError::UnsupportedCipherSuite),
        }
    }

    pub fn hash(&self, data: &[u8]) -> Vec<u8> {
        match self {
            Hash::Sha256 => nss_gk_api::hash::hash(nss_gk_api::hash::HashAlgorithm::SHA2_256, data)
                .expect("InternalError"),
            Hash::Sha384 => nss_gk_api::hash::hash(nss_gk_api::hash::HashAlgorithm::SHA2_384, data)
                .expect("InternalError"),
            Hash::Sha512 => nss_gk_api::hash::hash(nss_gk_api::hash::HashAlgorithm::SHA2_512, data)
                .expect("InternalError"),
        }
    }

    pub fn mac(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, HashError> {
        match self {
            Hash::Sha256 => Ok(hmac::hmac(&hmac::HmacAlgorithm::HMAC_SHA2_256, key, data)
                .map_err(|_| HashError::InternalError)?),
            Hash::Sha384 => Ok(hmac::hmac(&hmac::HmacAlgorithm::HMAC_SHA2_384, key, data)
                .map_err(|_| HashError::InternalError)?),
            Hash::Sha512 => Ok(hmac::hmac(&hmac::HmacAlgorithm::HMAC_SHA2_512, key, data)
                .map_err(|_| HashError::InternalError)?),
        }
    }
}
