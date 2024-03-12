// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

extern crate hmac as nss_hmac;
extern crate sha2 as nss_sha2;

use alloc::vec::Vec;
use mls_rs_core::crypto::CipherSuite;

use nss_hmac::Mac;
use nss_sha2::Digest;

// use nss_hmac::{
//     digest::{crypto_common::BlockSizeUser, FixedOutputReset},
//     SimpleHmac,
// };
// use nss_sha2::{Sha256, Sha384, Sha512};

#[derive(Debug)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum HashError {
    #[cfg_attr(feature = "std", error("invalid hmac length"))]
    InvalidHmacLength,
    #[cfg_attr(feature = "std", error("unsupported cipher suite"))]
    UnsupportedCipherSuite,
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
            Hash::Sha256 => nss_sha2::Sha256::digest(data).to_vec(),
            Hash::Sha384 => nss_sha2::Sha384::digest(data).to_vec(),
            Hash::Sha512 => nss_sha2::Sha512::digest(data).to_vec(),
        }
    }

    pub fn mac(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, HashError> {
        match self {
            Hash::Sha256 => generic_generate_tag(
                nss_hmac::SimpleHmac::<nss_sha2::Sha256>::new_from_slice(key)
                    .map_err(|_| HashError::InvalidHmacLength)?,
                data,
            ),
            Hash::Sha384 => generic_generate_tag(
                nss_hmac::SimpleHmac::<nss_sha2::Sha384>::new_from_slice(key)
                    .map_err(|_| HashError::InvalidHmacLength)?,
                data,
            ),
            Hash::Sha512 => generic_generate_tag(
                nss_hmac::SimpleHmac::<nss_sha2::Sha512>::new_from_slice(key)
                    .map_err(|_| HashError::InvalidHmacLength)?,
                data,
            ),
        }
    }
}

fn generic_generate_tag<
    D: nss_sha2::Digest + hmac::digest::crypto_common::BlockSizeUser + hmac::digest::FixedOutputReset,
>(
    mut hmac: nss_hmac::SimpleHmac<D>,
    data: &[u8],
) -> Result<Vec<u8>, HashError> {
    hmac.update(data);
    let res = hmac.finalize().into_bytes().to_vec();
    Ok(res)
}
