// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

pub mod cert;
pub mod crc_image;
pub mod signed_image;
pub mod verify;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("verification failed; see log for details")]
    VerificationFailed,

    #[error("struct packing error: {0}")]
    PackingError(#[from] packed_struct::PackingError),

    #[error("x509 parsing error: {0}")]
    X509Error(#[from] x509_parser::nom::Err<x509_parser::error::X509Error>),

    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("RSA PKCS#1 error: {0}")]
    RsaPkcs1Error(#[from] rsa::pkcs1::Error),

    #[error("RSA PKCS#8 error: {0}")]
    RsaPkcs8Error(#[from] rsa::pkcs8::Error),

    #[error("RSA error while signing: {0}")]
    SigningError(rsa::errors::Error),

    #[error("too many roots: expected 4 or fewer, got {0}")]
    TooManyRoots(usize),

    #[error("no signing certificate, need at least one")]
    NoSigningCertificate,

    #[error("no root certificate, need at least one")]
    NoRootCertificate,

    #[error("could not fit total image length in a `u32`")]
    SignedLengthOverflow,

    #[error("root certificate is not found in signing chain")]
    RootNotFound,

    #[error("must set secure boot to use DICE")]
    DiceWithoutSecureBoot,

    #[error("the given image is not a plain signed XIP image")]
    NotSigned,

    #[error("the image length field does not match data")]
    MismatchedLength,

    #[error("public keys have varying sizes (must all be 2048 or 4096 bit)")]
    VaryingPublicKeySizes,

    #[error("certificate with subject {subject} uses unsupported signature algorithm {algorithm}. Only sha256WithRSAEncryption is supported.")]
    UnsupportedCertificateSignatureAlgorithm { subject: String, algorithm: String },
}
