// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

pub mod cert;
pub mod crc_image;
pub mod signed_image;
pub mod verify;

fn is_unary(val: u16) -> bool {
    // There are multiple ways to test this:
    // * `val.leading_zeros() + val.trailing_ones() == 16`
    // * checked_add(1).is_power_of_2()
    // * wrapping addition and masking
    //
    // Wrapping addition and masking generates the shortest instruction
    // sequence.  For `x & (x+1)` to equal zero, x and (x+1) must have no bits
    // in common. That only occurs when (x+1) is a power of 2 and thus x is
    // 2^y-1 which is a unary number. Wrapping addition is needed for u16::MAX
    // as all bits are set and thus (x+1) must have all bits clear.
    val & val.wrapping_add(1) == 0
}

#[cfg(test)]
mod tests {
    use crate::is_unary;

    #[test]
    fn test_is_unary() {
        for val in 0..=u16::MAX {
            assert_eq!(
                is_unary(val),
                (val.leading_zeros() + val.trailing_ones() == 16)
            )
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("verification failed; see log for details")]
    VerificationFailed,

    #[error("struct packing error: {0}")]
    PackingError(#[from] packed_struct::PackingError),

    #[error("certificate decoding error: {0}")]
    DerError(#[from] der::Error),

    #[error("error decoding PEM: {0}")]
    Pem(#[from] pem_rfc7468::Error),

    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("RSA PKCS#1 error: {0}")]
    RsaPkcs1Error(#[from] rsa::pkcs1::Error),

    #[error("RSA PKCS#8 error: {0}")]
    RsaPkcs8Error(#[from] rsa::pkcs8::Error),

    #[error("RSA signature error: {0}")]
    RsaSignatureError(#[from] rsa::signature::Error),

    #[error("SPKI error: {0}")]
    SpkiError(#[from] rsa::pkcs8::spki::Error),

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

    #[error("attempt to use non-unary IMAGE_KEY_REVOKE in CFPA")]
    NonUnaryImageKeyRevoke(u16),
}
