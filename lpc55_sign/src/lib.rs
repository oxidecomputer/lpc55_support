// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

pub mod cert;
pub mod crc_image;
pub mod debug_auth;
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

    #[error("unexpected PEM label: {0}")]
    PemLabel(String),

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

    #[error("unsupported RSA key size: {key_size}")]
    UnsupportedRsaKeySize { key_size: usize },

    #[error("RSA exponents is too large for Debug Credential format")]
    RsaExponentTooLarge,

    #[error("Debug challenge is {0} bytes, expected 104 bytes")]
    DebugAuthChallengeWrongSize(usize),

    #[error("CMPA digest does not match expected hash")]
    CmpaDigestMismatch,

    #[error(
        "Secure boot is enabled but ROTKH is all zeros which implies no root certs are configured"
    )]
    NoRootCerts,

    #[error("Secure boot enabled but no RTKH table slots are enabled")]
    NoRtkhEnabled,

    #[error(
        "{0}.CC_SOCU_PIN is invalid {1}; the top and bottom u16s must be inverses of each other"
    )]
    InvalidCCSOCUPIN(String, u32),

    #[error(
        "{0}.CC_SOCU_DFLT is invalid {1}; the top and bottom u16s must be inverses of each other"
    )]
    InvalidCCSOCUDFLT(String, u32),

    #[error("Illegal configuration: bit {1} of {0}.CC_SOCU_* is set in CC_SOCU_DFLT but unset in CC_SOCU_PIN")]
    IllegalSocu(String, usize),

    #[error("IMAGE_KEY_REVOKE ({0}) should be a unary counter but isn't")]
    BadImageKeyRevoke(usize),

    #[error("Error with TZ Preset settings")]
    TzPresetErr,

    #[error("Secure Boot not enabled")]
    NoSecureBoot,

    #[error("Certificate header does not begin with 'cert'")]
    MissingCertHeader,

    #[error("Invalid image length in cert header: expected {0}, got {1}")]
    InvalidCertBlockLen(u32, u32),

    #[error("Invalid total image length: expected {0}, got {1}")]
    InvalidImageLen(usize, u32),

    #[error("Certificate public key size ({0} bits) does not match CMPA config ({1})")]
    InvalidPubkeySize(usize, usize),

    #[error("Signature offset {0} != total image length {1}")]
    InvalidSignatureOffset(usize, u32),

    #[error("Unsupported signature algorithm: {0}. Only sha256WithRSAEncryption is supported.")]
    UnsupportedAlgorithm(String),

    #[error("Failed to verify certificate signature: {0}")]
    BadCertSignature(String),

    #[error("ROTKH in CMPA does not match RKH table in image")]
    RotkhMismatch,

    #[error("RKH table slot {0} is disabled in CFPA")]
    KeyDisabled(usize),

    #[error("RKH table slot {0} is revoked in CFPA")]
    KeyRevoked(usize),

    #[error("Root certificate's public key is not in RKH table")]
    PubkeyNotInTable,

    #[error(
        "Last certificate's serial number has wrong magic prefix.  Expected 0x3cc3.  Found 0x{0}"
    )]
    BadSerialPrefix(String),

    #[error(
        "Last certificate's revocation ID (0x{0}) does not match CFPA IMAGE_KEY_REVOKE (0x{1})"
    )]
    BadRevocation(u16, u16),

    #[error("CRC32 does not match")]
    BadCrc,

    #[error("Secure boot is enabled but the image is not secure")]
    NotASecureImage,

    #[error("Image length is listed as longer than actual image")]
    ImageLengthTooLong,

    #[error("fmt error: {0}")]
    FmtError(#[from] std::fmt::Error),
}
