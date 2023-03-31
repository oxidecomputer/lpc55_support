use crate::Error;
use const_oid;
use der::{Decode as _, Encode as _, Reader as _};
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::RsaPublicKey;
use x509_cert::Certificate;

/// `Certificate::from_der` uses a `der::SliceReader`, which returns
/// an error if the slice is larger than the DER message it contains.
/// This is a problem for certs in the LPC55 certificate table, because
/// they are padded to a 4-byte boundary. But we can work around it by
/// manually computing the actual length from the DER header.
pub fn read_from_slice(bytes: &[u8]) -> Result<Certificate, Error> {
    let reader = der::SliceReader::new(bytes)?;
    let header = reader.peek_header()?;
    let length = (header.encoded_len()? + header.length)?.try_into()?;
    Ok(Certificate::from_der(&bytes[0..length])?)
}

/// Extract the RSA public key from a certificate.
pub fn public_key(cert: &Certificate) -> Result<RsaPublicKey, Error> {
    Ok(RsaPublicKey::from_pkcs1_der(
        cert.tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes(),
    )?)
}

pub fn uses_supported_signature_algorithm(cert: &Certificate) -> bool {
    cert.signature_algorithm.oid == const_oid::db::rfc5912::SHA_256_WITH_RSA_ENCRYPTION
}

pub fn signature_algorithm_name(cert: &Certificate) -> String {
    const_oid::db::DB
        .by_oid(&cert.signature_algorithm.oid)
        .map(|x| x.to_string())
        .unwrap_or_else(|| format!("{:?}", cert.signature_algorithm.oid))
}
