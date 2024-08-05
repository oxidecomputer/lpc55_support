use crate::Error;
use der::{Decode as _, Encode as _, Reader as _};
use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey};
use rsa::pkcs8::DecodePrivateKey;
use rsa::{RsaPrivateKey, RsaPublicKey};
use std::path::PathBuf;
use x509_cert::Certificate;

pub const CERT_END: &str = "-----END CERTIFICATE-----\n";

/// Parse PEM X.509 certificates from a string
pub fn read_pem_certs_str(s: &str) -> Result<Vec<Certificate>, Error> {
    let split = s.split_inclusive(CERT_END);
    // We have no way of knowing the length unfortunately
    let mut certs = Vec::new();
    for c in split {
        if c.starts_with("-----BEGIN CERTIFICATE-----\n") {
            let (label, der) = pem_rfc7468::decode_vec(c.as_bytes())?;
            if label != "CERTIFICATE" {
                return Err(Error::PemLabel(label.to_string()));
            }
            let cert = Certificate::from_der(&der)?;
            certs.push(cert);
        }
    }
    Ok(certs)
}

/// Read and parse X.509 certificates from DER or PEM encoded files.
pub fn read_certs(paths: &[PathBuf]) -> Result<Vec<Certificate>, Error> {
    let mut certs = Vec::with_capacity(paths.len());
    for path in paths {
        let bytes = std::fs::read(path)?;
        let der = if bytes.starts_with("-----BEGIN CERTIFICATE-----\n".as_bytes()) {
            let (label, der) = pem_rfc7468::decode_vec(&bytes)?;
            if label != "CERTIFICATE" {
                return Err(Error::PemLabel(label.to_string()));
            }
            der
        } else {
            bytes
        };
        let cert = Certificate::from_der(&der)?;
        certs.push(cert);
    }
    Ok(certs)
}

pub fn read_rsa_private_key(path: &PathBuf) -> Result<RsaPrivateKey, Error> {
    let bytes = std::fs::read(path)?;
    if bytes.starts_with(b"-----BEGIN") {
        let (label, der) = pem_rfc7468::decode_vec(&bytes)?;
        if label == "PRIVATE KEY" {
            Ok(RsaPrivateKey::from_pkcs8_der(&der)?)
        } else if label == "RSA PRIVATE KEY" {
            Ok(RsaPrivateKey::from_pkcs1_der(&der)?)
        } else {
            return Err(Error::PemLabel(label.to_string()));
        }
    } else {
        Ok(RsaPrivateKey::from_pkcs1_der(&bytes)
            .or_else(|_| RsaPrivateKey::from_pkcs8_der(&bytes))?)
    }
}

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
