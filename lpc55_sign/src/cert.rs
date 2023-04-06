use x509_parser::{
    certificate::X509Certificate,
    oid_registry::{self},
};

pub fn uses_supported_signature_algorithm(cert: &X509Certificate) -> bool {
    cert.signature_algorithm.algorithm == oid_registry::OID_PKCS1_SHA256WITHRSA
}

pub fn signature_algorithm_name(cert: &X509Certificate) -> String {
    let oid_registry = oid_registry::OidRegistry::default().with_crypto();
    if let Some(x) = oid_registry.get(&cert.signature_algorithm.algorithm) {
        x.sn().into()
    } else {
        cert.signature_algorithm.algorithm.to_string()
    }
}
