// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::{convert::TryInto, path::PathBuf};

use crate::{cert, Error};
use byteorder::{ByteOrder, LittleEndian};
use der::Encode as _;
use lpc55_areas::*;
use packed_struct::prelude::*;
use rsa::{traits::PublicKeyParts, RsaPrivateKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x509_cert::Certificate;

/// Struct defining the TOML format for `--cert-cfg`, which bundles up flags
/// that would otherwise need to appear on the command line.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct CertConfig {
    /// The file containing the private key with which to sign the image.
    pub private_key: Option<PathBuf>,

    /// The chain of DER-encoded signing certificate files, in root-to-leaf
    /// order. The image will be signed with the private key corresponding
    /// to the the leaf (last) certificate.
    pub signing_certs: Vec<PathBuf>,

    /// The full set of (up to four) DER-encoded root certificate files,
    /// from which the root key hashes are derived. Must contain the root
    /// (first) certificate in `signing_certs`.
    pub root_certs: Vec<PathBuf>,
}

#[derive(Copy, Clone, Debug, Deserialize)]
#[cfg_attr(feature = "clap", derive(clap::Parser))]
#[serde(deny_unknown_fields)]
pub struct DiceArgs {
    #[cfg_attr(feature = "clap", clap(long))]
    #[serde(default, rename = "enable-dice")]
    with_dice: bool,
    #[cfg_attr(feature = "clap", clap(long))]
    #[serde(default, rename = "dice-inc-nxp-cfg")]
    with_dice_inc_nxp_cfg: bool,
    #[cfg_attr(feature = "clap", clap(long))]
    #[serde(default, rename = "dice-cust-cfg")]
    with_dice_cust_cfg: bool,
    #[cfg_attr(feature = "clap", clap(long))]
    #[serde(default, rename = "dice-inc-sec-epoch")]
    with_dice_inc_sec_epoch: bool,
}

/// One of:
/// - a SHA2-256 of the modulus (`n`) and exponent (`e`) of an RSA public key,
/// - all zeros to indicate a missing root,
/// - a SHA2-256 of four such "hashes".
pub type Hash = [u8; 32];

/// Four root certificates, any subset of which may be missing (`None`).
pub type RootCerts = [Option<Certificate>; 4];

/// Ensure that there are exactly four root certificates.
pub fn pad_roots(roots: Vec<Certificate>) -> Result<RootCerts, Error> {
    if roots.len() > 4 {
        return Err(Error::TooManyRoots(roots.len()));
    }
    let mut roots = roots.into_iter().map(Option::Some).collect::<Vec<_>>();
    roots.resize_with(4, || None);
    Ok(roots.try_into().unwrap())
}

/// Prepare an image for signing: append a certificate table,
/// write the augmented length into the header, and compute &
/// append the root-key-hash table. Returns the stamped image
/// and the root-key-table hash.
pub fn stamp_image(
    mut image_bytes: Vec<u8>,
    signing_certs: Vec<Certificate>,
    root_certs: Vec<Certificate>,
    execution_address: u32,
) -> Result<Vec<u8>, Error> {
    // Pad to a 4-byte boundary.
    fn pad(val: usize) -> usize {
        match val.checked_rem(4) {
            Some(s) if s > 0 => 4 - s,
            _ => 0,
        }
    }

    // Check the certificates.
    if signing_certs.is_empty() {
        return Err(Error::NoSigningCertificate);
    }
    if root_certs.is_empty() {
        return Err(Error::NoRootCertificate);
    }
    if !root_certs.contains(&signing_certs[0]) {
        return Err(Error::RootNotFound);
    }

    // Generate the certificate table, including the padded length
    // of each certificate.
    let mut cert_table = Vec::new();
    for cert in &signing_certs {
        let cert_bytes = cert.to_der()?;
        let cert_pad = pad(cert_bytes.len());
        let padded_len = cert_bytes.len() + cert_pad;
        cert_table.extend_from_slice(&(padded_len as u32).to_le_bytes());
        cert_table.extend_from_slice(&cert_bytes);
        cert_table.resize(cert_table.len() + cert_pad, 0);
    }
    let cert_table_len = cert_table.len();
    let cert_header_len = CertHeader::packed_bytes_size(None)?;
    let mut cert_header: CertHeader = CertHeader::new(cert_header_len, cert_table_len);
    cert_header.certificate_count = signing_certs.len() as u32;
    let cert_table_len = cert_header.certificate_table_len as usize;

    // How many bytes we sign, including image, cert table, and root key hashes.
    let image_len = image_bytes.len();
    let image_pad = pad(image_len);
    let signed_len = image_len + image_pad + cert_header_len + cert_table_len + 4 * 32;
    cert_header.total_image_len = signed_len
        .try_into()
        .map_err(|_| Error::SignedLengthOverflow)?;

    // Total image length includes the length of the eventual signature.
    let leaf = signing_certs.last().unwrap();
    let pub_key = cert::public_key(leaf)?;
    let sig_len = pub_key.n().bits() / 8;
    let total_len = signed_len + sig_len;

    // Start writing the image header: first the total image length.
    LittleEndian::write_u32(&mut image_bytes[0x20..0x24], total_len as u32);

    // Next comes the boot field.
    let boot_field = BootField::new(BootImageType::SignedImage);
    image_bytes[0x24..0x28].clone_from_slice(&boot_field.pack()?);

    // Then the location of the certificate table: right after the image.
    LittleEndian::write_u32(&mut image_bytes[0x28..0x2c], (image_len + image_pad) as u32);

    // Optionally write the image execution address.
    if execution_address > 0 {
        LittleEndian::write_u32(&mut image_bytes[0x34..0x38], execution_address);
    }

    // Generate the image, see 7.3.4 of v2.4 UM 11126 for the layout.
    image_bytes.resize(image_bytes.len() + image_pad, 0);
    image_bytes.extend_from_slice(&cert_header.pack()?);
    image_bytes.extend_from_slice(&cert_table);

    // The hash of each root public key (i.e., of its raw `n` and `e` values)
    // goes into the image and _must_ match the hash-of-hashes programmed in
    // the CMPA!
    for root in pad_roots(root_certs)? {
        image_bytes.extend_from_slice(&root_key_hash(root.as_ref())?);
    }
    Ok(image_bytes)
}

/// Decode the private key, sign the stamped image with it,
/// and append the signature to the image.
pub fn sign_image(binary: &[u8], private_key: &RsaPrivateKey) -> Result<Vec<u8>, Error> {
    let mut image_hash = Sha256::new();
    image_hash.update(binary);

    let signature = private_key
        .sign(
            rsa::pkcs1v15::Pkcs1v15Sign::new::<rsa::sha2::Sha256>(),
            image_hash.finalize().as_slice(),
        )
        .map_err(Error::SigningError)?;

    let mut signed = binary.to_owned();
    signed.extend_from_slice(&signature);
    Ok(signed)
}

pub fn required_key_size(root_certs: &RootCerts) -> Result<Option<usize>, Error> {
    let mut required_key_size = None;
    for cert in root_certs.iter().flatten() {
        let public_key = cert::public_key(cert)?;
        let public_key_bits = public_key.size() * 8;
        if let Some(x) = required_key_size {
            if x != public_key_bits {
                return Err(Error::VaryingPublicKeySizes);
            }
        } else {
            required_key_size = Some(public_key_bits);
        }
    }
    Ok(required_key_size)
}

pub fn root_key_hash(root: Option<&Certificate>) -> Result<Hash, Error> {
    match root {
        None => Ok([0; 32]),
        Some(root) => {
            if !cert::uses_supported_signature_algorithm(root) {
                return Err(Error::UnsupportedCertificateSignatureAlgorithm {
                    subject: root.tbs_certificate.subject.to_string(),
                    algorithm: cert::signature_algorithm_name(root),
                });
            }
            let root_key = cert::public_key(root)?;
            let mut hash = Sha256::new();
            hash.update(&root_key.n().to_bytes_be());
            hash.update(&root_key.e().to_bytes_be());
            Ok(hash.finalize().into())
        }
    }
}

pub fn root_key_table_hash(root_certs: &RootCerts) -> Result<Hash, Error> {
    let mut rkth = Sha256::new();
    for root in root_certs {
        rkth.update(root_key_hash(root.as_ref())?);
    }
    Ok(rkth.finalize().into())
}

/// Generates a CMPA page
#[allow(clippy::too_many_arguments)]
pub fn generate_cmpa(
    dice: DiceArgs,
    enable_secure_boot: bool,
    debug: DebugSettings,
    default_isp: DefaultIsp,
    speed: BootSpeed,
    boot_error_pin: BootErrorPin,
    rotkh: [u8; 32],
    lock: bool,
    use_rsa_4096: bool,
) -> Result<CMPAPage, Error> {
    if dice.with_dice && !enable_secure_boot {
        return Err(Error::DiceWithoutSecureBoot);
    }

    let mut secure_boot_cfg = SecureBootCfg::new();
    secure_boot_cfg.set_dice(dice.with_dice);
    secure_boot_cfg.set_dice_inc_nxp_cfg(dice.with_dice_inc_nxp_cfg);
    secure_boot_cfg.set_dice_inc_cust_cfg(dice.with_dice_cust_cfg);
    secure_boot_cfg.set_dice_inc_sec_epoch(dice.with_dice_inc_sec_epoch);
    secure_boot_cfg.set_sec_boot(enable_secure_boot);
    secure_boot_cfg.set_rsa_4k(use_rsa_4096);

    let mut cmpa = CMPAPage::new();
    cmpa.set_secure_boot_cfg(secure_boot_cfg)?;
    cmpa.set_rotkh(&rotkh);
    cmpa.set_debug_fields(debug)?;
    cmpa.set_boot_cfg(default_isp, speed, boot_error_pin)?;

    if lock {
        let cmpa_bytes = cmpa.pack()?;
        let mut cmpa_sha = sha2::Sha256::new();
        cmpa_sha.update(&cmpa_bytes[0..cmpa_bytes.len() - 32]);
        let hash: [u8; 32] = cmpa_sha.finalize().into();
        cmpa.sha256_digest = hash;
    }
    Ok(cmpa)
}

pub fn generate_cfpa(
    settings: DebugSettings,
    revoke: [ROTKeyStatus; 4],
    image_key_revoke: u16,
) -> Result<CFPAPage, Error> {
    if !crate::is_unary(image_key_revoke) {
        return Err(Error::NonUnaryImageKeyRevoke(image_key_revoke));
    }

    let mut cfpa = CFPAPage::default();
    cfpa.version += 1; // allow overwrite of default 0
    cfpa.image_key_revoke = image_key_revoke as u32;

    let mut rkth = RKTHRevoke::new();
    rkth.rotk0 = revoke[0];
    rkth.rotk1 = revoke[1];
    rkth.rotk2 = revoke[2];
    rkth.rotk3 = revoke[3];
    cfpa.update_rkth_revoke(rkth)?;

    cfpa.set_debug_fields(settings)?;

    Ok(cfpa)
}

pub fn remove_image_signature(mut img: Vec<u8>) -> Result<Vec<u8>, Error> {
    let total_len = LittleEndian::read_u32(&img[0x20..0x24]);
    let boot_field = LittleEndian::read_u32(&img[0x24..0x28]);
    let cert_table_offset = LittleEndian::read_u32(&img[0x28..0x2c]);

    if boot_field != BootImageType::SignedImage as u32 {
        return Err(Error::NotSigned);
    }
    if total_len as usize != img.len() {
        return Err(Error::MismatchedLength);
    }

    // Plain images have a length of 0
    LittleEndian::write_u32(&mut img[0x20..0x24], 0);

    // Set imageType to a plain image
    LittleEndian::write_u32(&mut img[0x24..0x28], BootImageType::PlainImage as u32);

    // Clear the offset to the certificate header
    LittleEndian::write_u32(&mut img[0x28..0x2c], 0);

    // Strip the certificate table
    img.resize(cert_table_offset as usize, 0u8);

    Ok(img)
}
