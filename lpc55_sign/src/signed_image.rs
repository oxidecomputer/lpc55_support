// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::convert::TryInto;

use crate::Error;
use byteorder::{ByteOrder, LittleEndian};
use clap::Parser;
use lpc55_areas::*;
use packed_struct::prelude::*;
use rsa::{
    pkcs1::DecodeRsaPrivateKey, pkcs1::DecodeRsaPublicKey, pkcs8::DecodePrivateKey, PublicKeyParts,
    RsaPrivateKey, RsaPublicKey,
};
use sha2::{Digest, Sha256};
use x509_parser::parse_x509_certificate;

#[derive(Clone, Debug, Parser)]
pub struct DiceArgs {
    #[clap(long)]
    with_dice: bool,
    #[clap(long)]
    with_dice_inc_nxp_cfg: bool,
    #[clap(long)]
    with_dice_cust_cfg: bool,
    #[clap(long)]
    with_dice_inc_sec_epoch: bool,
}

fn get_pad(val: usize) -> usize {
    match val.checked_rem(4) {
        Some(s) if s > 0 => 4 - s,
        _ => 0,
    }
}

fn pad_roots(mut roots: Vec<Vec<u8>>) -> Result<[Vec<u8>; 4], Error> {
    if roots.len() > 4 {
        return Err(Error::TooManyRoots(roots.len()));
    }
    roots.resize_with(4, Vec::new);
    Ok(roots.try_into().unwrap())
}

/// Prepare an image for signing: append a certificate table,
/// write the augmented length into the header, and compute &
/// append the root-key-hash table. Returns the stamped image
/// and the root-key-table hash.
pub fn stamp_image(
    mut image_bytes: Vec<u8>,
    signing_certs: Vec<Vec<u8>>,
    root_certs: Vec<Vec<u8>>,
    execution_address: u32,
) -> Result<Vec<u8>, Error> {
    if signing_certs.is_empty() {
        return Err(Error::NoSigningCertificate);
    }
    if root_certs.is_empty() {
        return Err(Error::NoRootCertificate);
    }

    // Generate the certificate table, including the padded length
    // of each certificate.
    let mut cert_table = Vec::new();
    for cert in &signing_certs {
        let cert_pad = get_pad(cert.len());
        let padded_len = cert.len() + cert_pad;
        cert_table.extend_from_slice(&(padded_len as u32).to_le_bytes());
        cert_table.extend_from_slice(cert);
        cert_table.resize(cert_table.len() + cert_pad, 0);
    }
    let cert_table_len = cert_table.len();
    let cert_header_len = CertHeader::packed_bytes_size(None)?;
    let mut cert_header: CertHeader = CertHeader::new(cert_header_len, cert_table_len);
    cert_header.certificate_count = signing_certs.len() as u32;
    let cert_table_len = cert_header.certificate_table_len as usize;

    // How many bytes we sign, including image, cert table, and root key hashes.
    let image_len = image_bytes.len();
    let image_pad = get_pad(image_len);
    let signed_len = image_len + image_pad + cert_header_len + cert_table_len + 4 * 32;
    cert_header.total_image_len = signed_len
        .try_into()
        .map_err(|_| Error::SignedLengthOverflow)?;

    // Total image length includes the length of the eventual signature.
    let (_, leaf) = parse_x509_certificate(signing_certs.last().unwrap())?;
    let pub_key = RsaPublicKey::from_pkcs1_der(leaf.public_key().subject_public_key.as_ref())?;
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
        image_bytes.extend_from_slice(&root_key_hash(&root)?);
    }
    Ok(image_bytes)
}

/// Decode the private key, sign the stamped image with it,
/// and append the signature to the image.
pub fn sign_image(binary: &[u8], private_key: &str) -> Result<Vec<u8>, Error> {
    let mut image_hash = Sha256::new();
    image_hash.update(binary);

    let private_key = RsaPrivateKey::from_pkcs1_pem(private_key)
        .or_else(|_| RsaPrivateKey::from_pkcs8_pem(private_key))?;
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

pub fn root_key_hash(root: &[u8]) -> Result<[u8; 32], Error> {
    if root.is_empty() {
        Ok([0; 32])
    } else {
        let (_, root_cert) = parse_x509_certificate(root)?;
        let root_key = root_cert.public_key().subject_public_key.as_ref();
        let root_key = RsaPublicKey::from_pkcs1_der(root_key)?;
        let mut hash = Sha256::new();
        hash.update(&root_key.n().to_bytes_be());
        hash.update(&root_key.e().to_bytes_be());
        Ok(hash.finalize().into())
    }
}

pub fn root_key_table_hash(root_certs: Vec<Vec<u8>>) -> Result<[u8; 32], Error> {
    let mut rkth = Sha256::new();
    for root in pad_roots(root_certs)? {
        rkth.update(root_key_hash(&root)?);
    }
    Ok(rkth.finalize().into())
}

pub fn generate_cmpa(dice: DiceArgs, rotkh: [u8; 32]) -> Result<CMPAPage, Error> {
    let mut secure_boot_cfg = SecureBootCfg::new();
    secure_boot_cfg.set_dice(dice.with_dice);
    secure_boot_cfg.set_dice_inc_nxp_cfg(dice.with_dice_inc_nxp_cfg);
    secure_boot_cfg.set_dice_inc_cust_cfg(dice.with_dice_cust_cfg);
    secure_boot_cfg.set_dice_inc_sec_epoch(dice.with_dice_inc_sec_epoch);
    secure_boot_cfg.set_sec_boot(true);

    let mut cmpa = CMPAPage::new();
    cmpa.set_secure_boot_cfg(secure_boot_cfg)?;
    cmpa.set_rotkh(&rotkh);
    cmpa.set_debug_fields(DebugSettings::new())?;
    cmpa.set_boot_cfg(DefaultIsp::Auto, BootSpeed::Fro96mhz)?;
    Ok(cmpa)
}

pub fn generate_cfpa(_root_certs: Vec<Vec<u8>>) -> Result<CFPAPage, Error> {
    let mut cfpa = CFPAPage::default();
    cfpa.version += 1; // allow overwrite of default 0

    // TODO: derive these bits from root_certs
    let mut rkth = RKTHRevoke::new();
    rkth.rotk0 = ROTKeyStatus::enabled();
    rkth.rotk1 = ROTKeyStatus::invalid();
    rkth.rotk2 = ROTKeyStatus::invalid();
    rkth.rotk3 = ROTKeyStatus::invalid();
    cfpa.update_rkth_revoke(rkth)?;

    let cfpa_settings = DebugSettings::new();
    cfpa.set_debug_fields(cfpa_settings)?;

    Ok(cfpa)
}
