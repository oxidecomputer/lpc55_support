// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{anyhow, Result};
use byteorder::{ByteOrder, WriteBytesExt};
use lpc55_areas::*;
use rsa::{
    pkcs1::DecodeRsaPrivateKey, pkcs1::DecodeRsaPublicKey, pkcs8::DecodePrivateKey, PublicKeyParts,
};
use sha2::Digest;

use packed_struct::prelude::*;
use serde::Deserialize;
use std::convert::TryInto;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

fn get_pad(val: usize) -> usize {
    match val.checked_rem(4) {
        Some(s) if s > 0 => 4 - s,
        _ => 0,
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct CertChain {
    pub cert_paths: Vec<PathBuf>,
    pub priv_key: Option<PathBuf>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct CfgFile {
    pub certs: Vec<CertChain>,
}

fn validate_certs(certs: &[CertChain]) -> Result<()> {
    if certs.len() > 4 {
        return Err(anyhow!("Too many certificate chains, max is 4"));
    }

    let cnt = certs.iter().filter(|c| c.priv_key.is_some()).count();

    if cnt != 1 {
        return Err(anyhow!(
            "Exactly one certificate chain should specify a private key for signing"
        ));
    }

    Ok(())
}

pub fn sign_chain(
    binary_path: &Path,
    cert_path_prefix: Option<&Path>,
    certs: &[CertChain],
    outfile_path: &Path,
    execution_address: u32,
) -> Result<[u8; 32]> {
    validate_certs(certs)?;

    let prefix = if let Some(p) = cert_path_prefix {
        p
    } else {
        Path::new(".")
    };

    let mut bytes = std::fs::read(binary_path)?;
    let image_pad = get_pad(bytes.len());

    let signing_chain = certs.iter().find(|c| c.priv_key.is_some()).unwrap();

    // Generate the byte sequence for the signing certificates. This includes
    // adding the (padded) length of each certificate.
    let signing_certs: Vec<u8> = signing_chain
        .cert_paths
        .iter()
        .flat_map(|path| {
            let cert_bytes = std::fs::read(prefix.join(path)).unwrap();
            let cert_pad = get_pad(cert_bytes.len());
            let padded_len = cert_bytes.len() + cert_pad;
            let mut v = Vec::new();

            v.extend_from_slice(&(padded_len as u32).to_le_bytes());
            v.extend_from_slice(&cert_bytes);
            if cert_pad > 0 {
                v.extend_from_slice(&vec![0; cert_pad]);
            }

            v
        })
        .collect();

    let cert_len = signing_certs.len();

    let root_cnt = certs.len();

    // SHA of each Root Key. This needs to go into each image and _must_
    // match the SHA programmed in the CMPA area!
    let root_hashes = certs.iter().map(|c| {
        let root_bytes = std::fs::read(prefix.join(&c.cert_paths[0])).unwrap();
        let (_, root0) = x509_parser::parse_x509_certificate(&root_bytes).unwrap();
        let root0_pubkey =
            rsa::RsaPublicKey::from_pkcs1_der(root0.public_key().subject_public_key.as_ref())
                .unwrap();

        // We need the sha256 of the pubkeys. This is just the sha256
        // of n + e from the pubkey
        let n = root0_pubkey.n();
        let e = root0_pubkey.e();

        let mut sha = sha2::Sha256::new();
        sha.update(&n.to_bytes_be());
        sha.update(&e.to_bytes_be());
        let result = sha.finalize();
        let mut v: Vec<u8> = vec![0; 32];
        v.copy_from_slice(&result);
        v
    });

    // We're relying on packed_struct to catch errors of padding
    // or size since we know how big this should be
    let cert_header_size = CertHeader::packed_bytes_size(None)?;

    let mut new_cert_header: CertHeader = CertHeader::new(cert_header_size, cert_len);

    new_cert_header.certificate_count = signing_chain.cert_paths.len() as u32;

    // some math on how many bytes we sign
    //
    // Base image + padding
    // certificate header block
    // certificate length
    // 4 sha256 hashes
    let signed_len = bytes.len()
        + image_pad
        + cert_header_size
        + (new_cert_header.certificate_table_len as usize)
        + 32 * 4;

    // Total image length includes 256 bytes of signature
    let total_len = signed_len + 256;

    new_cert_header.total_image_len = signed_len.try_into().unwrap();

    let image_len = bytes.len();

    byteorder::LittleEndian::write_u32(&mut bytes[0x20..0x24], total_len as u32);

    let boot_field = BootField::new(BootImageType::SignedImage);

    bytes[0x24..0x28].clone_from_slice(&boot_field.pack()?);
    // Our execution address goes in the next word
    byteorder::LittleEndian::write_u32(&mut bytes[0x34..0x38], execution_address);
    // where to find the block. For now just stick it right after the image
    byteorder::LittleEndian::write_u32(&mut bytes[0x28..0x2c], (image_len + image_pad) as u32);

    let mut out = OpenOptions::new()
        .write(true)
        .truncate(true)
        .append(false)
        .create(true)
        .open(outfile_path)?;

    // Generate the image, see 7.3.4 of v2.4 UM 11126 for the layout
    out.write_all(&bytes)?;
    if image_pad > 0 {
        out.write_all(&vec![0; image_pad])?;
    }
    out.write_all(&new_cert_header.pack()?)?;
    out.write_all(&signing_certs)?;
    let mut rkth_sha = sha2::Sha256::new();
    for c in root_hashes {
        out.write_all(&c)?;
        rkth_sha.update(&c);
    }
    for _ in 0..(4 - root_cnt) {
        let empty_hash: [u8; 32] = [0; 32];
        out.write_all(&empty_hash)?;
        rkth_sha.update(empty_hash);
    }

    drop(out);

    // the easiest way to get the bytes we need to sign is to read back
    // what we just wrote
    let sign_bytes = std::fs::read(outfile_path)?;

    let mut img_hash = sha2::Sha256::new();
    img_hash.update(&sign_bytes);

    let priv_key_path = signing_chain.priv_key.as_ref().unwrap();
    let priv_key = rsa::RsaPrivateKey::read_pkcs1_pem_file(prefix.join(priv_key_path))
        .or_else(|_| rsa::RsaPrivateKey::read_pkcs8_pem_file(prefix.join(priv_key_path)))?;

    let sig = priv_key.sign(
        rsa::pkcs1v15::Pkcs1v15Sign::new::<rsa::sha2::Sha256>(),
        img_hash.finalize().as_slice(),
    )?;

    println!("Image signature {:x?}", sig);

    let mut out = OpenOptions::new()
        .write(true)
        .append(true)
        .open(outfile_path)?;

    out.write_all(sig.as_ref())?;
    drop(out);

    // TODO check the signature with the public key
    let rkth = rkth_sha.finalize();
    Ok(rkth.as_slice().try_into().expect("something went wrong?"))
}

pub fn sign_image(
    binary_path: &Path,
    priv_key_path: &Path,
    root_cert0_path: &Path,
    outfile_path: &Path,
    execution_address: u32,
) -> Result<[u8; 32]> {
    let mut bytes = std::fs::read(binary_path)?;
    let image_pad = get_pad(bytes.len());

    let priv_key = rsa::RsaPrivateKey::read_pkcs1_pem_file(priv_key_path)
        .or_else(|_| rsa::RsaPrivateKey::read_pkcs8_pem_file(priv_key_path))?;

    let root0_bytes = std::fs::read(root_cert0_path)?;
    let cert_pad = get_pad(root0_bytes.len());

    // We're relying on packed_struct to catch errors of padding
    // or size since we know how big this should be
    let cert_header_size = CertHeader::packed_bytes_size(None)?;

    let mut new_cert_header: CertHeader = CertHeader::new(
        cert_header_size,
        // This is the total length of all certificates (plus padding)
        // Plus 4 bytes to store the x509 certificate length
        root0_bytes.len() + 4 + cert_pad,
    );

    // some math on how many bytes we sign
    //
    // Base image + padding
    // certificate header block
    // 4 bytes for certificate length
    // certificate itself plus padding
    // 4 sha256 hashes
    let signed_len = bytes.len()
        + image_pad
        + cert_header_size
        + (new_cert_header.certificate_table_len as usize)
        + 32 * 4;

    // Total image length includes 256 bytes of signature
    let total_len = signed_len + 256;

    new_cert_header.total_image_len = signed_len.try_into().unwrap();

    let (_, root0) = x509_parser::parse_x509_certificate(&root0_bytes)?;

    let root0_pubkey =
        rsa::RsaPublicKey::from_pkcs1_der(root0.public_key().subject_public_key.as_ref())?;

    // We need the sha256 of the pubkeys. This is just the sha256
    // of n + e from the pubkey
    let n = root0_pubkey.n();
    let e = root0_pubkey.e();

    let mut sha = sha2::Sha256::new();
    sha.update(&n.to_bytes_be());
    sha.update(&e.to_bytes_be());
    let root0_sha = sha.finalize();

    let image_len = bytes.len();

    byteorder::LittleEndian::write_u32(&mut bytes[0x20..0x24], total_len as u32);

    let boot_field = BootField::new(BootImageType::SignedImage);

    bytes[0x24..0x28].clone_from_slice(&boot_field.pack()?);
    // Our execution address goes in the next word
    byteorder::LittleEndian::write_u32(&mut bytes[0x34..0x38], execution_address);
    // where to find the block. For now just stick it right after the image
    byteorder::LittleEndian::write_u32(&mut bytes[0x28..0x2c], (image_len + image_pad) as u32);

    let mut out = OpenOptions::new()
        .write(true)
        .truncate(true)
        .append(false)
        .create(true)
        .open(outfile_path)?;

    // Need to write out an empty sha since we only have one root key
    let empty_hash: [u8; 32] = [0; 32];

    out.write_all(&bytes)?;
    if image_pad > 0 {
        out.write_all(&vec![0; image_pad])?;
    }
    out.write_all(&new_cert_header.pack()?)?;
    out.write_u32::<byteorder::LittleEndian>((root0_bytes.len() + cert_pad) as u32)?;
    out.write_all(&root0_bytes)?;
    if cert_pad > 0 {
        out.write_all(&vec![0; cert_pad])?;
    }
    // We may eventually have more hashes
    out.write_all(&root0_sha)?;
    out.write_all(&empty_hash)?;
    out.write_all(&empty_hash)?;
    out.write_all(&empty_hash)?;

    // The sha256 of all the root keys gets put in in the CMPA area
    let mut rkth_sha = sha2::Sha256::new();
    rkth_sha.update(root0_sha);
    rkth_sha.update(empty_hash);
    rkth_sha.update(empty_hash);
    rkth_sha.update(empty_hash);

    let rkth = rkth_sha.finalize();

    drop(out);

    // the easiest way to get the bytes we need to sign is to read back
    // what we just wrote
    let sign_bytes = std::fs::read(outfile_path)?;

    let mut img_hash = sha2::Sha256::new();
    img_hash.update(&sign_bytes);

    let sig = priv_key.sign(
        rsa::pkcs1v15::Pkcs1v15Sign::new::<rsa::sha2::Sha256>(),
        img_hash.finalize().as_slice(),
    )?;

    println!("Image signature {:x?}", sig);

    let mut out = OpenOptions::new()
        .write(true)
        .append(true)
        .open(outfile_path)?;

    out.write_all(sig.as_ref())?;
    drop(out);

    Ok(rkth.as_slice().try_into().expect("something went wrong?"))
}

pub fn create_cmpa(
    with_dice: bool,
    with_dice_inc_nxp_cfg: bool,
    with_dice_cust_cfg: bool,
    with_dice_inc_sec_epoch: bool,
    rkth: &[u8; 32],
    cmpa_path: &Path,
) -> Result<()> {
    let mut cmpa_out = OpenOptions::new()
        .write(true)
        .truncate(true)
        .create(true)
        .open(cmpa_path)?;

    let mut secure_boot_cfg = SecureBootCfg::new();

    secure_boot_cfg.set_dice(with_dice);
    secure_boot_cfg.set_dice_inc_nxp_cfg(with_dice_inc_nxp_cfg);
    secure_boot_cfg.set_dice_inc_cust_cfg(with_dice_cust_cfg);
    secure_boot_cfg.set_dice_inc_sec_epoch(with_dice_inc_sec_epoch);
    secure_boot_cfg.set_sec_boot(true);

    let mut cmpa = CMPAPage::new();

    cmpa.set_secure_boot_cfg(secure_boot_cfg)?;
    cmpa.set_rotkh(rkth);

    cmpa.set_debug_fields(DebugSettings::new())?;
    cmpa.set_boot_cfg(DefaultIsp::Auto, BootSpeed::Fro96mhz)?;
    let cmpa_bytes = cmpa.pack()?;

    cmpa_out.write_all(&cmpa_bytes)?;
    Ok(())
}
