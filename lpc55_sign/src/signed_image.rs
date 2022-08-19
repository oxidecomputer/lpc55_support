// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::areas::*;
use anyhow::Result;
use byteorder::{ByteOrder, WriteBytesExt};
use rsa::{pkcs1::FromRsaPrivateKey, pkcs1::FromRsaPublicKey, PublicKeyParts};
use sha2::Digest;

use packed_struct::prelude::*;
use std::convert::TryInto;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

fn get_pad(val: usize) -> usize {
    match val.checked_rem(4) {
        Some(s) if s > 0 => 4 - s,
        _ => 0,
    }
}

pub fn sign_image(
    binary_path: &Path,
    priv_key_path: &Path,
    root_cert0_path: &Path,
    outfile_path: &Path,
) -> Result<[u8; 32]> {
    let mut bytes = std::fs::read(binary_path)?;
    let image_pad = get_pad(bytes.len());

    let priv_key = rsa::RsaPrivateKey::read_pkcs1_pem_file(priv_key_path)?;

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
    // Our execution address is always 0
    byteorder::LittleEndian::write_u32(&mut bytes[0x34..0x38], 0x0);
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
    rkth_sha.update(&root0_sha);
    rkth_sha.update(&empty_hash);
    rkth_sha.update(&empty_hash);
    rkth_sha.update(&empty_hash);

    let rkth = rkth_sha.finalize();

    drop(out);

    // the easiest way to get the bytes we need to sign is to read back
    // what we just wrote
    let sign_bytes = std::fs::read(outfile_path)?;

    let mut img_hash = sha2::Sha256::new();
    img_hash.update(&sign_bytes);

    let sig = priv_key.sign(
        rsa::padding::PaddingScheme::PKCS1v15Sign {
            hash: Some(rsa::hash::Hash::SHA2_256),
        },
        img_hash.finalize().as_slice(),
    )?;

    println!("Image signature {:x?}", sig);

    let mut out = OpenOptions::new()
        .write(true)
        .append(true)
        .open(outfile_path)?;

    out.write_all(&sig)?;
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

    if with_dice {
        secure_boot_cfg.skip_dice = EnableDiceStatus::EnableDice.into();
    } else {
        secure_boot_cfg.skip_dice = EnableDiceStatus::DisableDice1.into();
    }

    // fields are disabled by default
    if with_dice_inc_nxp_cfg {
        secure_boot_cfg.dice_inc_nxp_cfg = DiceNXPIncStatus::Included1.into();
    }
    if with_dice_cust_cfg {
        secure_boot_cfg.dice_cust_cfg = DiceCustIncStatus::Included1.into();
    }
    if with_dice_inc_sec_epoch {
        secure_boot_cfg.dice_inc_sec_epoch = DiceIncSecEpoch::Included1.into();
    }

    secure_boot_cfg.sec_boot_en = SecBootStatus::SignedImage3.into();

    let cmpa = CMPAPage::new(secure_boot_cfg)?;

    let mut cmpa_bytes = cmpa.pack()?;

    cmpa_bytes[0x50..0x70].clone_from_slice(rkth);
    cmpa_out.write_all(&cmpa_bytes)?;
    Ok(())
}
