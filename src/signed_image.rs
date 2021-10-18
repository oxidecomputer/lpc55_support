use crate::areas::*;
use anyhow::Result;
use byteorder::{ByteOrder, WriteBytesExt};
use openssl::{hash, pkey, rsa, sha, sign, x509};
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

fn do_signed_image(
    binary_path: &Path,
    priv_key_path: &Path,
    root_cert0_path: &Path,
    outfile_path: &Path,
) -> Result<[u8; 32]> {
    let mut bytes = std::fs::read(binary_path)?;
    let image_pad = get_pad(bytes.len());

    let priv_key_bytes = std::fs::read(priv_key_path)?;
    let priv_key = rsa::Rsa::private_key_from_pem(&priv_key_bytes)?;

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

    let root0: x509::X509 = x509::X509::from_der(&root0_bytes)?;

    let root0_pubkey = root0.public_key().unwrap().rsa()?;

    // We need the sha256 of the pubkeys. This is just the sha256
    // of n + e from the pubkey
    let n = root0_pubkey.n();
    let e = root0_pubkey.e();

    let mut sha = sha::Sha256::new();
    sha.update(&n.to_vec());
    sha.update(&e.to_vec());
    let root0_sha = sha.finish();

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
    let mut rkth_sha = sha::Sha256::new();
    rkth_sha.update(&root0_sha);
    rkth_sha.update(&empty_hash);
    rkth_sha.update(&empty_hash);
    rkth_sha.update(&empty_hash);

    let rkth = rkth_sha.finish();

    drop(out);

    let pkey = pkey::PKey::from_rsa(priv_key)?;
    let mut signer = sign::Signer::new(hash::MessageDigest::sha256(), &pkey)?;

    // the easiest way to get the bytes we need to sign is to read back
    // what we just wrote
    let sign_bytes = std::fs::read(outfile_path)?;
    signer.set_rsa_padding(rsa::Padding::PKCS1)?;
    signer.update(&sign_bytes)?;
    let sig = signer.sign_to_vec()?;

    println!("Image signature {:x?}", sig);

    let mut out = OpenOptions::new()
        .write(true)
        .append(true)
        .open(outfile_path)?;

    out.write_all(&sig)?;
    drop(out);

    Ok(rkth)
}

fn do_cmpa(cmpa_path: &Path, rkth: &[u8; 32]) -> Result<()> {
    let mut cmpa_out = OpenOptions::new()
        .write(true)
        .truncate(true)
        .create(true)
        .open(cmpa_path)?;

    let mut secure_boot_cfg = SecureBootCfg::new();

    secure_boot_cfg.skip_dice = EnableDiceStatus::DisableDice1.into();
    secure_boot_cfg.sec_boot_en = SecBootStatus::SignedImage3.into();

    let cmpa = CMPAPage::new(secure_boot_cfg)?;

    let mut cmpa_bytes = cmpa.pack()?;

    cmpa_bytes[0x50..0x70].clone_from_slice(rkth);
    cmpa_out.write_all(&cmpa_bytes)?;
    Ok(())
}

pub fn sign_image(
    src_bin: &Path,
    priv_key: &Path,
    root_cert0: &Path,
    dest_bin: &Path,
    cmpa_dest: &Path,
) -> Result<()> {
    let rkth = do_signed_image(&src_bin, &priv_key, &root_cert0, &dest_bin)?;

    do_cmpa(&cmpa_dest, &rkth)?;

    Ok(())
}
