use crate::areas::*;
use anyhow::Result;
use byteorder::{ByteOrder, WriteBytesExt};
use elliptic_curve::generic_array::typenum::Unsigned;
use elliptic_curve::pkcs8::der::Decodable;
use p256::{
    ecdsa::{signature::Signer, SigningKey, VerifyingKey},
    pkcs8::FromPrivateKey,
    NistP256,
};
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

// This is a work in progress and should be treated as such!
//
// This is a butchering^Wrework of NXP's format for signed image
// to use ECC instead of RSA.
//
// We sign the same data as with RSA.

fn do_ecc_sign_image(binary_path: &Path, priv_key_path: &Path, outfile_path: &Path) -> Result<()> {
    let mut bytes = std::fs::read(binary_path)?;
    let image_pad = get_pad(bytes.len());

    let priv_key_bytes = std::fs::read(priv_key_path)?;

    // XXX is this the right way to be accessing this? Can we abstract
    // this more to avoid being tied to p256?
    let priv_key_pkcs8 = p256::pkcs8::PrivateKeyInfo::from_der(&priv_key_bytes).unwrap();

    let signing_key = SigningKey::from_pkcs8_private_key_info(priv_key_pkcs8).unwrap();
    let verify_key = VerifyingKey::from(&signing_key);

    // Based on the docs, this format should be
    // https://www.secg.org/sec1-v2.pdf.
    //
    // XXX is this format considered stable? If we needed to upgrade
    // RustCrypto versions would it break?
    let verify_key_point = verify_key.to_encoded_point(false);
    let cert_pad = get_pad(verify_key_point.len());

    // We're relying on packed_struct to catch errors of padding
    // or size since we know how big this should be
    let cert_header_size = CertHeader::packed_bytes_size(None)?;

    let mut new_cert_header: CertHeader = CertHeader::new(
        cert_header_size,
        // This is the total length of all certificates (plus padding)
        // Plus 4 bytes to store the pub key length
        verify_key_point.len() + 4 + cert_pad,
    );

    // some math on how many bytes we sign
    //
    // Base image + padding
    // certificate header block
    // 4 bytes for certificate length
    // certificate itself plus padding
    let signed_len = bytes.len()
        + image_pad
        + cert_header_size
        + (new_cert_header.certificate_table_len as usize);

    let max_sig_size = ecdsa::der::MaxSize::<NistP256>::to_usize();

    let total_len = signed_len + 4 + max_sig_size;

    new_cert_header.total_image_len = signed_len.try_into().unwrap();

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

    out.write_all(&bytes)?;
    if image_pad > 0 {
        out.write_all(&vec![0; image_pad])?;
    }
    out.write_all(&new_cert_header.pack()?)?;
    out.write_u32::<byteorder::LittleEndian>((verify_key_point.len()) as u32)?;
    out.write_all(&verify_key_point.as_bytes())?;
    if cert_pad > 0 {
        out.write_all(&vec![0; cert_pad])?;
    }

    drop(out);

    let sign_bytes = std::fs::read(outfile_path)?;
    let sig = signing_key.sign(&sign_bytes);

    let sig_len = sig.to_der().as_bytes().len();

    println!("Image signature {:x?}", sig.to_der().as_bytes());

    let mut out = OpenOptions::new()
        .write(true)
        .append(true)
        .open(outfile_path)?;
    // XXX work out what to do. It seems like this _should_ work without
    // having to go full asn1 but I can't find the functions?
    out.write_u32::<byteorder::LittleEndian>(sig_len as u32)?;
    out.write_all(sig.to_der().as_bytes())?;
    if max_sig_size - sig_len > 0 {
        out.write_all(&vec![0; max_sig_size - sig_len])?;
    }

    drop(out);

    Ok(())
}

pub fn ecc_sign_image(src_bin: &Path, priv_key: &Path, dest_bin: &Path) -> Result<()> {
    do_ecc_sign_image(&src_bin, &priv_key, &dest_bin)
}
