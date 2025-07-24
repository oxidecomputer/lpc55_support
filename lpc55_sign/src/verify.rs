// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::{cert, Error};
use der::Encode as _;
use hex::ToHex as _;
use log::{info, warn};
use lpc55_areas::{
    BootField, BootImageType, CFPAPage, CMPAPage, CertHeader, ROTKeyStatus, RSA4KStatus,
    SecBootStatus, TZMImageStatus, TzmImageType, TzmPreset, HEADER_IMAGE_LENGTH, HEADER_IMAGE_TYPE,
    HEADER_LOAD_ADDR, HEADER_OFFSET,
};
use packed_struct::{EnumCatchAll, PackedStruct};
use rsa::{
    pkcs1v15::{Signature, VerifyingKey},
    signature::Verifier as _,
    traits::PublicKeyParts,
    RsaPublicKey,
};
use sha2::{Digest as _, Sha256};
use std::fmt::Write;
use std::io::Write as _;
use x509_cert::Certificate;

/// Initializes a logger that pretty-prints logging from `verify_image`
pub fn init_verify_logger(verbose: bool) {
    let mut builder = env_logger::Builder::from_default_env();
    builder
        .format(|buf, record| {
            let mut level_style = buf.style();

            level_style.set_color(match record.level() {
                log::Level::Info => env_logger::fmt::Color::Cyan,
                log::Level::Trace => env_logger::fmt::Color::Blue,
                log::Level::Warn => env_logger::fmt::Color::Yellow,
                log::Level::Error => env_logger::fmt::Color::Red,
                log::Level::Debug => env_logger::fmt::Color::Green,
            });

            writeln!(
                buf,
                "{: <5} | {}",
                level_style.value(match record.level() {
                    log::Level::Info => "",
                    log::Level::Trace => "",
                    log::Level::Warn => "WARN",
                    log::Level::Error => "ERROR",
                    log::Level::Debug => "OKAY",
                }),
                record.args().to_string().replace('\n', "\n      | ")
            )
        })
        .filter(
            None,
            if verbose {
                log::LevelFilter::Trace
            } else {
                log::LevelFilter::Debug
            },
        )
        .init();
}

pub fn verify_image(image: &[u8], cmpa: CMPAPage, cfpa: CFPAPage) -> Result<(), Error> {
    let secure_boot_cfg = cmpa.get_secure_boot_cfg()?;

    let secure_boot_enabled = matches!(
        secure_boot_cfg.sec_boot_en,
        SecBootStatus::SignedImage1 | SecBootStatus::SignedImage2 | SecBootStatus::SignedImage3
    );

    if cmpa.sha256_digest != [0; 32] {
        let cmpa_bytes = cmpa.pack()?;
        let mut cmpa_sha = sha2::Sha256::new();
        cmpa_sha.update(&cmpa_bytes[0..cmpa_bytes.len() - 32]);
        let expected_hash: [u8; 32] = cmpa_sha.finalize().into();
        if expected_hash != cmpa.sha256_digest {
            return Err(Error::CmpaDigestMismatch);
        }
    }

    if secure_boot_enabled {
        if cmpa.rotkh == [0u8; 32] {
            return Err(Error::NoRootCerts);
        }

        if (!cmpa.cc_socu_pin >> 16) as u16 != cmpa.cc_socu_pin as u16 {
            return Err(Error::InvalidCCSOCUPIN(
                "CMPA".to_string(),
                cmpa.cc_socu_pin,
            ));
        }
        if (!cmpa.cc_socu_dflt >> 16) as u16 != cmpa.cc_socu_dflt as u16 {
            return Err(Error::InvalidCCSOCUDFLT(
                "CMPA".to_string(),
                cmpa.cc_socu_dflt,
            ));
        }
        for i in 0..16 {
            if cmpa.cc_socu_dflt & (1 << i) != 0 && cmpa.cc_socu_pin & (1 << i) == 0 {
                return Err(Error::IllegalSocu("CMPA".to_string(), i));
            }
        }
    }

    let rkth_revoke = cfpa.get_rkth_revoke()?;

    // TODO: decide if we want to check CFPA digest

    if secure_boot_enabled {
        let at_least_one_rtkh_slot_enabled = (rkth_revoke.rotk0 == ROTKeyStatus::Enabled)
            | (rkth_revoke.rotk1 == ROTKeyStatus::Enabled)
            | (rkth_revoke.rotk2 == ROTKeyStatus::Enabled)
            | (rkth_revoke.rotk3 == ROTKeyStatus::Enabled);
        if !at_least_one_rtkh_slot_enabled {
            return Err(Error::NoRtkhEnabled);
        }

        if (cfpa.dcfg_cc_socu_ns_pin >> 16) as u16 != (!cfpa.dcfg_cc_socu_ns_pin & 0xFFFF) as u16 {
            return Err(Error::InvalidCCSOCUPIN(
                "CFPA".to_string(),
                cfpa.dcfg_cc_socu_ns_pin,
            ));
        }
        if (cfpa.dcfg_cc_socu_ns_dflt >> 16) as u16 != (!cfpa.dcfg_cc_socu_ns_dflt & 0xFFFF) as u16
        {
            return Err(Error::InvalidCCSOCUDFLT(
                "CFPA".to_string(),
                cfpa.dcfg_cc_socu_ns_dflt,
            ));
        }
        for i in 0..16 {
            if cfpa.dcfg_cc_socu_ns_dflt & (1 << i) != 0 && cfpa.dcfg_cc_socu_ns_pin & (1 << i) == 0
            {
                return Err(Error::IllegalSocu("CFPA".to_string(), i));
            }
        }
    }

    let cfpa_image_key_revoke = (cfpa.image_key_revoke & 0xFFFF) as u16;
    if !crate::is_unary(cfpa_image_key_revoke) {
        warn!(
            "IMAGE_KEY_REVOKE (0x{cfpa_image_key_revoke:04x}) should be a unary counter but isn't"
        )
    }

    // Check CMPA / CFPA consistency; this isn't a hard error, but could be
    // suspicious and worth investigating.
    if secure_boot_enabled {
        if cmpa.cc_socu_pin != cfpa.dcfg_cc_socu_ns_pin {
            warn!(
                "CMPA.CC_SOCU_PIN ({:08x}) != CFPA.DCFG_CC_SOCU_NS_PIN ({:08x})",
                cmpa.cc_socu_pin, cfpa.dcfg_cc_socu_ns_pin
            );
        }
        if cmpa.cc_socu_dflt != cfpa.dcfg_cc_socu_ns_dflt {
            warn!(
                "CMPA.CC_SOCU_DFLT ({:08x}) != CFPA.DCFG_CC_SOCU_NS_DFLT ({:08x})",
                cmpa.cc_socu_dflt, cfpa.dcfg_cc_socu_ns_dflt
            );
        }
    }

    let image_len = u32::from_le_bytes(image[0x20..0x24].try_into().unwrap());
    if (image_len as usize) > image.len() {
        return Err(Error::ImageLengthTooLong);
    }

    let image_type = BootField::unpack(image[0x24..0x28].try_into().unwrap())?;

    match secure_boot_cfg.tzm_image_type {
        TZMImageStatus::PresetTZM => {
            if image_type.tzm_preset == TzmPreset::NotPresent {
                return Err(Error::TzPresetErr);
            }
        }
        TZMImageStatus::InImageHeader => (),
        TZMImageStatus::DisableTZM => {
            if image_type.tzm_image_type == TzmImageType::Enabled
                || image_type.tzm_preset == TzmPreset::Present
            {
                return Err(Error::TzPresetErr);
            }
        }
        TZMImageStatus::EnableTZM => {
            if image_type.tzm_image_type == TzmImageType::Disabled {
                return Err(Error::TzPresetErr);
            }
        }
    }

    match image_type.img_type {
        EnumCatchAll::Enum(BootImageType::SignedImage) => {
            check_signed_image(image, cmpa, cfpa)?;
        }
        EnumCatchAll::Enum(BootImageType::CRCImage) => {
            if secure_boot_enabled {
                return Err(Error::NotASecureImage);
            }
            check_crc_image(image)?;
        }
        EnumCatchAll::Enum(BootImageType::PlainImage) => {
            if secure_boot_enabled {
                return Err(Error::NotASecureImage);
            }
            check_plain_image(image)?;
        }
        e => panic!("do not know how to check {e:?}"),
    }

    Ok(())
}

pub fn print_image(image: &[u8]) -> Result<(), Error> {
    info!("=== Image ====");
    let image_len = u32::from_le_bytes(image[HEADER_IMAGE_LENGTH].try_into().unwrap());
    let image_type = BootField::unpack(image[HEADER_IMAGE_TYPE].try_into().unwrap())?;
    let load_addr = u32::from_le_bytes(image[HEADER_LOAD_ADDR].try_into().unwrap());
    info!("image length: {image_len:#x} ({image_len})");
    info!("image type: {image_type:#?}");
    info!("load address: {load_addr:#x}");

    match image_type.img_type {
        EnumCatchAll::Enum(BootImageType::SignedImage) => {
            let header_offset = u32::from_le_bytes(image[HEADER_OFFSET].try_into().unwrap());
            let cert_header_size = std::mem::size_of::<CertHeader>();
            let cert_header = CertHeader::unpack(
                image[header_offset as usize..][..cert_header_size]
                    .try_into()
                    .unwrap(),
            )?;
            info!("header offset: {header_offset:#x} ({header_offset})");
            info!("cert header: {cert_header:#x?}");
            info!("data.len(): {:#x}", image.len());

            // If the cert header is bad the rest of the data is likely bad too
            // so just bail
            if cert_header.signature != *b"cert" {
                return Err(Error::MissingCertHeader);
            }

            let mut start = (header_offset + cert_header.header_length) as usize;
            let mut certs: Vec<Certificate> = vec![];

            for i in 0..cert_header.certificate_count {
                let x509_length = u32::from_le_bytes(image[start..start + 4].try_into().unwrap());
                info!("Certificate [{}/{}]", i + 1, cert_header.certificate_count);
                info!("    certificate length: {x509_length}");
                start += 4;
                let cert = &image[start..start + x509_length as usize];
                let cert = cert::read_from_slice(cert)?;
                let subject = &cert.tbs_certificate.subject;
                let issuer = &cert.tbs_certificate.issuer;
                info!(
                    "    Subject:\n      {}",
                    subject.to_string().replace(", ", "\n      ")
                );
                info!(
                    "    Issuer:\n      {}",
                    issuer.to_string().replace(", ", "\n      ")
                );
                info!(
                    "    Algorithm:\n   {}",
                    cert::signature_algorithm_name(&cert)
                );
                info!("    Serial:\n      {}", cert.tbs_certificate.serial_number);
                certs.push(cert);
                start += x509_length as usize;
            }

            let mut rkh_table = vec![];
            let mut rkh_sha = sha2::Sha256::new();
            for i in 0..4 {
                let rot_hash = &image[start..start + 32];
                info!("Root key hash {i}: ");
                info!("  {}", rot_hash.encode_hex::<String>());
                rkh_sha.update(rot_hash);
                rkh_table.push(rot_hash.to_owned());
                start += 32;
            }
            let mut s = String::new();
            for b in rkh_sha.finalize() {
                write!(s, "{:02x}", b)?;
            }
            info!("RKHT sha: {}", s);
        }
        EnumCatchAll::Enum(BootImageType::CRCImage) => {
            let crc = u32::from_le_bytes(image[HEADER_OFFSET].try_into().unwrap());
            info!("Expected CRC: {:x}", crc);
        }
        EnumCatchAll::Enum(BootImageType::PlainImage) => (),
        e => panic!("do not know how to check {e:?}"),
    }

    Ok(())
}

pub fn print_cmpa(cmpa: CMPAPage) -> Result<(), Error> {
    let boot_cfg = cmpa.get_boot_cfg()?;
    info!("boot_cfg = {boot_cfg:#?}");
    info!("spi_flash_cfg = {}", cmpa.spi_flash_cfg);
    info!("usb_id = {}", cmpa.usb_id);
    info!("sdio_cfg = {}", cmpa.sdio_cfg);
    info!("cc_socu_pin = {:#?}", cmpa.get_cc_socu_pin()?);
    info!("cc_socu_dflt = {:#?}", cmpa.get_cc_socu_dflt()?);
    info!("vendor_usage = {}", cmpa.vendor_usage);
    info!("secure_boot_cfg = {:#?}", cmpa.get_secure_boot_cfg()?);
    info!("prince_base_addr = {}", cmpa.prince_base_addr);
    info!("prince_sr_0 = {}", cmpa.prince_sr_0);
    info!("prince_sr_1 = {}", cmpa.prince_sr_1);
    info!("prince_sr_2 = {}", cmpa.prince_sr_2);
    info!(
        "xtal_32khz_capabank_trim = {}",
        cmpa.xtal_32khz_capabank_trim
    );
    info!(
        "xtal_16khz_capabank_trim = {}",
        cmpa.xtal_16khz_capabank_trim
    );
    info!("flash_remap_size = {}", cmpa.flash_remap_size);
    if cmpa.blank1 == [0; 20] {
        info!("blank1 = (zeroes)");
    } else {
        info!("blank1 = {:?}", cmpa.blank1);
    }
    let mut s = String::new();
    for byte in cmpa.rotkh {
        write!(s, "{byte:02x}")?;
    }
    info!("rotkh = {}", s);
    info!("");
    for (i, b) in [
        &cmpa.blank2[..],
        &cmpa.blank3,
        &cmpa.blank4,
        &cmpa.blank5,
        &cmpa.blank6,
    ]
    .into_iter()
    .enumerate()
    {
        let n = i + 2;
        if b.iter().all(|byte| *byte == 0) {
            info!("blank{n} = (zeroes)");
        } else {
            info!("blank{n} = {:?}", b);
        }
    }
    info!("Customer defined area:");
    for chunk in [
        &cmpa.customer_defined0,
        &cmpa.customer_defined1,
        &cmpa.customer_defined2,
        &cmpa.customer_defined3,
        &cmpa.customer_defined4,
        &cmpa.customer_defined5,
        &cmpa.customer_defined6,
    ] {
        info!("{:x?}", chunk);
    }

    let mut s = String::new();
    for byte in cmpa.sha256_digest {
        write!(s, "{byte:02x}")?;
    }
    info!("sha256 = {}", s);
    Ok(())
}

pub fn print_cfpa(cfpa: CFPAPage) -> Result<(), Error> {
    info!("header = {}", cfpa.header);
    info!("version = {}", cfpa.version);
    info!("secure_firmware_version = {}", cfpa.secure_firmware_version);
    info!("nonsecure_firmware_version = {}", cfpa.ns_fw_version);
    info!("image_key_revoke = {}", cfpa.image_key_revoke);
    info!("reserved = {}", cfpa.reserved);
    info!("rkth_revoke = {:#?}", cfpa.get_rkth_revoke()?);
    info!("vendor = {}", cfpa.vendor);
    info!("cc_socu_ns_pin = {:#?}", cfpa.get_cc_socu_ns_pin()?);
    info!("cc_socu_ns_dflt = {:#?}", cfpa.get_cc_socu_ns_dflt()?);
    info!("enable_fa_mode = {}", cfpa.enable_fa_mode);
    info!("cmpa_prog_in_progress = {}", cfpa.cmpa_prog_in_progress);
    info!("prince_region0_code0 = {:?}", cfpa.prince_region0_code0);
    info!("prince_region0_code1 = {:?}", cfpa.prince_region0_code1);
    info!("prince_region1_code0 = {:?}", cfpa.prince_region1_code0);
    info!("prince_region1_code1 = {:?}", cfpa.prince_region1_code1);
    info!("prince_region2_code0 = {:?}", cfpa.prince_region2_code0);
    info!("prince_region2_code1 = {:?}", cfpa.prince_region2_code1);
    info!("mysterious1 = {:?}", cfpa.mysterious1);
    info!("mysterious2 = {:?}", cfpa.mysterious2);
    info!("customer defined:");
    for chunk in [
        &cfpa.customer_defined0,
        &cfpa.customer_defined1,
        &cfpa.customer_defined2,
        &cfpa.customer_defined3,
        &cfpa.customer_defined4,
        &cfpa.customer_defined5,
        &cfpa.customer_defined6,
    ] {
        info!("{:x?}", chunk);
    }
    info!("sha256 = {:x?}", cfpa.sha256_digest);
    Ok(())
}

fn check_signed_image(image: &[u8], cmpa: CMPAPage, cfpa: CFPAPage) -> Result<(), Error> {
    let header_offset = u32::from_le_bytes(image[0x28..0x2c].try_into().unwrap());

    let cert_header_size = std::mem::size_of::<CertHeader>();
    let cert_header = CertHeader::unpack(
        image[header_offset as usize..][..cert_header_size]
            .try_into()
            .unwrap(),
    )?;
    if cert_header.signature != *b"cert" {
        return Err(Error::MissingCertHeader);
    }

    let expected_len =
        header_offset + cert_header.header_length + cert_header.certificate_table_len + 32 * 4;
    if cert_header.total_image_len != expected_len {
        return Err(Error::InvalidImageLen(
            expected_len,
            cert_header.total_image_len,
        ));
    }

    let mut start = (header_offset + cert_header.header_length) as usize;
    let mut certs: Vec<Certificate> = vec![];
    for _ in 0..cert_header.certificate_count {
        let x509_length = u32::from_le_bytes(image[start..start + 4].try_into().unwrap());
        start += 4;
        let cert = &image[start..start + x509_length as usize];
        let cert = cert::read_from_slice(cert)?;

        let cmpa_rsa4k = cmpa.get_secure_boot_cfg()?.rsa4k;
        let public_key_bits = cert::public_key(&cert).unwrap().size() * 8;
        if !matches!(
            (cmpa_rsa4k, public_key_bits),
            (RSA4KStatus::RSA2048Keys, 2048)
                | (RSA4KStatus::RSA4096Only1, 4096)
                | (RSA4KStatus::RSA4096Only2, 4096)
                | (RSA4KStatus::RSA4096Only3, 4096)
        ) {
            return Err(Error::InvalidPubkeySize(
                public_key_bits,
                cmpa_rsa4k as usize,
            ));
        }

        if !cert::uses_supported_signature_algorithm(&cert) {
            return Err(Error::UnsupportedAlgorithm(cert::signature_algorithm_name(
                &cert,
            )));
        }

        let prev_public_key = certs.last().map(|prev| cert::public_key(prev).unwrap());
        // If this is the root certificate, then `prev_public_key` is `None` and
        // `verify_cert_signature` checks that it is correctly self-signed.
        verify_cert_signature(&cert, prev_public_key)?;

        certs.push(cert);
        start += x509_length as usize;
    }

    let mut rkh_table = vec![];
    let mut rkh_sha = sha2::Sha256::new();
    for _ in 0..4 {
        let rot_hash = &image[start..start + 32];
        rkh_sha.update(rot_hash);
        rkh_table.push(rot_hash.to_owned());
        start += 32;
    }

    if rkh_sha.finalize().as_slice() != cmpa.rotkh {
        return Err(Error::RotkhMismatch);
    }

    let mut sha = sha2::Sha256::new();
    let public_key_rsa = cert::public_key(&certs[0])?;
    sha.update(public_key_rsa.n().to_bytes_be());
    sha.update(public_key_rsa.e().to_bytes_be());
    let out = sha.finalize().to_vec();
    if let Some((index, _)) = rkh_table.iter().enumerate().find(|(_, k)| *k == &out) {
        let rkth_revoke = cfpa.get_rkth_revoke()?;
        let rotk_status = match index {
            0 => rkth_revoke.rotk0,
            1 => rkth_revoke.rotk1,
            2 => rkth_revoke.rotk2,
            3 => rkth_revoke.rotk3,
            _ => unreachable!("rkh_table must be exactly 4 elements"),
        };
        match rotk_status {
            ROTKeyStatus::Invalid => {
                return Err(Error::KeyDisabled(index));
            }
            ROTKeyStatus::Enabled => (),
            ROTKeyStatus::Revoked1 | ROTKeyStatus::Revoked2 => {
                return Err(Error::KeyRevoked(index));
            }
        }
    } else {
        return Err(Error::PubkeyNotInTable);
    }

    let last_cert = &certs.last().unwrap();

    let last_cert_sn = last_cert.tbs_certificate.serial_number.as_bytes();
    let last_cert_sn_magic = &last_cert_sn[0..2];
    if last_cert_sn_magic != [0x3c, 0xc3] {
        return Err(Error::BadSerialPrefix(
            last_cert_sn_magic.encode_hex::<String>(),
        ));
    }

    let last_cert_sn_revoke_id = u16::from_le_bytes(last_cert_sn[2..4].try_into().unwrap());
    if !crate::is_unary(last_cert_sn_revoke_id) {
        warn!("Last certificate's revocation ID (0x{last_cert_sn_revoke_id:04x}) should be a unary counter but isn't")
    }

    let cfpa_image_key_revoke = (cfpa.image_key_revoke & 0xFFFF) as u16;
    let next_image_key_revoke = cfpa_image_key_revoke << 1 | 1;
    match last_cert_sn_revoke_id {
        x if x == cfpa_image_key_revoke => (),
        x if x == next_image_key_revoke => (),
        _ => {
            return Err(Error::BadRevocation(
                last_cert_sn_revoke_id,
                cfpa_image_key_revoke,
            ));
        }
    }

    let public_key_rsa = cert::public_key(certs.last().unwrap())?;
    let signature = &Signature::try_from(&image[start..]).unwrap();
    verify_signature(public_key_rsa, &image[..start], signature)?;
    Ok(())
}

fn check_crc_image(image: &[u8]) -> Result<(), Error> {
    let mut crc = crc_any::CRCu32::crc32mpeg2();
    crc.digest(&image[..HEADER_OFFSET.start]);
    crc.digest(&image[HEADER_OFFSET.end..]);
    let expected = crc.get_crc();
    let actual = u32::from_le_bytes(image[HEADER_OFFSET].try_into().unwrap());
    if expected != actual {
        return Err(Error::BadCrc);
    }
    Ok(())
}

fn check_plain_image(_image: &[u8]) -> Result<(), Error> {
    // Nothing to check for plain image
    Ok(())
}

fn verify_cert_signature(
    cert: &Certificate,
    public_key: Option<RsaPublicKey>,
) -> Result<(), Error> {
    let tbs = cert.tbs_certificate.to_der()?;
    let public_key = public_key.unwrap_or_else(|| cert::public_key(cert).unwrap());
    let signature = Signature::try_from(cert.signature.raw_bytes()).unwrap();
    verify_signature(public_key, &tbs, &signature)
}

fn verify_signature(
    public_key: RsaPublicKey,
    message: &[u8],
    signature: &Signature,
) -> Result<(), Error> {
    let verifying_key = VerifyingKey::<Sha256>::new(public_key);
    Ok(verifying_key.verify(message, signature)?)
}
