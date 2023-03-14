// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::Error;
use log::{debug as okay, error, info, trace, warn};
use lpc55_areas::{
    BootField, BootImageType, CFPAPage, CMPAPage, CertHeader, ROTKeyStatus, SecBootStatus,
    TZMImageStatus, TzmImageType, TzmPreset,
};
use packed_struct::{EnumCatchAll, PackedStruct};
use rsa::{pkcs1::DecodeRsaPublicKey, signature::Verifier, PublicKeyParts};
use sha2::Digest;
use std::fmt::Write as _;
use std::io::Write as _;

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
    let mut failed = false;

    info!("=== CMPA ====");
    let boot_cfg = cmpa.get_boot_cfg()?;
    let secure_boot_cfg = cmpa.get_secure_boot_cfg()?;
    let cc_socu_pin = cmpa.get_cc_socu_pin()?;
    let cc_socu_dflt = cmpa.get_cc_socu_dflt()?;

    trace!("{:#?}", boot_cfg);
    trace!("{:#?}", secure_boot_cfg);
    trace!("{:#?}", cc_socu_pin);
    trace!("{:#?}", cc_socu_dflt);
    trace!("ROTKH: {:}", hex::encode(cmpa.rotkh));
    info!("No CMPA verification implemented");

    info!("=== CFPA ====");
    let rkth_revoke = cfpa.get_rkth_revoke()?;

    trace!("Version: {:x}", cfpa.version);
    trace!("Secure FW Version: {:x}", cfpa.secure_firmware_version);
    trace!("Non-secure FW Version: {:x}", cfpa.ns_fw_version);
    trace!("Image key revoke: {:x}", cfpa.image_key_revoke);
    trace!("{:#?}", rkth_revoke);
    info!("No CFPA verification implemented");

    info!("=== Image ====");
    let image_len = u32::from_le_bytes(image[0x20..0x24].try_into().unwrap());
    let image_type = BootField::unpack(image[0x24..0x28].try_into().unwrap())?;

    let load_addr = u32::from_le_bytes(image[0x34..0x38].try_into().unwrap());
    let is_plain = image_type.img_type == EnumCatchAll::Enum(BootImageType::PlainImage);

    trace!("image length: {image_len:#x} ({image_len})");
    trace!("image type: {image_type:#?}");
    trace!("load address: {load_addr:#x}");
    if is_plain && load_addr != 0 {
        warn!("Load address is non-0 in a plain image",);
    } else if !is_plain && load_addr == 0 {
        warn!("Load address is 0 in a non-plain image",);
    }

    let secure_boot_enabled = matches!(
        secure_boot_cfg.sec_boot_en,
        SecBootStatus::SignedImage1 | SecBootStatus::SignedImage2 | SecBootStatus::SignedImage3
    );
    trace!("secure boot enabled in CMPA: {secure_boot_enabled}");

    info!("Checking TZM configuration");
    match secure_boot_cfg.tzm_image_type {
        TZMImageStatus::PresetTZM => {
            if image_type.tzm_preset == TzmPreset::NotPresent {
                error!("    CFPA requires TZ preset, but image header says it is not present");
                failed = true;
            } else {
                todo!("don't yet know how to decode TZ preset");
            }
        }
        TZMImageStatus::InImageHeader => {
            if image_type.tzm_image_type == TzmImageType::Enabled {
                if image_type.tzm_preset == TzmPreset::Present {
                    todo!("don't yet know how to decode TZ preset");
                } else {
                    okay!("    TZM enabled in image header, without preset data");
                }
            } else {
                okay!("    TZM disabled in image header");
            }
        }
        TZMImageStatus::DisableTZM => {
            if image_type.tzm_image_type == TzmImageType::Enabled {
                error!("    CFPA requires TZ disabled, but image header says it is enabled");
                failed = true;
            } else if image_type.tzm_preset == TzmPreset::Present {
                error!("    CFPA requires TZ disabled, but image header has tzm_preset");
                failed = true;
            } else {
                okay!("    TZM disabled in CMPA and in image header");
            }
        }
        TZMImageStatus::EnableTZM => {
            if image_type.tzm_image_type == TzmImageType::Disabled {
                error!("    CFPA requires TZ enabled, but image header says it is disabled");
                failed = true;
            } else if image_type.tzm_preset == TzmPreset::Present {
                todo!("don't yet know how to decode TZ preset");
            } else {
                okay!("    TZM enabled in CMPA and in image header, without preset data");
            }
        }
    }

    match image_type.img_type {
        EnumCatchAll::Enum(BootImageType::SignedImage) => {
            failed |= check_signed_image(image, cmpa, cfpa)?;
        }
        EnumCatchAll::Enum(BootImageType::CRCImage) => {
            if secure_boot_enabled {
                error!("Secure boot enabled in CPFA, but this is a CRC image");
                failed = true;
            }
            failed |= check_crc_image(image)?
        }
        EnumCatchAll::Enum(BootImageType::PlainImage) => {
            if secure_boot_enabled {
                error!("Secure boot enabled in CPFA, but this is a plain image");
                failed = true;
            }
            failed |= check_plain_image(image)?
        }
        e => panic!("do not know how to check {e:?}"),
    }

    if failed {
        Err(Error::VerificationFailed)
    } else {
        Ok(())
    }
}

fn check_signed_image(image: &[u8], cmpa: CMPAPage, cfpa: CFPAPage) -> Result<bool, Error> {
    let mut failed = false;
    let header_offset = u32::from_le_bytes(image[0x28..0x2c].try_into().unwrap());

    let cert_header_size = std::mem::size_of::<CertHeader>();
    let cert_header = CertHeader::unpack(
        image[header_offset as usize..][..cert_header_size]
            .try_into()
            .unwrap(),
    )?;
    trace!("header offset: {header_offset:#x} ({header_offset})");
    trace!("cert header: {cert_header:#x?}");
    trace!("data.len(): {:#x}", image.len());

    if cert_header.signature != *b"cert" {
        error!("Certificate header does not begin with 'cert'");
        failed = true;
    } else {
        okay!("Verified certificate header signature ('cert')");
    }

    let expected_len =
        header_offset + cert_header.header_length + cert_header.certificate_table_len + 32 * 4;
    if cert_header.total_image_len != expected_len {
        error!(
            "Invalid image length in cert header: expected {expected_len}, got {}",
            cert_header.total_image_len
        );
        failed = true;
    } else {
        okay!("Verified certificate header length");
    }

    let mut start = (header_offset + cert_header.header_length) as usize;
    let mut certs: Vec<x509_parser::certificate::X509Certificate> = vec![];
    for i in 0..cert_header.certificate_count {
        let x509_length = u32::from_le_bytes(image[start..start + 4].try_into().unwrap());
        info!(
            "Checking certificate [{}/{}]",
            i + 1,
            cert_header.certificate_count
        );
        trace!("    certificate length: {x509_length}");
        start += 4;
        let cert = &image[start..start + x509_length as usize];

        let (_, cert) = x509_parser::parse_x509_certificate(cert)?;
        okay!("    Successfully parsed certificate");
        info!(
            "    Subject:\n      {}",
            cert.subject().to_string().replace(", ", "\n      ")
        );
        info!(
            "    Issuer:\n      {}",
            cert.issuer().to_string().replace(", ", "\n      ")
        );

        let prev_public_key = certs.last().map(|prev| prev.public_key());
        let kind = if prev_public_key.is_some() {
            "chained"
        } else {
            "self-signed"
        };

        // If this is the root certificate, then `prev_public_key` is `None` and
        // `verify_signature` checks that it is correctly self-signed.
        match cert.verify_signature(prev_public_key) {
            Ok(()) => okay!("    Verified {kind} certificate signature"),
            Err(e) => {
                error!("    Failed to verify {kind} certificate signature: {e:?}");
                failed = true
            }
        }

        certs.push(cert);
        start += x509_length as usize;
    }

    let mut rkh_table = vec![];
    let mut rkh_sha = sha2::Sha256::new();
    for i in 0..4 {
        let rot_hash = &image[start..start + 32];
        trace!("Root key hash {i}: ");
        let mut s = String::new();
        for r in rot_hash {
            write!(&mut s, "{r:02x}").unwrap();
        }
        trace!("  {s}");
        rkh_sha.update(rot_hash);
        rkh_table.push(rot_hash.to_owned());
        start += 32;
    }

    if rkh_sha.finalize().as_slice() != cmpa.rotkh {
        error!("RKH in CMPA does not match Root Key hashes in image");
        failed = true;
    } else {
        okay!("RKH in CMPA matches Root Key hashes in image");
    }

    let mut sha = sha2::Sha256::new();
    let public_key = &certs[0].tbs_certificate.subject_pki.subject_public_key;
    let public_key_rsa = rsa::RsaPublicKey::from_pkcs1_der(public_key.as_ref()).unwrap();
    sha.update(public_key_rsa.n().to_bytes_be());
    sha.update(public_key_rsa.e().to_bytes_be());
    let out = sha.finalize().to_vec();
    if let Some((index, _)) = rkh_table.iter().enumerate().find(|(_, k)| *k == &out) {
        okay!("Root certificate's public key is in RKH table");
        let rkth_revoke = cfpa.get_rkth_revoke()?;
        let rotk_status = match index {
            0 => rkth_revoke.rotk0,
            1 => rkth_revoke.rotk1,
            2 => rkth_revoke.rotk2,
            3 => rkth_revoke.rotk3,
            _ => unreachable!("rkh_table must be exactly 4 elements"),
        };
        if rotk_status == ROTKeyStatus::Invalid {
            error!("RKH table has revoked this root certificate");
            failed = true;
        } else {
            okay!("RKH table has enabled this root certificate");
        }
    } else {
        error!("Certificate 0's public key is not in RKH table");
        failed = true;
    }

    let public_key = &certs
        .last()
        .unwrap()
        .tbs_certificate
        .subject_pki
        .subject_public_key;
    let public_key_rsa = rsa::RsaPublicKey::from_pkcs1_der(public_key.as_ref()).unwrap();
    let signature = rsa::pkcs1v15::Signature::try_from(&image[start..]).unwrap();
    trace!("signature length: {}", signature.as_ref().len());
    let verifying_key =
        rsa::pkcs1v15::VerifyingKey::<rsa::sha2::Sha256>::new_with_prefix(public_key_rsa);
    match verifying_key.verify(&image[..start], &signature) {
        Ok(()) => okay!("Verified image signature against last certificate"),
        Err(e) => {
            error!("Failed to verify signature: {e:?}");
            failed = true;
        }
    }
    Ok(failed)
}

fn check_crc_image(image: &[u8]) -> Result<bool, Error> {
    let mut failed = false;
    let mut crc = crc_any::CRCu32::crc32mpeg2();
    crc.digest(&image[..0x28]);
    crc.digest(&image[0x2c..]);
    let expected = crc.get_crc();
    let actual = u32::from_le_bytes(image[0x28..0x2c].try_into().unwrap());
    if expected == actual {
        okay!("CRC32 matches");
    } else {
        error!("CRC32 does not match");
        failed = true;
    }
    Ok(failed)
}

fn check_plain_image(_image: &[u8]) -> Result<bool, Error> {
    okay!("Nothing to check for plain image");
    Ok(false)
}
