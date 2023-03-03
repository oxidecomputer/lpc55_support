// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use clap::Parser;
use lpc55_areas::{
    BootField, BootImageType, CFPAPage, CMPAPage, CertHeader, DebugSettings, RKTHRevoke,
    ROTKeyStatus, SecBootStatus, TZMImageStatus, TzmImageType, TzmPreset,
};
use lpc55_sign::signed_image::CfgFile;
use lpc55_sign::{crc_image, sign_ecc, signed_image};
use packed_struct::{EnumCatchAll, PackedStruct};
use rsa::{pkcs1::DecodeRsaPublicKey, signature::Verifier, PublicKeyParts};
use sha2::Digest;
use std::io::Read;
use std::path::PathBuf;

#[derive(Debug, Parser)]
enum Command {
    /// Generate a non-secure CRC image
    #[clap(name = "crc")]
    Crc {
        #[clap(parse(from_os_str))]
        src_bin: PathBuf,
        #[clap(parse(from_os_str))]
        dest_bin: PathBuf,
        #[clap(long, parse(try_from_str = parse_int::parse), default_value = "0")]
        address: u32,
    },
    ChainedImage {
        #[clap(long)]
        with_dice: bool,
        #[clap(long)]
        with_dice_inc_nxp_cfg: bool,
        #[clap(long)]
        with_dice_cust_cfg: bool,
        #[clap(long)]
        with_dice_inc_sec_epoch: bool,
        #[clap(parse(from_os_str))]
        src_bin: PathBuf,
        #[clap(parse(from_os_str))]
        cfg: PathBuf,
        #[clap(parse(from_os_str))]
        dest_bin: PathBuf,
        #[clap(parse(from_os_str))]
        dest_cmpa: PathBuf,
        #[clap(long, parse(try_from_str = parse_int::parse), default_value = "0")]
        address: u32,
    },
    /// Generate a secure signed image and corresponding CMPA region
    #[clap(name = "signed-image")]
    SignedImage {
        #[clap(long)]
        with_dice: bool,
        #[clap(long)]
        with_dice_inc_nxp_cfg: bool,
        #[clap(long)]
        with_dice_cust_cfg: bool,
        #[clap(long)]
        with_dice_inc_sec_epoch: bool,
        #[clap(parse(from_os_str))]
        src_bin: PathBuf,
        #[clap(parse(from_os_str))]
        priv_key: PathBuf,
        #[clap(parse(from_os_str))]
        root_cert0: PathBuf,
        #[clap(parse(from_os_str))]
        dest_bin: PathBuf,
        #[clap(parse(from_os_str))]
        dest_cmpa: PathBuf,
        #[clap(long, parse(try_from_str = parse_int::parse), default_value = "0")]
        address: u32,
        #[clap(long)]
        cfpa: Option<PathBuf>,
    },
    #[clap(name = "ecc-image")]
    EccImage {
        #[clap(parse(from_os_str))]
        src_bin: PathBuf,
        #[clap(parse(from_os_str))]
        priv_key: PathBuf,
        #[clap(parse(from_os_str))]
        dest_bin: PathBuf,
        #[clap(long, parse(try_from_str = parse_int::parse), default_value = "0")]
        address: u32,
    },
    VerifySignedImage {
        #[clap(short, long)]
        verbose: bool,

        #[clap(parse(from_os_str))]
        src_cmpa: PathBuf,

        #[clap(parse(from_os_str))]
        src_cfpa: PathBuf,

        #[clap(parse(from_os_str))]
        src_img: PathBuf,
    },
}

#[derive(Debug, Parser)]
struct Opts {
    #[clap(subcommand)]
    cmd: Command,
}

fn main() -> Result<()> {
    let cmd = Opts::parse();

    match cmd.cmd {
        Command::Crc {
            src_bin,
            dest_bin,
            address,
        } => {
            crc_image::update_crc(&src_bin, &dest_bin, address)?;
            println!("Done! CRC image written to {:?}", &dest_bin);
        }
        Command::ChainedImage {
            with_dice,
            with_dice_inc_nxp_cfg,
            with_dice_cust_cfg,
            with_dice_inc_sec_epoch,
            src_bin,
            cfg,
            dest_bin,
            dest_cmpa,
            address,
        } => {
            let cfg_contents = std::fs::read(&cfg)?;
            let toml: CfgFile = toml::from_slice(&cfg_contents)?;

            let rkth = signed_image::sign_chain(&src_bin, None, &toml.certs, &dest_bin, address)?;
            signed_image::create_cmpa(
                with_dice,
                with_dice_inc_nxp_cfg,
                with_dice_cust_cfg,
                with_dice_inc_sec_epoch,
                &rkth,
                &dest_cmpa,
            )?;

            println!(
                "Done! Signed image written to {:?}, CMPA to {:?}",
                &dest_bin, &dest_cmpa
            );
        }
        Command::SignedImage {
            with_dice,
            with_dice_inc_nxp_cfg,
            with_dice_cust_cfg,
            with_dice_inc_sec_epoch,
            src_bin,
            priv_key,
            root_cert0,
            dest_bin,
            dest_cmpa,
            address,
            cfpa,
        } => {
            let rkth =
                signed_image::sign_image(&src_bin, &priv_key, &root_cert0, &dest_bin, address)?;
            signed_image::create_cmpa(
                with_dice,
                with_dice_inc_nxp_cfg,
                with_dice_cust_cfg,
                with_dice_inc_sec_epoch,
                &rkth,
                &dest_cmpa,
            )?;
            println!(
                "Done! Signed image written to {:?}, CMPA to {:?}",
                &dest_bin, &dest_cmpa
            );
            if let Some(cfpa_path) = cfpa {
                let mut cfpa = CFPAPage::default();
                cfpa.version += 1; // allow overwrite of default 0

                let mut rkth = RKTHRevoke::new();
                rkth.rotk0 = ROTKeyStatus::enabled().into();
                rkth.rotk1 = ROTKeyStatus::invalid().into();
                rkth.rotk2 = ROTKeyStatus::invalid().into();
                rkth.rotk3 = ROTKeyStatus::invalid().into();

                cfpa.update_rkth_revoke(rkth)?;
                let cfpa_settings = DebugSettings::new();
                cfpa.set_debug_fields(cfpa_settings)?;

                std::fs::write(&cfpa_path, &cfpa.to_vec()?)?;
                println!("CFPA written to {}", cfpa_path.display());
            }
        }
        Command::EccImage {
            src_bin,
            priv_key,
            dest_bin,
            address,
        } => {
            sign_ecc::ecc_sign_image(&src_bin, &priv_key, &dest_bin, address)?;
            println!("Done! ECC image written to {:?}", &dest_bin);
        }
        Command::VerifySignedImage {
            src_cmpa,
            src_cfpa,
            src_img,
            verbose,
        } => {
            println!("=== CMPA ====");
            let cmpa = {
                let mut cmpa_bytes = [0u8; 512];
                let mut cmpa_file = std::fs::File::open(src_cmpa)?;
                cmpa_file.read_exact(&mut cmpa_bytes)?;
                CMPAPage::from_bytes(&cmpa_bytes)?
            };

            let boot_cfg = cmpa.get_boot_cfg()?;
            let secure_boot_cfg = cmpa.get_secure_boot_cfg()?;
            let cc_socu_pin = cmpa.get_cc_socu_pin()?;
            let cc_socu_dflt = cmpa.get_cc_socu_dflt()?;

            if verbose {
                println!("{:#?}", boot_cfg);
                println!("{:#?}", secure_boot_cfg);
                println!("{:#?}", cc_socu_pin);
                println!("{:#?}", cc_socu_dflt);
                println!("ROTKH: {:}", hex::encode(cmpa.rotkh));
            }
            println!("No CMPA verification implemented");

            println!("=== CFPA ====");
            let cfpa = {
                let mut cfpa_bytes = [0u8; 512];
                let mut cfpa_file = std::fs::File::open(src_cfpa)?;
                cfpa_file.read_exact(&mut cfpa_bytes)?;
                CFPAPage::from_bytes(&cfpa_bytes)?
            };

            let rkth_revoke = cfpa.get_rkth_revoke()?;

            if verbose {
                println!("Version: {:x}", cfpa.version);
                println!("Secure FW Version: {:x}", cfpa.secure_firmware_version);
                println!("Non-secure FW Version: {:x}", cfpa.ns_fw_version);
                println!("Image key revoke: {:x}", cfpa.image_key_revoke);
                println!("{:#?}", rkth_revoke);
            }
            println!("No CFPA verification implemented");

            println!("=== Image ====");
            let image = std::fs::read(src_img)?;
            let image_len = u32::from_le_bytes(image[0x20..0x24].try_into().unwrap());
            let image_type = BootField::unpack(image[0x24..0x28].try_into().unwrap())?;

            let load_addr = u32::from_le_bytes(image[0x34..0x38].try_into().unwrap());
            let is_plain = image_type.img_type == EnumCatchAll::Enum(BootImageType::PlainImage);

            if verbose {
                println!("image length: {image_len:#x} ({image_len})");
                println!("image type: {image_type:#?}");
                println!("load address: {load_addr:#x}");
            }
            if is_plain && load_addr != 0 {
                println!("⚠️  Load address is non-0 in a non-plain image");
            } else if !is_plain && load_addr == 0 {
                println!("⚠️  Load address is 0 in a non-plain image");
            }

            let secure_boot_enabled = matches!(
                secure_boot_cfg.sec_boot_en,
                SecBootStatus::SignedImage1
                    | SecBootStatus::SignedImage2
                    | SecBootStatus::SignedImage3
            );
            if verbose {
                println!("secure boot enabled in CMPA: {secure_boot_enabled}");
            }

            println!("Checking TZM configuration");
            match secure_boot_cfg.tzm_image_type {
                TZMImageStatus::PresetTZM => {
                    if matches!(image_type.tzm_preset, TzmPreset::NotPresent) {
                        println!("    ❌ CFPA requires TZ preset, but image header says it is not present");
                    } else {
                        todo!("don't yet know how to decode TZ preset");
                    }
                }
                TZMImageStatus::InImageHeader => {
                    if matches!(image_type.tzm_image_type, TzmImageType::Enabled) {
                        if matches!(image_type.tzm_preset, TzmPreset::Present) {
                            todo!("don't yet know how to decode TZ preset");
                        } else {
                            println!("    ✅ TZM enabled in image header, without preset data");
                        }
                    } else {
                        println!("    ✅ TZM disabled in image header");
                    }
                }
                TZMImageStatus::DisableTZM => {
                    if matches!(image_type.tzm_image_type, TzmImageType::Enabled) {
                        println!(
                            "    ❌ CFPA requires TZ disabled, but image header says it is enabled"
                        );
                    } else if matches!(image_type.tzm_preset, TzmPreset::Present) {
                        println!(
                            "    ❌ CFPA requires TZ disabled, but image header has tzm_preset"
                        );
                    } else {
                        println!("    ✅ TZM disabled in CMPA and in image header");
                    }
                }
                TZMImageStatus::EnableTZM => {
                    if matches!(image_type.tzm_image_type, TzmImageType::Disabled) {
                        println!(
                            "    ❌ CFPA requires TZ enabled, but image header says it is disabled"
                        );
                    } else if matches!(image_type.tzm_preset, TzmPreset::Present) {
                        todo!("don't yet know how to decode TZ preset");
                    } else {
                        println!(
                            "    ✅ TZM enabled in CMPA and in image header, without preset data"
                        );
                    }
                }
            }

            match image_type.img_type {
                EnumCatchAll::Enum(BootImageType::SignedImage) => {
                    check_signed_image(&image, cmpa, verbose)?
                }
                EnumCatchAll::Enum(BootImageType::CRCImage) => {
                    if secure_boot_enabled {
                        println!("❌ Secure boot enabled in CPFA, but this is a CRC image");
                    }
                    check_crc_image(&image)?
                }
                EnumCatchAll::Enum(BootImageType::PlainImage) => {
                    if secure_boot_enabled {
                        println!("❌ Secure boot enabled in CPFA, but this is a plain image");
                    }
                    check_plain_image(&image)?
                }
                e => panic!("do not know how to check {e:?}"),
            }
        }
    }

    Ok(())
}

fn check_signed_image(image: &[u8], cmpa: CMPAPage, verbose: bool) -> Result<()> {
    let header_offset = u32::from_le_bytes(image[0x28..0x2c].try_into().unwrap());

    let cert_header_size = std::mem::size_of::<CertHeader>();
    let cert_header = CertHeader::unpack(
        image[header_offset as usize..][..cert_header_size]
            .try_into()
            .unwrap(),
    )?;
    if verbose {
        println!("header offset: {header_offset:#x} ({header_offset})");
        println!("cert header: {cert_header:#x?}");
        println!("data.len(): {:#x}", image.len());
    }

    if cert_header.signature != *b"cert" {
        println!("❌ Certificate header does not begin with 'cert'");
    } else {
        println!("✅ Verified certificate header signature ('cert')");
    }

    let expected_len =
        header_offset + cert_header.header_length + cert_header.certificate_table_len + 32 * 4;
    if cert_header.total_image_len != expected_len {
        println!(
            "❌ Invalid image length in cert header: expected {expected_len}, got {}",
            cert_header.total_image_len
        );
    } else {
        println!("✅ Verified certificate header length");
    }

    let mut start = (header_offset + cert_header.header_length) as usize;
    let mut certs: Vec<x509_parser::certificate::X509Certificate> = vec![];
    for i in 0..cert_header.certificate_count {
        let x509_length = u32::from_le_bytes(image[start..start + 4].try_into().unwrap());
        println!(
            "Checking certificate [{}/{}]",
            i + 1,
            cert_header.certificate_count
        );
        if verbose {
            println!("    certificate length: {x509_length}");
        }
        start += 4;
        let cert = &image[start..start + x509_length as usize];

        let (_, cert) = x509_parser::parse_x509_certificate(cert)?;
        println!("    ✅ successfully parsed certificate");

        let prev_public_key = certs.last().map(|prev| prev.public_key());
        match cert.verify_signature(prev_public_key) {
            Ok(()) => println!("    ✅ Verified certificate signature"),
            Err(e) => println!("    ❌ Failed to verify certificate signature: {e:?}"),
        }

        certs.push(cert);
        start += x509_length as usize;

        // TODO: verify that this certificate is signed by the previous one
    }

    let mut rkh_table = vec![];
    let mut rkh_sha = sha2::Sha256::new();
    for i in 0..4 {
        let rot_hash = &image[start..start + 32];
        if verbose {
            print!("Root key hash {i}: ");
            for r in rot_hash {
                print!("{r:02x}");
            }
            println!();
        }
        rkh_sha.update(rot_hash);
        rkh_table.push(rot_hash.to_owned());
        start += 32;
    }

    if rkh_sha.finalize().as_slice() != cmpa.rotkh {
        println!("❌ RKH in CMPA does not match Root Key hashes in image");
    } else {
        println!("✅ RKH in CMPA matches Root Key hashes in image");
    }

    let mut sha = sha2::Sha256::new();
    let public_key = &certs[0].tbs_certificate.subject_pki.subject_public_key;
    let public_key_rsa = rsa::RsaPublicKey::from_pkcs1_der(public_key.as_ref()).unwrap();
    sha.update(public_key_rsa.n().to_bytes_be());
    sha.update(public_key_rsa.e().to_bytes_be());
    let out = sha.finalize().to_vec();
    if !rkh_table.contains(&out) {
        println!("❌ Certificate 0's public key is not in RKH table");
    } else {
        println!("✅ Certificate 0's public key is in RKH table");
    }

    let public_key = &certs
        .last()
        .unwrap()
        .tbs_certificate
        .subject_pki
        .subject_public_key;
    let public_key_rsa = rsa::RsaPublicKey::from_pkcs1_der(public_key.as_ref()).unwrap();
    let signature = rsa::pkcs1v15::Signature::try_from(&image[start..]).unwrap();
    if verbose {
        println!("signature length: {}", signature.as_ref().len());
    }
    let verifying_key =
        rsa::pkcs1v15::VerifyingKey::<rsa::sha2::Sha256>::new_with_prefix(public_key_rsa);
    match verifying_key.verify(&image[..start], &signature) {
        Ok(()) => println!("✅ Verified signature against last certificate"),
        Err(e) => println!("❌ Failed to verify signature: {e:?}"),
    }
    Ok(())
}

fn check_crc_image(image: &[u8]) -> Result<()> {
    let mut crc = crc_any::CRCu32::crc32mpeg2();
    crc.digest(&image[..0x28]);
    crc.digest(&image[0x2c..]);
    let expected = crc.get_crc();
    let actual = u32::from_le_bytes(image[0x28..0x2c].try_into().unwrap());
    if expected == actual {
        println!("✅ CRC32 matches");
    } else {
        println!("❌ CRC32 does not match");
    }
    Ok(())
}

fn check_plain_image(_image: &[u8]) -> Result<()> {
    println!("✅ Nothing to check for plain image");
    Ok(())
}
