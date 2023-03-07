// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{bail, Context, Result};
use clap::Parser;
use colored::Colorize;
use lpc55_areas::{
    BootField, BootImageType, CFPAPage, CMPAPage, CertHeader, DebugSettings, RKTHRevoke,
    ROTKeyStatus, SecBootStatus, TZMImageStatus, TzmImageType, TzmPreset,
};
use lpc55_sign::{crc_image, sign_ecc, signed_image};
use packed_struct::{EnumCatchAll, PackedStruct};
use rsa::{pkcs1::DecodeRsaPublicKey, signature::Verifier, PublicKeyParts};
use serde::Deserialize;
use sha2::Digest;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::PathBuf;

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct CertConfig {
    /// The file containing the private key with which to sign the image.
    pub private_key: PathBuf,

    /// The chain of signing certificates, in root-to-leaf order.
    /// The image will be signed with the private key corresponding
    /// to the leaf (last) certificate.
    pub signing_certs: Vec<PathBuf>,

    /// The full set of (up to four) root certificates, from which the root
    /// key hashes are derived. Must contain the root (first) certificate
    /// in `signing_certs`.
    pub root_certs: Vec<PathBuf>,
}

#[derive(Debug, Parser)]
struct DiceArgs {
    #[clap(long)]
    with_dice: bool,
    #[clap(long)]
    with_dice_inc_nxp_cfg: bool,
    #[clap(long)]
    with_dice_cust_cfg: bool,
    #[clap(long)]
    with_dice_inc_sec_epoch: bool,
}

#[derive(Debug, Parser)]
struct ImageArgs {
    #[clap(parse(from_os_str))]
    src_bin: PathBuf,
    #[clap(parse(from_os_str))]
    dest_bin: PathBuf,
    #[clap(parse(from_os_str))]
    dest_cmpa: PathBuf,
    #[clap(long, parse(try_from_str = parse_int::parse), default_value = "0")]
    address: u32,
    #[clap(long)]
    cfpa: Option<PathBuf>,
}

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
        #[clap(flatten)]
        dice_args: DiceArgs,
        #[clap(flatten)]
        image_args: ImageArgs,
        #[clap(parse(from_os_str))]
        cert_cfg: PathBuf,
    },
    /// Generate a secure signed image and corresponding CMPA region
    #[clap(name = "signed-image")]
    SignedImage {
        #[clap(flatten)]
        dice_args: DiceArgs,
        #[clap(flatten)]
        image_args: ImageArgs,
        #[clap(parse(from_os_str))]
        private_key: PathBuf,
        #[clap(parse(from_os_str))]
        root_cert: PathBuf,
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

macro_rules! check {
    (OK, $($arg:tt)*) => {
        check!("[okay]".green(), $($arg)*)
    };
    (WARN, $($arg:tt)*) => {
        check!("[warn]".yellow(), $($arg)*)
    };
    (ERR, $($arg:tt)*) => {
        check!("[err] ".red(), $($arg)*)
    };
    ($foo:expr, $($arg:tt)*) => {{
        let s = format!($($arg)*);
        let s_ = s.trim_start();
        let pad = s.len() - s_.len();
        println!("{:pad$}{} {}", "", $foo, s_, pad=pad)
    }};
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
            dice_args,
            image_args,
            cert_cfg,
        } => {
            let cfg_contents = std::fs::read(&cert_cfg)?;
            let cfg: CertConfig = toml::from_slice(&cfg_contents)?;
            let signing_certs = read_certs(&cfg.signing_certs)?;
            let root_certs = read_certs(&cfg.root_certs)?;
            write_signed_image(
                image_args,
                dice_args,
                signing_certs,
                root_certs,
                cfg.private_key,
            )?;
        }
        Command::SignedImage {
            dice_args,
            image_args,
            private_key,
            root_cert,
        } => {
            let root_cert = std::fs::read(root_cert)?;
            let signing = vec![root_cert.clone()];
            let roots = vec![root_cert, vec![], vec![], vec![]];
            write_signed_image(image_args, dice_args, signing, roots, private_key)?;
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
                let mut cmpa_file = std::fs::File::open(&src_cmpa)
                    .with_context(|| format!("could not open {src_cmpa:?}"))?;
                cmpa_file.read_exact(&mut cmpa_bytes)?;
                CMPAPage::from_bytes(&cmpa_bytes).context("could not load CMPA from bytes")?
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
                let mut cfpa_file = std::fs::File::open(&src_cfpa)
                    .with_context(|| format!("could not open {src_cfpa:?}"))?;
                cfpa_file.read_exact(&mut cfpa_bytes)?;
                CFPAPage::from_bytes(&cfpa_bytes).context("could not load CFPA from bytes")?
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
                check!(WARN, "Load address is non-0 in a plain image",);
            } else if !is_plain && load_addr == 0 {
                check!(WARN, "Load address is 0 in a non-plain image",);
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
                    if image_type.tzm_preset == TzmPreset::NotPresent {
                        check!(
                            ERR,
                            "CFPA requires TZ preset, but image header says it is not present"
                        );
                    } else {
                        todo!("don't yet know how to decode TZ preset");
                    }
                }
                TZMImageStatus::InImageHeader => {
                    if image_type.tzm_image_type == TzmImageType::Enabled {
                        if image_type.tzm_preset == TzmPreset::Present {
                            todo!("don't yet know how to decode TZ preset");
                        } else {
                            check!(OK, "TZM enabled in image header, without preset data");
                        }
                    } else {
                        check!(OK, "TZM disabled in image header");
                    }
                }
                TZMImageStatus::DisableTZM => {
                    if image_type.tzm_image_type == TzmImageType::Enabled {
                        check!(
                            ERR,
                            "CFPA requires TZ disabled, but image header says it is enabled"
                        );
                    } else if image_type.tzm_preset == TzmPreset::Present {
                        check!(
                            ERR,
                            "CFPA requires TZ disabled, but image header has tzm_preset"
                        );
                    } else {
                        check!(OK, "TZM disabled in CMPA and in image header");
                    }
                }
                TZMImageStatus::EnableTZM => {
                    if image_type.tzm_image_type == TzmImageType::Disabled {
                        check!(
                            ERR,
                            "CFPA requires TZ enabled, but image header says it is disabled"
                        );
                    } else if image_type.tzm_preset == TzmPreset::Present {
                        todo!("don't yet know how to decode TZ preset");
                    } else {
                        check!(
                            OK,
                            "TZM enabled in CMPA and in image header, without preset data"
                        );
                    }
                }
            }

            match image_type.img_type {
                EnumCatchAll::Enum(BootImageType::SignedImage) => {
                    check_signed_image(&image, cmpa, cfpa, verbose)?
                }
                EnumCatchAll::Enum(BootImageType::CRCImage) => {
                    if secure_boot_enabled {
                        check!(ERR, "Secure boot enabled in CPFA, but this is a CRC image");
                    }
                    check_crc_image(&image)?
                }
                EnumCatchAll::Enum(BootImageType::PlainImage) => {
                    if secure_boot_enabled {
                        check!(
                            ERR,
                            "Secure boot enabled in CPFA, but this is a plain image"
                        );
                    }
                    check_plain_image(&image)?
                }
                e => panic!("do not know how to check {e:?}"),
            }
        }
    }

    Ok(())
}

fn check_signed_image(image: &[u8], cmpa: CMPAPage, cfpa: CFPAPage, verbose: bool) -> Result<()> {
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
        check!(ERR, "Certificate header does not begin with 'cert'");
    } else {
        check!(OK, "Verified certificate header signature ('cert')");
    }

    let expected_len =
        header_offset + cert_header.header_length + cert_header.certificate_table_len + 32 * 4;
    if cert_header.total_image_len != expected_len {
        check!(
            ERR,
            "Invalid image length in cert header: expected {expected_len}, got {}",
            cert_header.total_image_len
        );
    } else {
        check!(OK, "Verified certificate header length");
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
        check!(OK, "    Successfully parsed certificate");
        println!(
            "    Subject:\n      {}",
            cert.subject().to_string().replace(", ", "\n      ")
        );
        println!(
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
            Ok(()) => check!(OK, "    Verified {kind} certificate signature"),
            Err(e) => check!(
                ERR,
                "    Failed to verify {kind} certificate signature: {e:?}"
            ),
        }

        certs.push(cert);
        start += x509_length as usize;
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
        check!(ERR, "RKH in CMPA does not match Root Key hashes in image");
    } else {
        check!(OK, "RKH in CMPA matches Root Key hashes in image");
    }

    let mut sha = sha2::Sha256::new();
    let public_key = &certs[0].tbs_certificate.subject_pki.subject_public_key;
    let public_key_rsa = rsa::RsaPublicKey::from_pkcs1_der(public_key.as_ref()).unwrap();
    sha.update(public_key_rsa.n().to_bytes_be());
    sha.update(public_key_rsa.e().to_bytes_be());
    let out = sha.finalize().to_vec();
    if let Some((index, _)) = rkh_table.iter().enumerate().find(|(_, k)| *k == &out) {
        check!(OK, "Root certificate's public key is in RKH table");
        let rkth_revoke = cfpa.get_rkth_revoke()?;
        let rotk_status = match index {
            0 => rkth_revoke.rotk0,
            1 => rkth_revoke.rotk1,
            2 => rkth_revoke.rotk2,
            3 => rkth_revoke.rotk3,
            i => bail!("Invalid certificate index {i}"),
        };
        if rotk_status == ROTKeyStatus::Invalid {
            check!(ERR, "RKH table has revoked this root certificate");
        } else {
            check!(OK, "RKH table has enabled this root certificate");
        }
    } else {
        check!(ERR, "Certificate 0's public key is not in RKH table");
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
        Ok(()) => check!(OK, "Verified image signature against last certificate"),
        Err(e) => check!(ERR, "Failed to verify signature: {e:?}"),
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
        check!(OK, "CRC32 matches");
    } else {
        check!(ERR, "CRC32 does not match");
    }
    Ok(())
}

fn check_plain_image(_image: &[u8]) -> Result<()> {
    check!(OK, "Nothing to check for plain image");
    Ok(())
}

fn read_certs(paths: &[PathBuf]) -> Result<Vec<Vec<u8>>> {
    Ok(paths
        .iter()
        .map(std::fs::read)
        .collect::<Result<Vec<Vec<u8>>, _>>()?)
}

fn write_to_file(path: &PathBuf, bytes: &[u8]) -> Result<()> {
    Ok(OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)?
        .write_all(&bytes)?)
}

fn write_signed_image(
    image: ImageArgs,
    dice: DiceArgs,
    signing_certs: Vec<Vec<u8>>,
    root_certs: Vec<Vec<u8>>,
    private_key: PathBuf,
) -> Result<()> {
    let bin = std::fs::read(&image.src_bin)?;
    let (stamped, rkth) = signed_image::stamp_image(bin, signing_certs, root_certs, image.address)?;

    let private_key = std::fs::read_to_string(private_key)?;
    let signed = signed_image::sign_image(&stamped, &private_key)?;

    let cmpa = signed_image::create_cmpa(
        dice.with_dice,
        dice.with_dice_inc_nxp_cfg,
        dice.with_dice_cust_cfg,
        dice.with_dice_inc_sec_epoch,
        &rkth,
    )?;
    write_to_file(&image.dest_bin, &signed)?;
    write_to_file(&image.dest_cmpa, &cmpa)?;
    println!(
        "Done! Signed image written to {}, CMPA to {}",
        &image.dest_bin.display(),
        &image.dest_cmpa.display()
    );

    if let Some(cfpa_path) = &image.cfpa {
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

        write_to_file(&cfpa_path, &cfpa.to_vec()?)?;
        println!("CFPA written to {}", cfpa_path.display());
    }

    Ok(())
}
