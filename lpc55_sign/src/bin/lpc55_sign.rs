// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use clap::Parser;
use lpc55_areas::{CFPAPage, CMPAPage, DebugSettings, RKTHRevoke, ROTKeyStatus, SecureBootCfg};
use lpc55_sign::signed_image::CfgFile;
use lpc55_sign::{crc_image, sign_ecc, signed_image};
use packed_struct::PackedStruct;
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
    /// Generate a secure saigned image and corresponding CMPA region
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
        } => {
            println!("=== CMPA ====");

            let cmpa = {
                let mut cmpa_bytes = [0u8; 512];
                let mut cmpa_file = std::fs::File::open(src_cmpa)?;
                cmpa_file.read_exact(&mut cmpa_bytes)?;
                CMPAPage::from_bytes(&cmpa_bytes)?
            };

            let boot_cfg = cmpa.get_boot_cfg()?;
            println!("{:#?}", boot_cfg);

            let secure_boot_cfg = cmpa.get_secure_boot_cfg()?;
            println!("{:#?}", secure_boot_cfg);

            let cc_socu_pin = cmpa.get_cc_socu_pin()?;
            println!("{:#?}", cc_socu_pin);

            let cc_socu_dflt = cmpa.get_cc_socu_dflt()?;
            println!("{:#?}", cc_socu_dflt);

            println!("ROTKH: {:}", hex::encode(cmpa.rotkh));

            let cfpa = {
                let mut cfpa_bytes = [0u8; 512];
                let mut cfpa_file = std::fs::File::open(src_cfpa)?;
                cfpa_file.read_exact(&mut cfpa_bytes)?;
                CFPAPage::from_bytes(&cfpa_bytes)?
            };

            println!("");
            println!("=== CFPA ====");

            println!("Version: {:x}", cfpa.version);
            println!("Secure FW Version: {:x}", cfpa.secure_firmware_version);
            println!("Non-secure FW Version: {:x}", cfpa.ns_fw_version);
            println!("Image key revoke: {:x}", cfpa.image_key_revoke);

            let rkth_revoke = cfpa.get_rkth_revoke()?;
            println!("{:#?}", rkth_revoke);

            let image = std::fs::read(src_img)?;
        }
    }

    Ok(())
}
