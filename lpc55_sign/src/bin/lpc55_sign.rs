// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use clap::Parser;
use lpc55_sign::signed_image::CfgFile;
use lpc55_sign::{crc_image, sign_ecc, signed_image};
use std::path::PathBuf;

#[derive(Debug, Parser)]
enum ImageType {
    /// Generate a non-secure CRC image
    #[clap(name = "crc")]
    Crc {
        #[clap(parse(from_os_str))]
        src_bin: PathBuf,
        #[clap(parse(from_os_str))]
        dest_bin: PathBuf,
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
    },
    #[clap(name = "ecc-image")]
    EccImage {
        #[clap(parse(from_os_str))]
        src_bin: PathBuf,
        #[clap(parse(from_os_str))]
        priv_key: PathBuf,
        #[clap(parse(from_os_str))]
        dest_bin: PathBuf,
    },
}

#[derive(Debug, Parser)]
#[clap(name = "images")]
struct Images {
    #[clap(subcommand)]
    cmd: ImageType,
}

fn main() -> Result<()> {
    let cmd = Images::parse();

    match cmd.cmd {
        ImageType::Crc { src_bin, dest_bin } => {
            crc_image::update_crc(&src_bin, &dest_bin)?;
            println!("Done! CRC image written to {:?}", &dest_bin);
        }
        ImageType::ChainedImage {
            with_dice,
            with_dice_inc_nxp_cfg,
            with_dice_cust_cfg,
            with_dice_inc_sec_epoch,
            src_bin,
            cfg,
            dest_bin,
            dest_cmpa,
        } => {
            let cfg_contents = std::fs::read(&cfg)?;
            let toml: CfgFile = toml::from_slice(&cfg_contents)?;

            let rkth = signed_image::sign_chain(&src_bin, None, &toml.certs, &dest_bin)?;
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
        ImageType::SignedImage {
            with_dice,
            with_dice_inc_nxp_cfg,
            with_dice_cust_cfg,
            with_dice_inc_sec_epoch,
            src_bin,
            priv_key,
            root_cert0,
            dest_bin,
            dest_cmpa,
        } => {
            let rkth = signed_image::sign_image(&src_bin, &priv_key, &root_cert0, &dest_bin)?;
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
        ImageType::EccImage {
            src_bin,
            priv_key,
            dest_bin,
        } => {
            sign_ecc::ecc_sign_image(&src_bin, &priv_key, &dest_bin)?;
            println!("Done! ECC image written to {:?}", &dest_bin);
        }
    }

    Ok(())
}
