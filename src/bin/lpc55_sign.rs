// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use lpc55_support::{crc_image, sign_ecc, signed_image};
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
enum ImageType {
    /// Generate a non-secure CRC image
    #[structopt(name = "crc")]
    Crc {
        #[structopt(parse(from_os_str))]
        src_bin: PathBuf,
        #[structopt(parse(from_os_str))]
        dest_bin: PathBuf,
    },
    /// Generate a secure saigned image and corresponding CMPA region
    #[structopt(name = "signed-image")]
    SignedImage {
        #[structopt(parse(from_os_str))]
        src_bin: PathBuf,
        #[structopt(parse(from_os_str))]
        priv_key: PathBuf,
        #[structopt(parse(from_os_str))]
        root_cert0: PathBuf,
        #[structopt(parse(from_os_str))]
        dest_bin: PathBuf,
        #[structopt(parse(from_os_str))]
        dest_cmpa: PathBuf,
    },
    #[structopt(name = "ecc-image")]
    EccImage {
        #[structopt(parse(from_os_str))]
        src_bin: PathBuf,
        #[structopt(parse(from_os_str))]
        priv_key: PathBuf,
        #[structopt(parse(from_os_str))]
        dest_bin: PathBuf,
    },
}

#[derive(Debug, StructOpt)]
#[structopt(name = "images")]
struct Images {
    #[structopt(subcommand)]
    cmd: ImageType,
}

fn main() -> Result<()> {
    let cmd = Images::from_args();

    match cmd.cmd {
        ImageType::Crc { src_bin, dest_bin } => {
            crc_image::update_crc(&src_bin, &dest_bin)?;
            println!("Done! CRC image written to {:?}", &dest_bin);
        }
        ImageType::SignedImage {
            src_bin,
            priv_key,
            root_cert0,
            dest_bin,
            dest_cmpa,
        } => {
            signed_image::sign_image(&src_bin, &priv_key, &root_cert0, &dest_bin, &dest_cmpa)?;
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
