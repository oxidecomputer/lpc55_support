// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{Context, Result};
use clap::Parser;
use log::info;
use lpc55_areas::{CFPAPage, CMPAPage};
use lpc55_sign::{
    crc_image, sign_ecc,
    signed_image::{self, DiceArgs},
};
use serde::Deserialize;
use std::io::Read;
use std::path::PathBuf;

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct CertConfig {
    /// The file containing the private key with which to sign the image.
    private_key: PathBuf,

    /// The chain of DER-encoded signing certificate files, in root-to-leaf
    /// order. The image will be signed with the private key corresponding
    /// to the the leaf (last) certificate.
    signing_certs: Vec<PathBuf>,

    /// The full set of (up to four) DER-encoded root certificate files,
    /// from which the root key hashes are derived. Must contain the root
    /// (first) certificate in `signing_certs`.
    root_certs: Vec<PathBuf>,
}

#[derive(Debug, Parser)]
struct ImageArgs {
    src_bin: PathBuf,
    dest_bin: PathBuf,
    #[clap(long, default_value_t = 0)]
    address: u32,
    #[clap(long = "cmpa")]
    dest_cmpa: Option<PathBuf>,
    #[clap(long = "cfpa")]
    dest_cfpa: Option<PathBuf>,
}

#[derive(Debug, Parser)]
enum Command {
    /// Generate a non-secure CRC image
    #[clap(name = "crc")]
    Crc {
        src_bin: PathBuf,
        dest_bin: PathBuf,
        #[clap(long, default_value_t = 0)]
        address: u32,
    },
    ChainedImage {
        #[clap(flatten)]
        dice_args: DiceArgs,
        #[clap(flatten)]
        image_args: ImageArgs,
        cert_cfg: PathBuf,
    },
    /// Generate a secure signed image and corresponding CMPA region
    #[clap(name = "signed-image")]
    SignedImage {
        #[clap(flatten)]
        dice_args: DiceArgs,
        #[clap(flatten)]
        image_args: ImageArgs,
        private_key: PathBuf,
        root_cert: PathBuf,
    },
    #[clap(name = "ecc-image")]
    EccImage {
        src_bin: PathBuf,
        priv_key: PathBuf,
        dest_bin: PathBuf,
        #[clap(long, default_value_t = 0)]
        address: u32,
    },
    VerifySignedImage {
        #[clap(short, long)]
        verbose: bool,
        src_cmpa: PathBuf,
        src_cfpa: PathBuf,
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

    // VerifySignedImage has a custom logger; everyone else can use the default
    if !matches!(cmd.cmd, Command::VerifySignedImage { .. }) {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    }

    match cmd.cmd {
        Command::Crc {
            src_bin,
            dest_bin,
            address,
        } => {
            crc_image::update_crc(&src_bin, &dest_bin, address)?;
            info!("CRC image written to {:?}", &dest_bin);
        }
        Command::ChainedImage {
            dice_args,
            image_args:
                ImageArgs {
                    address,
                    src_bin,
                    dest_bin,
                    dest_cmpa,
                    dest_cfpa,
                },
            cert_cfg,
        } => {
            let cfg_contents = std::fs::read(cert_cfg)?;
            let cfg: CertConfig = toml::from_slice(&cfg_contents)?;
            let private_key = std::fs::read_to_string(&cfg.private_key)?;
            let image = std::fs::read(src_bin)?;
            let signing_certs = read_certs(&cfg.signing_certs)?;
            let root_certs = read_certs(&cfg.root_certs)?;
            let stamped =
                signed_image::stamp_image(image, signing_certs, root_certs.clone(), address)?;
            let signed = signed_image::sign_image(&stamped, &private_key)?;
            std::fs::write(&dest_bin, signed)?;
            info!("Signed image written to {}", &dest_bin.display());

            if let Some(dest_cmpa) = &dest_cmpa {
                let rotkh = signed_image::root_key_table_hash(root_certs.clone())?;
                std::fs::write(
                    dest_cmpa,
                    signed_image::generate_cmpa(dice_args, rotkh)?.to_vec()?,
                )?;
                info!("CMPA written to {}", dest_cmpa.display());
            }
            if let Some(dest_cfpa) = &dest_cfpa {
                std::fs::write(
                    dest_cfpa,
                    signed_image::generate_cfpa(root_certs)?.to_vec()?,
                )?;
                info!("CFPA written to {}", dest_cfpa.display());
            }
        }
        Command::SignedImage {
            dice_args,
            image_args:
                ImageArgs {
                    address,
                    src_bin,
                    dest_bin,
                    dest_cmpa,
                    dest_cfpa,
                },
            private_key,
            root_cert,
        } => {
            let private_key = std::fs::read_to_string(private_key)?;
            let root_cert = std::fs::read(root_cert)?;
            let signing_certs = vec![root_cert.clone()];
            let root_certs = vec![root_cert, vec![], vec![], vec![]];

            let image = std::fs::read(src_bin)?;
            let stamped =
                signed_image::stamp_image(image, signing_certs, root_certs.clone(), address)?;
            let signed = signed_image::sign_image(&stamped, &private_key)?;
            std::fs::write(&dest_bin, signed)?;
            info!("Signed image written to {}", &dest_bin.display());

            if let Some(dest_cmpa) = &dest_cmpa {
                let rotkh = signed_image::root_key_table_hash(root_certs.clone())?;
                std::fs::write(
                    dest_cmpa,
                    signed_image::generate_cmpa(dice_args, rotkh)?.to_vec()?,
                )?;
                info!("CMPA written to {}", dest_cmpa.display());
            }
            if let Some(dest_cfpa) = &dest_cfpa {
                std::fs::write(
                    dest_cfpa,
                    signed_image::generate_cfpa(root_certs)?.to_vec()?,
                )?;
                info!("CFPA written to {}", dest_cfpa.display());
            }
        }
        Command::EccImage {
            src_bin,
            priv_key,
            dest_bin,
            address,
        } => {
            sign_ecc::ecc_sign_image(&src_bin, &priv_key, &dest_bin, address)?;
            info!("ECC image written to {:?}", &dest_bin);
        }
        Command::VerifySignedImage {
            src_cmpa,
            src_cfpa,
            src_img,
            verbose,
        } => {
            let cmpa = {
                let mut cmpa_bytes = [0u8; 512];
                let mut cmpa_file = std::fs::File::open(&src_cmpa)
                    .with_context(|| format!("could not open {src_cmpa:?}"))?;
                cmpa_file.read_exact(&mut cmpa_bytes)?;
                CMPAPage::from_bytes(&cmpa_bytes).context("could not load CMPA from bytes")?
            };

            let cfpa = {
                let mut cfpa_bytes = [0u8; 512];
                let mut cfpa_file = std::fs::File::open(&src_cfpa)
                    .with_context(|| format!("could not open {src_cfpa:?}"))?;
                cfpa_file.read_exact(&mut cfpa_bytes)?;
                CFPAPage::from_bytes(&cfpa_bytes).context("could not load CFPA from bytes")?
            };
            let image = std::fs::read(src_img)?;
            lpc55_sign::verify::init_verify_logger(verbose);
            lpc55_sign::verify::verify_image(&image, cmpa, cfpa)?;
        }
    }

    Ok(())
}

fn read_certs(paths: &[PathBuf]) -> Result<Vec<Vec<u8>>> {
    Ok(paths
        .iter()
        .map(std::fs::read)
        .collect::<Result<Vec<Vec<u8>>, _>>()?)
}
