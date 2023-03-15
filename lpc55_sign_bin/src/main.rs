// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use log::info;
use lpc55_areas::{
    BootErrorPin, BootSpeed, CFPAPage, CMPAPage, DebugSettings, DefaultIsp, ROTKeyStatus,
};
use lpc55_sign::{
    crc_image,
    signed_image::{self, CertConfig, DiceArgs},
};
use std::io::Read;
use std::path::PathBuf;

#[derive(Debug, Parser)]
struct ImageArgs {
    #[clap(short = 'i', long = "in", help = "source file (binary)")]
    src_bin: PathBuf,
    #[clap(short = 'o', long = "out", help = "output file (binary)")]
    dest_bin: PathBuf,
    #[clap(long, default_value_t = 0)]
    address: u32,
}

#[derive(Debug, Parser)]
enum Command {
    /// Generate a non-secure CRC image
    #[clap(name = "crc")]
    Crc {
        #[clap(flatten)]
        image: ImageArgs,
    },
    Cmpa {
        #[clap(flatten)]
        dice_args: DiceArgs,

        #[clap(short = 'o', long = "out", help = "output file (binary)")]
        dest_cmpa: PathBuf,

        #[clap(flatten)]
        certs: CertArgs,

        #[clap(
            long,
            default_value_t = 0,
            help = "port on which to indicate boot errors"
        )]
        boot_err_port: u8,
        #[clap(
            long,
            default_value_t = 0,
            help = "pin on which to indicate boot errors"
        )]
        boot_err_pin: u8,
    },
    Cfpa {
        dest_cfpa: PathBuf,
    },
    /// Generate a secure signed image
    #[clap(name = "signed-image", group = clap::ArgGroup::new("mode").multiple(false))]
    SignedImage {
        #[clap(flatten)]
        image_args: ImageArgs,

        #[clap(flatten)]
        certs: CertArgs,
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
struct CertArgs {
    #[clap(long, requires = "root_cert")]
    private_key: Option<PathBuf>,
    #[clap(long, requires = "private_key")]
    root_cert: Option<PathBuf>,

    #[clap(long, conflicts_with_all = ["private_key", "root_cert"])]
    cert_cfg: Option<PathBuf>,
}

impl CertArgs {
    fn try_into_config(self) -> Result<CertConfig> {
        if (self.private_key.is_none() || self.root_cert.is_none()) && self.cert_cfg.is_none() {
            bail!("must provide either root-cert + private-key, or cert-cfg")
        } else if let Some(s) = self.cert_cfg {
            let cfg_contents = std::fs::read(s)?;
            let cfg = toml::from_slice(&cfg_contents)?;
            Ok(cfg)
        } else {
            let root = self.root_cert.unwrap();
            Ok(CertConfig {
                private_key: self.private_key.unwrap(),
                root_certs: vec![root.clone()],
                signing_certs: vec![root],
            })
        }
    }
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
        Command::Crc { image } => {
            crc_image::update_crc(&image.src_bin, &image.dest_bin, image.address)?;
            info!("CRC image written to {:?}", &image.dest_bin);
        }
        Command::Cmpa {
            dest_cmpa,
            dice_args,
            certs,
            boot_err_pin,
            boot_err_port,
        } => {
            let cfg: CertConfig = certs.try_into_config()?;
            let root_certs = read_certs(&cfg.root_certs)?;
            let debug_settings = DebugSettings::default();
            let rotkh = signed_image::root_key_table_hash(root_certs)?;
            std::fs::write(
                &dest_cmpa,
                signed_image::generate_cmpa(
                    dice_args,
                    true,
                    debug_settings,
                    DefaultIsp::Auto,
                    BootSpeed::Fro96mhz,
                    BootErrorPin::new(boot_err_port, boot_err_pin).ok_or_else(|| {
                        anyhow!("invalid boot port: {boot_err_port}:{boot_err_pin}")
                    })?,
                    rotkh,
                )?
                .to_vec()?,
            )?;
            info!("CMPA written to {}", dest_cmpa.display());
        }
        Command::Cfpa { dest_cfpa } => {
            let debug_settings = DebugSettings::default();
            std::fs::write(
                &dest_cfpa,
                signed_image::generate_cfpa(
                    debug_settings,
                    [
                        ROTKeyStatus::enabled(),
                        ROTKeyStatus::invalid(),
                        ROTKeyStatus::invalid(),
                        ROTKeyStatus::invalid(),
                    ],
                )?
                .to_vec()?,
            )?;
            info!("CFPA written to {}", dest_cfpa.display());
        }

        Command::SignedImage {
            image_args:
                ImageArgs {
                    address,
                    src_bin,
                    dest_bin,
                },
            certs,
        } => {
            let cfg = certs.try_into_config()?;
            let private_key = std::fs::read_to_string(&cfg.private_key)?;
            let image = std::fs::read(src_bin)?;
            let signing_certs = read_certs(&cfg.signing_certs)?;
            let root_certs = read_certs(&cfg.root_certs)?;
            let stamped = signed_image::stamp_image(image, signing_certs, root_certs, address)?;
            let signed = signed_image::sign_image(&stamped, &private_key)?;
            std::fs::write(&dest_bin, signed)?;
            info!("Signed image written to {}", &dest_bin.display());
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
