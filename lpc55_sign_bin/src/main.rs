// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use colored::Colorize;
use log::info;
use lpc55_areas::{
    BootErrorPin, BootSpeed, CFPAPage, CMPAPage, DebugSettings, DefaultIsp, ROTKeyStatus,
};
use lpc55_sign::{
    cert::read_certs,
    crc_image,
    signed_image::{self, pad_roots, CertConfig, DiceArgs},
};
use std::io::{Read, Write};
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

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum)]
enum RKTHState {
    Disabled,
    Enabled,
    Revoked,
}

#[derive(Debug, Parser)]
enum Command {
    /// Generate a non-secure CRC image
    #[clap(name = "crc")]
    Crc {
        #[clap(flatten)]
        image: ImageArgs,
    },
    /// Generate a CPFA bin with default debug settings
    Cmpa {
        #[clap(long)]
        without_secure_boot: bool,

        #[clap(flatten)]
        dice_args: DiceArgs,

        /// output file (binary)
        #[clap(short = 'o', long = "out")]
        dest_cmpa: PathBuf,

        #[clap(flatten)]
        certs: CertArgs,

        /// Port on which to indicate boot errors (0-7)
        #[clap(long, default_value_t = 0)]
        boot_err_port: u8,

        /// Pin on which to indicate boot errors (0-31)
        #[clap(long, default_value_t = 0)]
        boot_err_pin: u8,

        /// Configure the CMPA to be locked.  THIS CANNOT BE UNDONE.
        #[clap(long)]
        lock: bool,

        /// Skip interactive verification of the `--lock` option
        #[clap(short, long)]
        yes: bool,
    },
    /// Generate a CPFA bin with certificate 1 enabled and default debug
    /// settings
    Cfpa {
        dest_cfpa: PathBuf,

        #[clap(long, default_value = "enabled")]
        rkth0: RKTHState,

        #[clap(long, default_value = "disabled")]
        rkth1: RKTHState,

        #[clap(long, default_value = "disabled")]
        rkth2: RKTHState,

        #[clap(long, default_value = "disabled")]
        rkth3: RKTHState,

        #[clap(long, default_value_t = 0)]
        image_key_revoke: u16,
    },
    /// Generate a secure signed image
    SignImage {
        #[clap(flatten)]
        image_args: ImageArgs,

        #[clap(flatten)]
        certs: CertArgs,
    },
    /// Verify a signed image, along with its CMPA / CFPA
    VerifySignedImage {
        #[clap(short, long)]
        verbose: bool,
        src_cmpa: PathBuf,
        src_cfpa: PathBuf,
        src_img: PathBuf,
    },
    /// Removes the signature from a signed image
    RemoveSignature {
        /// output file (binary)
        #[clap(short = 'i', long = "in")]
        src_img: PathBuf,

        #[clap(short = 'o', long = "out")]
        dst_img: PathBuf,
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
            let cfg_contents = std::fs::read_to_string(s)?;
            let cfg = toml::from_str(&cfg_contents)?;
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
            without_secure_boot,
            dice_args,
            certs,
            boot_err_pin,
            boot_err_port,
            lock,
            yes,
        } => {
            if lock {
                println!("{}: CMPA locking CANNOT BE UNDONE!", "WARNING".red());
                if !yes {
                    const EXPECTED: &str = "Lock the CMPA";
                    println!("Please type '{EXPECTED}' to continue:");
                    print!("> ");
                    std::io::stdout().flush().unwrap();
                    let mut reply = String::new();
                    std::io::stdin().read_line(&mut reply).unwrap();
                    let reply = reply.trim();
                    if reply != EXPECTED {
                        bail!(
                            "invalid reply: expected '{EXPECTED}', \
                             got '{reply}'"
                        );
                    }
                }
            }
            let cfg: CertConfig = certs.try_into_config()?;
            let root_certs = pad_roots(read_certs(&cfg.root_certs)?)?;
            let debug_settings = DebugSettings::default();

            let required_key_size = signed_image::required_key_size(&root_certs)?;
            let use_rsa_4096 = match required_key_size {
                Some(2048) | None => false,
                Some(4096) => true,
                Some(x) => bail!("Certificates have unsupported {x}-bit public keys"),
            };

            let rotkh = signed_image::root_key_table_hash(&root_certs)?;

            std::fs::write(
                &dest_cmpa,
                signed_image::generate_cmpa(
                    dice_args,
                    !without_secure_boot,
                    debug_settings,
                    DefaultIsp::Auto,
                    BootSpeed::Fro96mhz,
                    BootErrorPin::new(boot_err_port, boot_err_pin).ok_or_else(|| {
                        anyhow!("invalid boot port: {boot_err_port}:{boot_err_pin}")
                    })?,
                    rotkh,
                    lock,
                    use_rsa_4096,
                )?
                .to_vec()?,
            )?;
            info!("CMPA written to {}", dest_cmpa.display());
        }
        Command::Cfpa {
            dest_cfpa,
            rkth0,
            rkth1,
            rkth2,
            rkth3,
            image_key_revoke,
        } => {
            let debug_settings = DebugSettings::default();

            //  NXP ROM only allows the revocation fields to have 0->1
            //  transitions for each individual bit.  Each slot starts in
            //  Invalid (0b00) where the table slot is not considered for use.
            //  Normal lifecycle enables a slot's key by transitioning to
            //  Enabled (0b01).  Revoking a key can happen via two different
            //  states: Revoke1 and Revoke2. Enabled -> Revoke1 is invalid as it
            //  would require setting the low bit 1->0. Instead, revocation
            //  happens by going to Revoke2 (0b11).  Revoke1 should really never
            //  be used as the only path it can be used on is Invalid -> Revoke1
            //  -> Revoke2
            let rotkey_status_for_rkth_state = |x| match x {
                RKTHState::Disabled => ROTKeyStatus::Invalid,
                RKTHState::Enabled => ROTKeyStatus::Enabled,
                RKTHState::Revoked => ROTKeyStatus::Revoked2,
            };

            std::fs::write(
                &dest_cfpa,
                signed_image::generate_cfpa(
                    debug_settings,
                    [
                        rotkey_status_for_rkth_state(rkth0),
                        rotkey_status_for_rkth_state(rkth1),
                        rotkey_status_for_rkth_state(rkth2),
                        rotkey_status_for_rkth_state(rkth3),
                    ],
                    image_key_revoke,
                )?
                .to_vec()?,
            )?;
            info!("CFPA written to {}", dest_cfpa.display());
        }

        Command::SignImage {
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
        Command::RemoveSignature { src_img, dst_img } => {
            let image = std::fs::read(src_img)?;
            let out = lpc55_sign::signed_image::remove_image_signature(image)?;
            std::fs::write(dst_img, out)?;
        }
    }

    Ok(())
}
