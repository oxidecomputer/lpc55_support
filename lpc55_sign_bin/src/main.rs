// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use colored::Colorize;
use hex::FromHex;
use log::info;
use lpc55_areas::{
    BootErrorPin, BootSpeed, CFPAPage, CMPAPage, DebugSettings, DefaultIsp, ROTKeyStatus,
};
use lpc55_sign::{
    cert::{read_certs, read_rsa_private_key},
    crc_image,
    debug_auth::{debug_auth_response, debug_credential, DebugAuthChallenge},
    signed_image::{self, pad_roots, CertConfig, DiceArgs},
};
use std::io::{Read, Write};
use std::path::PathBuf;
use zerocopy::FromBytes;

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

        /// TOML file containing initial configuration of debug access
        /// permissions. These set the most permissive permissions allowable.
        /// CFPA may only further restrict them. When not provided, all debug
        /// features are set to always enabled.
        #[clap(long)]
        debug_settings_cfg: Option<PathBuf>,
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

        /// TOML file containing field configuration of debug access
        /// permissions. These may only further restrict the permissions set in
        /// CMPA. When not provided, all debug features are set to always
        /// enabled.
        #[clap(long)]
        debug_settings_cfg: Option<PathBuf>,
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
    /// Generate a debug credential used to sign debug authentication challenges
    DebugCredential {
        dest_dc: PathBuf,

        /// 16 byte UUID in hex.  If provided, the debug certificate will only
        /// be sign challenges for a device that specifies the same UUID in its
        /// debug authentication challenge.
        #[clap(long)]
        uuid: Option<String>,

        /// TOML file containing the list of root certificates configured as
        /// trust anchors in the CMPA.
        #[clap(long)]
        root_certs_cfg: PathBuf,

        /// File containing the private key matching one of the root
        /// certificates specified in roots_cert_cfg.
        #[clap(long)]
        root_key: PathBuf,

        /// File containing the private key that will be used to sign debug
        /// authentication challenges.
        #[clap(long)]
        debug_key: PathBuf,

        /// Must match Vendor Usage fields in CMPA/CFPA.  Acts as a revocation
        /// scheme for debug credentials.
        #[clap(long, default_value_t = 0)]
        vendor_usage: u32,

        /// When non-zero, ROM defers to running application when processing a
        /// debug authentication response signed by this credential.  This
        /// beacon value is provided to the running application to allow it to
        /// decide what steps to take to prepare for debugging based on the
        /// credential used.
        #[clap(long, default_value_t = 0)]
        beacon: u16,

        /// TOML file containing debug access rights that the debug credential
        /// will request.  These may not exceed the permissions specified by
        /// CMPA and CFPA.
        #[clap(long)]
        debug_settings_cfg: PathBuf,
    },
    DebugAuthResponse {
        dest_dar: PathBuf,

        #[clap(long)]
        debug_cred: PathBuf,

        #[clap(long)]
        debug_key: PathBuf,

        #[clap(long)]
        debug_auth_challenge: PathBuf,

        /// When non-zero, ROM defers to running application when processing a
        /// debug authentication response signed by this credential.  This
        /// beacon value is provided to the running application to allow it to
        /// decide what steps to take to prepare for debugging based on the
        /// credential used.
        #[clap(long, default_value_t = 0)]
        beacon: u16,
    },
    /// Generates a TOML file encapsulating certificate settings, which can then
    /// be passed to the `--cert-cfg` option for other subcommands.
    GenCertCfg {
        /// Path to private key, if available.
        #[clap(long)]
        private_key: Option<PathBuf>,
        /// Path to root cert; can be repeated.
        #[clap(long)]
        root_cert: Vec<PathBuf>,
        /// Path to signing cert; can be repeated.
        #[clap(long)]
        signing_cert: Vec<PathBuf>,
    },
}

#[derive(Debug, Parser)]
struct CertArgs {
    /// Path to private key file, if available. Not all operations require this.
    ///
    /// Cannot be combined with the `--cert-cfg` option.
    #[clap(long)]
    private_key: Option<PathBuf>,
    /// Path to root certificate.
    ///
    /// This interface will also reuse the root certificate as the signing
    /// certificate. To override signing certificates, see the `--cert-cfg`
    /// option.
    ///
    /// Cannot be combined with the `--cert-cfg` option.
    #[clap(long)]
    root_cert: Option<PathBuf>,

    /// Path to a TOML file specifying the cert configuration. This file can
    /// contain three top-level keys, all optional. `private-key` gives the path
    /// to a private key on disk, if available. `root-certs` should be an array
    /// of strings giving the absolute paths to the root certificates.
    /// `signing-certs` should be an array of strings giving the absolute paths
    /// to signing certificates.
    ///
    /// This is intended to avoid having to pass all that on the command line
    /// every time.
    ///
    /// See the `gen-cert-cfg` subcommand to generate this file automatically.
    ///
    /// Cannot be combined with either the `--private-key` or `--root-cert`
    /// options.
    #[clap(long, conflicts_with_all = ["private_key", "root_cert"])]
    cert_cfg: Option<PathBuf>,
}

impl CertArgs {
    fn try_into_config(self) -> Result<CertConfig> {
        if let Some(s) = self.cert_cfg {
            let cfg_contents = std::fs::read_to_string(s)?;
            let cfg = toml::from_str(&cfg_contents)?;
            Ok(cfg)
        } else {
            let root_vec = self.root_cert.into_iter().collect::<Vec<_>>();
            Ok(CertConfig {
                private_key: self.private_key,
                root_certs: root_vec.clone(),
                signing_certs: root_vec,
            })
        }
    }
}

#[derive(Debug, Parser)]
struct Opts {
    #[clap(subcommand)]
    cmd: Command,
}

fn from_toml_file<T>(path: PathBuf) -> Result<T>
where
    T: for<'de> toml::macros::Deserialize<'de>,
{
    let toml =
        std::fs::read_to_string(&path).with_context(|| format!("Reading {}", path.display()))?;
    toml::from_str(&toml).with_context(|| format!("Parsing {} as TOML", path.display()))
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
            debug_settings_cfg,
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

            let debug_settings = match debug_settings_cfg {
                Some(path) => from_toml_file(path)?,
                None => DebugSettings::default(),
            };

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
                    DefaultIsp::Uart,
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
            debug_settings_cfg,
        } => {
            let debug_settings = match debug_settings_cfg {
                Some(path) => from_toml_file(path)?,
                None => DebugSettings::default(),
            };

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
            let Some(private_key) = cfg.private_key.as_ref() else {
                bail!("sign-image requires a private key to be provided as an \
                       arg or in the cert-cfg.");
            };
            let private_key = read_rsa_private_key(private_key)?;
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
        Command::DebugCredential {
            root_certs_cfg,
            root_key,
            debug_key,
            uuid,
            vendor_usage,
            beacon,
            debug_settings_cfg,
            dest_dc,
        } => {
            let root_certs_cfg = std::fs::read_to_string(root_certs_cfg)?;
            let root_certs_cfg: CertConfig = toml::from_str(&root_certs_cfg)?;
            let root_certs =
                read_certs(&root_certs_cfg.root_certs).context("Reading root certificates")?;

            let root_private_key =
                read_rsa_private_key(&root_key).context("Reading root private key")?;

            let debug_private_key =
                read_rsa_private_key(&debug_key).context("Reading debug private key")?;
            let debug_public_key = debug_private_key.to_public_key();

            let uuid = match uuid {
                Some(x) => <[u8; 16]>::from_hex(x)?,
                None => [0; 16],
            };

            let debug_settings = from_toml_file(debug_settings_cfg)?;

            let debug_cred = debug_credential(
                root_certs,
                &root_private_key,
                &debug_public_key,
                &uuid,
                vendor_usage,
                debug_settings,
                beacon,
            )?;

            std::fs::write(dest_dc, debug_cred)?
        }
        Command::DebugAuthResponse {
            dest_dar,
            debug_cred,
            debug_key,
            debug_auth_challenge,
            beacon,
        } => {
            let debug_cred = std::fs::read(debug_cred).context("Loading debug credential")?;

            let debug_private_key =
                read_rsa_private_key(&debug_key).context("Reading debug private key")?;

            let debug_auth_challenge =
                std::fs::read(debug_auth_challenge).context("Loading debug auth challenge")?;
            let debug_auth_challenge =
                DebugAuthChallenge::read_from(debug_auth_challenge.as_slice())
                    .ok_or(anyhow!("Parsing Debug Auth Challenge failed"))?;
            info!("Debug Auth Challenge: {debug_auth_challenge:#?}");

            let debug_auth_response =
                debug_auth_response(&debug_cred, debug_private_key, debug_auth_challenge, beacon)?;

            std::fs::write(dest_dar, debug_auth_response)?
        }
        Command::GenCertCfg {
            private_key,
            root_cert,
            signing_cert,
        } => {
            let cfg = CertConfig {
                private_key,
                signing_certs: signing_cert,
                root_certs: root_cert,
            };
            println!("{}", toml::to_string_pretty(&cfg)?);
        }
    }

    Ok(())
}
