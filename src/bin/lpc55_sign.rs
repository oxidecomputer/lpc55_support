use anyhow::Result;
use lpc55_support::crc_image;
use lpc55_support::signed_image;
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
enum ImageType {
    /// Generate a non-secure CRC image
    #[structopt(name = "crc")]
    CRC {
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
        ImageType::CRC { src_bin, dest_bin } => {
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
    }

    Ok(())
}