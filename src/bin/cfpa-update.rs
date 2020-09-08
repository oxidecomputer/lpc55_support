use anyhow::Result;
use lpc55_support::areas::*;
use lpc55_support::isp::*;
use openssl::sha;
use packed_struct::prelude::*;
use serialport::{DataBits, FlowControl, Parity, SerialPortSettings, StopBits};
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;
use structopt::StructOpt;

#[derive(StructOpt)]
#[structopt(name = "cfpa_setup", max_term_width = 80)]
struct Args {
    /// UART port
    #[structopt(name = "port", parse(from_os_str))]
    isp_port: PathBuf,
    /// Optional out file for the CFPA region
    #[structopt(name = "outfile", parse(from_os_str))]
    outfile: Option<PathBuf>,
}

fn main() -> Result<()> {
    let args = Args::from_args();

    // The target _technically_ has autobaud but it's very flaky
    // and these seem to be the preferred settings
    let mut settings: SerialPortSettings = Default::default();
    settings.timeout = Duration::from_millis(1000);
    settings.baud_rate = 57600;
    settings.data_bits = DataBits::Eight;
    settings.flow_control = FlowControl::None;
    settings.parity = Parity::None;
    settings.stop_bits = StopBits::One;

    let mut port = serialport::open_with_settings(&args.isp_port, &settings)?;

    do_ping(&mut *port)?;

    // 0x9de00 is the fixed address of the CFPA region
    let m = do_isp_read_memory(&mut *port, 0x9de00, 512)?;

    let mut cfpa: [u8; 512] = [0; 512];

    cfpa.clone_from_slice(&m);

    let mut cfpa: CFPAPage = CFPAPage::unpack(&cfpa)?;

    // We always need to bump the version
    cfpa.update_version();

    let mut rkth = RKTHRevoke::new();

    rkth.rotk0 = ROTKeyStatus::Enabled.into();

    cfpa.update_rkth_revoke(rkth);

    let mut updated = cfpa.pack();

    // need to recalculate sha over the updated data
    let mut sha = sha::Sha256::new();
    sha.update(&updated[..0x1e0]);

    let updated_sha = sha.finish();

    updated[0x1e0..].clone_from_slice(&updated_sha);

    if let Some(f) = args.outfile {
        let mut new_cfpa = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .create(true)
            .open(&f)?;

        new_cfpa.write_all(&updated)?;

        println!("done! new CFPA file written to {}", &f.to_string_lossy());
    } else {
        println!("Writing updated CFPA region back to the device");

        do_isp_write_memory(&mut *port, 0x9de00, updated.to_vec())?;
        println!("done!");
    }

    Ok(())
}
