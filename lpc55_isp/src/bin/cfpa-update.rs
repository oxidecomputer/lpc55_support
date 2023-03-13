// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use clap::Parser;
use lpc55_areas::*;
use lpc55_isp::cmd::{do_isp_read_memory, do_isp_write_memory};
use lpc55_isp::isp::do_ping;
use packed_struct::prelude::*;
use serialport::{DataBits, FlowControl, Parity, StopBits};
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Parser)]
#[clap(name = "cfpa_setup", max_term_width = 80)]
struct Args {
    /// UART port
    #[clap(name = "port")]
    isp_port: String,
    /// Optional out file for the CFPA region
    #[clap(name = "outfile")]
    outfile: Option<PathBuf>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // The target _technically_ has autobaud but it's very flaky
    // and these seem to be the preferred settings
    // TODO: unwrap is most certainly not the right thing to do here
    // if serialport::new can't take a PathBuf why take this param as one?
    let mut port = serialport::new(&args.isp_port, 57600)
        .timeout(Duration::from_millis(1000))
        .data_bits(DataBits::Eight)
        .flow_control(FlowControl::None)
        .parity(Parity::None)
        .stop_bits(StopBits::One)
        .open()?;

    do_ping(port.as_mut())?;

    // 0x9de00 is the fixed address of the CFPA region
    let m = do_isp_read_memory(&mut *port, 0x9de00, 512)?;

    let mut cfpa: [u8; 512] = [0; 512];

    cfpa.clone_from_slice(&m);

    let mut cfpa: CFPAPage = CFPAPage::unpack(&cfpa)?;

    // We always need to bump the version
    cfpa.version += 1;

    let mut rkth = RKTHRevoke::new();

    rkth.enable_keys(true, false, false, false);

    cfpa.update_rkth_revoke(rkth)?;

    let updated = cfpa.pack()?;

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
