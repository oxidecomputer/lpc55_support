use anyhow::Result;
use lpc55_support::isp::*;
use serialport::{DataBits, FlowControl, Parity, SerialPortSettings, StopBits};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::Duration;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
enum ISPCommand {
    /// Runs a single ping to verify communication with the target
    #[structopt(name = "ping")]
    Ping,
    /// Reads memory from the specified address and saves it at the path
    #[structopt(name = "read-memory")]
    ReadMemory {
        #[structopt(parse(try_from_str = parse_int::parse))]
        address: u32,
        #[structopt(parse(try_from_str = parse_int::parse))]
        count: u32,
        #[structopt(parse(from_os_str))]
        path: PathBuf,
    },
    /// Write the file to the specified address
    #[structopt(name = "write-memory")]
    WriteMemory {
        #[structopt(parse(try_from_str = parse_int::parse))]
        address: u32,
        #[structopt(parse(from_os_str))]
        file: PathBuf,
    },
    /// Erases all non-secure flash. This MUST be done before writing!
    #[structopt(name = "flash-erase-all")]
    FlashEraseAll,
    /// Write a file to the CMPA region
    #[structopt(name = "write-cmpa")]
    WriteCMPA {
        #[structopt(parse(from_os_str))]
        file: PathBuf
    },
    /// Erase the CMPA region (use to boot non-secure binaries again)
    #[structopt(name = "erase-cmpa")]
    EraseCMPA
}

#[derive(Debug, StructOpt)]
#[structopt(name = "isp")]
struct ISP {
    /// UART port
    #[structopt(name = "port")]
    port: PathBuf,
    #[structopt(subcommand)]
    cmd: ISPCommand,
}

fn main() -> Result<()> {
    let cmd = ISP::from_args();

    // The target _technically_ has autobaud but it's very flaky
    // and these seem to be the preferred settings
    let mut settings: SerialPortSettings = Default::default();
    settings.timeout = Duration::from_millis(1000);
    settings.baud_rate = 57600;
    settings.data_bits = DataBits::Eight;
    settings.flow_control = FlowControl::None;
    settings.parity = Parity::None;
    settings.stop_bits = StopBits::One;

    let mut port = serialport::open_with_settings(&cmd.port, &settings)?;

    match cmd.cmd {
        ISPCommand::Ping => {
            do_ping(&mut *port)?;
            println!("ping success.");
        }
        ISPCommand::ReadMemory {
            address,
            count,
            path,
        } => {
            do_ping(&mut *port)?;

            let m = do_isp_read_memory(&mut *port, address, count)?;

            let mut out = std::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .create(true)
                .open(&path)?;

            out.write(&m)?;
            println!("Output written to {:?}", path);
        }
        ISPCommand::WriteMemory { address, file } => {
            do_ping(&mut *port)?;

            println!("If you didn't already erase the flash this operation will fail!");
            println!("This operation may take a while");
            let mut infile = std::fs::OpenOptions::new().read(true).open(&file)?;

            let mut bytes = Vec::new();

            infile.read_to_end(&mut bytes)?;

            do_isp_write_memory(&mut *port, address, bytes)?;
            println!("Write complete!");
        }
        ISPCommand::FlashEraseAll => {
            do_ping(&mut *port)?;

            do_isp_flash_erase_all(&mut *port)?;

            println!("Flash erased!");
        }
        // Yes this is just another write-memory call but remembering addresses
        // is hard.
        ISPCommand::WriteCMPA { file } => {
            do_ping(&mut *port)?;

            let mut infile = std::fs::OpenOptions::new().read(true).open(&file)?;

            let mut bytes = Vec::new();

            infile.read_to_end(&mut bytes)?;

            do_isp_write_memory(&mut *port, 0x9e400, bytes)?;
            println!("Write to CMPA done!");
        }
        ISPCommand::EraseCMPA => {
            do_ping(&mut *port)?;

            // Write 512 bytes of zero
            let bytes = vec![0; 512];

            do_isp_write_memory(&mut *port, 0x9e400, bytes)?;
            println!("CMPA region erased!");
            println!("You can now boot unsigned images");
        }

    }

    Ok(())
}
