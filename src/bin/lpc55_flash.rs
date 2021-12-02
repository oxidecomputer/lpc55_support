// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use byteorder::ByteOrder;
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
        file: PathBuf,
    },
    /// Erase the CMPA region (use to boot non-secure binaries again)
    #[structopt(name = "erase-cmpa")]
    EraseCMPA,
    /// Save the CMPA region to a file
    ReadCMPA {
        #[structopt(parse(from_os_str))]
        file: PathBuf,
    },
    /// Save the CFPA region to a file
    ReadCFPA {
        #[structopt(parse(from_os_str))]
        file: PathBuf,
    },
    /// Put a minimalist program on to allow attaching via SWD
    Restore,
    /// Send SB update file
    SendSBUpdate {
        #[structopt(parse(from_os_str))]
        file: PathBuf,
    },
    /// Set up key store this involves
    /// - Enroll
    /// - Setting UDS
    /// - Setting SBKEK
    /// - Writing to persistent storage
    SetupKeyStore {
        #[structopt(parse(from_os_str))]
        file: PathBuf,
    },
    /// Trigger a new enrollment in the PUF
    Enroll,
    /// Generate a new device secret for use in DICE
    GenerateUDS,
    /// Write keystore to flash
    WriteKeyStore,
    /// Erase existing keystore
    EraseKeyStore,
    /// Set the SBKEK, required for SB Updates
    SetSBKek {
        #[structopt(parse(from_os_str))]
        file: PathBuf,
    },
}

#[derive(Debug, StructOpt)]
#[structopt(name = "isp")]
struct Isp {
    /// UART port
    #[structopt(name = "port")]
    port: PathBuf,
    /// How fast to run the UART. 57,600 baud seems very reliable but is rather
    /// slow. In certain test setups we've gotten rates of up to 1Mbaud to work
    /// reliably -- your mileage may vary!
    #[structopt(short = "b", default_value = "57600")]
    baud_rate: u32,
    #[structopt(subcommand)]
    cmd: ISPCommand,
}

fn main() -> Result<()> {
    let cmd = Isp::from_args();

    // The target _technically_ has autobaud but it's very flaky
    // and these seem to be the preferred settings
    let settings = SerialPortSettings {
        timeout: Duration::from_millis(1000),
        baud_rate: cmd.baud_rate,
        data_bits: DataBits::Eight,
        flow_control: FlowControl::None,
        parity: Parity::None,
        stop_bits: StopBits::One
    };

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

            out.write_all(&m)?;
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
        ISPCommand::ReadCMPA { file } => {
            do_ping(&mut *port)?;

            let m = do_isp_read_memory(&mut *port, 0x9e400, 512)?;

            let mut out = std::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .create(true)
                .open(&file)?;

            out.write_all(&m)?;
            println!("CMPA Output written to {:?}", file);
        }
        ISPCommand::ReadCFPA { file } => {
            do_ping(&mut *port)?;

            let m = do_isp_read_memory(&mut *port, 0x9de00, 512)?;

            let mut out = std::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .create(true)
                .open(&file)?;

            out.write_all(&m)?;
            println!("CFPA Output written to {:?}", file);
        }
        ISPCommand::Restore => {
            do_ping(&mut *port)?;

            println!("Erasing flash");
            do_isp_flash_erase_all(&mut *port)?;
            println!("Erasing done.");

            // we need to fill 0x134 bytes to cover the vector table
            // plus all interrupts
            let mut bytes: [u8; 0x134] = [0u8; 0x134];

            // Choose a RAM address for the stack (we shouldn't use the stack
            // but it should be valid anyway)
            byteorder::LittleEndian::write_u32(&mut bytes[0x0..0x4], 0x20004000);
            // Everything else targets the loop to branch instruction at 0x00000130
            let mut offset = 4;
            while offset < 0x130 {
                byteorder::LittleEndian::write_u32(&mut bytes[offset..offset + 4], 0x00000131);
                offset += 4;
            }
            // This is two branch to self instructions
            byteorder::LittleEndian::write_u32(&mut bytes[0x130..0x134], 0xe7fee7fe);

            println!("Writing bytes");
            do_isp_write_memory(&mut *port, 0x0, bytes.to_vec())?;

            println!("Restore done! SWD should work now.");
        }
        ISPCommand::SendSBUpdate { file } => {
            do_ping(&mut *port)?;

            println!("Sending SB file, this may take a while");
            let mut infile = std::fs::OpenOptions::new().read(true).open(&file)?;

            let mut bytes = Vec::new();

            infile.read_to_end(&mut bytes)?;

            do_recv_sb_file(&mut *port, bytes)?;
            println!("Send complete!");
        }
        ISPCommand::Enroll => {
            do_ping(&mut *port)?;

            println!("Generating new activation code");

            do_enroll(&mut *port)?;
            println!("done.");
            println!("If you want to save this, remember to write to non-volatile memory");
        }
        ISPCommand::GenerateUDS => {
            do_ping(&mut *port)?;

            println!("Generating new UDS");

            do_generate_uds(&mut *port)?;
            println!("done.");
            println!("If you want to save this, remember to write to non-volatile memory");
        }
        ISPCommand::WriteKeyStore => {
            do_ping(&mut *port)?;

            println!("Writing key store to flash");
            do_save_keystore(&mut *port)?;
            println!("done.");
        }
        ISPCommand::EraseKeyStore => {
            do_ping(&mut *port)?;

            println!("Erasing existing keystore");
            // Write 3 * 512 bytes of 0
            let bytes = vec![0; 512 * 3];

            do_isp_write_keystore(&mut *port, bytes)?;
            do_save_keystore(&mut *port)?;
            println!("done.")
        }
        ISPCommand::SetSBKek { file } => {
            do_ping(&mut *port)?;

            let mut infile = std::fs::OpenOptions::new().read(true).open(&file)?;

            let mut raw_bytes = Vec::new();

            infile.read_to_end(&mut raw_bytes)?;

            let mut actual_bytes = hex::decode(&raw_bytes)?;

            actual_bytes.reverse();

            do_isp_set_userkey(&mut *port, KeyType::SBKEK, actual_bytes)?;
            println!("done.");
        }
        ISPCommand::SetupKeyStore { file } => {
            do_ping(&mut *port)?;

            // Step 1: Enroll
            println!("Generating new activation code");
            do_enroll(&mut *port)?;

            // Step 2: Generate UDS
            println!("Generating new UDS");
            do_generate_uds(&mut *port)?;

            // Step 3: Set the SBKEK
            let mut infile = std::fs::OpenOptions::new().read(true).open(&file)?;

            let mut raw_bytes = Vec::new();

            infile.read_to_end(&mut raw_bytes)?;

            let mut actual_bytes = hex::decode(&raw_bytes)?;

            // NXP stores the key reversed? It's very unclear...
            actual_bytes.reverse();

            println!("Setting user key");
            do_isp_set_userkey(&mut *port, KeyType::SBKEK, actual_bytes)?;

            println!("Writing keystore");
            // Step 4: Write the keystore to persistent storage
            do_save_keystore(&mut *port)?;
        }
    }

    Ok(())
}
