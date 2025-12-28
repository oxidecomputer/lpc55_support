// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{bail, Context, Result};
use byteorder::ByteOrder;
use clap::Parser;
use lpc55_isp::cmd::*;
use lpc55_isp::isp::{do_ping, BootloaderProperty, KeyType};
use serialport::{DataBits, FlowControl, Parity, StopBits};
use std::io::{ErrorKind, Read, Write};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Parser)]
enum ISPCommand {
    /// Runs a single ping to verify communication with the target
    #[clap(name = "ping")]
    Ping,
    /// Reads memory from the specified address and saves it at the path
    #[clap(name = "read-memory")]
    ReadMemory {
        #[arg(value_parser = parse_int::parse::<u32>)]
        address: u32,
        #[arg(value_parser = parse_int::parse::<u32>)]
        count: u32,
        path: PathBuf,
    },
    /// Write the file to the specified address
    #[clap(name = "write-memory")]
    WriteMemory {
        #[arg(value_parser = parse_int::parse::<u32>)]
        address: u32,
        file: PathBuf,
    },
    /// Erases all non-secure flash. This MUST be done before writing!
    #[clap(name = "flash-erase-all")]
    FlashEraseAll,
    /// Erases a portion of non-secure flash. This MUST be done before writing!
    FlashEraseRegion {
        #[arg(value_parser = parse_int::parse::<u32>)]
        start_address: u32,
        #[arg(value_parser = parse_int::parse::<u32>)]
        byte_count: u32,
    },
    /// Write a file to the CMPA region
    #[clap(name = "write-cmpa")]
    WriteCMPA {
        file: PathBuf,
    },
    /// Erase the CMPA region (use to boot non-secure binaries again)
    #[clap(name = "erase-cmpa")]
    EraseCMPA,
    /// Save the CMPA region to a file
    ReadCMPA {
        /// Write to FILE, or stdout if omitted
        file: Option<PathBuf>,
    },
    /// Save the CFPA region to a file
    ReadCFPA {
        #[clap(short, long)]
        page: Option<CfpaChoice>,
        file: PathBuf,
    },
    /// Write the CFPA region from the contents of a file.
    WriteCFPA {
        #[clap(short, long)]
        update_version: bool,
        file: PathBuf,
    },
    /// Put a minimalist program on to allow attaching via SWD
    Restore,
    /// Send SB update file
    SendSBUpdate {
        file: PathBuf,
    },
    /// Set up key store this involves
    /// - Enroll
    /// - Setting UDS
    /// - Setting SBKEK
    /// - Writing to persistent storage
    SetupKeyStore {
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
        file: PathBuf,
    },
    GetProperty {
        prop: BootloaderProperty,
    },
    LastError,
}

#[derive(Copy, Clone, Debug, clap::ValueEnum)]
enum CfpaChoice {
    Scratch,
    Ping,
    Pong,
}

#[derive(Debug, Parser)]
#[clap(name = "isp")]
struct Isp {
    /// UART port
    #[clap(name = "port")]
    port: String,
    /// How fast to run the UART. 57,600 baud seems very reliable but is rather
    /// slow. In certain test setups we've gotten rates of up to 1Mbaud to work
    /// reliably -- your mileage may vary!
    #[clap(short = 'b', default_value = "57600")]
    baud_rate: u32,
    #[clap(subcommand)]
    cmd: ISPCommand,
}

fn pretty_print_bootloader_prop(prop: BootloaderProperty, params: Vec<u32>) {
    match prop {
        BootloaderProperty::BootloaderVersion => {
            println!("Version {:x}", params[1]);
        }
        BootloaderProperty::AvailablePeripherals => {
            println!("Bitmask of peripherals {:x}", params[1]);
        }
        BootloaderProperty::FlashStart => {
            println!("Flash start = 0x{:x}", params[1]);
        }
        BootloaderProperty::FlashSize => {
            println!("Flash Size = {:x}", params[1]);
        }
        BootloaderProperty::FlashSectorSize => {
            println!("Flash Sector Size = {:x}", params[1]);
        }
        BootloaderProperty::AvailableCommands => {
            println!("Bitmask of commands = {:x}", params[1]);
        }
        BootloaderProperty::CRCStatus => {
            println!("CRC status = {}", params[1]);
        }
        BootloaderProperty::VerifyWrites => {
            println!("Verify Writes (bool) {}", params[1]);
        }
        BootloaderProperty::MaxPacketSize => {
            println!("Max Packet Size = {}", params[1]);
        }
        BootloaderProperty::ReservedRegions => {
            println!("Reserved regions? = {:x?}", params);
        }
        BootloaderProperty::RAMStart => {
            println!("RAM start = 0x{:x}", params[1]);
        }
        BootloaderProperty::RAMSize => {
            println!("RAM size = 0x{:x}", params[1]);
        }
        BootloaderProperty::SystemDeviceID => {
            println!("DEVICE_ID0 register = 0x{:x}", params[1]);
        }
        BootloaderProperty::SecurityState => {
            println!(
                "Security State = {}",
                if params[1] == 0x5aa55aa5 {
                    "UNLOCKED"
                } else {
                    "LOCKED"
                }
            );
        }
        BootloaderProperty::UniqueID => {
            println!(
                "UUID = {:x}{:x}{:x}{:x}",
                params[1], params[2], params[3], params[4]
            );
        }
        BootloaderProperty::TargetVersion => {
            println!("Target version = {:x}", params[1]);
        }
        BootloaderProperty::FlashPageSize => {
            println!("Flash page size = {:x}", params[1]);
        }
        BootloaderProperty::IRQPinStatus => {
            println!("IRQ Pin Status = {}", params[1]);
        }
        BootloaderProperty::FFRKeyStoreStatus => {
            println!("FFR Store Status = {}", params[1]);
        }
    }
}

fn pretty_print_error(params: Vec<u32>) {
    let reason = params[1] & 0xfffffff0;
    if reason == 0 {
        println!("No errors reported");
    } else if reason == 0x0602f300 {
        println!("Passive boot failed, reason:");
        let specific_reason = params[2] & 0xfffffff0;
        match specific_reason {
            0x0b36f300 => {
                println!("Secure image authentication failed. Check:");
                println!("- Is the image you are booting signed?");
                println!("- Is the image signed with the corresponding key?");
            }
            0x0b37f300 => {
                println!("Application CRC failed");
            }
            0x0b35f300 => {
                println!("Application entry point and/or stack is invalid");
            }
            0x0b38f300 => {
                println!("DICE failure. Check:");
                println!("- Key store is set up properly (UDS)");
            }
            0x0d70f300 => {
                println!("Trying to boot a TZ image on a device that doesn't have TZ!");
            }
            0x0d71f300 => {
                println!("Error reading TZ Image type from CMPA");
            }
            0x0d72f300 => {
                println!("Bad TZ image mode, check your image");
            }
            0x0c00f500 => {
                println!("Application returned to the ROM?");
            }
            _ => {
                println!("Some other reason, raw bytes: {:x?}", params);
            }
        }
    } else {
        println!("Something bad happen: {:x?}", params);
    }
}

fn main() -> Result<()> {
    let cmd = Isp::parse();

    // The target _technically_ has autobaud but it's very flaky
    // and these seem to be the preferred settings
    //
    // We initially set the timeout short so we can drain the incoming buffer in
    // a portable manner below. We'll adjust it up after that.
    let mut port = serialport::new(&cmd.port, cmd.baud_rate)
        .timeout(Duration::from_millis(100))
        .data_bits(DataBits::Eight)
        .flow_control(FlowControl::None)
        .parity(Parity::None)
        .stop_bits(StopBits::One)
        .open()?;

    // Extract any bytes left over in the serial port driver from previous
    // interaction.
    loop {
        let mut throwaway = [0; 16];
        match port.read(&mut throwaway) {
            Ok(0) => {
                // This should only happen on nonblocking reads, which we
                // haven't asked for, but it does mean the buffer is empty so
                // treat it as success.
                break;
            }
            Ok(_) => {
                // We've collected some characters to throw away, keep going.
            }
            Err(e) if e.kind() == ErrorKind::TimedOut => {
                // Buffer is empty!
                break;
            }
            Err(e) => {
                return Err(e.into());
            }
        }
    }
    // Crank the timeout back up.
    port.set_timeout(Duration::from_secs(1))?;

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
            let infile = std::fs::read(file)?;

            do_isp_write_memory(&mut *port, address, &infile)?;
            println!("Write complete!");
        }
        ISPCommand::FlashEraseAll => {
            do_ping(&mut *port)?;

            do_isp_flash_erase_all(&mut *port)?;

            println!("Flash erased!");
        }
        ISPCommand::FlashEraseRegion {
            start_address,
            byte_count,
        } => {
            do_ping(&mut *port)?;

            do_isp_flash_erase_region(&mut *port, start_address, byte_count)?;

            println!("Flash region erased!");
        }
        // Yes this is just another write-memory call but remembering addresses
        // is hard.
        ISPCommand::WriteCMPA { file } => {
            do_ping(&mut *port)?;

            let infile = std::fs::read(file)?;

            do_isp_write_memory(&mut *port, 0x9e400, &infile)?;
            println!("Write to CMPA done!");
        }
        ISPCommand::EraseCMPA => {
            do_ping(&mut *port)?;

            // Write 512 bytes of zero
            let bytes = [0; 512];

            do_isp_write_memory(&mut *port, 0x9e400, &bytes)?;
            println!("CMPA region erased!");
            println!("You can now boot unsigned images");
        }
        ISPCommand::ReadCMPA { file } => {
            do_ping(&mut *port)?;

            let m = do_isp_read_memory(&mut *port, 0x9e400, 512)?;

            let mut out = match file {
                Some(ref path) => Box::new(
                    std::fs::OpenOptions::new()
                        .write(true)
                        .truncate(true)
                        .create(true)
                        .open(path)?,
                ) as Box<dyn Write>,
                None => Box::new(std::io::stdout()) as Box<dyn Write>,
            };

            out.write_all(&m)?;
            eprintln!("CMPA Output written to {:?}", file);
        }
        ISPCommand::ReadCFPA { page, file } => {
            do_ping(&mut *port)?;

            let data = if let Some(page) = page {
                // Only read one page as requested
                let addr = match page {
                    CfpaChoice::Scratch => 0x9de00,
                    CfpaChoice::Ping => 0x9e000,
                    CfpaChoice::Pong => 0x9e200,
                };
                do_isp_read_memory(&mut *port, addr, 512)?
            } else {
                // Read ping and pong pages and only write out the latest one.
                let ping = do_isp_read_memory(&mut *port, 0x9e000, 512)
                    .context("reading CFPA ping page")?;
                let pong = do_isp_read_memory(&mut *port, 0x9e200, 512)
                    .context("reading CFPA pong page")?;
                let ping_d = lpc55_areas::CFPAPage::from_bytes(ping[..].try_into().unwrap())?;
                let pong_d = lpc55_areas::CFPAPage::from_bytes(pong[..].try_into().unwrap())?;
                println!(
                    "CFPA versions: ping={}, pong={}",
                    ping_d.version, pong_d.version
                );
                if ping_d.version > pong_d.version {
                    println!("choosing ping");
                    ping
                } else {
                    println!("choosing pong");
                    pong
                }
            };

            let mut out = std::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .create(true)
                .open(&file)?;

            out.write_all(&data)?;
            println!("CFPA written to {file:?}");
        }
        ISPCommand::WriteCFPA {
            update_version,
            file,
        } => {
            do_ping(&mut *port)?;

            let bytes = std::fs::read(file)?;
            let mut new_cfpa = lpc55_areas::CFPAPage::from_bytes(
                bytes[..].try_into().context("CFPA file is not 512 bytes")?,
            )?;

            // Read the CMPA so we can compare the two to try to avoid locking
            // the user out of their chip.
            let m = do_isp_read_memory(&mut *port, 0x9e400, 512)?;
            let cmpa = lpc55_areas::CMPAPage::from_bytes(m[..].try_into().unwrap())?;
            if (new_cfpa.dcfg_cc_socu_ns_pin != 0 || new_cfpa.dcfg_cc_socu_ns_dflt != 0)
                && (cmpa.cc_socu_pin == 0 || cmpa.cc_socu_dflt == 0)
            {
                bail!(
                    "It looks like the CMPA debug settings aren't set but \
                     the CFPA settings are! This will brick the chip!"
                );
                // TODO I guess it's remotely possible that we might want an
                // override for this check.
            }

            if update_version {
                // Read the current CFPA areas to figure out what version we
                // need to set.
                let ping = do_isp_read_memory(&mut *port, 0x9_e000, 512)?;
                let pong = do_isp_read_memory(&mut *port, 0x9_e200, 512)?;

                let ping = lpc55_areas::CFPAPage::from_bytes(ping[..].try_into().unwrap())?;
                let pong = lpc55_areas::CFPAPage::from_bytes(pong[..].try_into().unwrap())?;

                println!(
                    "ping sector v={}, pong sector v={}",
                    ping.version, pong.version
                );
                let start_version = u32::max(ping.version, pong.version);
                new_cfpa.version = start_version + 1;
                println!("note: updated version is {}", new_cfpa.version);
            }

            let new_bytes = new_cfpa.to_vec()?;
            do_isp_write_memory(&mut *port, 0x9_de00, &new_bytes)?;
            println!("Write to CFPA done!");
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
            do_isp_write_memory(&mut *port, 0x0, &bytes)?;

            println!("Restore done! SWD should work now.");
        }
        ISPCommand::SendSBUpdate { file } => {
            do_ping(&mut *port)?;

            println!("Sending SB file, this may take a while");
            let infile = std::fs::read(file)?;

            do_recv_sb_file(&mut *port, &infile)?;
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

            do_isp_write_keystore(&mut *port, &bytes)?;
            do_save_keystore(&mut *port)?;
            println!("done.")
        }
        ISPCommand::SetSBKek { file } => {
            do_ping(&mut *port)?;

            let mut infile = std::fs::OpenOptions::new().read(true).open(file)?;

            let mut raw_bytes = Vec::new();

            infile.read_to_end(&mut raw_bytes)?;

            let mut actual_bytes = hex::decode(&raw_bytes)?;

            actual_bytes.reverse();

            do_isp_set_userkey(&mut *port, KeyType::SBKEK, &actual_bytes)?;
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
            let mut infile = std::fs::OpenOptions::new().read(true).open(file)?;

            let mut raw_bytes = Vec::new();

            infile.read_to_end(&mut raw_bytes)?;

            let mut actual_bytes = hex::decode(&raw_bytes)?;

            // NXP stores the key reversed? It's very unclear...
            actual_bytes.reverse();

            println!("Setting user key");
            do_isp_set_userkey(&mut *port, KeyType::SBKEK, &actual_bytes)?;

            println!("Writing keystore");
            // Step 4: Write the keystore to persistent storage
            do_save_keystore(&mut *port)?;
        }
        ISPCommand::GetProperty { prop } => {
            do_ping(&mut *port)?;
            let result = do_isp_get_property(&mut *port, prop)?;
            pretty_print_bootloader_prop(prop, result);
        }
        ISPCommand::LastError => {
            do_ping(&mut *port)?;
            let result = do_isp_last_error(&mut *port)?;
            pretty_print_error(result);
        }
    }

    Ok(())
}
