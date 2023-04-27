// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{anyhow, Result};
use crc_any::CRCu16;
use num_derive::FromPrimitive;
use packed_struct::prelude::*;
use std::cmp::min;
use std::convert::TryInto;
use strum_macros::EnumString;

#[repr(u8)]
#[derive(Debug)]
enum PacketType {
    Ack = 0xA1,
    //Nak = 0xA2,
    AckAbort = 0xA3,
    Command = 0xA4,
    Data = 0xA5,
    Ping = 0xA6,
    PingResponse = 0xA7,
}

#[repr(u8)]
#[derive(Copy, Clone, Debug)]
pub enum ResponseCode {
    Generic = 0xA0,
    ReadMemory = 0xA3,
    GetProperty = 0xA7,
    //FlashReadOnce = 0xAF,
    KeyProvision = 0xB5,
}

#[repr(u32)]
#[derive(Copy, Clone, Debug)]
pub enum KeyType {
    // Secureboot Key Encryption Key
    SBKEK = 0x3,
    // Prince = 7 - 9
    // USER is available to use for whatever
    // Wish there were more than one user :(
    USERKEK = 0xB,
    // UDS used in DICE
    UDS = 0xC,
}

#[repr(u32)]
#[derive(Copy, Clone, Debug)]
pub enum KeyProvisionCmds {
    Enroll = 0x0,
    SetUserKey = 0x1,
    SetIntrinsicKey = 0x2,
    WriteNonVolatile = 0x3,
    //ReadNonVolatile = 0x4,
    WriteKeyStore = 0x5,
    //ReadKeyStore = 0x6,
}

// Commands are abbridged right now for what we care about
#[repr(u8)]
#[derive(Debug)]
pub enum CommandTag {
    FlashEraseAll = 0x1,
    FlashEraseRegion = 0x2,
    ReadMemory = 0x3,
    WriteMemory = 0x4,
    GetProperty = 0x7,
    ReceiveSbFile = 0x8,
    KeyProvision = 0x15,
}

#[repr(C)]
#[derive(Debug, PackedStruct)]
#[packed_struct(size_bytes = "2", bit_numbering = "msb0", endian = "msb")]
pub struct PacketHeader {
    #[packed_field(bytes = "0")]
    start_byte: u8,
    #[packed_field(bytes = "1")]
    packet_type: u8,
}

impl PacketHeader {
    fn new(ptype: PacketType) -> PacketHeader {
        PacketHeader {
            start_byte: 0x5A_u8,
            packet_type: ptype as u8,
        }
    }
}

#[repr(C)]
#[derive(Debug, EnumString, FromPrimitive, Clone, Copy)]
pub enum BootloaderProperty {
    BootloaderVersion = 1,
    AvailablePeripherals = 2,
    FlashStart = 3,
    FlashSize = 4,
    FlashSectorSize = 5,
    AvailableCommands = 7,
    CRCStatus = 8,
    VerifyWrites = 10,
    MaxPacketSize = 11,
    ReservedRegions = 12,
    RAMStart = 14,
    RAMSize = 15,
    SystemDeviceID = 16,
    SecurityState = 17,
    UniqueID = 18,
    TargetVersion = 24,
    FlashPageSize = 27,
    IRQPinStatus = 28,
    FFRKeyStoreStatus = 29,
}

#[repr(C)]
#[derive(Debug, PackedStruct)]
#[packed_struct(bit_numbering = "msb0")]
pub struct PingResponse {
    #[packed_field(size_bytes = "2")]
    header: PacketHeader,
    protocol_bugfix: u8,
    protocol_minor: u8,
    protocol_major: u8,
    protocol_name: u8,
    options_low: u8,
    options_high: u8,
    crc16_low: u8,
    crc16_high: u8,
}

#[repr(C)]
#[derive(Debug, PackedStruct)]
#[packed_struct(bit_numbering = "msb0", endian = "msb")]
pub struct FramingPacket {
    #[packed_field(size_bytes = "2")]
    header: PacketHeader,
    length_low: u8,
    length_high: u8,
    crc16_low: u8,
    crc16_high: u8,
}

impl FramingPacket {
    fn new(ptype: PacketType) -> FramingPacket {
        FramingPacket {
            header: PacketHeader::new(ptype),
            length_low: 0,
            length_high: 0,
            crc16_low: 0,
            crc16_high: 0,
        }
    }
}

#[derive(Debug, PackedStruct, Default)]
#[packed_struct(bit_numbering = "msb0", endian = "msb")]
#[repr(C)]
pub struct RawCommand {
    tag: u8,
    flags: u8,
    reserved: u8,
    parameter_count: u8,
}

impl RawCommand {
    fn new(c: CommandTag, count: usize) -> RawCommand {
        RawCommand {
            tag: c as u8,
            flags: 0,
            reserved: 0,
            parameter_count: count as u8,
        }
    }
}

// Command packets can take a variable number
// of arguments. This is unfortunately a pain to serialize
// in a structure. So we cheat a little and and only make the
// existing structure a packed_struct and later append the
// arguments manually
#[derive(Debug, PackedStruct)]
#[packed_struct(bit_numbering = "msb0", endian = "msb")]
#[repr(C)]
pub struct VariablePacket {
    #[packed_field(size_bytes = "6")]
    packet: FramingPacket,
    #[packed_field(size_bytes = "4")]
    raw_command: RawCommand,
}

pub struct CommandPacket {
    packet: VariablePacket,
    params: Vec<u32>,
}

impl CommandPacket {
    fn new_command(c: CommandTag, args: Vec<u32>) -> Result<CommandPacket> {
        let mut v = VariablePacket {
            packet: FramingPacket::new(PacketType::Command),
            raw_command: RawCommand::new(c, args.len()),
        };

        let arg_bytes = args.len() * 4;
        // Total length of the command packet. the 4 bytes are for
        // the fixed fields
        let len: u16 = (4 + arg_bytes) as u16;

        v.packet.length_low = (len & 0xFF) as u8;
        v.packet.length_high = ((len >> 8) & 0xff) as u8;

        let mut crc = CRCu16::crc16xmodem();

        let bytes = v.pack()?;

        // CRC over everything except the CRC field, this includes the framing
        // header as well as the rest of the argument
        crc.digest(&bytes[..0x4]);
        crc.digest(&bytes[0x6..]);

        for e in args.iter() {
            crc.digest(&e.to_le_bytes());
        }

        let digest = crc.get_crc();

        v.packet.crc16_low = (digest & 0xff) as u8;
        v.packet.crc16_high = ((digest >> 8) & 0xff) as u8;

        Ok(CommandPacket {
            packet: v,
            params: args,
        })
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut v = Vec::new();

        v.extend_from_slice(&self.packet.pack()?);

        for e in self.params.iter() {
            v.extend_from_slice(&e.to_le_bytes());
        }

        Ok(v)
    }
}

pub struct DataPacket {
    packet: FramingPacket,
    data: Vec<u8>,
}

impl DataPacket {
    fn new_data(args: Vec<u8>) -> Result<DataPacket> {
        let arg_len: u16 = args.len() as u16;

        let mut f = FramingPacket::new(PacketType::Data);

        f.length_low = (arg_len & 0xFF) as u8;
        f.length_high = ((arg_len >> 8) & 0xff) as u8;

        let mut crc = CRCu16::crc16xmodem();

        let bytes = f.pack()?;

        crc.digest(&bytes[..0x4]);
        crc.digest(&bytes[0x6..]);
        crc.digest(&args);

        let digest = crc.get_crc();

        f.crc16_low = (digest & 0xff) as u8;
        f.crc16_high = ((digest >> 8) & 0xff) as u8;

        Ok(DataPacket {
            packet: f,
            data: args,
        })
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut v = Vec::new();

        v.extend_from_slice(&self.packet.pack()?);
        v.extend_from_slice(&self.data);

        Ok(v)
    }
}

pub fn do_ping(port: &mut dyn serialport::SerialPort) -> Result<()> {
    let ping = PacketHeader::new(PacketType::Ping);

    let ping_bytes = ping.pack()?;

    port.write_all(&ping_bytes)?;

    port.flush()?;

    let mut response_bytes: [u8; 10] = [0; 10];

    port.read_exact(&mut response_bytes)?;

    let response = PingResponse::unpack(&response_bytes)?;

    if response.header.packet_type != (PacketType::PingResponse as u8) {
        return Err(anyhow!(
            "Incorrect ACK byte from ping {:x}",
            response.header.packet_type
        ));
    }

    Ok(())
}

fn send_ack(port: &mut dyn serialport::SerialPort) -> Result<()> {
    let packet = PacketHeader::new(PacketType::Ack);

    let bytes = packet.pack()?;

    port.write_all(&bytes)?;
    port.flush()?;

    Ok(())
}

fn read_ack(port: &mut dyn serialport::SerialPort) -> Result<()> {
    let mut ack_bytes: [u8; 2] = [0; 2];

    port.read_exact(&mut ack_bytes)?;

    let ack = PacketHeader::unpack_from_slice(&ack_bytes).unwrap();

    // Ack abort comes with a response packet explaining why
    if ack.packet_type == (PacketType::AckAbort as u8) {
        match read_response(port, ResponseCode::Generic) {
            Ok(p) => {
                if p.is_empty() {
                    return Err(anyhow!("Response returned an unknown error code?"));
                }
                // The return value is always the first parameter
                let retval = p[0];

                // Some more specific error messages.
                if retval == 10203 {
                    return Err(anyhow!("Did you forget to erase the flash? (err 10203)"));
                } else if retval == 10101 {
                    return Err(anyhow!(
                        "Incorrect signature. Is the SBKEK set correctly? (err 10101)"
                    ));
                } else {
                    return Err(anyhow!("ISP error returned: {}", retval));
                }
            }
            Err(e) => return Err(e),
        }
    }

    if ack.packet_type != (PacketType::Ack as u8) {
        return Err(anyhow!("Incorrect ACK byte {:x}", ack.packet_type));
    }

    Ok(())
}

fn check_crc(frame_bytes: &[u8], response: &[u8], frame: &FramingPacket) -> Result<()> {
    let mut crc = CRCu16::crc16xmodem();
    crc.digest(&frame_bytes[..0x4]);
    crc.digest(&frame_bytes[0x6..]);
    crc.digest(&response);

    let digest = crc.get_crc();

    if !(((digest & 0xff) == frame.crc16_low.into())
        && (((digest >> 8) & 0xff) == frame.crc16_high.into()))
    {
        return Err(anyhow!(
            "CRC failure on packet expect {:x}{:x} got {:x}",
            frame.crc16_high,
            frame.crc16_low,
            digest
        ));
    }

    Ok(())
}

pub fn read_data(port: &mut dyn serialport::SerialPort) -> Result<Vec<u8>> {
    let mut frame_bytes = vec![0; FramingPacket::packed_bytes_size(None)?];
    let mut cnt = 0;

    while cnt != FramingPacket::packed_bytes_size(None)? {
        let r = port.read(&mut frame_bytes[cnt..])?;
        cnt += r;
    }

    let frame = FramingPacket::unpack_from_slice(&frame_bytes).unwrap();

    if frame.header.packet_type != (PacketType::Data as u8) {
        return Err(anyhow!(
            "Expected a data packet, got {:x} instead",
            frame.header.packet_type
        ));
    }

    cnt = 0;
    let length: usize = (frame.length_low as usize) | ((frame.length_high as usize) << 8);
    let mut response = vec![0; length];

    while cnt != length {
        let r = port.read(&mut response[cnt..])?;
        cnt += r;
    }

    check_crc(&frame_bytes, &response, &frame)?;

    Ok(response)
}

// Okay _technically_ the response can return values from get-property but for
// now just return (). If we _really_ need properties we can add that later
pub fn read_response(
    port: &mut dyn serialport::SerialPort,
    response_type: ResponseCode,
) -> Result<Vec<u32>> {
    let mut frame_bytes = vec![0; FramingPacket::packed_bytes_size(None)?];
    let mut cnt = 0;

    while cnt != FramingPacket::packed_bytes_size(None)? {
        let r = port.read(&mut frame_bytes[cnt..])?;
        cnt += r;
    }

    let frame = FramingPacket::unpack_from_slice(&frame_bytes).unwrap();

    // A response packet is a specific type of command packet.
    if frame.header.packet_type != (PacketType::Command as u8) {
        return Err(anyhow!(
            "Expected a command, got {:x}",
            frame.header.packet_type
        ));
    }

    cnt = 0;
    let length: usize = (frame.length_low as usize) | ((frame.length_high as usize) << 8);
    let mut response = vec![0; length];

    while cnt != length {
        let r = port.read(&mut response[cnt..])?;
        cnt += r;
    }

    check_crc(&frame_bytes, &response, &frame)?;

    let command = RawCommand::unpack_from_slice(&response[..RawCommand::packed_bytes_size(None)?])?;

    if command.tag != (response_type as u8) {
        return Err(anyhow!(
            "Expected a response type of {:x}, got {:x}",
            response_type as u8,
            command.tag
        ));
    }

    let mut params: Vec<u32> = Vec::new();
    let mut cnt = 0;
    let mut index = RawCommand::packed_bytes_size(None)?;

    while cnt < command.parameter_count {
        params.push(u32::from_le_bytes(response[index..index + 4].try_into()?));
        cnt += 1;
        index += 4;
    }

    send_ack(port)?;

    // First paramter is always the return code;
    let retval = params[0];

    if retval != 0 {
        // Some more specific error messages.
        if retval == 10203 {
            Err(anyhow!("Did you forget to erase the flash? (err 10203)"))
        } else if retval == 10101 {
            Err(anyhow!(
                "Incorrect signature. Is the SBKEK set correctly? (err 10101)"
            ))
        } else {
            Err(anyhow!("ISP error returned: {}", retval))
        }
    } else {
        Ok(params)
    }
}

pub fn send_command(
    port: &mut dyn serialport::SerialPort,
    cmd: CommandTag,
    args: Vec<u32>,
) -> Result<()> {
    let command = CommandPacket::new_command(cmd, args)?;

    let command_bytes = command.to_bytes()?;

    port.write_all(&command_bytes)?;
    port.flush()?;

    read_ack(port)?;

    Ok(())
}

pub fn send_data(port: &mut dyn serialport::SerialPort, data: &[u8]) -> Result<()> {
    let mut cnt = 0;

    // Target doesn't like it when we send an entire binary in one pass
    // so break it down into 512 byte chunks which is what the existing
    // tools seem to use
    while cnt < data.len() {
        let end = min(data.len(), cnt + 512);

        let data_packet = DataPacket::new_data(data[cnt..end].to_vec())?;

        let data_bytes = data_packet.to_bytes()?;

        port.write_all(&data_bytes)?;
        port.flush()?;

        read_ack(port)?;
        cnt += 512;
    }

    Ok(())
}

pub fn recv_data(port: &mut dyn serialport::SerialPort, cnt: u32) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    let mut received: usize = 0;

    while received < (cnt as usize) {
        let d = read_data(port)?;

        data.extend_from_slice(&d);

        received += d.len();

        send_ack(port)?;
    }

    Ok(data)
}

pub fn do_isp_write_memory(
    port: &mut dyn serialport::SerialPort,
    address: u32,
    data: Vec<u8>,
) -> Result<()> {
    let args = vec![address, data.len() as u32, 0x0];

    send_command(port, CommandTag::WriteMemory, args)?;

    read_response(port, ResponseCode::Generic)?;

    send_data(port, &data)?;

    read_response(port, ResponseCode::Generic)?;

    Ok(())
}

pub fn do_isp_flash_erase_all(port: &mut dyn serialport::SerialPort) -> Result<()> {
    let args = vec![
        // Erase internal flash
        0x0_u32,
    ];

    send_command(port, CommandTag::FlashEraseAll, args)?;

    read_response(port, ResponseCode::Generic)?;

    Ok(())
}

pub fn do_isp_flash_erase_region(
    port: &mut dyn serialport::SerialPort,
    start_address: u32,
    byte_count: u32,
) -> Result<()> {
    let args = vec![
        start_address,
        byte_count,
        0_u32, // internal flash memory identifier
    ];

    send_command(port, CommandTag::FlashEraseRegion, args)?;

    read_response(port, ResponseCode::Generic)?;

    Ok(())
}
