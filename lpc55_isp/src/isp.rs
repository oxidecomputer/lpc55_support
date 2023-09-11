// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crc_any::CRCu16;
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::FromPrimitive;
use packed_struct::prelude::*;
use std::convert::TryInto;
use strum_macros::EnumString;
use thiserror::Error;

#[repr(u8)]
#[derive(Copy, Clone, Debug)]
pub enum PacketType {
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
    fn new_command(c: CommandTag, args: impl Into<Vec<u32>>) -> CommandPacket {
        let args = args.into();

        let mut v = VariablePacket {
            packet: FramingPacket::new(PacketType::Command),
            raw_command: RawCommand::new(c, args.len()),
        };

        let arg_bytes = args.len() * 4;
        // Total length of the command packet. the 4 bytes are for
        // the fixed fields
        let len: u16 = u16::try_from(4 + arg_bytes).expect("args vec too long for command packet");

        v.packet.length_low = (len & 0xFF) as u8;
        v.packet.length_high = ((len >> 8) & 0xff) as u8;

        let mut crc = CRCu16::crc16xmodem();

        let bytes = v.pack().unwrap();

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

        CommandPacket {
            packet: v,
            params: args,
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::new();

        v.extend_from_slice(&self.packet.pack().unwrap());

        for e in self.params.iter() {
            v.extend_from_slice(&e.to_le_bytes());
        }

        v
    }
}

pub struct DataPacket {
    packet: FramingPacket,
    data: Vec<u8>,
}

impl DataPacket {
    fn new_data(args: impl Into<Vec<u8>>) -> DataPacket {
        let args = args.into();
        let arg_len = u16::try_from(args.len()).expect("args vector too long for DataPacket");

        let mut f = FramingPacket::new(PacketType::Data);

        f.length_low = (arg_len & 0xFF) as u8;
        f.length_high = ((arg_len >> 8) & 0xff) as u8;

        let mut crc = CRCu16::crc16xmodem();

        let bytes = f.pack().unwrap();

        crc.digest(&bytes[..0x4]);
        crc.digest(&bytes[0x6..]);
        crc.digest(&args);

        let digest = crc.get_crc();

        f.crc16_low = (digest & 0xff) as u8;
        f.crc16_high = ((digest >> 8) & 0xff) as u8;

        DataPacket {
            packet: f,
            data: args,
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::new();

        v.extend_from_slice(&self.packet.pack().unwrap());
        v.extend_from_slice(&self.data);

        v
    }
}

pub fn do_ping(port: &mut dyn serialport::SerialPort) -> Result<(), IspError> {
    let ping = PacketHeader::new(PacketType::Ping);

    let ping_bytes = ping.pack().unwrap();

    port.write_all(&ping_bytes)?;

    port.flush()?;

    let mut response_bytes: [u8; 10] = [0; 10];

    port.read_exact(&mut response_bytes)?;

    let response = PingResponse::unpack(&response_bytes).map_err(IspError::Unpack)?;

    if response.header.packet_type != (PacketType::PingResponse as u8) {
        return Err(IspError::BadAck(response.header.packet_type));
    }

    Ok(())
}

fn send_ack(port: &mut dyn serialport::SerialPort) -> Result<(), IspError> {
    let packet = PacketHeader::new(PacketType::Ack);

    let bytes = packet.pack().unwrap();

    port.write_all(&bytes)?;
    port.flush()?;

    Ok(())
}

fn read_ack(port: &mut dyn serialport::SerialPort) -> Result<(), IspError> {
    let mut ack_bytes: [u8; 2] = [0; 2];

    port.read_exact(&mut ack_bytes)?;

    // Note: PacketHeader unpack should not be able to fail here
    let ack = PacketHeader::unpack_from_slice(&ack_bytes).unwrap();

    // Ack abort comes with a response packet explaining why
    if ack.packet_type == PacketType::AckAbort as u8 {
        let p = read_response(port, ResponseCode::Generic)?;
        if p.is_empty() {
            return Err(IspError::MissingErrorCode);
        }
        // The return value is always the first parameter
        let retval = p[0];

        return Err(retval2err(retval).into());
    }

    if ack.packet_type != (PacketType::Ack as u8) {
        return Err(IspError::BadAck(ack.packet_type));
    }

    Ok(())
}

fn retval2err(retval: u32) -> StatusResponse {
    if let Some(e) = KnownError::from_u32(retval) {
        StatusResponse::Known(e)
    } else {
        StatusResponse::GenericErrorCode(retval)
    }
}

fn check_crc(frame_bytes: &[u8], response: &[u8], frame: &FramingPacket) -> Result<(), IspError> {
    let mut crc = CRCu16::crc16xmodem();
    crc.digest(&frame_bytes[..0x4]);
    crc.digest(&frame_bytes[0x6..]);
    crc.digest(&response);

    let digest = crc.get_crc();

    if !(((digest & 0xff) == frame.crc16_low.into())
        && (((digest >> 8) & 0xff) == frame.crc16_high.into()))
    {
        return Err(IspError::CrcFailure {
            expected: u16::from_le_bytes([frame.crc16_low, frame.crc16_high]),
            got: digest,
        });
    }

    Ok(())
}

pub fn read_data(port: &mut dyn serialport::SerialPort) -> Result<Vec<u8>, IspError> {
    let mut frame_bytes = vec![0; FramingPacket::packed_bytes_size(None).unwrap()];
    port.read_exact(&mut frame_bytes)?;

    let frame = FramingPacket::unpack_from_slice(&frame_bytes).unwrap();

    require_frame_type(&frame, PacketType::Data)?;

    let length = usize::from(u16::from_le_bytes([frame.length_low, frame.length_high]));
    let mut response = vec![0; length];
    port.read_exact(&mut response)?;

    check_crc(&frame_bytes, &response, &frame)?;

    Ok(response)
}

// Okay _technically_ the response can return values from get-property but for
// now just return (). If we _really_ need properties we can add that later
pub fn read_response(
    port: &mut dyn serialport::SerialPort,
    response_type: ResponseCode,
) -> Result<Vec<u32>, IspError> {
    let mut frame_bytes = vec![0; FramingPacket::packed_bytes_size(None).unwrap()];
    port.read_exact(&mut frame_bytes)?;

    let frame = FramingPacket::unpack_from_slice(&frame_bytes).unwrap();

    // A response packet is a specific type of command packet.
    require_frame_type(&frame, PacketType::Command)?;

    let length: usize = usize::from(u16::from_le_bytes([frame.length_low, frame.length_high]));
    let mut response = vec![0; length];
    port.read_exact(&mut response)?;

    check_crc(&frame_bytes, &response, &frame)?;

    let command =
        RawCommand::unpack_from_slice(&response[..RawCommand::packed_bytes_size(None).unwrap()])
            .map_err(IspError::Unpack)?;

    // Note: we tolerate A0 (generic response) here because many commands return
    // it on failure instead of the expected response type.
    if command.tag != (response_type as u8) && command.tag != 0xA0 {
        return Err(IspError::WrongResponse {
            expected: response_type,
            got: command.tag,
        });
    }

    let mut params: Vec<u32> = Vec::new();
    let index = RawCommand::packed_bytes_size(None).unwrap();

    let end_of_params = index + usize::from(command.parameter_count) * 4;
    let param_bytes = response
        .get(index..end_of_params)
        .ok_or(IspError::TruncatedParams {
            expected_len: end_of_params,
            actual_len: response.len(),
        })?;

    for p in param_bytes.chunks_exact(4) {
        params.push(u32::from_le_bytes(p.try_into().unwrap()));
    }

    send_ack(port)?;

    // First paramter is always the return code;
    let retval = params[0];

    if retval != 0 {
        Err(retval2err(retval).into())
    } else {
        Ok(params)
    }
}

pub fn send_command(
    port: &mut dyn serialport::SerialPort,
    cmd: CommandTag,
    args: impl Into<Vec<u32>>,
) -> Result<(), IspError> {
    let command_bytes = CommandPacket::new_command(cmd, args).to_bytes();

    port.write_all(&command_bytes)?;
    port.flush()?;

    read_ack(port)?;

    Ok(())
}

pub fn send_data(port: &mut dyn serialport::SerialPort, data: &[u8]) -> Result<(), IspError> {
    // Target doesn't like it when we send an entire binary in one pass
    // so break it down into 512 byte chunks which is what the existing
    // tools seem to use
    for chunk in data.chunks(512) {
        let data_bytes = DataPacket::new_data(chunk).to_bytes();

        port.write_all(&data_bytes)?;
        port.flush()?;

        read_ack(port)?;
    }

    Ok(())
}

pub fn recv_data(port: &mut dyn serialport::SerialPort, cnt: u32) -> Result<Vec<u8>, IspError> {
    let cnt = cnt as usize;
    let mut data = Vec::with_capacity(cnt);

    while data.len() < cnt {
        data.extend_from_slice(&read_data(port)?);
        send_ack(port)?;
    }

    Ok(data)
}

pub fn do_isp_write_memory(
    port: &mut dyn serialport::SerialPort,
    address: u32,
    data: &[u8],
) -> Result<(), IspError> {
    let len = u32::try_from(data.len()).expect("can't send more than 4 GiB");
    let args = vec![address, len, 0x0];

    send_command(port, CommandTag::WriteMemory, args)?;

    read_response(port, ResponseCode::Generic)?;

    send_data(port, data)?;

    read_response(port, ResponseCode::Generic)?;

    Ok(())
}

pub fn do_isp_flash_erase_all(port: &mut dyn serialport::SerialPort) -> Result<(), IspError> {
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
) -> Result<(), IspError> {
    let args = vec![
        start_address,
        byte_count,
        0_u32, // internal flash memory identifier
    ];

    send_command(port, CommandTag::FlashEraseRegion, args)?;

    read_response(port, ResponseCode::Generic)?;

    Ok(())
}

/// Errors encountered during ISP interaction with the LPC55.
#[derive(Debug, Error)]
pub enum IspError {
    /// In a situation where we needed an ACK, we got something else.
    #[error("Expected ACK (0xA1), got: {0:#x}")]
    BadAck(u8),

    /// In a situation where our understanding of the protocol suggested that
    /// the next packet should be of type `expected`, we instead got a packet of
    /// type `got`.
    #[error("Expected a {expected:?} packet, got {got:#02x}")]
    WrongPacket { expected: PacketType, got: u8 },

    /// We got the packet we were expecting but it contained an unexpcted
    /// response code.
    #[error("Expected a response code {expected:?}, got {got:#02x}")]
    WrongResponse { expected: ResponseCode, got: u8 },

    /// The command packet contains a parameter count, which is the number of
    /// 32-bit parameters contained therein. It's encapsulated in a framing
    /// packet that contains a length. This means the two can be _mismatched._
    ///
    /// This error is returned if a command packet claims to have more
    /// parameters than could fit in its enclosing framing packet.
    #[error(
        "Command packet claimed to have {expected_len} bytes of params, \
        had {actual_len}"
    )]
    TruncatedParams {
        expected_len: usize,
        actual_len: usize,
    },

    /// We got a GenericResponse after a command (common) but it was ... empty?
    /// We've never seen this in the field and it would likely indicate a crash
    /// or other bug in the bootloader.
    #[error("GenericResponse was empty, should have contained an error code")]
    MissingErrorCode,

    /// Framing packets are protected by a reasonably sturdy CRC16; this error
    /// almost certainly indicates signal integrity issues.
    #[error("Incorrect CRC on packet; expected {expected:#x}, got {got:#x}")]
    CrcFailure { expected: u16, got: u16 },

    /// Communication went fine, but the packet we got back indicated that the
    /// _operation_ we requested failed thus.
    #[error("ISP returned an error status in response")]
    ErrorStatus(#[from] StatusResponse),

    /// Packet contained an invalid value for an enum field or other case that
    /// caused `packed_struct` to refuse to unpack it.
    // NOTE: this variant deliberately does not have a #[from] annotation
    // because pack and unpack use the same error type, frustratingly, giving us
    // no way of distinguishing the two in a From impl.
    #[error("unpacking response failed")]
    Unpack(#[source] packed_struct::PackingError),

    /// Our actual use of the serial port failed.
    #[error("Communications error")]
    Comms(#[from] std::io::Error),
}

/// Describes a non-success status returned by a command.
#[derive(Debug, Error)]
pub enum StatusResponse {
    /// In cases where we can sucessfully turn the numeric status into a
    /// `KnownError`, we'll do so and use this variant.
    #[error(transparent)]
    Known(#[from] KnownError),

    /// This variant is for other cases, errors we haven't felt like adding to
    /// `KnownError` yet (probably because we don't hit them very often).
    // NOTE: the NXP docs list all error codes in decimal, so we do the same
    // here.
    #[error("ISP returned error {0}")]
    GenericErrorCode(u32),
}

/// Error codes that we've hit often enough to give them names and explanatory
/// messages.
///
/// See LPC55 User Manual chapter 8.7 table 251 for more.
#[derive(Debug, FromPrimitive, Copy, Clone, Eq, PartialEq, ToPrimitive, Error)]
pub enum KnownError {
    #[error("Cumulative write error (did you forget to erase?) (err 10203)")]
    CumulativeWriteError = 10203,
    #[error("Incorrect signature or version (err 10101)")]
    IncorrectSignature = 10101,
    #[error("Security violation (err 10001)")]
    SecurityViolation = 10001,
}

fn require_frame_type(frame: &FramingPacket, ty: PacketType) -> Result<(), IspError> {
    if frame.header.packet_type != ty as u8 {
        return Err(IspError::WrongPacket {
            expected: ty,
            got: frame.header.packet_type,
        });
    }
    Ok(())
}
