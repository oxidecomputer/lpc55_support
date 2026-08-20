// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// This implementation focuses on UART as that is the common interface available
// on hosts, however the packet format applies to other serial protocols

use crate::isp::*;
use crc_any::CRCu16;
use packed_struct::prelude::*;
use std::convert::TryInto;
use std::io::{Read, Write};

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

#[repr(C)]
#[derive(Debug, PackedStruct)]
#[packed_struct(size_bytes = "2", bit_numbering = "msb0", endian = "msb")]
pub struct PacketHeader {
    #[packed_field(bytes = "0")]
    pub start_byte: u8,
    #[packed_field(bytes = "1")]
    pub packet_type: u8,
}

impl PacketHeader {
    pub fn new(ptype: PacketType) -> PacketHeader {
        PacketHeader {
            start_byte: 0x5A_u8,
            packet_type: ptype as u8,
        }
    }
}

pub fn require_packet_type(frame: &FramingPacket, ty: PacketType) -> Result<(), IspError> {
    if frame.header.packet_type != ty as u8 {
        return Err(IspError::WrongPacket {
            expected: ty as u8,
            got: frame.header.packet_type,
        });
    }
    Ok(())
}

#[repr(C)]
#[derive(Debug, PackedStruct)]
#[packed_struct(bit_numbering = "msb0")]
pub struct PingResponse {
    #[packed_field(size_bytes = "2")]
    pub header: PacketHeader,
    pub protocol_bugfix: u8,
    pub protocol_minor: u8,
    pub protocol_major: u8,
    pub protocol_name: u8,
    pub options_low: u8,
    pub options_high: u8,
    pub crc16_low: u8,
    pub crc16_high: u8,
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

fn send_ack<RW: Read + Write>(port: &mut RW) -> Result<(), IspError> {
    let packet = PacketHeader::new(PacketType::Ack);

    let bytes = packet.pack().unwrap();

    port.write_all(&bytes)?;
    port.flush()?;

    Ok(())
}

fn read_ack<RW: Read + Write>(port: &mut RW) -> Result<(), IspError> {
    let mut ack_bytes: [u8; 2] = [0; 2];

    port.read_exact(&mut ack_bytes)?;

    // Note: PacketHeader unpack should not be able to fail here
    let ack = PacketHeader::unpack_from_slice(&ack_bytes).unwrap();

    // Ack abort comes with a response packet explaining why
    if ack.packet_type == PacketType::AckAbort as u8 {
        let p = port.read_response(ResponseCode::Generic)?;
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

fn read_data<RW: Read + Write>(port: &mut RW) -> Result<Vec<u8>, IspError> {
    let mut frame_bytes = vec![0; FramingPacket::packed_bytes_size(None).unwrap()];
    port.read_exact(&mut frame_bytes)?;

    let frame = FramingPacket::unpack_from_slice(&frame_bytes).unwrap();

    require_packet_type(&frame, PacketType::Data)?;

    let length = usize::from(u16::from_le_bytes([frame.length_low, frame.length_high]));
    let mut response = vec![0; length];
    port.read_exact(&mut response)?;

    check_crc(&frame_bytes, &response, &frame)?;

    Ok(response)
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

impl<RW: Read + Write> Isp for RW {
    fn do_ping(&mut self) -> Result<(), IspError> {
        let ping = PacketHeader::new(PacketType::Ping);

        let ping_bytes = ping.pack().unwrap();

        self.write_all(&ping_bytes)?;

        self.flush()?;

        let mut response_bytes: [u8; 10] = [0; 10];

        self.read_exact(&mut response_bytes)?;

        let response = PingResponse::unpack(&response_bytes).map_err(IspError::Unpack)?;

        if response.header.packet_type != (PacketType::PingResponse as u8) {
            return Err(IspError::BadAck(response.header.packet_type));
        }

        Ok(())
    }

    // Okay _technically_ the response can return values from get-property but for
    // now just return (). If we _really_ need properties we can add that later
    fn read_response(&mut self, response_type: ResponseCode) -> Result<Vec<u32>, IspError> {
        let mut frame_bytes = vec![0; FramingPacket::packed_bytes_size(None).unwrap()];
        self.read_exact(&mut frame_bytes)?;

        let frame = FramingPacket::unpack_from_slice(&frame_bytes).unwrap();

        // A response packet is a specific type of command packet.
        require_packet_type(&frame, PacketType::Command)?;

        let length: usize = usize::from(u16::from_le_bytes([frame.length_low, frame.length_high]));
        let mut response = vec![0; length];
        self.read_exact(&mut response)?;

        check_crc(&frame_bytes, &response, &frame)?;

        let command = RawCommand::unpack_from_slice(
            &response[..RawCommand::packed_bytes_size(None).unwrap()],
        )
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

        send_ack(self)?;

        // First paramter is always the return code;
        let retval = params[0];

        if retval != 0 {
            Err(retval2err(retval).into())
        } else {
            Ok(params)
        }
    }

    fn send_command(&mut self, cmd: CommandTag, args: &[u32]) -> Result<(), IspError> {
        let command_bytes = CommandPacket::new_command(cmd, args).to_bytes();

        self.write_all(&command_bytes)?;
        self.flush()?;

        read_ack(self)?;

        Ok(())
    }

    fn send_data(&mut self, data: &[u8]) -> Result<(), IspError> {
        // Target doesn't like it when we send an entire binary in one pass
        // so break it down into 512 byte chunks which is what the existing
        // tools seem to use
        for chunk in data.chunks(512) {
            let data_bytes = DataPacket::new_data(chunk).to_bytes();

            self.write_all(&data_bytes)?;
            self.flush()?;

            read_ack(self)?;
        }

        Ok(())
    }

    fn recv_data(&mut self, cnt: u32) -> Result<Vec<u8>, IspError> {
        let cnt = cnt as usize;
        let mut data = Vec::with_capacity(cnt);

        while data.len() < cnt {
            data.extend_from_slice(&read_data(self)?);
            send_ack(self)?;
        }

        Ok(data)
    }
}
