// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// The USB protocol is only partially documented in the manual. The main part
// that they leave out is that there are no ACKs. There is no documented ping
// command format, and `blhost` does not seem to try use a ping when
// communicating over USB.

use crate::isp::*;
use nusb::transfer::{In, Interrupt, Out};
use nusb::{list_devices, MaybeFuture};
use packed_struct::prelude::*;
use std::convert::TryInto;
use std::io::{self, ErrorKind, Read, Write};
use std::time::Duration;
use thiserror::Error;

const DEFAULT_USB_TIMEOUT: Duration = Duration::from_millis(100);
const MAX_TX_SIZE: usize = 60; // per the docs

#[repr(u8)]
#[derive(Copy, Clone, Debug)]
pub enum ReportId {
    CommandOut = 0x01,
    DataOut = 0x02,
    CommandIn = 0x03,
    DataIn = 0x04,
}

pub fn require_packet_type(
    frame: &FramingPacket,
    ty: ReportId,
) -> Result<(), IspError> {
    if frame.report_id != ty as u8 {
        return Err(IspError::WrongPacket {
            expected: ty as u8,
            got: frame.report_id,
        });
    }
    Ok(())
}

#[repr(C)]
#[derive(Debug, PackedStruct)]
#[packed_struct(bit_numbering = "msb0", endian = "msb")]
pub struct FramingPacket {
    #[packed_field(size_bytes = "1")]
    report_id: u8,
    pad: u8,
    length_low: u8,
    length_high: u8,
}

impl FramingPacket {
    fn new(ctype: ReportId) -> FramingPacket {
        FramingPacket {
            report_id: ctype as u8,
            pad: 0,
            length_low: 0,
            length_high: 0,
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
    #[packed_field(size_bytes = "4")]
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
            packet: FramingPacket::new(ReportId::CommandOut),
            raw_command: RawCommand::new(c, args.len()),
        };

        let arg_bytes = args.len() * 4;
        // Total length of the command packet. the 4 bytes are for
        // the fixed fields
        // TODO check that length is less than max for USB
        let len: u16 = u16::try_from(4 + arg_bytes)
            .expect("args vec too long for command packet");

        v.packet.length_low = (len & 0xFF) as u8;
        v.packet.length_high = ((len >> 8) & 0xff) as u8;

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
        let arg_len = u16::try_from(args.len())
            .expect("args vector too long for DataPacket");

        let mut f = FramingPacket::new(ReportId::DataOut);

        f.length_low = (arg_len & 0xFF) as u8;
        f.length_high = ((arg_len >> 8) & 0xff) as u8;

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

impl Isp for UsbIsp {
    // TODO figure out what the ping method is on USB
    fn do_ping(&mut self) -> Result<(), IspError> {
        Ok(())
    }

    fn read_response(
        &mut self,
        response_type: ResponseCode,
    ) -> Result<Vec<u32>, IspError> {
        let frame_size = FramingPacket::packed_bytes_size(None).unwrap();

        let mut rx_bytes = vec![0; MAX_TX_SIZE];
        self.reader.read_exact(&mut rx_bytes)?;

        let frame =
            FramingPacket::unpack_from_slice(&rx_bytes[..frame_size]).unwrap();

        // A response packet is a specific type of command packet.
        require_packet_type(&frame, ReportId::CommandIn)?;

        let length: usize = usize::from(u16::from_le_bytes([
            frame.length_low,
            frame.length_high,
        ]));
        let response = &rx_bytes[frame_size..frame_size + length];

        let command = RawCommand::unpack_from_slice(
            &response[..RawCommand::packed_bytes_size(None).unwrap()],
        )
        .map_err(IspError::Unpack)?;

        // Note: we tolerate A0 (generic response) here because many commands
        // return it on failure instead of the expected response type.
        if command.tag != (response_type as u8) && command.tag != 0xA0 {
            return Err(IspError::WrongResponse {
                expected: response_type,
                got: command.tag,
            });
        }

        let mut params: Vec<u32> = Vec::new();
        let index = RawCommand::packed_bytes_size(None).unwrap();

        let end_of_params = index + usize::from(command.parameter_count) * 4;
        let param_bytes = response.get(index..end_of_params).ok_or(
            IspError::TruncatedParams {
                expected_len: end_of_params,
                actual_len: response.len(),
            },
        )?;

        for p in param_bytes.chunks_exact(4) {
            params.push(u32::from_le_bytes(p.try_into().unwrap()));
        }

        // First parameter is always the return code;
        let retval = params[0];

        if retval != 0 {
            Err(retval2err(retval).into())
        } else {
            Ok(params)
        }
    }

    fn send_command(
        &mut self,
        cmd: CommandTag,
        args: &[u32],
    ) -> Result<(), IspError> {
        let command_bytes = CommandPacket::new_command(cmd, args).to_bytes();

        self.writer.write_all(&command_bytes)?;
        self.writer.flush()?;

        Ok(())
    }

    fn send_data(&mut self, data: &[u8]) -> Result<(), IspError> {
        let frame_size = FramingPacket::packed_bytes_size(None).unwrap();
        // we must send transfer sized chunks.
        for chunk in data.chunks(MAX_TX_SIZE - frame_size) {
            let data_bytes = DataPacket::new_data(chunk).to_bytes();

            self.writer.write_all(&data_bytes)?;
            self.writer.flush()?;
        }

        Ok(())
    }

    fn recv_data(&mut self, cnt: u32) -> Result<Vec<u8>, IspError> {
        let cnt = cnt as usize;
        let mut data = Vec::with_capacity(cnt);
        let mut buffer = [0u8; MAX_TX_SIZE];
        let frame_size = FramingPacket::packed_bytes_size(None).unwrap();

        while data.len() < cnt {
            self.reader.read_exact(&mut buffer)?;

            let frame = FramingPacket::unpack_from_slice(&buffer[..frame_size])
                .unwrap();
            // A response packet is a specific type of command packet.
            require_packet_type(&frame, ReportId::DataIn)?;

            let length: usize = usize::from(u16::from_le_bytes([
                frame.length_low,
                frame.length_high,
            ]));
            let response = &buffer[frame_size..frame_size + length];

            data.extend_from_slice(response);
        }

        Ok(data)
    }
}

/// Used for USB interface to ISP devices
pub struct UsbIsp {
    writer: nusb::io::EndpointWrite<Interrupt>,
    reader: nusb::io::EndpointRead<Interrupt>,
}

#[derive(Clone, Copy, PartialEq)]
pub struct UsbId {
    pub vendor_id: u16,
    pub product_id: u16,
}

// because we are accustomed to seeing USB ID's in hex
impl std::fmt::Debug for UsbId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "UsbId {{ vendor_id: 0x{:04x}, product_id: 0x{:04x} }}",
            self.vendor_id, self.product_id
        )
    }
}

// ideally we would use the serial here, but the ISP ROM bootloader doesn't seem
// to provide one. in the case where multiple devices are present we let the
// user optionally supply a port chain
#[derive(Default, Debug, Clone)]
pub struct DeviceSelector {
    pub usb_id: Option<UsbId>,
    pub port_chain: Option<Vec<u8>>,
}

#[derive(Error, Debug, PartialEq, Eq)]
pub enum ParseError {
    #[error("invalid device selector `{0}`")]
    InvalidFormat(String),
    #[error("invalid vendor ID `{0}`")]
    InvalidVendorId(String),
    #[error("invalid device ID `{0}`")]
    InvalidDeviceId(String),
    #[error("invalid port chain `{0}`")]
    InvalidPortChain(String),
}

fn parse_port_chain(s: &str) -> Result<Vec<u8>, ParseError> {
    s.trim()
        .split("-")
        .map(|v| {
            v.parse::<u8>()
                .map_err(|_| ParseError::InvalidPortChain(s.to_owned()))
        })
        .collect()
}

impl std::str::FromStr for DeviceSelector {
    type Err = ParseError;

    /// Parse a DeviceSelector from a string that looks like
    /// `vid:pid[:port-chain-items]`
    ///
    /// `vid` and `pid` are hex vendor/product IDs without 0x prefix. the port
    /// chain is base 10 integers separated by '-' such as "1" or "1-5-2" with
    /// left most being the first in the chain
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let toks: Vec<&str> = s.trim().split(":").collect();
        // ensure we have a reasonable number of tokens
        if toks.len() < 2 || toks.len() > 3 {
            return Err(ParseError::InvalidFormat(s.to_owned()));
        }
        Ok(DeviceSelector {
            usb_id: Some(UsbId {
                vendor_id: u16::from_str_radix(toks[0], 16).map_err(|_| {
                    ParseError::InvalidVendorId(toks[0].to_owned())
                })?,
                product_id: u16::from_str_radix(toks[1], 16).map_err(|_| {
                    ParseError::InvalidDeviceId(toks[1].to_owned())
                })?,
            }),
            port_chain: if let Some(port_chain) = toks.get(2) {
                Some(parse_port_chain(port_chain)?)
            } else {
                None
            },
        })
    }
}

impl UsbIsp {
    pub fn new(dev_sel: &DeviceSelector) -> Result<UsbIsp, io::Error> {
        let device = list_devices()
            .wait()?
            .find(|dev| {
                let id_match = if let Some(ref id_sel) = dev_sel.usb_id {
                    dev.vendor_id() == id_sel.vendor_id
                        && dev.product_id() == id_sel.product_id
                } else {
                    true
                };
                let port_match = if let Some(ref chain_sel) = dev_sel.port_chain
                {
                    chain_sel == dev.port_chain()
                } else {
                    true
                };
                id_match && port_match
            })
            .ok_or(io::Error::new(ErrorKind::NotFound, "device not found"))?;

        let device = device.open().wait()?;
        let interface = device.detach_and_claim_interface(0).wait()?;
        let writer = interface
            .endpoint::<Interrupt, Out>(0x02)?
            .writer(MAX_TX_SIZE)
            .with_write_timeout(DEFAULT_USB_TIMEOUT);
        let mut reader = interface
            .endpoint::<Interrupt, In>(0x81)?
            .reader(MAX_TX_SIZE)
            .with_num_transfers(2)
            .with_read_timeout(DEFAULT_USB_TIMEOUT);
        // drain any existing messages
        let mut buffer = [0; 128];
        while reader.read(&mut buffer).is_ok() {}
        Ok(UsbIsp { writer, reader })
    }

    pub fn close(self) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_device_selector() {
        let ds: DeviceSelector = "AA:55".parse().unwrap();
        assert_eq!(
            ds.usb_id,
            Some(UsbId {
                vendor_id: 0xAA,
                product_id: 0x55
            })
        );
        assert_eq!(ds.port_chain, None);
        let ds: DeviceSelector = "AA:55:1-2".parse().unwrap();
        assert_eq!(
            ds.usb_id,
            Some(UsbId {
                vendor_id: 0xAA,
                product_id: 0x55
            })
        );
        assert_eq!(ds.port_chain, Some(vec![1, 2]));
        let ds: DeviceSelector = "AA:55:1".parse().unwrap();
        assert_eq!(
            ds.usb_id,
            Some(UsbId {
                vendor_id: 0xAA,
                product_id: 0x55
            })
        );
        assert_eq!(ds.port_chain, Some(vec![1]));
        let err = "AZ:55".parse::<DeviceSelector>().err().unwrap();
        assert!(matches!(err, ParseError::InvalidVendorId(_)));
        let err = "AA:5Z".parse::<DeviceSelector>().err().unwrap();
        assert!(matches!(err, ParseError::InvalidDeviceId(_)));
        let err = "AAAAA:55".parse::<DeviceSelector>().err().unwrap();
        assert!(matches!(err, ParseError::InvalidVendorId(_)));
        let err = "AA:5Z::".parse::<DeviceSelector>().err().unwrap();
        assert!(matches!(err, ParseError::InvalidFormat(_)));
        let err = "Foo".parse::<DeviceSelector>().err().unwrap();
        assert!(matches!(err, ParseError::InvalidFormat(_)));
        let err = "AA:55:foo".parse::<DeviceSelector>().err().unwrap();
        assert!(matches!(err, ParseError::InvalidPortChain(_)));
    }
}
