// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use clap::ValueEnum;
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::FromPrimitive;
use packed_struct::prelude::*;
use thiserror::Error;

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
#[derive(Debug, FromPrimitive, Clone, Copy, ValueEnum)]
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

#[derive(Debug, PackedStruct, Default)]
#[packed_struct(bit_numbering = "msb0", endian = "msb")]
#[repr(C)]
pub struct RawCommand {
    pub tag: u8,
    pub flags: u8,
    pub reserved: u8,
    pub parameter_count: u8,
}

impl RawCommand {
    pub fn new(c: CommandTag, count: usize) -> RawCommand {
        RawCommand {
            tag: c as u8,
            flags: 0,
            reserved: 0,
            parameter_count: count as u8,
        }
    }
}

pub trait Isp {
    fn do_ping(&mut self) -> Result<(), IspError>;
    fn read_response(
        &mut self,
        response_type: ResponseCode,
    ) -> Result<Vec<u32>, IspError>;
    fn send_command(
        &mut self,
        cmd: CommandTag,
        args: &[u32],
    ) -> Result<(), IspError>;
    fn send_data(&mut self, data: &[u8]) -> Result<(), IspError>;
    fn recv_data(&mut self, cnt: u32) -> Result<Vec<u8>, IspError>;
}

pub fn retval2err(retval: u32) -> StatusResponse {
    if let Some(e) = KnownError::from_u32(retval) {
        StatusResponse::Known(e)
    } else {
        StatusResponse::GenericErrorCode(retval)
    }
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
    WrongPacket { expected: u8, got: u8 },

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

    /// Our actual use of the I/O device failed.
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
#[derive(
    Debug, FromPrimitive, Copy, Clone, Eq, PartialEq, ToPrimitive, Error,
)]
pub enum KnownError {
    #[error("Cumulative write error (did you forget to erase?) (err 10203)")]
    CumulativeWriteError = 10203,
    #[error("Incorrect signature or version (err 10101)")]
    IncorrectSignature = 10101,
    #[error("Security violation (err 10001)")]
    SecurityViolation = 10001,
}
