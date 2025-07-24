// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::Error;
use byteorder::ByteOrder;
use crc_any::CRCu32;
use lpc55_areas::{
    BootField, BootImageType, HEADER_IMAGE_LENGTH, HEADER_IMAGE_TYPE, HEADER_LOAD_ADDR,
    HEADER_OFFSET,
};
use packed_struct::prelude::*;
use std::path::Path;

pub fn update_crc(src: &Path, dest: &Path, address: u32) -> Result<(), Error> {
    let mut bytes = std::fs::read(src)?;

    // We need to update 3 fields before calculating the CRC:
    //
    // 0x20 = image length (4 bytes)
    // 0x24 = image type (4 bytes)
    // 0x34 = image execution address (4 bytes)
    //
    // The crc gets placed at 0x28. For other types of images the CRC is a
    // pointer where the key data lives
    //

    let len = bytes.len();
    byteorder::LittleEndian::write_u32(&mut bytes[HEADER_IMAGE_LENGTH], len as u32);

    // indicates TZ image and plain CRC XIP image
    // See 7.5.3.1 for details on why we need the TZ bit
    let boot_field = BootField::new(BootImageType::CRCImage);
    bytes[HEADER_IMAGE_TYPE].clone_from_slice(&boot_field.pack()?);

    byteorder::LittleEndian::write_u32(&mut bytes[HEADER_LOAD_ADDR], address);

    // The CRC algorithm NXP uses is crc32 / MPEG-2
    // poly: 0x04c11db7
    // initial: 0xffffffff
    // final xor: 0x00000000
    // reflected: no (left shifting)
    let mut crc = CRCu32::crc32mpeg2();

    // Now calculate the CRC on everything except the bytes where the CRC goes
    crc.digest(&bytes[..HEADER_OFFSET.start]);
    crc.digest(&bytes[HEADER_OFFSET.end..]);

    byteorder::LittleEndian::write_u32(&mut bytes[HEADER_OFFSET], crc.get_crc());

    std::fs::write(dest, &bytes)?;
    Ok(())
}
