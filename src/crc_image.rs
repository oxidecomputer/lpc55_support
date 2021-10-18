use crate::areas::{BootField, BootImageType};
use anyhow::Result;
use byteorder::ByteOrder;
use crc_any::CRCu32;
use packed_struct::prelude::*;
use std::path::Path;

pub fn update_crc(src: &Path, dest: &Path) -> Result<()> {
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
    byteorder::LittleEndian::write_u32(&mut bytes[0x20..0x24], len as u32);

    // indicates TZ image and plain CRC XIP image
    // See 7.5.3.1 for details on why we need the TZ bit
    let boot_field = BootField::new(BootImageType::CRCImage);
    bytes[0x24..0x28].clone_from_slice(&boot_field.pack()?);

    // Our execution address is always 0
    byteorder::LittleEndian::write_u32(&mut bytes[0x34..0x38], 0x0);

    // The CRC algorithm NXP uses is crc32 / MPEG-2
    // poly: 0x04c11db7
    // initial: 0xffffffff
    // final xor: 0x00000000
    // reflected: no (left shifting)
    let mut crc = CRCu32::crc32mpeg2();

    // Now calculate the CRC on everything except the bytes where the CRC goes
    crc.digest(&bytes[..0x28]);
    crc.digest(&bytes[0x2c..]);

    byteorder::LittleEndian::write_u32(&mut bytes[0x28..0x2c], crc.get_crc());

    std::fs::write(dest, &bytes)?;
    Ok(())
}
