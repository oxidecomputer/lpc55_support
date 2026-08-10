// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::isp::*;

enum DataPhase<'a> {
    NoData,
    Send { code: ResponseCode, data: &'a [u8] },
    Recv { code: ResponseCode, cnt: u32 },
}

fn do_command<P: Isp>(
    port: &mut P,
    tag: CommandTag,
    command_resp: ResponseCode,
    args: impl Into<Vec<u32>>,
    d: DataPhase,
) -> Result<Option<Vec<u8>>, IspError> {
    port.send_command(tag, args)?;

    port.read_response(command_resp)?;

    let ret = match d {
        DataPhase::NoData => None,
        DataPhase::Send { code, data } => {
            port.send_data(data)?;
            port.read_response(code)?;
            None
        }
        DataPhase::Recv { code, cnt } => {
            let r = port.recv_data(cnt)?;
            port.read_response(code)?;
            Some(r)
        }
    };

    Ok(ret)
}

pub fn do_save_keystore<P: Isp>(port: &mut P) -> Result<(), IspError> {
    do_command(
        port,
        CommandTag::KeyProvision,
        ResponseCode::Generic,
        [
            // Arg 0 =  WriteNonVolatile
            KeyProvisionCmds::WriteNonVolatile as u32,
            // Arg 1 = Memory ID (0 = internal flash)
            0_u32,
        ],
        DataPhase::NoData,
    )?;

    Ok(())
}

pub fn do_enroll<P: Isp>(port: &mut P) -> Result<(), IspError> {
    do_command(
        port,
        CommandTag::KeyProvision,
        ResponseCode::Generic,
        [KeyProvisionCmds::Enroll as u32],
        DataPhase::NoData,
    )?;

    Ok(())
}

pub fn do_generate_uds<P: Isp>(port: &mut P) -> Result<(), IspError> {
    do_command(
        port,
        CommandTag::KeyProvision,
        ResponseCode::Generic,
        [
            // Arg 0 =  SetIntrinsicKey
            KeyProvisionCmds::SetIntrinsicKey as u32,
            // Arg 1 = UDS
            KeyType::UDS as u32,
            // Arg 2 = size
            32,
        ],
        DataPhase::NoData,
    )?;

    Ok(())
}

pub fn do_isp_write_keystore<P: Isp>(port: &mut P, data: &[u8]) -> Result<(), IspError> {
    do_command(
        port,
        CommandTag::KeyProvision,
        ResponseCode::KeyProvision,
        [KeyProvisionCmds::WriteKeyStore as u32],
        DataPhase::Send {
            code: ResponseCode::Generic,
            data,
        },
    )?;

    Ok(())
}

pub fn do_recv_sb_file<P: Isp>(port: &mut P, data: &[u8]) -> Result<(), IspError> {
    do_command(
        port,
        CommandTag::ReceiveSbFile,
        ResponseCode::Generic,
        [data.len() as u32],
        DataPhase::Send {
            code: ResponseCode::Generic,
            data,
        },
    )?;

    Ok(())
}

pub fn do_isp_set_userkey<P: Isp>(
    port: &mut P,
    key_type: KeyType,
    data: &[u8],
) -> Result<(), IspError> {
    do_command(
        port,
        CommandTag::KeyProvision,
        ResponseCode::KeyProvision,
        [
            // Arg0 = Set User Key
            KeyProvisionCmds::SetUserKey as u32,
            // Arg1 =  Key type
            key_type as u32,
            // Arg2 = Key size
            data.len() as u32,
        ],
        DataPhase::Send {
            code: ResponseCode::Generic,
            data,
        },
    )?;

    Ok(())
}

pub fn do_isp_read_memory<P: Isp>(
    port: &mut P,
    address: u32,
    cnt: u32,
) -> Result<Vec<u8>, IspError> {
    let f = do_command(
        port,
        CommandTag::ReadMemory,
        ResponseCode::ReadMemory,
        [
            // Arg0 = address
            address, // Arg1 = length
            cnt,     // Arg2 = memory type
            0x0,
        ],
        DataPhase::Recv {
            code: ResponseCode::Generic,
            cnt,
        },
    )?;

    Ok(f.unwrap())
}

pub fn do_isp_write_memory<P: Isp>(
    port: &mut P,
    address: u32,
    data: &[u8],
) -> Result<(), IspError> {
    do_command(
        port,
        CommandTag::WriteMemory,
        ResponseCode::Generic,
        [
            // arg 0 = address
            address,
            // arg 1 = len
            data.len() as u32,
            // arg 2 = memory type
            0x0_u32,
        ],
        DataPhase::Send {
            code: ResponseCode::Generic,
            data,
        },
    )?;

    Ok(())
}

pub fn do_isp_flash_erase_all<P: Isp>(port: &mut P) -> Result<(), IspError> {
    do_command(
        port,
        CommandTag::FlashEraseAll,
        ResponseCode::Generic,
        [
            // Erase internal flash
            0x0_u32,
        ],
        DataPhase::NoData,
    )?;

    Ok(())
}

pub fn do_isp_flash_erase_region<P: Isp>(
    port: &mut P,
    start_address: u32,
    byte_count: u32,
) -> Result<(), IspError> {
    do_command(
        port,
        CommandTag::FlashEraseRegion,
        ResponseCode::Generic,
        [
            start_address,
            byte_count,
            // Erase internal flash
            0x0,
        ],
        DataPhase::NoData,
    )?;

    Ok(())
}

pub fn do_isp_get_property<P: Isp>(
    port: &mut P,
    prop: BootloaderProperty,
) -> Result<Vec<u32>, IspError> {
    port.send_command(CommandTag::GetProperty, [prop as u32])?;

    let f = port.read_response(ResponseCode::GetProperty)?;

    Ok(f)
}

pub fn do_isp_last_error<P: Isp>(port: &mut P) -> Result<Vec<u32>, IspError> {
    port.send_command(
        CommandTag::GetProperty,
        [
            // Arg 0 = LastCRC
            BootloaderProperty::CRCStatus as u32,
            // Arg 1 = Last error
            1,
        ],
    )?;

    let f = port.read_response(ResponseCode::GetProperty)?;

    Ok(f)
}
