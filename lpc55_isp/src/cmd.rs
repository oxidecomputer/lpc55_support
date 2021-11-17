use crate::isp::*;
use anyhow::Result;

enum DataPhase<'a> {
    NoData,
    Send {
        code: ResponseCode,
        data: &'a Vec<u8>,
    },
    Recv {
        code: ResponseCode,
        cnt: u32,
    },
}

fn do_command(
    port: &mut dyn serialport::SerialPort,
    tag: CommandTag,
    command_resp: ResponseCode,
    args: Vec<u32>,
    d: DataPhase,
) -> Result<Option<Vec<u8>>> {
    send_command(port, tag, args)?;

    read_response(port, command_resp)?;

    let ret = match d {
        DataPhase::NoData => None,
        DataPhase::Send { code, data } => {
            send_data(port, data)?;
            read_response(port, code)?;
            None
        }
        DataPhase::Recv { code, cnt } => {
            let r = recv_data(port, cnt)?;
            read_response(port, code)?;
            Some(r)
        }
    };

    Ok(ret)
}

pub fn do_save_keystore(port: &mut dyn serialport::SerialPort) -> Result<()> {
    let args = vec![
        // Arg 0 =  WriteNonVolatile
        KeyProvisionCmds::WriteNonVolatile as u32,
        // Arg 1 = Memory ID (0 = internal flash)
        0_u32,
    ];

    do_command(
        port,
        CommandTag::KeyProvision,
        ResponseCode::Generic,
        args,
        DataPhase::NoData,
    )?;

    Ok(())
}

pub fn do_enroll(port: &mut dyn serialport::SerialPort) -> Result<()> {
    let args = vec![
        // Arg =  Enroll
        KeyProvisionCmds::Enroll as u32,
    ];

    do_command(
        port,
        CommandTag::KeyProvision,
        ResponseCode::Generic,
        args,
        DataPhase::NoData,
    )?;

    Ok(())
}

pub fn do_generate_uds(port: &mut dyn serialport::SerialPort) -> Result<()> {
    let args = vec![
        // Arg 0 =  SetIntrinsicKey
        KeyProvisionCmds::SetIntrinsicKey as u32,
        // Arg 1 = UDS
        KeyType::UDS as u32,
        // Arg 2 = size
        32_u32,
    ];

    do_command(
        port,
        CommandTag::KeyProvision,
        ResponseCode::Generic,
        args,
        DataPhase::NoData,
    )?;

    Ok(())
}

pub fn do_isp_write_keystore(port: &mut dyn serialport::SerialPort, data: Vec<u8>) -> Result<()> {
    let args = vec![KeyProvisionCmds::WriteKeyStore as u32];

    do_command(
        port,
        CommandTag::KeyProvision,
        ResponseCode::KeyProvision,
        args,
        DataPhase::Send {
            code: ResponseCode::Generic,
            data: &data,
        },
    )?;

    Ok(())
}

pub fn do_recv_sb_file(port: &mut dyn serialport::SerialPort, data: Vec<u8>) -> Result<()> {
    let args = vec![
        // Arg0 = File len
        data.len() as u32,
    ];

    do_command(
        port,
        CommandTag::ReceiveSbFile,
        ResponseCode::Generic,
        args,
        DataPhase::Send {
            code: ResponseCode::Generic,
            data: &data,
        },
    )?;

    Ok(())
}

pub fn do_isp_set_userkey(
    port: &mut dyn serialport::SerialPort,
    key_type: KeyType,
    data: Vec<u8>,
) -> Result<()> {
    let args = vec![
        // Arg0 = Set User Key
        KeyProvisionCmds::SetUserKey as u32,
        // Arg1 =  Key type
        key_type as u32,
        // Arg2 = Key size
        data.len() as u32,
    ];

    do_command(
        port,
        CommandTag::KeyProvision,
        ResponseCode::KeyProvision,
        args,
        DataPhase::Send {
            code: ResponseCode::Generic,
            data: &data,
        },
    )?;

    Ok(())
}

pub fn do_isp_read_memory(
    port: &mut dyn serialport::SerialPort,
    address: u32,
    cnt: u32,
) -> Result<Vec<u8>> {
    let args = vec![
        // Arg0 = address
        address, // Arg1 = length
        cnt,     // Arg2 = memory type
        0x0,
    ];

    let f = do_command(
        port,
        CommandTag::ReadMemory,
        ResponseCode::ReadMemory,
        args,
        DataPhase::Recv {
            code: ResponseCode::Generic,
            cnt,
        },
    )?;

    Ok(f.unwrap())
}

pub fn do_isp_write_memory(
    port: &mut dyn serialport::SerialPort,
    address: u32,
    data: Vec<u8>,
) -> Result<()> {
    let args = vec![
        // arg 0 = address
        address,
        // arg 1 = len
        data.len() as u32,
        // arg 2 = memory type
        0x0_u32,
    ];

    do_command(
        port,
        CommandTag::WriteMemory,
        ResponseCode::Generic,
        args,
        DataPhase::Send {
            code: ResponseCode::Generic,
            data: &data,
        },
    )?;

    Ok(())
}

pub fn do_isp_flash_erase_all(port: &mut dyn serialport::SerialPort) -> Result<()> {
    let args = vec![
        // Erase internal flash
        0x0_u32,
    ];

    do_command(
        port,
        CommandTag::FlashEraseAll,
        ResponseCode::Generic,
        args,
        DataPhase::NoData,
    )?;

    Ok(())
}

pub fn do_isp_get_property(
    port: &mut dyn serialport::SerialPort,
    prop: BootloaderProperty,
) -> Result<Vec<u32>> {
    let args = vec![
        // Arg 0 = property
        prop as u32,
    ];

    send_command(port, CommandTag::GetProperty, args)?;

    let f = read_response(port, ResponseCode::GetProperty)?;

    Ok(f)
}
