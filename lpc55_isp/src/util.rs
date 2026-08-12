use crate::isp::{CommandTag, Isp, IspError, ResponseCode};
use crate::usb::{DeviceSelector, UsbIsp};
use anyhow::Result;
use nusb::MaybeFuture;
use serialport::{DataBits, FlowControl, Parity, StopBits};
use std::time::Duration;

pub enum InterfaceOptions {
    Usb {
        selector: DeviceSelector,
    },
    Serial {
        name: String,
        baud_rate: Option<u32>,
    },
}

pub enum Interface {
    Usb(UsbIsp),
    Serial(Box<dyn serialport::SerialPort>),
}

impl Isp for Interface {
    fn do_ping(&mut self) -> std::result::Result<(), IspError> {
        match self {
            Interface::Usb(i) => i.do_ping(),
            Interface::Serial(i) => i.do_ping(),
        }
    }

    fn send_data(&mut self, data: &[u8]) -> std::result::Result<(), IspError> {
        match self {
            Interface::Usb(i) => i.send_data(data),
            Interface::Serial(i) => i.send_data(data),
        }
    }

    fn recv_data(
        &mut self,
        cnt: u32,
    ) -> std::result::Result<Vec<u8>, IspError> {
        match self {
            Interface::Usb(i) => i.recv_data(cnt),
            Interface::Serial(i) => i.recv_data(cnt),
        }
    }

    fn send_command(
        &mut self,
        cmd: CommandTag,
        args: &[u32],
    ) -> std::result::Result<(), IspError> {
        match self {
            Interface::Usb(i) => i.send_command(cmd, args),
            Interface::Serial(i) => i.send_command(cmd, args),
        }
    }

    fn read_response(
        &mut self,
        response_type: ResponseCode,
    ) -> std::result::Result<Vec<u32>, IspError> {
        match self {
            Interface::Usb(i) => i.read_response(response_type),
            Interface::Serial(i) => i.read_response(response_type),
        }
    }
}

pub fn open_interface(interface: InterfaceOptions) -> Result<Interface> {
    match interface {
        InterfaceOptions::Serial { name, baud_rate } => {
            // The target _technically_ has autobaud but it's very flaky and
            // these seem to be the preferred settings. 57,600 baud seems very
            // reliable but is rather slow. In certain test setups we've gotten
            // rates of up to 1Mbaud to work reliably -- your mileage may vary!
            //
            // We initially set the timeout short so we can drain the incoming
            // buffer in a portable manner below. We'll adjust it up after that.
            let mut port = serialport::new(name, baud_rate.unwrap_or(57600))
                .timeout(Duration::from_millis(100))
                .data_bits(DataBits::Eight)
                .flow_control(FlowControl::None)
                .parity(Parity::None)
                .stop_bits(StopBits::One)
                .open()?;

            // Extract any bytes left over in the serial port driver from
            // previous interaction.
            loop {
                let mut throwaway = [0; 16];
                match port.read(&mut throwaway) {
                    Ok(0) => {
                        // This should only happen on nonblocking reads, which
                        // we haven't asked for, but it does mean the buffer is
                        // empty so treat it as success.
                        break;
                    }
                    Ok(_) => {
                        // We've collected some characters to throw away, keep
                        // going.
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
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
            Ok(Interface::Serial(port))
        }
        InterfaceOptions::Usb { selector } => {
            Ok(Interface::Usb(UsbIsp::new(&selector)?))
        }
    }
}

pub struct InterfaceList {
    pub serial: Vec<String>,
    pub usb: Vec<(String, String, String)>,
}

pub fn list_interfaces() -> Result<InterfaceList> {
    let mut serial = Vec::new();
    for port in serialport::available_ports()?.into_iter() {
        serial.push(port.port_name.clone());
    }
    serial.sort();

    let mut usb = Vec::new();
    for port in nusb::list_devices().wait()? {
        let vid = format!("{0:04x}", port.vendor_id());
        let pid = format!("{0:04x}", port.product_id());
        let bus = port.bus_id();
        let port_chain = port
            .port_chain()
            .iter()
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join("-");
        let mfg = port.manufacturer_string().unwrap_or("");
        let dsc = port.product_string().unwrap_or("");
        usb.push((
            format!("{vid}:{pid}"),
            format!("{bus}@{port_chain}"),
            format!("{}: {}", mfg, dsc),
        ))
    }
    usb.sort_by_cached_key(|dev| dev.1.clone());

    Ok(InterfaceList { serial, usb })
}

impl std::fmt::Display for InterfaceList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for ser in self.serial.iter() {
            writeln!(f, "ser {}", ser)?;
        }
        let padding = self.usb.iter().fold(0, |acc, usb| usb.1.len().max(acc));
        for usb in self.usb.iter() {
            writeln!(f, "usb {}:{:padding$} {}", usb.0, usb.1, usb.2)?;
        }
        Ok(())
    }
}
