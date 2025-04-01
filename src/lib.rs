use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::ChannelType;
use pnet::datalink::Config;
use pnet::datalink::DataLinkReceiver;
use pnet::datalink::DataLinkSender;
use pnet::datalink::MacAddr;
use pnet::datalink::NetworkInterface;
use pnet::ipnetwork::IpNetwork;
use std::time::Duration;

pub mod error;
pub mod pcap;

use error::PcaptureError;

static DEFAULT_BUFFER_SIZE: usize = 4096;
static DEFAULT_TIMEOUT: f32 = 1.0;

#[derive(Debug, Clone)]
pub struct PcapFs {}

impl PcapFs {
    pub fn read() {}
}

#[derive(Debug, Clone)]
pub struct Device {
    pub name: String,
    pub desc: Option<String>,
    pub ips: Vec<IpNetwork>,
    pub mac: Option<MacAddr>,
}

impl Device {
    pub fn list() -> Vec<Device> {
        let ni = datalink::interfaces();
        let mut ret = Vec::new();
        for n in ni {
            let name = n.name;
            let desc = if n.description.len() > 0 {
                Some(n.description)
            } else {
                None
            };
            let mac = n.mac;
            let ips = n.ips;

            let d = Device {
                name,
                desc,
                mac,
                ips,
            };
            ret.push(d);
        }
        ret
    }
}

pub struct Capture {
    config: Config,
    interface: NetworkInterface,
    tx: Box<dyn DataLinkSender>,
    rx: Box<dyn DataLinkReceiver>,
}

impl Capture {
    pub fn init(iface_name: &str) -> Result<Capture, PcaptureError> {
        let interfaces = datalink::interfaces();
        for interface in interfaces {
            if interface.name == iface_name {
                let timeout = Duration::from_secs_f32(DEFAULT_TIMEOUT);
                let config = Config {
                    write_buffer_size: DEFAULT_BUFFER_SIZE,
                    read_buffer_size: DEFAULT_BUFFER_SIZE,
                    read_timeout: Some(timeout),
                    write_timeout: Some(timeout),
                    channel_type: ChannelType::Layer2,
                    bpf_fd_attempts: 1000,
                    linux_fanout: None,
                    promiscuous: true,
                    socket_fd: None,
                };
                let (tx, rx) = match datalink::channel(&interface, config) {
                    Ok(Ethernet(tx, rx)) => (tx, rx),
                    Ok(_) => return Err(PcaptureError::UnhandledChannelType),
                    Err(e) => return Err(PcaptureError::UnableCreateChannel { e: e.to_string() }),
                };
                let c = Capture {
                    config,
                    interface,
                    tx,
                    rx,
                };
                return Ok(c);
            }
        }
        Err(PcaptureError::UnableFoundInterface {
            i: iface_name.to_string(),
        })
    }
    fn regen(&mut self) -> Result<(), PcaptureError> {
        let (tx, rx) = match datalink::channel(&self.interface, self.config) {
            Ok(Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => return Err(PcaptureError::UnhandledChannelType),
            Err(e) => return Err(PcaptureError::UnableCreateChannel { e: e.to_string() }),
        };
        self.tx = tx;
        self.rx = rx;
        Ok(())
    }
    pub fn buffer_size(&mut self, buffer_size: usize) -> Result<(), PcaptureError> {
        self.config.read_buffer_size = buffer_size;
        self.config.write_buffer_size = buffer_size;
        self.regen()
    }
    /// timeout as sec
    pub fn timeout(&mut self, timeout: f32) -> Result<(), PcaptureError> {
        let timeout_fix = Duration::from_secs_f32(timeout);
        self.config.read_timeout = Some(timeout_fix);
        self.config.write_timeout = Some(timeout_fix);
        self.regen()
    }
    pub fn promiscuous(&mut self, promiscuous: bool) -> Result<(), PcaptureError> {
        self.config.promiscuous = promiscuous;
        self.regen()
    }
    pub fn next(&mut self) -> Result<Vec<u8>, PcaptureError> {
        match self.rx.next() {
            Ok(packet) => Ok(packet.to_vec()),
            Err(e) => Err(PcaptureError::CapturePacketError { e: e.to_string() }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test() {
        let ni = datalink::interfaces();
        for n in ni {
            println!("{:?}", n);
        }
    }
}
