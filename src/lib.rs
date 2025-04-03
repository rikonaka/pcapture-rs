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
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

pub mod error;
pub mod pcap;
pub mod pcapng;

pub use error::PcaptureError;
pub use pcap::Pcap;
pub use pcap::PcapByteOrder;
pub use pcap::PcapHeader;
pub use pcap::PcapRecord;

static DEFAULT_BUFFER_SIZE: usize = 4096;
static DEFAULT_TIMEOUT: f32 = 1.0;
static DETAULT_WIRESHARK_MAX_LEN: usize = 262144;

#[derive(Debug, Clone)]
pub struct Device {
    // Interface name.
    pub name: String,
    /// Interface description.
    pub desc: Option<String>,
    // All ip address (include IPv6 if exists).
    pub ips: Vec<IpNetwork>,
    // Mac address.
    pub mac: Option<MacAddr>,
}

impl Device {
    /// Returns all interfaces in the system.
    /// ```rust
    /// use pcapture::Device;
    ///
    /// fn main() {
    ///     let devices = Device::list();
    ///     for device in {
    ///         println!("device name: {}", device.name);
    ///     }
    /// }
    /// ```
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
    pcap: Pcap,
}

impl Capture {
    /// Returns all interfaces in the system.
    /// ```rust
    /// use pcapture::Capture;
    /// use pcapture::PcapByteOrder;
    ///
    /// fn main() {
    ///     let iface_name = "ens33";
    ///     let cap = Capture::new(iface_name).unwrap();
    ///     // Only five packets are captured for testing.
    ///     for _ in 0..5 {
    ///         let packet: &[u8] = cap.next().unwrap();
    ///         println!("{:?}", packet);
    ///     }
    ///     // Write the five packets captured above into a pcap file.
    ///     // You can then use wireshark to view.
    ///     let _ = cap
    ///        .save_as_pcap("test.pcap", PcapByteOrder::WiresharkDefault)
    ///        .unwrap();
    /// }
    /// ```
    pub fn new(iface_name: &str) -> Result<Capture, PcaptureError> {
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
                    pcap: Pcap::default(),
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
    pub fn next(&mut self) -> Result<&[u8], PcaptureError> {
        match self.rx.next() {
            Ok(packet) => {
                let packet_slice = if packet.len() > DETAULT_WIRESHARK_MAX_LEN {
                    &packet[..DETAULT_WIRESHARK_MAX_LEN]
                } else {
                    packet
                };
                let dura = SystemTime::now().duration_since(UNIX_EPOCH)?;
                let (ts_sec, ts_usec) = if self.pcap.header.magic_number == 0xa1b2c3d4 {
                    // u32 is pcap file struct defined data type, and in pcapng it will be u64
                    let ts_sec = dura.as_secs() as u32;
                    let ts_usec = dura.subsec_micros();
                    (ts_sec, ts_usec)
                } else {
                    let ts_sec = dura.as_secs() as u32;
                    let ts_usec = dura.subsec_nanos();
                    (ts_sec, ts_usec)
                };
                let capt_len = packet_slice.len() as u32;
                let orig_len = packet.len() as u32;
                let pcap_record =
                    PcapRecord::new(ts_sec, ts_usec, capt_len, orig_len, packet_slice);

                self.pcap.append(pcap_record);
                Ok(packet)
            }
            Err(e) => Err(PcaptureError::CapturePacketError { e: e.to_string() }),
        }
    }
    pub fn save_as_pcap(
        &mut self,
        filename: &str,
        pbo: PcapByteOrder,
    ) -> Result<(), PcaptureError> {
        self.pcap.write_all(filename, pbo)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_write_capture() {
        let mut cap = Capture::new("ens33").unwrap();
        for _ in 0..5 {
            let _ = cap.next();
        }
        let _ = cap
            .save_as_pcap("test.pcap", PcapByteOrder::WiresharkDefault)
            .unwrap();
    }
    #[test]
    fn test_read_capture() {
        let pcap = Pcap::read_all("test.pcap", PcapByteOrder::WiresharkDefault).unwrap();
        println!("len: {}", pcap.record.len());
    }
}
