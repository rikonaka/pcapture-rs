use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::ChannelType;
use pnet::datalink::Config;
use pnet::datalink::DataLinkReceiver;
use pnet::datalink::DataLinkSender;
use pnet::datalink::MacAddr;
use pnet::datalink::NetworkInterface;
use pnet::ipnetwork::IpNetwork;
use std::fs::File;
use std::time::Duration;

pub mod error;
pub mod pcap;
pub mod pcapng;

use error::PcaptureError;
use pcap::PacketRecord;
use pcap::Pcap;
use pcap::PcapByteOrder;
use pcapng::EnhancedPacketBlock;
use pcapng::GeneralBlockStructure;
use pcapng::PcapNg;

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

#[derive(Debug, Clone)]
pub enum PFormat {
    Pcap(Pcap),
    PcapNg(PcapNg),
}
pub struct Capture {
    config: Config,
    interface: NetworkInterface,
    tx: Box<dyn DataLinkSender>,
    rx: Box<dyn DataLinkReceiver>,
    pformat: PFormat,
    sync_mode: bool,
    fs: Option<File>,
    pbo: PcapByteOrder,
}

impl Capture {
    /// Capture the traffic packet and save to file.
    /// ```rust
    /// use pcapture::Capture;
    /// use pcapture::PcapByteOrder;
    ///
    /// fn main() {
    ///     let iface_name = "ens33";
    ///     // Capture as pcap format.
    ///     let cap = Capture::new_pcap(iface_name, , PcapByteOrder::WiresharkDefault).unwrap();
    ///     // Only five packets are captured for testing.
    ///     for _ in 0..5 {
    ///         let packet: &[u8] = cap.next().unwrap();
    ///         println!("{:?}", packet);
    ///     }
    ///     // Write all the five packets captured above once into a pcap file, you can then use wireshark to view it.
    ///     // Suitable for capturing a small number of packets, if the number of packets is large, please use sync_mode.
    ///     let _ = cap.save_all("test.pcap").unwrap();
    /// }
    /// ```
    pub fn new_pcap(iface_name: &str, pbo: PcapByteOrder) -> Result<Capture, PcaptureError> {
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
                    pformat: PFormat::Pcap(Pcap::default()),
                    sync_mode: false,
                    fs: None,
                    pbo,
                };
                return Ok(c);
            }
        }
        Err(PcaptureError::UnableFoundInterface {
            i: iface_name.to_string(),
        })
    }
    pub fn new_pcapng(iface_name: &str, pbo: PcapByteOrder) -> Result<Capture, PcaptureError> {
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
                    interface: interface.clone(),
                    tx,
                    rx,
                    pformat: PFormat::PcapNg(PcapNg::new(interface)?),
                    sync_mode: false,
                    fs: None,
                    pbo,
                };
                return Ok(c);
            }
        }
        Err(PcaptureError::UnableFoundInterface {
            i: iface_name.to_string(),
        })
    }
    /// Capture the traffic packet and save to file.
    /// ```rust
    /// use pcapture::Capture;
    /// use pcapture::PcapByteOrder;
    ///
    /// fn main() {
    ///     let iface_name = "ens33";
    ///     let cap = Capture::new(iface_name, PcapByteOrder::WiresharkDefault).unwrap();
    ///     // Set the sync mode to avoid storing large packets in memory and write them directly to the file.
    ///     cap.sync_mode("test.pcap")
    ///     // Only five packets are captured for testing.
    ///     for _ in 0..5 {
    ///         let packet: &[u8] = cap.next().unwrap();
    ///         println!("{:?}", packet);
    ///     }
    /// }
    /// ```
    pub fn sync_mode(&mut self, path: &str) -> Result<(), PcaptureError> {
        let mut fs = File::create(path)?;
        // write the header to file
        match &mut self.pformat {
            PFormat::Pcap(pcap) => {
                pcap.header.write(&mut fs, self.pbo)?;
                for r in &pcap.records {
                    r.write(&mut fs, self.pbo)?;
                }
                // remove all the records from memory
                pcap.records.clear();
            }
            PFormat::PcapNg(pcapng) => {
                for b in &mut pcapng.blocks {
                    b.write(&mut fs, self.pbo)?;
                }
                // remove all the blocks from memory
                pcapng.blocks.clear();
            }
        }

        // update the config
        self.fs = Some(fs);
        self.sync_mode = true;

        Ok(())
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
    pub fn byte_order(&mut self, pbo: PcapByteOrder) {
        self.pbo = pbo;
    }
    pub fn next(&mut self) -> Result<&[u8], PcaptureError> {
        match self.rx.next() {
            Ok(packet_data) => {
                match &mut self.pformat {
                    PFormat::Pcap(pcap) => {
                        let pcap_record = PacketRecord::new(pcap.header.magic_number, packet_data)?;
                        if self.sync_mode {
                            let fs = match &mut self.fs {
                                Some(fs) => fs,
                                None => return Err(PcaptureError::FileDescriptorDoesNotExist),
                            };
                            // write it to file
                            pcap_record.write(fs, self.pbo)?;
                        } else {
                            pcap.append(pcap_record);
                        }
                        Ok(packet_data)
                    }
                    PFormat::PcapNg(pcapng) => {
                        let mut block = EnhancedPacketBlock::new(1, packet_data)?;
                        if self.sync_mode {
                            let fs = match &mut self.fs {
                                Some(fs) => fs,
                                None => return Err(PcaptureError::FileDescriptorDoesNotExist),
                            };
                            // write it to file
                            block.write(fs, self.pbo)?;
                        } else {
                            let general_block = GeneralBlockStructure::EnhancedPacketBlock(block);
                            pcapng.append(general_block);
                        }
                        Ok(packet_data)
                    }
                }
            }
            Err(e) => Err(PcaptureError::CapturePacketError { e: e.to_string() }),
        }
    }
    pub fn save_all(&mut self, path: &str) -> Result<(), PcaptureError> {
        match &mut self.pformat {
            PFormat::Pcap(pcap) => {
                pcap.write_all(path, self.pbo)?;
            }
            PFormat::PcapNg(pcapng) => {
                pcapng.write_all(path, self.pbo)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_pcap_capture_and_write() {
        let mut cap = Capture::new_pcap("ens33", PcapByteOrder::WiresharkDefault).unwrap();
        for _ in 0..5 {
            let _ = cap.next();
        }
        let _ = cap.save_all("test.pcap").unwrap();
    }
    #[test]
    fn test_pcapng_capture_and_write() {
        let mut cap = Capture::new_pcapng("ens33", PcapByteOrder::WiresharkDefault).unwrap();
        for _ in 0..5 {
            let _ = cap.next();
        }
        let _ = cap.save_all("test.pcapng").unwrap();
    }
    #[test]
    fn test_read_capture() {
        let pcap = Pcap::read_all("test.pcap", PcapByteOrder::WiresharkDefault).unwrap();
        println!("len: {}", pcap.records.len());
    }
}
