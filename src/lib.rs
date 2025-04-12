use pcapng::InterfaceDescriptionBlock;
use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::ChannelType;
use pnet::datalink::Config;
use pnet::datalink::DataLinkReceiver;
use pnet::datalink::DataLinkSender;
use pnet::datalink::MacAddr;
use pnet::datalink::NetworkInterface;
use pnet::ipnetwork::IpNetwork;
use std::collections::HashMap;
use std::fs::File;
use std::sync::LazyLock;
use std::sync::Mutex;
use std::time::Duration;
use std::u32;

pub mod error;
pub mod pcap;
pub mod pcapng;
pub mod transport;

use error::PcaptureError;
use pcap::PacketRecord;
use pcap::Pcap;
use pcapng::EnhancedPacketBlock;
use pcapng::GeneralBlockStructure;
use pcapng::PcapNg;

static DEFAULT_BUFFER_SIZE: usize = 65535;
static DEFAULT_TIMEOUT: u64 = 1;
static DETAULT_SNAPLEN: usize = 65535;
static INTERFACE_ID: LazyLock<Mutex<u32>> = LazyLock::new(|| Mutex::new(0));
static INTERFACE_IDS_MAP: LazyLock<Mutex<HashMap<String, u32>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

#[derive(Debug, Clone, Copy)]
pub enum PcapByteOrder {
    BigEndian,
    LittleEndian,
    WiresharkDefault, // LittleEndian
}

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
    ///     for device in devices {
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
pub enum CaptureFormat {
    Pcap(Pcap),
    PcapNg(PcapNg),
}

#[derive(Debug, Clone)]
pub struct Iface {
    pub id: u32,
    pub interface: NetworkInterface,
}

#[derive(Debug, Clone)]
pub struct Ifaces {
    pub interfaces: Vec<Iface>,
}

impl Ifaces {
    pub fn find(&self, iface_name: &str) -> Option<Iface> {
        for i in &self.interfaces {
            if i.interface.name == iface_name {
                return Some(i.clone());
            }
        }
        None
    }
}

impl<'a> IntoIterator for &'a Ifaces {
    type Item = &'a Iface;
    type IntoIter = std::slice::Iter<'a, Iface>;

    fn into_iter(self) -> Self::IntoIter {
        self.interfaces.iter()
    }
}

fn get_new_interface_id() -> Result<u32, PcaptureError> {
    let mut id = match INTERFACE_ID.lock() {
        Ok(i) => i,
        Err(e) => {
            return Err(PcaptureError::UnlockGlobalVariableError {
                name: String::from("INTERFACE_ID"),
                e: e.to_string(),
            });
        }
    };
    let current_id = *id;
    *id += 1;
    Ok(current_id)
}

fn update_interface_id_map(iface_name: &str, interface_id: u32) -> Result<(), PcaptureError> {
    let mut map = match INTERFACE_IDS_MAP.lock() {
        Ok(m) => m,
        Err(e) => {
            return Err(PcaptureError::UnlockGlobalVariableError {
                name: String::from("INTERFACE_IDS_MAP"),
                e: e.to_string(),
            });
        }
    };
    let _ = (*map).insert(iface_name.to_string(), interface_id);
    Ok(())
}

fn check_interface_id_map(iface_name: &str) -> Result<Option<u32>, PcaptureError> {
    let map = match INTERFACE_IDS_MAP.lock() {
        Ok(m) => m,
        Err(e) => {
            return Err(PcaptureError::UnlockGlobalVariableError {
                name: String::from("INTERFACE_IDS_MAP"),
                e: e.to_string(),
            });
        }
    };
    for (k, &v) in &(*map) {
        if k == iface_name {
            return Ok(Some(v));
        }
    }
    Ok(None)
}

pub struct Capture {
    config: Config,
    pis: Ifaces,
    pi: Iface,
    tx: Box<dyn DataLinkSender>,
    rx: Box<dyn DataLinkReceiver>,
    pformat: CaptureFormat,
    sync_mode: bool,
    snaplen: usize,
    fs: Option<File>,
    pbo: PcapByteOrder,
}

impl Capture {
    fn new(
        iface_name: &str,
        pbo: PcapByteOrder,
        is_pcapng: bool,
    ) -> Result<Capture, PcaptureError> {
        let mut pvec = Vec::new();
        let interfaces = datalink::interfaces();
        for interface in interfaces {
            let pi = Iface {
                id: u32::MAX, // indicates unused state
                interface,
            };
            pvec.push(pi);
        }
        let pis = Ifaces { interfaces: pvec };

        let timeout = Duration::from_secs(DEFAULT_TIMEOUT);
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
        match &mut pis.find(iface_name) {
            Some(pi) => {
                let (tx, rx) = match datalink::channel(&pi.interface, config) {
                    Ok(Ethernet(tx, rx)) => (tx, rx),
                    Ok(_) => return Err(PcaptureError::UnhandledChannelType),
                    Err(e) => return Err(PcaptureError::UnableCreateChannel { e: e.to_string() }),
                };
                // assign the interface id here (start value is 0, next is 1)
                let current_id = get_new_interface_id()?;
                update_interface_id_map(iface_name, current_id)?;
                pi.id = current_id;
                let pformat = if is_pcapng {
                    CaptureFormat::PcapNg(PcapNg::new(&pi)?)
                } else {
                    CaptureFormat::Pcap(Pcap::default())
                };
                let c = Capture {
                    config,
                    pis,
                    pi: pi.clone(),
                    tx,
                    rx,
                    pformat,
                    sync_mode: false,
                    snaplen: DETAULT_SNAPLEN,
                    fs: None,
                    pbo,
                };
                return Ok(c);
            }
            None => Err(PcaptureError::UnableFoundInterface {
                i: iface_name.to_string(),
            }),
        }
    }
    /// Capture the traffic packet and save to file.
    /// ```rust
    /// use pcapture::Capture;
    /// use pcapture::PcapByteOrder;
    ///
    /// fn main() {
    ///     let iface_name = "ens33";
    ///     // Capture as pcap format.
    ///     let cap = Capture::new_pcap(iface_name, , PcapByteOrder::WiresharkDefault).unwrap();
    ///     // Only five packets are captured for testing and store it at memory.
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
        Capture::new(iface_name, pbo, false)
    }
    /// In this mode, like Wireshark, Enhanced Packet Block (EPB) is used by default to store packet.
    pub fn new_pcapng(iface_name: &str, pbo: PcapByteOrder) -> Result<Capture, PcaptureError> {
        Capture::new(iface_name, pbo, true)
    }
    /// As soon as the packet is received, it is written to the file.
    /// ```rust
    /// use pcapture::Capture;
    /// use pcapture::PcapByteOrder;
    ///
    /// fn main() {
    ///     let iface_name = "ens33";
    ///     let cap = Capture::new_pcapng(iface_name, PcapByteOrder::WiresharkDefault).unwrap();
    ///     // Set the sync mode to avoid storing large packets in memory.
    ///     cap.sync_mode("test.pcapng")
    ///     // Only five packets are captured for testing.
    ///     for _ in 0..5 {
    ///         let packet: &[u8] = cap.next().unwrap();
    ///         println!("{:?}", packet);
    ///     }
    ///     // The captured data will be automatically saved to `test.pcapng`.
    ///     // So there is no need to call the `save_all` function at all.
    ///     // let _ = cap.save_all("test.pcapng").unwrap();
    /// }
    /// ```
    pub fn sync_mode(&mut self, path: &str) -> Result<(), PcaptureError> {
        let mut fs = File::create(path)?;
        // write the header to file
        match &mut self.pformat {
            CaptureFormat::Pcap(pcap) => {
                pcap.header.write(&mut fs, self.pbo)?;
                for r in &pcap.records {
                    r.write(&mut fs, self.pbo)?;
                }
                // remove all the records from memory
                pcap.records.clear();
            }
            CaptureFormat::PcapNg(pcapng) => {
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
        let (tx, rx) = match datalink::channel(&self.pi.interface, self.config) {
            Ok(Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => return Err(PcaptureError::UnhandledChannelType),
            Err(e) => return Err(PcaptureError::UnableCreateChannel { e: e.to_string() }),
        };
        self.tx = tx;
        self.rx = rx;
        Ok(())
    }
    /// Change the capture interface (pcapng format only).
    /// ```rust
    /// use pcapture::Capture;
    /// use pcapture::PcapByteOrder;
    ///
    /// fn main() {
    ///     let iface_name = "ens33";
    ///     let cap = Capture::new_pcapng(iface_name, PcapByteOrder::WiresharkDefault).unwrap();
    ///     // Set the sync mode to avoid storing large packets in memory and write them directly to the file.
    ///     cap.sync_mode("test.pcapng")
    ///     // Only five packets are captured for testing.
    ///     for _ in 0..5 {
    ///         let packet: &[u8] = cap.next().unwrap();
    ///         println!("{:?}", packet);
    ///     }
    ///     // Change to other interface.
    ///     cap.change_iface("ens38").unwrap();
    ///     // Still only five packets are captured for testing.
    ///     for _ in 0..5 {
    ///         let packet: &[u8] = cap.next().unwrap();
    ///         println!("{:?}", packet);
    ///     }
    /// }
    /// ```
    pub fn change_iface(&mut self, iface_name: &str) -> Result<(), PcaptureError> {
        if iface_name == self.pi.interface.name {
            return Err(PcaptureError::SameInterafceError {
                new: iface_name.to_string(),
                pre: self.pi.interface.name.clone(),
            });
        } else {
            let mut need_regen = false;
            for pi in &self.pis {
                if pi.interface.name == iface_name {
                    let mut new_pi = pi.clone();
                    // check if it has been used before
                    let find_id = match check_interface_id_map(iface_name)? {
                        Some(i) => i,
                        None => {
                            let interface_id = get_new_interface_id()?;
                            update_interface_id_map(iface_name, interface_id)?;
                            interface_id
                        }
                    };
                    new_pi.id = find_id;
                    let mut idb = InterfaceDescriptionBlock::new(&new_pi)?;
                    match self.sync_mode {
                        true => {
                            // we need to write the new idb to the file
                            let fs = match &mut self.fs {
                                Some(fs) => fs,
                                None => return Err(PcaptureError::FileDescriptorDoesNotExist),
                            };
                            idb.write(fs, self.pbo)?;
                        }
                        false => match &mut self.pformat {
                            CaptureFormat::Pcap(_) => return Err(PcaptureError::PcapNgOnlyError),
                            CaptureFormat::PcapNg(pcapng) => {
                                let gbs = GeneralBlockStructure::InterfaceDescriptionBlock(idb);
                                pcapng.append(gbs);
                            }
                        },
                    }
                    self.pi = new_pi;
                    need_regen = true;
                }
            }
            if need_regen {
                self.regen()
            } else {
                Err(PcaptureError::UnableFoundInterface {
                    i: iface_name.to_string(),
                })
            }
        }
    }
    pub fn buffer_size(&mut self, buffer_size: usize) -> Result<(), PcaptureError> {
        self.config.read_buffer_size = buffer_size;
        self.config.write_buffer_size = buffer_size;
        self.regen()
    }
    /// timeout as sec
    pub fn timeout(&mut self, timeout: u64) -> Result<(), PcaptureError> {
        let timeout_fix = Duration::from_secs(timeout);
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
    pub fn snaplen(&mut self, snaplen: usize) {
        self.snaplen = snaplen;
    }
    pub fn next(&mut self) -> Result<&[u8], PcaptureError> {
        match self.rx.next() {
            Ok(packet_data) => {
                match &mut self.pformat {
                    CaptureFormat::Pcap(pcap) => {
                        let pcap_record =
                            PacketRecord::new(pcap.header.magic_number, packet_data, self.snaplen)?;
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
                    CaptureFormat::PcapNg(pcapng) => {
                        let interface_id = self.pi.id;
                        let mut block =
                            EnhancedPacketBlock::new(interface_id, packet_data, self.snaplen)?;
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
        match self.sync_mode {
            true => (), // do nothing
            false => match &mut self.pformat {
                CaptureFormat::Pcap(pcap) => {
                    pcap.write_all(path, self.pbo)?;
                }
                CaptureFormat::PcapNg(pcapng) => {
                    pcapng.write_all(path, self.pbo)?;
                }
            },
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn capture_and_write_pcap() {
        let mut cap = Capture::new_pcap("ens33", PcapByteOrder::WiresharkDefault).unwrap();
        for _ in 0..5 {
            let _ = cap.next();
        }
        let _ = cap.save_all("test.pcap").unwrap();
    }
    #[test]
    fn capture_and_write_pcapng() {
        let mut cap = Capture::new_pcapng("ens33", PcapByteOrder::WiresharkDefault).unwrap();
        for _ in 0..5 {
            let _ = cap.next();
        }
        let _ = cap.save_all("test.pcapng").unwrap();
    }
    #[test]
    fn capture_and_write_pcapng_multi_interface() {
        let mut cap = Capture::new_pcapng("ens33", PcapByteOrder::WiresharkDefault).unwrap();
        cap.sync_mode("test.pcapng").unwrap();
        for _ in 0..5 {
            let _ = cap.next();
        }
        cap.change_iface("lo").unwrap();
        for _ in 0..5 {
            let _ = cap.next();
        }
        cap.change_iface("ens33").unwrap();
        for _ in 0..5 {
            let _ = cap.next();
        }
    }
    #[test]
    fn pcapng_one_by_one() {
        let mut cap = Capture::new_pcapng("ens33", PcapByteOrder::WiresharkDefault).unwrap();
        for _ in 0..5 {
            let _ = cap.next();
        }
        let mut fs = File::create("test.pcapng").unwrap();
        match &cap.pformat {
            CaptureFormat::PcapNg(pcapng) => {
                let mut shb = pcapng.blocks[0].clone();
                let mut idb = pcapng.blocks[1].clone();
                shb.write(&mut fs, PcapByteOrder::WiresharkDefault).unwrap();
                idb.write(&mut fs, PcapByteOrder::WiresharkDefault).unwrap();
            }
            _ => (),
        }
    }
    #[test]
    fn read_capture() {
        let pcap = Pcap::read_all("test.pcap", PcapByteOrder::WiresharkDefault).unwrap();
        println!("len: {}", pcap.records.len());
    }
}
