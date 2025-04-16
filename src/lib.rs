use bincode::Decode;
use bincode::Encode;
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
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::LazyLock;
use std::sync::Mutex;
use std::time::Duration;
use std::u32;

pub mod error;
pub mod filter;
pub mod pcap;
pub mod pcapng;

pub use error::PcaptureError;
pub use filter::Filters;
pub use pcap::PacketRecord;
pub use pcap::Pcap;
pub use pcapng::EnhancedPacketBlock;
pub use pcapng::GeneralBlock;
pub use pcapng::PcapNg;

static DEFAULT_BUFFER_SIZE: usize = 65535;
static DEFAULT_TIMEOUT: u64 = 1;
static DETAULT_SNAPLEN: usize = 65535;
static INTERFACE_ID: LazyLock<Mutex<u32>> = LazyLock::new(|| Mutex::new(0));
static INTERFACE_IDS_MAP: LazyLock<Mutex<HashMap<String, u32>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode)]
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
pub struct Iface {
    id: u32,
    interface: NetworkInterface,
}

pub struct InterfaceID {
    id: u32,
    used_before: bool,
}

impl InterfaceID {
    fn new() -> Result<u32, PcaptureError> {
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

    fn update(iface_name: &str, interface_id: u32) -> Result<(), PcaptureError> {
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

    fn check(iface_name: &str) -> Result<Option<u32>, PcaptureError> {
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
    fn clear() -> Result<(), PcaptureError> {
        let mut id = match INTERFACE_ID.lock() {
            Ok(i) => i,
            Err(e) => {
                return Err(PcaptureError::UnlockGlobalVariableError {
                    name: String::from("INTERFACE_ID"),
                    e: e.to_string(),
                });
            }
        };
        *id = 0;
        let mut map = match INTERFACE_IDS_MAP.lock() {
            Ok(m) => m,
            Err(e) => {
                return Err(PcaptureError::UnlockGlobalVariableError {
                    name: String::from("INTERFACE_IDS_MAP"),
                    e: e.to_string(),
                });
            }
        };
        *map = HashMap::new();
        Ok(())
    }
    pub fn get_id(iface_name: &str) -> Result<InterfaceID, PcaptureError> {
        match InterfaceID::check(iface_name)? {
            Some(id) => {
                // this interface has been used before
                Ok(InterfaceID {
                    id,
                    used_before: true,
                })
            }
            None => {
                // nerver used before
                let id = InterfaceID::new()?;
                InterfaceID::update(iface_name, id)?;
                Ok(InterfaceID {
                    id,
                    used_before: false,
                })
            }
        }
    }
    pub fn init(iface_name: &str) -> Result<InterfaceID, PcaptureError> {
        // clear the all data before
        InterfaceID::clear()?;

        let id = InterfaceID::new()?;
        InterfaceID::update(iface_name, id)?;
        Ok(InterfaceID {
            id,
            used_before: false,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Ifaces {
    interfaces: Vec<Iface>,
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

pub struct Capture {
    config: Config,
    ifaces: Ifaces,
    iface: Iface,
    tx: Box<dyn DataLinkSender>,
    rx: Box<dyn DataLinkReceiver>,
    snaplen: usize,
    // Filters
    fls: Option<Filters>,
}

impl Capture {
    fn init(iface_name: &str, filters: Option<&str>) -> Result<Capture, PcaptureError> {
        let mut iface_vec = Vec::new();
        let interfaces = datalink::interfaces();
        for interface in interfaces {
            let pi = Iface {
                id: u32::MAX, // indicates unused state
                interface,
            };
            iface_vec.push(pi);
        }
        let ifaces = Ifaces {
            interfaces: iface_vec,
        };

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
        match &mut ifaces.find(iface_name) {
            Some(iface) => {
                let (tx, rx) = match datalink::channel(&iface.interface, config) {
                    Ok(Ethernet(tx, rx)) => (tx, rx),
                    Ok(_) => return Err(PcaptureError::UnhandledChannelType),
                    Err(e) => return Err(PcaptureError::UnableCreateChannel { e: e.to_string() }),
                };
                // this will clear all the data
                let iid = InterfaceID::init(iface_name)?;
                iface.id = iid.id;

                let fls = match filters {
                    Some(filters) => Some(Filters::parser(filters)),
                    None => None,
                };

                let c = Capture {
                    config,
                    ifaces,
                    iface: iface.clone(),
                    tx,
                    rx,
                    snaplen: DETAULT_SNAPLEN,
                    fls,
                };
                return Ok(c);
            }
            None => Err(PcaptureError::UnableFoundInterface {
                i: iface_name.to_string(),
            }),
        }
    }
    /// A simple example showing how to capture data packets and save them in pcapng format.
    /// ```rust
    /// use pcapture::Capture;
    /// use pcapture::PcapByteOrder;
    ///
    /// fn main() {
    ///     let path = "test.pcapng";
    ///     let pbo = PcapByteOrder::WiresharkDefault;
    ///
    ///     let mut cap = Capture::new("ens33").unwrap();
    ///     let mut pcap = cap.gen_pcapng(pbo);
    ///     for _ in 0..5 {
    ///         let record = cap.next_with_pcapng().unwrap();
    ///         pcap.append(record);
    ///     }
    ///     // write all capture data to test.pcap
    ///     pcap.write_all(path).unwrap();
    /// }
    /// ```
    pub fn new(iface_name: &str) -> Result<Capture, PcaptureError> {
        Capture::init(iface_name, None)
    }
    /// A simple example showing how to capture data packets and save them in pcapng format.
    /// ```rust
    /// use pcapture::Capture;
    /// use pcapture::PcapByteOrder;
    ///
    /// fn main() {
    ///     let path = "test.pcapng";
    ///     let pbo = PcapByteOrder::WiresharkDefault;
    ///     // valid values: [mac, srcmac, dstmac, ip, addr, srcip, srcaddr, dstip, dstaddr, port, srcport, dstport]
    ///     let valid_procotol = filter::show_valid_protocol();
    ///     println!("{:?}", valid_procotol);
    ///     // valid procotol:
    ///     // ["ipv4", "arp", "wakeonlan", "trill", "decnet",
    ///     //  "rarp", "appletalk", "aarp", "ipx", "qnx",
    ///     //  "ipv6", "flowcontrol", "cobranet", "mpls",
    ///     //  "mplsmcast", "pppoediscovery", "pppoesession",
    ///     //  "vlan", "pbridge", "lldp", "ptpoe", "cfm", "qinq",
    ///     //  "hopopt", "icmp", "igmp", "ggp", "ipv4encapsulation",
    ///     //  "st", "tcp", "cbt", "egp", "igp", "bbnrccmon", "nvpii",
    ///     //  "pup", "argus", "emcon", "xnet", "chaos", "udp", "mux",
    ///     //  "dcnmeas", "hmp", "prm", "xnsidp", "trunk1", "trunk2",
    ///     //  "leaf1", "leaf2", "rdp", "irtp", "isotp4", "netblt",
    ///     //  "mfensp", "meritinp", "dccp", "threepc", "idpr",
    ///     //  "xtp", "ddp", "idprcmtp", "tpplusplus", "il",
    ///     //  "ipv6encapsulation", "sdrp", "ipv6route", "ipv6frag",
    ///     //  "idrp", "rsvp", "gre", "dsr", "bna", "esp", "ah",
    ///     //  "inlsp", "swipe", "narp", "mobile", "tlsp", "skip",
    ///     //  "icmpv6", "ipv6nonxt", "ipv6opts", "hostinternal",
    ///     //  "cftp", "localnetwork", "satexpak", "kryptolan",
    ///     //  "rvd", "ippc", "distributedfs", "satmon", "visa",
    ///     //  "ipcv", "cpnx", "cphb", "wsn", "pvp", "brsatmon",
    ///     //  "sunnd", "wbmon", "wbexpak", "isoip", "vmtp",
    ///     //  "securevmtp", "vines", "ttporiptm", "nsfnetigp",
    ///     //  "dgp", "tcf", "eigrp", "ospfigp", "spriterpc",
    ///     //  "larp", "mtp", "ax25", "ipip", "micp", "sccsp",
    ///     //  "etherip", "encap", "privencryption", "gmtp",
    ///     //  "ifmp", "pnni", "pim", "aris", "scps", "qnx2",
    ///     //  "an", "ipcomp", "snp", "compaqpeer", "ipxinip",
    ///     //  "vrrp", "pgm", "zerohop", "l2tp", "ddx", "iatp",
    ///     //  "stp", "srp", "uti", "smp", "sm", "ptp", "isisoveripv4",
    ///     //  "fire", "crtp", "crudp", "sscopmce", "iplt", "sps", "pipe",
    ///     //  "sctp", "fc", "rsvpe2eignore", "mobilityheader", "udplite",
    ///     //  "mplsinip", "manet", "hip", "shim6", "wesp", "rohc",
    ///     //  "test1", "test2", "reserved"]
    ///     // example: `icmp or addr=192.168.1.1`
    ///     // exmaple: `tcp and (addr=192.168.1.1 and port=80)`
    ///     let filter_str = "icmp and addr=192.168.1.1";
    ///
    ///     let mut cap = Capture::new_with_filters("ens33", filter_str).unwrap();
    ///     let mut pcapng = cap.gen_pcapng(pbo);
    ///     for _ in 0..5 {
    ///         let block = cap.next_with_pcapng().unwrap();
    ///         pcapng.append(block);
    ///     }
    ///
    ///     pcapng.write_all(path).unwrap();
    /// }
    /// ```
    pub fn new_with_filters(iface_name: &str, filters: &str) -> Result<Capture, PcaptureError> {
        Capture::init(iface_name, Some(filters))
    }
    /// Generate pcap format content.
    pub fn gen_pcap(&self, pbo: PcapByteOrder) -> Pcap {
        let pcap = Pcap::new(pbo);
        pcap
    }
    /// Generate pcapng format content.
    pub fn gen_pcapng(&self, pbo: PcapByteOrder) -> PcapNg {
        let pcapng = PcapNg::new(&self.iface, pbo);
        pcapng
    }
    fn regen(&mut self) -> Result<(), PcaptureError> {
        let (tx, rx) = match datalink::channel(&self.iface.interface, self.config) {
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
    ///     let path = "test.pcapng";
    ///     let pbo = PcapByteOrder::WiresharkDefault;

    ///     let mut cap = Capture::new("ens33").unwrap();
    ///     let mut pcapng = cap.gen_pcapng(pbo);
    ///     for _ in 0..5 {
    ///         let block = cap.next_with_pcapng().unwrap();
    ///         pcapng.append(block);
    ///     }
    ///
    ///     let ret = cap.change_iface("lo").unwrap();
    ///     // According to the pcapng format specification,
    ///     // when using other interfaces to capture, you need to update the idb file to pcapng.
    ///     // Since this interface has not been used before, an idb block will be returned here.
    ///     assert_eq!(ret.is_some(), true);
    ///     let idb = ret.unwrap();
    ///     pcapng.append(idb);
    ///     for _ in 0..5 {
    ///         let block = cap.next_with_pcapng().unwrap();
    ///         pcapng.append(block);
    ///     }
    ///
    ///     let ret = cap.change_iface("ens33").unwrap();
    ///     // If we have used this interface before,
    ///     // we do not need to update the IDB to the pcapng file.
    ///     assert_eq!(ret.is_none(), true);
    ///     for _ in 0..5 {
    ///         let block = cap.next_with_pcapng().unwrap();
    ///         pcapng.append(block);
    ///     }
    ///
    ///     // If you don't want to remember these cumbersome rules,
    ///     // you can use match to do the same work,
    ///     // if the returned value is not None, just add it to the pcapng file.
    ///
    ///     pcapng.write_all(path).unwrap();
    /// }
    /// ```
    pub fn change_iface(
        &mut self,
        iface_name: &str,
    ) -> Result<Option<GeneralBlock>, PcaptureError> {
        if iface_name == self.iface.interface.name {
            return Err(PcaptureError::SameInterafceError {
                new: iface_name.to_string(),
                pre: self.iface.interface.name.clone(),
            });
        } else {
            for iface in &self.ifaces {
                if iface.interface.name == iface_name {
                    let mut new_iface = iface.clone();
                    // check if it has been used before
                    let iid = InterfaceID::get_id(iface_name)?;
                    new_iface.id = iid.id;
                    let idb = InterfaceDescriptionBlock::new(&new_iface);
                    self.iface = new_iface;
                    self.regen()?;
                    if iid.used_before {
                        // If it has been used before, there is no need to generate IDB again
                        return Ok(None);
                    } else {
                        let ret = GeneralBlock::InterfaceDescriptionBlock(idb);
                        return Ok(Some(ret));
                    }
                }
            }
        }
        Err(PcaptureError::UnableFoundInterface {
            i: iface_name.to_string(),
        })
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
    pub fn snaplen(&mut self, snaplen: usize) {
        self.snaplen = snaplen;
    }
    /// Capture the original data.
    /// ```rust
    /// use pcapture::Capture;
    ///
    /// fn main() {
    ///     let mut packets = Vec::new();
    ///     let mut cap = Capture::new("ens33").unwrap();
    ///     for _ in 0..5 {
    ///         let packet_raw = cap.next_with_raw().unwrap();
    ///         packets.push(packet_raw)
    ///     }
    /// }
    /// ```
    pub fn next_with_raw(&mut self) -> Result<Vec<u8>, PcaptureError> {
        loop {
            let packet_data = match self.rx.next() {
                // In order to make packet_data out of its original life cycle,
                // avoid the borrow as mutable more than once at a time error.
                Ok(packet_data) => packet_data.to_vec(),
                Err(e) => return Err(PcaptureError::CapturePacketError { e: e.to_string() }),
            };
            match &self.fls {
                Some(fls) => {
                    if fls.check(&packet_data)? {
                        return Ok(packet_data);
                    }
                }
                None => return Ok(packet_data),
            }
        }
    }
    pub fn next_with_pcap(&mut self) -> Result<PacketRecord, PcaptureError> {
        loop {
            let packet_data = match self.rx.next() {
                Ok(packet_data) => packet_data.to_vec(),
                Err(e) => return Err(PcaptureError::CapturePacketError { e: e.to_string() }),
            };
            match &self.fls {
                Some(fls) => {
                    if fls.check(&packet_data)? {
                        let pcap_record = PacketRecord::new(&packet_data, self.snaplen)?;
                        return Ok(pcap_record);
                    }
                }
                None => {
                    let pcap_record = PacketRecord::new(&packet_data, self.snaplen)?;
                    return Ok(pcap_record);
                }
            }
        }
    }
    pub fn next_with_pcapng(&mut self) -> Result<GeneralBlock, PcaptureError> {
        loop {
            let packet_data = match self.rx.next() {
                Ok(packet_data) => packet_data.to_vec(),
                Err(e) => return Err(PcaptureError::CapturePacketError { e: e.to_string() }),
            };
            match &self.fls {
                Some(fls) => {
                    if fls.check(&packet_data)? {
                        let interface_id = self.iface.id;
                        let block =
                            EnhancedPacketBlock::new(interface_id, &packet_data, self.snaplen)?;
                        let ret = GeneralBlock::EnhancedPacketBlock(block);
                        return Ok(ret);
                    }
                }
                None => {
                    let interface_id = self.iface.id;
                    let block = EnhancedPacketBlock::new(interface_id, &packet_data, self.snaplen)?;
                    let ret = GeneralBlock::EnhancedPacketBlock(block);
                    return Ok(ret);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn capture_raw() {
        let mut packets: Vec<Vec<u8>> = Vec::new();
        let mut cap = Capture::new("ens33").unwrap();
        for _ in 0..5 {
            let packet_raw = cap.next_with_raw().unwrap();
            packets.push(packet_raw)
        }
    }
    #[test]
    fn capture_pcap() {
        let path = "test.pcap";
        let pbo = PcapByteOrder::WiresharkDefault;

        let mut cap = Capture::new("ens33").unwrap();
        let mut pcap = cap.gen_pcap(pbo);
        for _ in 0..5 {
            let record = cap.next_with_pcap().unwrap();
            pcap.append(record);
        }
        // write all capture data to test.pcap
        pcap.write_all(path).unwrap();

        let read_pcap = Pcap::read_all(path, pbo).unwrap();
        assert_eq!(read_pcap.records.len(), 5);
    }
    #[test]
    fn capture_pcapng() {
        let path = "test.pcapng";
        let pbo = PcapByteOrder::WiresharkDefault;

        let mut cap = Capture::new("ens33").unwrap();
        let mut pcapng = cap.gen_pcapng(pbo);
        for _ in 0..5 {
            let block = cap.next_with_pcapng().unwrap();
            pcapng.append(block);
        }

        pcapng.write_all(path).unwrap();

        let read_pcapng = PcapNg::read_all(path, pbo).unwrap();
        assert_eq!(read_pcapng.blocks.len(), 7);
    }
    #[test]
    fn capture_pcapng_filter() {
        let path = "test.pcapng";
        let pbo = PcapByteOrder::WiresharkDefault;
        // let valid_procotol = filter::show_valid_protocol();
        // println!("{:?}", valid_procotol);
        let filter_str = "tcp and (addr=192.168.1.1 and port=80)";

        let mut cap = Capture::new_with_filters("ens33", filter_str).unwrap();
        let mut pcapng = cap.gen_pcapng(pbo);
        for _ in 0..5 {
            let block = cap.next_with_pcapng().unwrap();
            pcapng.append(block);
        }

        pcapng.write_all(path).unwrap();

        let read_pcapng = PcapNg::read_all(path, pbo).unwrap();
        assert_eq!(read_pcapng.blocks.len(), 7);
    }
    #[test]
    fn capture_change_iface() {
        let path = "test.pcapng";
        let pbo = PcapByteOrder::WiresharkDefault;

        let mut cap = Capture::new("ens33").unwrap();
        let mut pcapng = cap.gen_pcapng(pbo);
        for _ in 0..5 {
            let block = cap.next_with_pcapng().unwrap();
            pcapng.append(block);
        }

        let ret = cap.change_iface("lo").unwrap();
        // According to the pcapng format specification,
        // when using other interfaces to capture, you need to update the idb file to pcapng.
        // Since this interface has not been used before, an idb block will be returned here.
        assert_eq!(ret.is_some(), true);
        let idb = ret.unwrap();
        pcapng.append(idb);
        for _ in 0..5 {
            let block = cap.next_with_pcapng().unwrap();
            pcapng.append(block);
        }

        let ret = cap.change_iface("ens33").unwrap();
        // If we have used this interface before,
        // we do not need to update the IDB to the pcapng file.
        assert_eq!(ret.is_none(), true);
        for _ in 0..5 {
            let block = cap.next_with_pcapng().unwrap();
            pcapng.append(block);
        }

        // If you don't want to remember these cumbersome rules,
        // you can use match to match,
        // and if the returned idb is not None, add it to the pcapng file.

        pcapng.write_all(path).unwrap();

        let read_pcapng = PcapNg::read_all(path, pbo).unwrap();
        assert_eq!(read_pcapng.blocks.len(), 18); // 1 shb + 1 idb + 5 epb + 1 idb + 5 epb _+ 5 epb
    }
}
