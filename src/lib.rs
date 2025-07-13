use bincode::Decode;
use bincode::Encode;
use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::ChannelType;
use pnet::datalink::Config;
use pnet::datalink::MacAddr;
use pnet::datalink::NetworkInterface;
use pnet::ipnetwork::IpNetwork;
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashMap;
use std::io::ErrorKind;
use std::ops::Deref;
use std::result;
use std::slice;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;
use std::u32;

pub mod error;
pub mod filter;
pub mod pcap;
pub mod pcapng;

use error::PcaptureError;
use filter::Filters;

#[cfg(feature = "pcap")]
use pcap::PacketRecord;
#[cfg(feature = "pcap")]
use pcap::Pcap;
#[cfg(feature = "pcapng")]
use pcapng::EnhancedPacketBlock;
#[cfg(feature = "pcapng")]
use pcapng::GeneralBlock;
#[cfg(feature = "pcapng")]
use pcapng::PcapNg;

static DEFAULT_BUFFER_SIZE: usize = 65535;
static DEFAULT_TIMEOUT: f32 = 1.0;
static DETAULT_SNAPLEN: usize = 65535;

static PACKETS_PIPE: LazyLock<Arc<Mutex<Vec<PipePacket>>>> =
    LazyLock::new(|| Arc::new(Mutex::new(Vec::new())));

static THREAD_STATUS: LazyLock<Arc<Mutex<HashMap<u32, ThreadStatus>>>> =
    LazyLock::new(|| Arc::new(Mutex::new(HashMap::new())));

pub type Result<T, E = error::PcaptureError> = result::Result<T, E>;

#[derive(Debug, Clone)]
pub struct PipePacket {
    interface_id: u32,
    data: Vec<u8>,
}

struct PcapturePipe;

impl PcapturePipe {
    fn push(interface_id: u32, data: &[u8]) -> Result<(), PcaptureError> {
        match PACKETS_PIPE.lock() {
            Ok(mut p) => {
                let pp = PipePacket {
                    interface_id,
                    data: data.to_vec(),
                };
                (*p).push(pp);
                Ok(())
            }
            Err(e) => Err(PcaptureError::UnlockGlobalVariableError {
                name: String::from("PACKETS_PIPE"),
                e: e.to_string(),
            }),
        }
    }
    fn pop() -> Result<Option<PipePacket>, PcaptureError> {
        match PACKETS_PIPE.lock() {
            Ok(mut p) => {
                let pp = (*p).pop();
                Ok(pp)
            }
            Err(e) => Err(PcaptureError::UnlockGlobalVariableError {
                name: String::from("PACKETS_PIPE"),
                e: e.to_string(),
            }),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum ThreadStatus {
    Running,
    AskStop,
    Stoped,
}

impl ThreadStatus {
    fn update(thread_id: u32, thread_status: ThreadStatus) -> Result<(), PcaptureError> {
        match THREAD_STATUS.lock() {
            Ok(mut t) => {
                let _ = (*t).insert(thread_id, thread_status);
                Ok(())
            }
            Err(e) => Err(PcaptureError::UnlockGlobalVariableError {
                name: String::from("THREAD_STATUS"),
                e: e.to_string(),
            }),
        }
    }
    fn check_status(thread_id: u32) -> Result<ThreadStatus, PcaptureError> {
        match THREAD_STATUS.lock() {
            Ok(t) => match (*t).get(&thread_id) {
                Some(s) => Ok(*s),
                None => Err(PcaptureError::UnableGetThreadStatus { thread_id }),
            },
            Err(e) => Err(PcaptureError::UnlockGlobalVariableError {
                name: String::from("THREAD_STATUS"),
                e: e.to_string(),
            }),
        }
    }
    fn stop_all_threads() -> Result<(), PcaptureError> {
        match THREAD_STATUS.lock() {
            Ok(mut t) => {
                for (_thread_id, thread_status) in &mut (*t) {
                    (*thread_status) = ThreadStatus::AskStop;
                }
                Ok(())
            }
            Err(e) => Err(PcaptureError::UnlockGlobalVariableError {
                name: String::from("THREAD_STATUS"),
                e: e.to_string(),
            }),
        }
    }
    fn is_all_stoped() -> Result<bool, PcaptureError> {
        match THREAD_STATUS.lock() {
            Ok(t) => {
                let mut all_stoped = true;
                for (_thread_id, thread_status) in &(*t) {
                    match thread_status {
                        ThreadStatus::Running => all_stoped = false,
                        _ => (),
                    }
                }
                Ok(all_stoped)
            }
            Err(e) => Err(PcaptureError::UnlockGlobalVariableError {
                name: String::from("THREAD_STATUS"),
                e: e.to_string(),
            }),
        }
    }
}

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

#[derive(Debug, Clone)]
pub struct Ifaces(Vec<Iface>);

impl Ifaces {
    pub fn find(&self, iface_name: &str) -> Option<Iface> {
        for i in &self.0 {
            if i.interface.name == iface_name {
                return Some(i.clone());
            }
        }
        None
    }
    pub fn value(&self) -> Vec<Iface> {
        self.0.clone()
    }
}

impl<'a> IntoIterator for &'a Ifaces {
    type Item = &'a Iface;
    type IntoIter = slice::Iter<'a, Iface>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl Deref for Ifaces {
    type Target = [Iface];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a> IntoIterator for &'a mut Ifaces {
    type Item = &'a mut Iface;
    type IntoIter = std::slice::IterMut<'a, Iface>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter_mut()
    }
}

pub struct Capture {
    config: Config,
    // the all interface in system
    all_ifaces: Ifaces,
    // current used interfaces
    cur_ifaces: Ifaces,
    snaplen: usize,
    // Filters
    fls: Option<Filters>,
}

impl Capture {
    /// A simple example showing how to capture packets and save them in pcapng format.
    /// ```rust
    /// use pcapture::Capture;
    /// use pcapture::PcapByteOrder;
    ///
    /// fn main() {
    ///     let path = "test.pcapng";
    ///     let pbo = PcapByteOrder::WiresharkDefault;
    ///     // [mac, srcmac, dstmac, ip, addr, srcip, srcaddr, dstip, dstaddr, port, srcport, dstport]
    ///     // let valid_procotol = filter::valid_protocol();
    ///     // println!("{:?}", valid_procotol);
    ///
    ///     let filter_str = Some("icmp and ip=192.168.1.1");
    ///
    ///     let mut cap = Capture::new("ens33", filter_str).unwrap();
    ///     // let mut cap = Capture::new("any", filter_str).unwrap(); // monitor all interfaces
    ///     let mut pcapng = cap.gen_pcapng(pbo);
    ///     for _ in 0..5 {
    ///         let block = cap.next_with_pcapng().unwrap();
    ///         pcapng.append(block);
    ///     }
    ///
    ///     pcapng.write_all(path).unwrap();
    /// }
    /// ```
    pub fn new(iface_name: &str, filters: Option<&str>) -> Result<Capture, PcaptureError> {
        let mut ifaces_vec = Vec::new();
        let interfaces = datalink::interfaces();
        for interface in interfaces {
            let pi = Iface {
                id: u32::MAX,
                interface,
            };
            ifaces_vec.push(pi);
        }

        let ifaces = Ifaces(ifaces_vec);
        let fls = match filters {
            Some(filters) => Filters::parser(filters)?,
            None => None,
        };
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
        if iface_name == "any" {
            // listen at all interfaces
            let c = Capture {
                config,
                all_ifaces: ifaces.clone(),
                cur_ifaces: ifaces.clone(),
                snaplen: DETAULT_SNAPLEN,
                fls,
            };
            return Ok(c);
        } else {
            // find the target interface and listen
            match &ifaces.find(iface_name) {
                Some(iface) => {
                    let c = Capture {
                        config,
                        all_ifaces: ifaces,
                        cur_ifaces: Ifaces(vec![iface.clone()]),
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
    }
    /// A simple example showing how to capture packets with multi interface and save them in pcapng format.
    /// ```rust
    /// use pcapture::Capture;
    /// use pcapture::PcapByteOrder;
    ///
    /// fn main() {
    ///     let path = "test.pcapng";
    ///     let pbo = PcapByteOrder::WiresharkDefault;
    ///     // [mac, srcmac, dstmac, ip, addr, srcip, srcaddr, dstip, dstaddr, port, srcport, dstport]
    ///     // let valid_procotol = filter::valid_protocol();
    ///     // println!("{:?}", valid_procotol);
    ///
    ///     let filter_str = Some("icmp and ip=192.168.1.1");
    ///
    ///     let mut cap = Capture::new_multi(&["ens33", "lo"], filter_str).unwrap();
    ///     // let mut cap = Capture::new("any", filter_str).unwrap(); // monitor all interfaces
    ///     let mut pcapng = cap.gen_pcapng(pbo);
    ///     for _ in 0..5 {
    ///         let block = cap.next_with_pcapng().unwrap();
    ///         pcapng.append(block);
    ///     }
    ///
    ///     pcapng.write_all(path).unwrap();
    /// }
    /// ```
    pub fn new_multi(
        ifaces_name: &[&str],
        filters: Option<&str>,
    ) -> Result<Capture, PcaptureError> {
        let mut ifaces_vec = Vec::new();
        let interfaces = datalink::interfaces();
        for (id, interface) in interfaces.iter().enumerate() {
            let pi = Iface {
                id: id as u32,
                interface: interface.clone(),
            };
            ifaces_vec.push(pi);
        }

        let ifaces = Ifaces(ifaces_vec);
        let fls = match filters {
            Some(filters) => Filters::parser(filters)?,
            None => None,
        };
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

        let mut cur_ifaces = Vec::new();
        for iface_name in ifaces_name {
            // find the target interface and listen
            match &ifaces.find(iface_name) {
                Some(iface) => cur_ifaces.push(iface.clone()),
                None => {
                    return Err(PcaptureError::UnableFoundInterface {
                        i: iface_name.to_string(),
                    });
                }
            }
        }
        let c = Capture {
            config,
            all_ifaces: ifaces,
            cur_ifaces: Ifaces(cur_ifaces),
            snaplen: DETAULT_SNAPLEN,
            fls,
        };
        return Ok(c);
    }
    fn start_threads(&self) -> Result<(), PcaptureError> {
        for (thread_id, iface) in self.cur_ifaces.iter().enumerate() {
            let interface_id = iface.id;
            let (_tx, mut rx) = match datalink::channel(&iface.interface, self.config) {
                Ok(Ethernet(tx, rx)) => (tx, rx),
                Ok(_) => return Err(PcaptureError::UnhandledChannelType),
                Err(e) => {
                    return Err(PcaptureError::UnableCreateChannel { e: e.to_string() });
                }
            };
            // push the recv data into pipe and waitting for user get
            thread::spawn(move || {
                let thread_id = thread_id as u32;
                ThreadStatus::update(thread_id as u32, ThreadStatus::Running)
                    .expect("update thread status to running failed");
                loop {
                    match ThreadStatus::check_status(thread_id) {
                        Ok(thread_status) => match thread_status {
                            ThreadStatus::AskStop => {
                                ThreadStatus::update(thread_id, ThreadStatus::Stoped)
                                    .expect("update thread status to stoped failed");
                                break;
                            }
                            ThreadStatus::Stoped => break, // it should not happen anytime
                            ThreadStatus::Running => match rx.next() {
                                Ok(data) => {
                                    if data.len() > 0 {
                                        match PcapturePipe::push(interface_id, data) {
                                            _ => (),
                                        };
                                    }
                                }
                                Err(_) => (), // ignore error here
                            },
                        },
                        Err(e) => {
                            println!("check thread status failed: {}", e);
                            break;
                        }
                    };
                }
            });
        }
        Ok(())
    }
    fn stop_threads(&self) -> Result<(), PcaptureError> {
        // waitting for all the threads is stoped
        ThreadStatus::stop_all_threads()?;
        loop {
            if ThreadStatus::is_all_stoped()? {
                break;
            }
        }
        Ok(())
    }
    /// Ready for row format data.
    #[cfg(feature = "pcap")]
    pub fn start(&self) -> Result<(), PcaptureError> {
        Self::start_threads(&self)?;
        Ok(())
    }
    /// Generate pcap format header.
    #[cfg(feature = "pcap")]
    pub fn start_pcap(&self, pbo: PcapByteOrder) -> Result<Pcap, PcaptureError> {
        Self::start_threads(&self)?;
        let pcap = Pcap::new(pbo);
        Ok(pcap)
    }
    /// Generate pcapng format header.
    #[cfg(feature = "pcapng")]
    pub fn start_pcapng(&self, pbo: PcapByteOrder) -> Result<PcapNg, PcaptureError> {
        Self::start_threads(&self)?;
        let pcapng = PcapNg::new(&self.cur_ifaces.value(), pbo);
        Ok(pcapng)
    }
    /// Change the capture interface (pcapng format only).
    /// ```rust
    /// use pcapture::Capture;
    /// use pcapture::PcapByteOrder;
    ///
    /// fn main() {
    ///     let path = "test.pcapng";
    ///     let pbo = PcapByteOrder::WiresharkDefault;

    ///     let mut cap = Capture::new("ens33", None).unwrap();
    ///     let mut pcapng = cap.gen_pcapng(pbo);
    ///     for _ in 0..5 {
    ///         let block = cap.next_with_pcapng().unwrap();
    ///         pcapng.append(block);
    ///     }
    ///     
    ///     cap.change_iface("lo").unwrap();
    ///     for _ in 0..5 {
    ///         let block = cap.next_with_pcapng().unwrap();
    ///         pcapng.append(block);
    ///     }
    ///
    ///     cap.change_iface("ens33").unwrap();
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
    #[cfg(feature = "pcapng")]
    pub fn change_iface(&mut self, iface_name: &str) -> Result<(), PcaptureError> {
        if iface_name == "any" {
            self.cur_ifaces = self.all_ifaces.clone();
        } else {
            for iface in &self.all_ifaces {
                if iface.interface.name == iface_name {
                    let new_iface = iface.clone();
                    self.cur_ifaces = Ifaces(vec![new_iface]);
                }
            }
        }
        Self::stop_threads(&self)?;
        Self::start_threads(&self)?;
        Err(PcaptureError::UnableFoundInterface {
            i: iface_name.to_string(),
        })
    }
    pub fn buffer_size(&mut self, buffer_size: usize) {
        self.config.read_buffer_size = buffer_size;
        self.config.write_buffer_size = buffer_size;
    }
    /// timeout as sec
    pub fn timeout(&mut self, timeout: f32) {
        let timeout_fix = Duration::from_secs_f32(timeout);
        self.config.read_timeout = Some(timeout_fix);
        self.config.write_timeout = Some(timeout_fix);
    }
    pub fn promiscuous(&mut self, promiscuous: bool) {
        self.config.promiscuous = promiscuous;
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
    pub fn next_as_raw(&mut self) -> Result<Vec<u8>, PcaptureError> {
        loop {
            let packet_data = match PcapturePipe::pop() {
                Ok(pd) => pd,
                Err(e) => {
                    match e {
                        PcaptureError::IOError(e) => {
                            if e.kind() != ErrorKind::TimedOut && e.kind() != ErrorKind::Interrupted
                            {
                                return Err(PcaptureError::CapturePacketError { e: e.to_string() });
                            } else {
                                // no data captured try next loop
                                None
                            }
                        }
                        _ => return Err(e),
                    }
                }
            };
            match packet_data {
                Some(pipe_packet) => match &self.fls {
                    Some(fls) => {
                        if fls.check(&pipe_packet.data)? {
                            return Ok(pipe_packet.data);
                        }
                    }
                    None => return Ok(pipe_packet.data),
                },
                None => (),
            }
        }
    }
    #[cfg(feature = "pcap")]
    pub fn next_as_pcap(&mut self) -> Result<PacketRecord, PcaptureError> {
        loop {
            let packet_data = PcapturePipe::pop()?;
            match packet_data {
                Some(pipe_packet) => match &self.fls {
                    Some(fls) => {
                        if fls.check(&pipe_packet.data)? {
                            let pcap_record = PacketRecord::new(&pipe_packet.data, self.snaplen)?;
                            return Ok(pcap_record);
                        }
                    }
                    None => {
                        let pcap_record = PacketRecord::new(&pipe_packet.data, self.snaplen)?;
                        return Ok(pcap_record);
                    }
                },
                None => (),
            }
        }
    }
    #[cfg(feature = "pcapng")]
    pub fn next_as_pcapng(&mut self) -> Result<GeneralBlock, PcaptureError> {
        loop {
            let packet_data = PcapturePipe::pop()?;
            match packet_data {
                Some(pipe_packet) => match &self.fls {
                    Some(fls) => {
                        if fls.check(&pipe_packet.data)? {
                            let block = EnhancedPacketBlock::new(
                                pipe_packet.interface_id,
                                &pipe_packet.data,
                                self.snaplen,
                            )?;
                            let ret = GeneralBlock::EnhancedPacketBlock(block);
                            return Ok(ret);
                        }
                    }
                    None => {
                        let block = EnhancedPacketBlock::new(
                            pipe_packet.interface_id,
                            &pipe_packet.data,
                            self.snaplen,
                        )?;
                        let ret = GeneralBlock::EnhancedPacketBlock(block);
                        return Ok(ret);
                    }
                },
                None => (),
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
        let mut cap = Capture::new("ens33", None).unwrap();
        cap.start().unwrap();
        for _ in 0..5 {
            let packet_raw = cap.next_as_raw().unwrap();
            println!("packet len: {}", packet_raw.len());
            packets.push(packet_raw);
        }
    }
    #[test]
    fn capture_any_raw() {
        let mut packets: Vec<Vec<u8>> = Vec::new();
        let mut cap = Capture::new("any", None).unwrap();
        cap.start().unwrap();
        for _ in 0..5 {
            let packet_raw = cap.next_as_raw().unwrap();
            println!("packet len: {}", packet_raw.len());
            packets.push(packet_raw);
        }
    }
    #[test]
    #[cfg(feature = "pcap")]
    fn capture_pcap() {
        let path = "test.pcap";
        let pbo = PcapByteOrder::WiresharkDefault;

        let mut cap = Capture::new("ens33", None).unwrap();
        let mut pcap = cap.start_pcap(pbo).unwrap();
        for _ in 0..5 {
            let record = cap.next_as_pcap().unwrap();
            pcap.append(record);
        }
        // write all capture data to test.pcap
        pcap.write_all(path).unwrap();

        let read_pcap = Pcap::read_all(path, pbo).unwrap();
        assert_eq!(read_pcap.records.len(), 5);
    }
    #[test]
    #[cfg(feature = "pcap")]
    fn capture_any_pcap() {
        let path = "test_any.pcap";
        let pbo = PcapByteOrder::WiresharkDefault;

        let mut cap = Capture::new("any", None).unwrap();
        let mut pcap = cap.start_pcap(pbo).unwrap();
        for _ in 0..5 {
            let record = cap.next_as_pcap().unwrap();
            pcap.append(record);
        }
        // write all capture data to test.pcap
        pcap.write_all(path).unwrap();

        let read_pcap = Pcap::read_all(path, pbo).unwrap();
        assert_eq!(read_pcap.records.len(), 5);
    }
    #[test]
    #[cfg(feature = "pcapng")]
    fn capture_pcapng() {
        let path = "test.pcapng";
        let pbo = PcapByteOrder::WiresharkDefault;

        let mut cap = Capture::new("ens33", None).unwrap();
        let mut pcapng = cap.start_pcapng(pbo).unwrap();
        for _ in 0..5 {
            let block = cap.next_as_pcapng().unwrap();
            pcapng.append(block);
        }

        pcapng.write_all(path).unwrap();

        let read_pcapng = PcapNg::read_all(path, pbo).unwrap();
        assert_eq!(read_pcapng.blocks.len(), 7);
    }
    #[test]
    #[cfg(feature = "pcapng")]
    fn capture_pcapng_filter() {
        let path = "test.pcapng";
        let pbo = PcapByteOrder::WiresharkDefault;
        // let valid_procotol = filter::valid_protocol();
        // println!("{:?}", valid_procotol);
        let filter_str = "tcp and (addr=192.168.1.1 and port=80)";

        let mut cap = Capture::new("ens33", Some(filter_str)).unwrap();
        let mut pcapng = cap.start_pcapng(pbo).unwrap();
        for _ in 0..5 {
            let block = cap.next_as_pcapng().unwrap();
            pcapng.append(block);
        }

        pcapng.write_all(path).unwrap();

        let read_pcapng = PcapNg::read_all(path, pbo).unwrap();
        assert_eq!(read_pcapng.blocks.len(), 7);
    }
    #[test]
    #[cfg(feature = "pcapng")]
    fn capture_change_iface() {
        let path = "test.pcapng";
        let pbo = PcapByteOrder::WiresharkDefault;

        let mut cap = Capture::new("ens33", None).unwrap();
        let mut pcapng = cap.start_pcapng(pbo).unwrap();
        for _ in 0..5 {
            let block = cap.next_as_pcapng().unwrap();
            pcapng.append(block);
        }

        cap.change_iface("lo").unwrap();
        for _ in 0..5 {
            let block = cap.next_as_pcapng().unwrap();
            pcapng.append(block);
        }

        cap.change_iface("ens33").unwrap();
        for _ in 0..5 {
            let block = cap.next_as_pcapng().unwrap();
            pcapng.append(block);
        }

        pcapng.write_all(path).unwrap();

        let read_pcapng = PcapNg::read_all(path, pbo).unwrap();
        assert_eq!(read_pcapng.blocks.len(), 18); // 1 shb + 1 idb + 5 epb + 1 idb + 5 epb _+ 5 epb
    }
}
