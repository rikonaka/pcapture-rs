use bincode::Decode;
use bincode::Encode;
#[cfg(feature = "libpnet")]
use pnet::datalink;
#[cfg(feature = "libpnet")]
use pnet::datalink::Channel::Ethernet;
#[cfg(feature = "libpnet")]
use pnet::datalink::ChannelType;
#[cfg(feature = "libpnet")]
use pnet::datalink::Config;
use pnet::datalink::DataLinkReceiver;
#[cfg(feature = "libpnet")]
use pnet::datalink::NetworkInterface;
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashMap;
use std::io::ErrorKind;
use std::ops::Deref;
use std::ops::DerefMut;
use std::result;
use std::slice;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::Mutex;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::Sender;
use std::sync::mpsc::channel;
#[cfg(feature = "libpcap")]
use std::sync::mpsc::channel;
use std::thread;
#[cfg(feature = "libpnet")]
use std::time::Duration;
#[cfg(feature = "libpnet")]
use std::time::SystemTime;
#[cfg(feature = "libpnet")]
use std::time::UNIX_EPOCH;
use std::u32;

mod libpcap;

pub mod error;
pub mod filter;
pub mod fs;

use error::PcaptureError;
#[cfg(feature = "libpnet")]
use filter::Filter;
#[cfg(feature = "libpcap")]
use libpcap::Addresses;
#[cfg(feature = "libpcap")]
use libpcap::Libpcap;

#[cfg(feature = "pcap")]
use fs::pcap::PacketRecord;
#[cfg(feature = "pcap")]
use fs::pcap::Pcap;
#[cfg(feature = "pcapng")]
use fs::pcapng::EnhancedPacketBlock;
#[cfg(feature = "pcapng")]
use fs::pcapng::GeneralBlock;
#[cfg(feature = "pcapng")]
use fs::pcapng::PcapNg;

static DEFAULT_BUFFER_SIZE: usize = 4096;
static DEFAULT_TIMEOUT: f32 = 0.1;
static DETAULT_SNAPLEN: usize = 65535;

pub type Result<T, E = PcaptureError> = result::Result<T, E>;

#[derive(Debug, Clone)]
pub struct PacketData<'a> {
    pub data: &'a [u8],
    pub iface_id: u32,
    pub tv_sec: i64,
    pub tv_usec: i64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode)]
pub enum PcapByteOrder {
    BigEndian,
    LittleEndian,
    WiresharkDefault, // LittleEndian
}

#[cfg(feature = "libpnet")]
#[derive(Debug, Clone)]
pub struct Device(NetworkInterface);

#[cfg(feature = "libpcap")]
#[derive(Debug, Clone)]
pub struct Device {
    // Interface name.
    pub name: String,
    /// Interface description.
    pub description: Option<String>,
    // All ip address (include IPv4, IPv6 and Mac if exists).
    pub addresses: Vec<Addresses>,
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
    #[cfg(feature = "libpnet")]
    pub fn list() -> Result<Vec<Device>, PcaptureError> {
        let nis = datalink::interfaces();
        let mut ret = Vec::new();
        for ni in nis {
            let device = Device(ni);
            ret.push(device);
        }
        Ok(ret)
    }
    #[cfg(feature = "libpcap")]
    pub fn list() -> Result<Vec<Device>, PcaptureError> {
        Libpcap::devices()
    }
}

#[derive(Debug, Clone)]
pub struct Iface {
    id: u32,
    device: Device,
}

#[cfg(feature = "libpnet")]
pub struct Capture<'a> {
    name: &'a str,
    buffer_size: usize,
    timeout: Duration,
    snaplen: usize,
    promisc: bool,
    // filter
    filter: Option<Filter>,
    // all system ifaces
    ifaces: Vec<Iface>,
    // current used interface
    iface_id: usize,
    // inner use
    sender: Sender<PacketData<'a>>,
    receiver: Receiver<PacketData<'a>>,
    pnet_rx: Option<Box<dyn DataLinkReceiver>>,
}

#[cfg(feature = "libpnet")]
impl<'a> Capture<'a> {
    /// A simple example showing how to capture packets and save them in pcapng format.
    /// ```rust
    /// use pcapture::Capture;
    /// use pcapture::PcapByteOrder;
    ///
    /// fn main() {
    ///     let path = "test.pcapng";
    ///     let pbo = PcapByteOrder::WiresharkDefault;
    ///
    ///     // suggest value
    ///     let buffer_size = 4096;
    ///     let snaplen = 65535;
    ///     let promisc = true;
    ///     let timeout = 0.1;
    ///
    ///     // [mac, srcmac, dstmac, ip, addr, srcip, srcaddr, dstip, dstaddr, port, srcport, dstport]
    ///     // let valid_procotol = filter::valid_protocol();
    ///     // println!("{:?}", valid_procotol);
    ///     let filter = Some("icmp and ip=192.168.1.1");
    ///
    ///     // device name 'any' is not supported due to the performance consider.
    ///     let mut cap = Capture::new("ens33", buffer_size, snaplen, promisc, timeout, filter).unwrap();
    ///     let mut pcapng = cap.gen_pcapng(pbo).unwrap();
    ///     for _ in 0..5 {
    ///         let block = cap.next_as_pcapng().unwrap();
    ///         pcapng.append(block);
    ///     }
    ///
    ///     pcapng.write_all(path).unwrap();
    /// }
    /// ```
    pub fn new(name: &'a str) -> Capture<'a> {
        let interfaces = datalink::interfaces();
        let timeout = Duration::from_secs_f32(DEFAULT_TIMEOUT);
        let buffer_size = DEFAULT_BUFFER_SIZE;
        let snaplen = DETAULT_SNAPLEN;
        let promisc = true;

        let mut ifaces = Vec::new();
        let mut id = 0;
        for interface in interfaces {
            let iface = Iface {
                id: id as u32,
                device: Device(interface),
            };
            ifaces.push(iface);
            id += 1;
        }

        let (sender, receiver) = channel();
        Capture {
            name,
            buffer_size,
            timeout,
            snaplen,
            promisc,
            ifaces: ifaces,
            iface_id: 0,
            filter: None,
            sender,
            receiver,
            pnet_rx: None,
        }
    }
    /// Ready for row format data.
    pub fn gen_raw(&self) -> Result<(), PcaptureError> {
        Ok(())
    }
    /// Generate pcap format header.
    #[cfg(feature = "pcap")]
    pub fn gen_pcap(&self, pbo: PcapByteOrder) -> Result<Pcap, PcaptureError> {
        let pcap = Pcap::new(pbo);
        Ok(pcap)
    }
    /// Generate pcapng format header.
    #[cfg(feature = "pcapng")]
    pub fn gen_pcapng(&self, pbo: PcapByteOrder) -> Result<PcapNg, PcaptureError> {
        let pcapng = PcapNg::new(&self.ifaces, pbo);
        Ok(pcapng)
    }
    pub fn buffer_size(&mut self, buffer_size: usize) {
        self.buffer_size = buffer_size;
    }
    /// timeout as sec
    pub fn timeout(&mut self, timeout: f32) {
        let timeout_fix = Duration::from_secs_f32(timeout);
        self.timeout = timeout_fix;
    }
    pub fn promiscuous(&mut self, promiscuous: bool) {
        self.promisc = promiscuous;
    }
    pub fn snaplen(&mut self, snaplen: usize) {
        self.snaplen = snaplen;
    }
    pub fn set_filter(&mut self, filter: &str) -> Result<(), PcaptureError> {
        let fls = Filter::parser(filter)?;
        self.filter = fls;
        Ok(())
    }
    pub fn ready(&mut self) -> Result<(), PcaptureError> {
        let config = Config {
            write_buffer_size: self.buffer_size, // use a bigger enough value
            read_buffer_size: self.buffer_size,  // use a bigger enough value
            read_timeout: Some(self.timeout),
            write_timeout: Some(self.timeout),
            channel_type: ChannelType::Layer2,
            bpf_fd_attempts: 1000,
            linux_fanout: None,
            promiscuous: self.promisc,
            socket_fd: None,
        };

        // find the target interface and listen
        for i in &self.ifaces {
            if i.device.0.name == self.name {
                let (_pnet_tx, pnet_rx) = match datalink::channel(&i.device.0, config) {
                    Ok(Ethernet(tx, rx)) => (tx, rx),
                    Ok(_) => return Err(PcaptureError::UnhandledChannelType),
                    Err(e) => return Err(PcaptureError::UnableCreateChannel { e: e.to_string() }),
                };

                self.pnet_rx = Some(pnet_rx);
                return Ok(());
            }
        }
        Err(PcaptureError::UnableFoundInterface {
            i: self.name.to_string(),
        })
    }
    fn next(&mut self) -> Result<PacketData, PcaptureError> {
        let pnet_rx = match &self.pnet_rx {
            Some(pnet_rx) => pnet_rx.clone(),
            None => return Err(PcaptureError::UnableFoundChannel),
        };

        let data = (*pnet_rx).next()?; // timeout error, should be ignore it here
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time went backwards");

        let tv_sec = now.as_secs() as i64;
        let tv_usec = (now.subsec_micros()) as i64;
        let packet_data = PacketData {
            iface_id: self.iface_id as u32,
            data,
            tv_sec,
            tv_usec,
        };

        Ok(packet_data)
    }
}

#[cfg(feature = "libpcap")]
pub struct Capture<'a> {
    // current used interfaces
    ifaces: Ifaces,
    snaplen: usize,
    // Filters
    fls: Option<&'a str>,
    promisc: bool,
    timeout_ms: i64,
}

#[cfg(feature = "libpcap")]
impl<'a> Capture<'a> {
    /// A simple example showing how to capture packets and save them in pcapng format.
    /// ```rust
    /// use pcapture::Capture;
    /// use pcapture::PcapByteOrder;
    ///
    /// fn main() {
    ///     let path = "test.pcapng";
    ///     let pbo = PcapByteOrder::WiresharkDefault;
    ///
    ///     let buffer_size = Some(4096);
    ///     let timeout = Some(0.1);
    ///     let promisc = Some(true);
    ///
    ///     // [mac, srcmac, dstmac, ip, addr, srcip, srcaddr, dstip, dstaddr, port, srcport, dstport]
    ///     // let valid_procotol = filter::valid_protocol();
    ///     // println!("{:?}", valid_procotol);
    ///     let filter_str = Some("icmp and ip=192.168.1.1");
    ///
    ///     // device name is 'any' means listen on all interfaces
    ///     let mut cap = Capture::new("ens33", buffer_size, timeout, promisc, filter_str).unwrap();
    ///     let mut pcapng = cap.gen_pcapng(pbo).unwrap();
    ///     for _ in 0..5 {
    ///         let block = cap.next_as_pcapng().unwrap();
    ///         pcapng.append(block);
    ///     }
    ///
    ///     pcapng.write_all(path).unwrap();
    /// }
    /// ```
    pub fn new(iface: &str, filters: Option<&'a str>) -> Result<Capture<'a>, PcaptureError> {
        let devices = Libpcap::devices()?;
        if iface == "any" {
            // listen at all interfaces
            let mut ifaces = Vec::new();
            let mut id = 0;
            for device in devices {
                let pi = Iface { id, device };
                ifaces.push(pi);
                id += 1;
            }
            let c = Capture {
                ifaces: Ifaces(ifaces),
                snaplen: DETAULT_SNAPLEN,
                fls: filters,
                promisc: true,
                timeout_ms: 1000,
            };
            return Ok(c);
        } else {
            // find the target interface and listen
            for device in devices {
                if device.name == iface {
                    let iface = Iface { id: 0, device };
                    let c = Capture {
                        ifaces: Ifaces(vec![iface]),
                        snaplen: DETAULT_SNAPLEN,
                        fls: filters,
                        promisc: true,
                        timeout_ms: 1000,
                    };
                    // only one interface
                    return Ok(c);
                }
            }
            Err(PcaptureError::UnableFoundInterface {
                i: iface.to_string(),
            })
        }
    }

    #[cfg(feature = "libpcap")]
    fn start_threads(&self) -> Result<(), PcaptureError> {
        for (thread_id, iface) in self.ifaces.iter().enumerate() {
            let interface_id = iface.id;
            let fls = self.fls.clone();
            let iface_name = iface.device.name.clone();
            // push the recv data into pipe and waitting for user get
            let promisc = self.promisc;
            let snaplen = self.snaplen;
            thread::spawn(move || {
                let mut lp = Libpcap::new();
                let (tx, rx) = channel();

                let timeout_ms = 1000;

                lp.start(&iface_name, snaplen, promisc, timeout_ms, fls, rx);

                let thread_id = thread_id as u32;
                ThreadStatus::update(thread_id as u32, ThreadStatus::Running)
                    .expect("update thread status to running failed");
                loop {
                    match ThreadStatus::get(thread_id) {
                        Ok(thread_status) => match thread_status {
                            ThreadStatus::AskStop => {
                                ThreadStatus::update(thread_id, ThreadStatus::Stoped)
                                    .expect("update thread status to stoped failed");
                                let _ = Libpcap::stop(tx);
                                break;
                            }
                            ThreadStatus::Stoped => break, // it should not happen anytime
                            ThreadStatus::Running => (),
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
    pub fn stop(&self) -> Result<(), PcaptureError> {
        // waitting for all the threads is stoped
        ThreadStatus::stop_all()?;
        loop {
            if ThreadStatus::is_all_stoped()? {
                break;
            }
        }
        Ok(())
    }
    /// Ready for row format data.
    #[cfg(feature = "pcap")]
    pub fn gen_raw(&self) -> Result<(), PcaptureError> {
        Self::start_threads(&self)?;
        Ok(())
    }
    /// Generate pcap format header.
    #[cfg(feature = "pcap")]
    pub fn gen_pcap(&self, pbo: PcapByteOrder) -> Result<Pcap, PcaptureError> {
        Self::start_threads(&self)?;
        let pcap = Pcap::new(pbo);
        Ok(pcap)
    }
    /// Generate pcapng format header.
    #[cfg(feature = "pcapng")]
    pub fn gen_pcapng(&self, pbo: PcapByteOrder) -> Result<PcapNg, PcaptureError> {
        Self::start_threads(&self)?;
        let pcapng = PcapNg::new(&self.ifaces.value(), pbo);
        Ok(pcapng)
    }
    #[cfg(feature = "libpnet")]
    pub fn buffer_size(&mut self, buffer_size: usize) {
        self.config.read_buffer_size = buffer_size;
        self.config.write_buffer_size = buffer_size;
    }
    /// timeout as sec
    #[cfg(feature = "libpnet")]
    pub fn timeout(&mut self, timeout: f32) {
        let timeout_fix = Duration::from_secs_f32(timeout);
        self.config.read_timeout = Some(timeout_fix);
        self.config.write_timeout = Some(timeout_fix);
    }
    /// timeout as sec
    #[cfg(feature = "libpcap")]
    pub fn timeout(&mut self, timeout_ms: i64) {
        self.timeout_ms = timeout_ms;
    }
    #[cfg(feature = "libpnet")]
    pub fn promiscuous(&mut self, promiscuous: bool) {
        self.config.promiscuous = promiscuous;
    }
    #[cfg(feature = "libpcap")]
    pub fn promiscuous(&mut self, promiscuous: bool) {
        self.promisc = promiscuous;
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
    ///     let mut cap = Capture::new("ens33", None).unwrap();
    ///     let _ = cap.gen_raw().unwrap();
    ///     for _ in 0..5 {
    ///         let packet_raw = cap.next_as_raw().unwrap();
    ///         packets.push(packet_raw)
    ///     }
    /// }
    /// ```
    pub fn next_as_raw(&mut self) -> Result<Vec<u8>, PcaptureError> {
        loop {
            let packet_data = match PipeWork::pop() {
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
            let packet_data = PipeWork::pop()?;
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
            let packet_data = PipeWork::pop()?;
            match packet_data {
                Some(pipe_packet) => match &self.fls {
                    Some(fls) => {
                        if fls.check(&pipe_packet.data)? {
                            let block = EnhancedPacketBlock::new(
                                pipe_packet.iface_id,
                                &pipe_packet.data,
                                self.snaplen,
                            )?;
                            let ret = GeneralBlock::EnhancedPacketBlock(block);
                            return Ok(ret);
                        }
                    }
                    None => {
                        let block = EnhancedPacketBlock::new(
                            pipe_packet.iface_id,
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
    use std::net::Ipv4Addr;

    use super::*;
    #[test]
    fn capture_raw() {
        let mut packets: Vec<Vec<u8>> = Vec::new();
        let mut cap = Capture::new("ens33", None).unwrap();
        let _ = cap.gen_raw().unwrap();
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
        let _ = cap.gen_raw().unwrap();
        for _ in 0..5 {
            let packet_raw = cap.next_as_raw().unwrap();
            println!("packet len: {}", packet_raw.len());
            packets.push(packet_raw);
        }
    }
    #[test]
    #[cfg(feature = "pcap")]
    fn capture_pcap() {
        let path = "test_ens33.pcap";
        let pbo = PcapByteOrder::WiresharkDefault;

        let mut cap = Capture::new("ens33", None).unwrap();
        let mut pcap = cap.gen_pcap(pbo).unwrap();
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
        let mut pcap = cap.gen_pcap(pbo).unwrap();
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
        let path = "test_ens33.pcapng";
        let pbo = PcapByteOrder::WiresharkDefault;

        let mut cap = Capture::new("ens33", None).unwrap();
        let mut pcapng = cap.gen_pcapng(pbo).unwrap();
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
        let path = "test_filter.pcapng";
        let pbo = PcapByteOrder::WiresharkDefault;
        // let valid_procotol = filter::valid_protocol();
        // println!("{:?}", valid_procotol);
        let filter_str = "tcp and (addr=192.168.1.1 and port=80)".to_owned();

        let mut cap = Capture::new("ens33", Some(filter_str)).unwrap();
        let mut pcapng = cap.gen_pcapng(pbo).unwrap();
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
    fn capture_multi_iface() {
        let path = "test_multi.pcapng";
        let pbo = PcapByteOrder::WiresharkDefault;

        let mut cap = Capture::new_multi(&["ens33", "lo"], None).unwrap();
        let mut pcapng = cap.gen_pcapng(pbo).unwrap();
        for _ in 0..15 {
            let block = cap.next_as_pcapng().unwrap();
            pcapng.append(block);
        }

        assert_eq!(pcapng.blocks.len(), 18); // 1 shb + 2 idb + 15 epb
        pcapng.write_all(path).unwrap();

        let read_pcapng = PcapNg::read_all(path, pbo).unwrap();
        assert_eq!(read_pcapng.blocks.len(), 18); // 1 shb + 2 idb + 15 epb
    }
    #[test]
    fn test_ipnetwork() {
        let ip = Ipv4Addr::new(192, 168, 1, 250);
        let ipn = IpNetwork::new(ip.into(), 24).unwrap();

        for i in &ipn {
            println!("{}", i);
        }
    }
}
