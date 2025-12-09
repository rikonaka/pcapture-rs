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
#[cfg(feature = "libpnet")]
use pnet::datalink::DataLinkReceiver;
#[cfg(feature = "libpnet")]
use pnet::datalink::NetworkInterface;
use serde::Deserialize;
use serde::Serialize;
#[cfg(feature = "libpnet")]
use std::io::ErrorKind;
#[cfg(any(feature = "libpcap", feature = "libpnet"))]
use std::result;
#[cfg(feature = "libpnet")]
use std::time::Duration;
#[cfg(feature = "libpnet")]
use std::time::SystemTime;
#[cfg(feature = "libpnet")]
use std::time::UNIX_EPOCH;
use std::u32;

mod libpcap;

pub mod error;
#[cfg(any(feature = "libpcap", feature = "libpnet"))]
pub mod filter;
pub mod fs;

#[cfg(feature = "libpnet")]
use crate::filter::Filter;
#[cfg(any(feature = "libpcap", feature = "libpnet"))]
use error::PcaptureError;
#[cfg(feature = "libpcap")]
use libpcap::Addresses;
#[cfg(feature = "libpcap")]
use libpcap::Libpcap;

#[cfg(feature = "pcap")]
pub use fs::pcap::PacketRecord;
#[cfg(feature = "pcap")]
pub use fs::pcap::Pcap;
#[cfg(feature = "pcapng")]
pub use fs::pcapng::PcapNg;

#[cfg(feature = "pcapng")]
use fs::pcapng::EnhancedPacketBlock;
#[cfg(feature = "pcapng")]
use fs::pcapng::GeneralBlock;

#[cfg(any(feature = "libpcap", feature = "libpnet"))]
static DEFAULT_BUFFER_SIZE: usize = 4096;
#[cfg(feature = "libpnet")]
static DEFAULT_TIMEOUT: f32 = 0.1;
#[cfg(feature = "libpcap")]
static DEFAULT_TIMEOUT_MS: i32 = 1000;
#[cfg(any(feature = "libpcap", feature = "libpnet"))]
static DETAULT_SNAPLEN: usize = 65535;

#[cfg(any(feature = "libpcap", feature = "libpnet"))]
pub type Result<T, E = PcaptureError> = result::Result<T, E>;

#[derive(Debug, Clone)]
pub struct PacketData<'a> {
    pub data: &'a [u8],
    pub tv_sec: u64,
    pub tv_usec: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode)]
pub enum PcapByteOrder {
    BigEndian,
    LittleEndian,
    /// LittleEndian
    WiresharkDefault,
}

#[cfg(feature = "libpnet")]
#[derive(Debug, Clone)]
pub struct Device(pub NetworkInterface);

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

#[cfg(feature = "libpcap")]
impl Device {
    /// Returns all interfaces in the system.
    /// ```rust
    /// use pcapture::Device;
    ///
    /// fn main() {
    ///     let devices = Device::list().unwrap();
    ///     for device in devices {
    ///         println!("device name: {}", device.0.name);
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

#[cfg(any(feature = "libpcap", feature = "libpnet"))]
#[derive(Debug, Clone)]
pub struct Iface {
    pub id: u32,
    pub device: Device,
}

#[cfg(feature = "libpnet")]
pub struct Capture {
    pub name: String,
    buffer_size: usize,
    timeout: Duration,
    snaplen: usize,
    promisc: bool,
    // filter
    filter: Option<Filter>,
    // store the all system ifaces here
    ifaces: Vec<Iface>,
    // this is the current used interface
    iface_id: u32,
    // inner use
    pnet_rx: Option<Box<dyn DataLinkReceiver>>,
}

#[cfg(feature = "libpnet")]
impl Capture {
    /// A simple example showing how to capture packets and save them in pcapng format.
    /// ```rust
    /// use pcapture::Capture;
    /// use pcapture::PcapByteOrder;
    ///
    /// fn main() {
    ///     let path = "test.pcapng";
    ///     let pbo = PcapByteOrder::WiresharkDefault;
    ///
    ///     // default value
    ///     // let buffer_size = 4096;
    ///     // let snaplen = 65535;
    ///     // let promisc = true;
    ///     // let timeout = 0.1;
    ///
    ///     // [mac, srcmac, dstmac, ip, addr, srcip, srcaddr, dstip, dstaddr, port, srcport, dstport]
    ///     // let valid_procotol = filter::valid_protocol();
    ///     // println!("{:?}", valid_procotol);
    ///
    ///     // Note that the filter here is my own implementation,
    ///     // and this syntax is only correct when the underlying technology uses libpnet.
    ///     // When your underlying technology uses libpcap, please use the standard BPF filter syntax.
    ///     let filter_str = "icmp and ip=192.168.5.2";
    ///
    ///     // device name 'any' is not supported due to the performance consider.
    ///     let mut cap = Capture::new("ens33").unwrap();
    ///     cap.filter(filter_str).unwrap();
    ///     let mut pcapng = cap.gen_pcapng_header(pbo).unwrap();
    ///     for _ in 0..5 {
    ///         let block = cap.next_as_pcapng().unwrap();
    ///         pcapng.append(block);
    ///     }
    ///     pcapng.write_all(path).unwrap();
    ///     
    /// }
    /// ```
    pub fn new(name: &str) -> Result<Self, PcaptureError> {
        let interfaces = datalink::interfaces();
        let timeout = Duration::from_secs_f32(DEFAULT_TIMEOUT);
        let buffer_size = DEFAULT_BUFFER_SIZE;
        let snaplen = DETAULT_SNAPLEN;
        let promisc = true;

        let mut ifaces = Vec::new();
        let mut i = 0;
        let mut iface_id = 0;
        for interface in interfaces {
            if interface.name == name {
                iface_id = i;
            }
            let iface = Iface {
                id: i as u32,
                device: Device(interface),
            };
            ifaces.push(iface);
            i += 1;
        }

        let config = Config {
            write_buffer_size: buffer_size, // use a bigger enough value
            read_buffer_size: buffer_size,  // use a bigger enough value
            read_timeout: Some(timeout),
            write_timeout: Some(timeout),
            channel_type: ChannelType::Layer2,
            bpf_fd_attempts: 1000,
            linux_fanout: None,
            promiscuous: promisc,
            socket_fd: None,
        };

        // find the target interface and listen
        let iface = &ifaces[iface_id as usize];
        // only recv and no send
        let (_pnet_tx, pnet_rx) = match datalink::channel(&iface.device.0, config) {
            Ok(Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => return Err(PcaptureError::UnhandledChannelType),
            Err(e) => return Err(PcaptureError::UnableCreateChannel { e: e.to_string() }),
        };

        Ok(Capture {
            name: name.to_string(),
            buffer_size,
            timeout,
            snaplen,
            promisc,
            ifaces,
            iface_id,
            filter: None,
            pnet_rx: Some(pnet_rx),
        })
    }
    /// Generate pcap format header.
    #[cfg(feature = "pcap")]
    pub fn gen_pcap_header(&self, pbo: PcapByteOrder) -> Result<Pcap, PcaptureError> {
        let pcap = Pcap::new(pbo);
        Ok(pcap)
    }
    /// Generate pcapng format header.
    #[cfg(feature = "pcapng")]
    pub fn gen_pcapng_header(&self, pbo: PcapByteOrder) -> Result<PcapNg, PcaptureError> {
        let pcapng = PcapNg::new(&self.ifaces, pbo);
        Ok(pcapng)
    }
    /// Set the buffer size.
    pub fn set_buffer_size(&mut self, buffer_size: usize) {
        self.buffer_size = buffer_size;
        // set pnet_rx none means needs regenerate config and pnext_rx next time
        self.pnet_rx = None;
    }
    /// Get the buffer size.
    pub fn get_buffer_size(&self) -> usize {
        self.buffer_size
    }
    /// Set timeout (as sec).
    pub fn set_timeout(&mut self, timeout: f32) {
        let timeout_fix = Duration::from_secs_f32(timeout);
        self.timeout = timeout_fix;
        // set pnet_rx none means needs regenerate config and pnext_rx next time
        self.pnet_rx = None;
    }
    /// Get the timeout (as sec).
    pub fn get_timeout(&self) -> f32 {
        self.timeout.as_secs_f32()
    }
    /// Set promiscuous mode.
    pub fn set_promiscuous(&mut self, promiscuous: bool) {
        self.promisc = promiscuous;
        // set pnet_rx none means needs regenerate config and pnext_rx next time
        self.pnet_rx = None;
    }
    /// Get promiscuous mode.
    pub fn get_promiscuous(&self) -> bool {
        self.promisc
    }
    /// Set snaplen value.
    pub fn set_snaplen(&mut self, snaplen: usize) {
        self.snaplen = snaplen;
        // set pnet_rx none means needs regenerate config and pnext_rx next time
        self.pnet_rx = None;
    }
    /// Get snaplen value.
    pub fn get_snaplen(&self) -> usize {
        self.snaplen
    }
    /// Set filter with pcapture syntax.
    pub fn set_filter(&mut self, filter: &str) -> Result<(), PcaptureError> {
        let filter = Filter::parser(filter)?;
        self.filter = filter;
        // set pnet_rx none means needs regenerate config and pnext_rx next time
        self.pnet_rx = None;
        Ok(())
    }
    /// Get current filter.
    pub fn get_filter(&self) -> Option<String> {
        if let Some(filter) = &self.filter {
            Some(filter.input_str.to_string())
        } else {
            None
        }
    }
    /// Very low level next return call, no filter can be applied.
    pub fn next(&'_ mut self) -> Result<PacketData<'_>, PcaptureError> {
        if self.pnet_rx.is_none() {
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
            let iface = &self.ifaces[self.iface_id as usize];
            let (_pnet_tx, pnet_rx) = match datalink::channel(&iface.device.0, config) {
                Ok(Ethernet(tx, rx)) => (tx, rx),
                Ok(_) => return Err(PcaptureError::UnhandledChannelType),
                Err(e) => return Err(PcaptureError::UnableCreateChannel { e: e.to_string() }),
            };

            self.pnet_rx = Some(pnet_rx);
        }

        if let Some(pnet_rx) = &mut self.pnet_rx {
            let data = pnet_rx.next()?; // sometimes here will return timeout error, and it should be ignore
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time went backwards");

            let tv_sec = now.as_secs();
            let tv_usec = now.subsec_micros() as u64;
            let packet_data = PacketData {
                data,
                tv_sec,
                tv_usec,
            };

            Ok(packet_data)
        } else {
            unreachable!("pnet_rx must have value")
        }
    }
    /// Capture the packets as raw format.
    /// ```rust
    /// use pcapture::Capture;
    ///
    /// fn main() {
    ///     let mut packets = Vec::new();
    ///     let mut cap = Capture::new("ens33").unwrap();
    ///     for _ in 0..5 {
    ///         let packet_raw = cap.next_as_vec().unwrap();
    ///         packets.push(packet_raw)
    ///     }
    /// }
    /// ```
    pub fn next_as_vec(&mut self) -> Result<Vec<u8>, PcaptureError> {
        let filter = self.filter.clone();
        loop {
            let packet_data = match self.next() {
                Ok(pd) => pd,
                Err(e) => match e {
                    PcaptureError::IOError(e) => {
                        if e.kind() == ErrorKind::TimedOut {
                            continue;
                        } else {
                            return Err(e.into());
                        }
                    }
                    _ => return Err(e.into()),
                },
            };

            match &filter {
                Some(fls) => {
                    if fls.check(packet_data.data)? {
                        return Ok(packet_data.data.to_vec());
                    }
                }
                None => {
                    return Ok(packet_data.data.to_vec());
                }
            }
        }
    }
    /// Capture the packets as pcap format.
    #[cfg(feature = "pcap")]
    pub fn next_as_pcap(&mut self) -> Result<PacketRecord, PcaptureError> {
        let filter = self.filter.clone();
        let snaplen = self.snaplen;
        loop {
            let packet_data = match self.next() {
                Ok(pd) => pd,
                Err(e) => match e {
                    PcaptureError::IOError(e) => {
                        if e.kind() == ErrorKind::TimedOut {
                            continue;
                        } else {
                            return Err(e.into());
                        }
                    }
                    _ => return Err(e.into()),
                },
            };

            match &filter {
                Some(fls) => {
                    if fls.check(packet_data.data)? {
                        let pcap_record = PacketRecord::new(&packet_data.data, snaplen)?;
                        return Ok(pcap_record);
                    }
                }
                None => {
                    let pcap_record = PacketRecord::new(&packet_data.data, snaplen)?;
                    return Ok(pcap_record);
                }
            }
        }
    }
    /// Capture the packets as pcapng format.
    #[cfg(feature = "pcapng")]
    pub fn next_as_pcapng(&mut self) -> Result<GeneralBlock, PcaptureError> {
        let filter = self.filter.clone();
        let snaplen = self.snaplen;
        let iface_id = self.iface_id;

        loop {
            let packet_data = match self.next() {
                Ok(pd) => pd,
                Err(e) => match e {
                    PcaptureError::IOError(e) => {
                        if e.kind() == ErrorKind::TimedOut {
                            continue;
                        } else {
                            return Err(e.into());
                        }
                    }
                    _ => return Err(e.into()),
                },
            };

            match &filter {
                Some(fls) => {
                    if fls.check(packet_data.data)? {
                        let block = EnhancedPacketBlock::new(iface_id, &packet_data.data, snaplen)?;
                        let ret = GeneralBlock::EnhancedPacketBlock(block);
                        return Ok(ret);
                    }
                }
                None => {
                    let block = EnhancedPacketBlock::new(iface_id, &packet_data.data, snaplen)?;
                    let ret = GeneralBlock::EnhancedPacketBlock(block);
                    return Ok(ret);
                }
            }
        }
    }
}

#[cfg(feature = "libpcap")]
#[derive(Debug, Clone)]
pub struct Capture {
    pub name: String,
    buffer_size: usize,
    timeout_ms: i32,
    snaplen: i32,
    promisc: bool,
    // filter
    filter: Option<String>,
    // all system ifaces
    ifaces: Vec<Iface>,
    // current used interface
    iface_id: u32,
    lp: Option<Libpcap>,
}

#[cfg(feature = "libpcap")]
impl<'a> Capture {
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
    ///     // let buffer_size = 4096;
    ///     // let snaplen = 65535;
    ///     // let promisc = true;
    ///     // let timeout = 0.1;
    ///
    ///     // [mac, srcmac, dstmac, ip, addr, srcip, srcaddr, dstip, dstaddr, port, srcport, dstport]
    ///     // let valid_procotol = filter::valid_protocol();
    ///     // println!("{:?}", valid_procotol);
    ///
    ///     // Please use the BPF filter syntax here.
    ///     let filter = "icmp and host 192.168.5.2";
    ///
    ///     // when the underlying layer is libpcap, the supported interface name is any.
    ///     let mut cap = Capture::new("ens33").unwrap();
    ///     cap.set_filter(filter);
    ///     let mut pcapng = cap.gen_pcapng_header(pbo).unwrap();
    ///     for _ in 0..5 {
    ///         let blocks = cap.fetch_as_pcapng().unwrap();
    ///         for b in blocks {
    ///             pcapng.append(b);
    ///         }
    ///     }
    ///     pcapng.write_all(path).unwrap();
    ///     
    /// }
    /// ```
    pub fn new(name: &str) -> Result<Self, PcaptureError> {
        let devices = Libpcap::devices()?;
        let timeout_ms = DEFAULT_TIMEOUT_MS;
        let buffer_size = DEFAULT_BUFFER_SIZE;
        let snaplen = DETAULT_SNAPLEN as i32;
        let promisc = true;

        let mut ifaces = Vec::new();
        let mut i = 0;
        let mut iface_id = 0;
        for device in devices {
            if device.name == name {
                iface_id = i;
            }
            let iface = Iface {
                id: i as u32,
                device,
            };
            ifaces.push(iface);
            i += 1;
        }
        let filter = None;
        let lp = Libpcap::new(name, snaplen, promisc, timeout_ms, filter)?;

        Ok(Self {
            name: name.to_string(),
            buffer_size,
            timeout_ms,
            snaplen,
            promisc,
            ifaces,
            iface_id,
            filter: None,
            lp: Some(lp),
        })
    }
    /// Generate pcap format header.
    #[cfg(feature = "pcap")]
    pub fn gen_pcap_header(&self, pbo: PcapByteOrder) -> Result<Pcap, PcaptureError> {
        let pcap = Pcap::new(pbo);
        Ok(pcap)
    }
    /// Generate pcapng format header.
    #[cfg(feature = "pcapng")]
    pub fn gen_pcapng_header(&self, pbo: PcapByteOrder) -> Result<PcapNg, PcaptureError> {
        let pcapng = PcapNg::new(&self.ifaces, pbo);
        Ok(pcapng)
    }
    /// Set buffer size.
    pub fn set_buffer_size(&mut self, buffer_size: usize) {
        self.buffer_size = buffer_size;
        // none means regenerate lp in fetch func
        self.lp = None;
    }
    /// Get the buffer size.
    pub fn get_buffer_size(&self) -> usize {
        self.buffer_size
    }
    /// Set timeout as milliseconds.
    pub fn set_timeout(&mut self, timeout_ms: i32) {
        self.timeout_ms = timeout_ms;
        // none means regenerate lp in fetch func
        self.lp = None;
    }
    /// Get the timeout as milliseconds.
    pub fn get_timeout(&self) -> i32 {
        self.timeout_ms
    }
    /// Set promiscuous mode.
    pub fn set_promiscuous(&mut self, promiscuous: bool) {
        self.promisc = promiscuous;
        // none means regenerate lp in fetch func
        self.lp = None;
    }
    /// Get promiscuous mode.
    pub fn get_promiscuous(&self) -> bool {
        self.promisc
    }
    /// Set snaplen value.
    pub fn set_snaplen(&mut self, snaplen: i32) {
        self.snaplen = snaplen;
        // none means regenerate lp in fetch func
        self.lp = None;
    }
    /// Get snaplen value.
    pub fn get_snaplen(&self) -> i32 {
        self.snaplen
    }
    /// Set filter with BPF syntax.
    pub fn set_filter(&mut self, filter: &str) {
        self.filter = Some(filter.to_string());
        // none means regenerate lp in fetch func
        self.lp = None;
    }
    /// Get current filter.
    pub fn get_filter(&self) -> Option<String> {
        self.filter.clone()
    }
    /// Return all packets in the system cache.
    pub fn fetch(&mut self) -> Result<Vec<PacketData<'_>>, PcaptureError> {
        if self.lp.is_none() {
            let lp = Libpcap::new(
                &self.name,
                self.snaplen,
                self.promisc,
                self.timeout_ms,
                self.filter.clone(),
            )?;
            self.lp = Some(lp);
        }

        if let Some(lp) = &mut self.lp {
            let packets = lp.fetch()?;
            Ok(packets)
        } else {
            unreachable!("lp must have a value here");
        }
    }
    /// Please perform this step to clear memory when exiting the program.
    pub fn stop(&mut self) -> Result<(), PcaptureError> {
        if let Some(libpcap) = &mut self.lp {
            let _ = libpcap.stop()?;
        }
        Ok(())
    }
    /// Capture the all packets in system cache as raw format.
    /// ```rust
    /// use pcapture::Capture;
    ///
    /// fn main() {
    ///     let mut packets = Vec::new();
    ///     let mut cap = Capture::new("ens33").unwrap();
    ///     for _ in 0..5 {
    ///         let ret = cap.fetch_as_vec().unwrap();
    ///         for p in ret {
    ///             packets.push(p.to_vec());
    ///         }
    ///     }
    ///     
    /// }
    /// ```
    pub fn fetch_as_vec(&'a mut self) -> Result<Vec<&'a [u8]>, PcaptureError> {
        let packets = self.fetch()?;
        let mut ret = Vec::new();
        for p in packets {
            ret.push(p.data)
        }
        return Ok(ret);
    }
    /// Capture the all packets in system cache as the pcap format.
    #[cfg(feature = "pcap")]
    pub fn fetch_as_pcap(&mut self) -> Result<Vec<PacketRecord>, PcaptureError> {
        let snaplen = self.snaplen as usize;
        let packets = self.fetch()?;

        let mut ret = Vec::new();
        for p in packets {
            let data = p.data;
            let ts_sec = p.tv_sec as u32;
            let ts_usec = p.tv_usec as u32;
            let pcap_record = PacketRecord::new(data, snaplen, ts_sec, ts_usec)?;
            ret.push(pcap_record);
        }
        return Ok(ret);
    }
    /// Capture the all packets in system cache as the pcapng format.
    #[cfg(feature = "pcapng")]
    pub fn fetch_as_pcapng(&mut self) -> Result<Vec<GeneralBlock>, PcaptureError> {
        let snaplen = self.snaplen as usize;
        let iface_id = self.iface_id;
        let packets = self.fetch()?;

        let mut ret = Vec::new();
        for p in packets {
            let data = p.data;
            let ts_sec = p.tv_sec as u32;
            let ts_usec = p.tv_usec as u32;
            let block = EnhancedPacketBlock::new(iface_id, data, snaplen, ts_sec, ts_usec)?;
            let block = GeneralBlock::EnhancedPacketBlock(block);
            ret.push(block);
        }

        return Ok(ret);
    }
}

#[cfg(feature = "libpcap")]
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn capture_raw() {
        let mut cap = Capture::new("ens33").unwrap();
        cap.set_buffer_size(4096);
        for i in 0..5 {
            let packet_raw = cap.fetch_as_vec().unwrap();
            println!("fetch[{}], packets num: {}", i, packet_raw.len());
        }
    }
    #[cfg(feature = "pcap")]
    #[test]
    fn capture_pcap() {
        let path = "test_ens33.pcap";
        let pbo = PcapByteOrder::WiresharkDefault;

        let mut cap = Capture::new("ens33").unwrap();
        cap.set_buffer_size(4096);
        let mut pcap = cap.gen_pcap_header(pbo).unwrap();

        let mut packet_count = 0;
        for _ in 0..5 {
            let record = cap.fetch_as_pcap().unwrap();
            for r in record {
                pcap.append(r);
                packet_count += 1;
            }
        }
        println!("packet count: {}", packet_count);

        // write all capture data to test.pcap
        pcap.write_all(path).unwrap();

        let read_pcap = Pcap::read_all(path, pbo).unwrap();
        assert_eq!(read_pcap.records.len(), packet_count);
    }
    #[cfg(feature = "pcapng")]
    #[test]
    fn capture_pcapng() {
        let path = "test_ens33.pcapng";
        let pbo = PcapByteOrder::WiresharkDefault;

        let mut cap = Capture::new("ens33").unwrap();
        cap.set_buffer_size(4096);
        cap.set_timeout(1);
        cap.set_promiscuous(true);
        cap.set_snaplen(65535);

        let mut pcapng = cap.gen_pcapng_header(pbo).unwrap();

        // libpcap => 9
        // libpnet => 3
        println!("pcapng header len: {}", pcapng.blocks.len());

        let mut packets_count = pcapng.blocks.len();
        for _ in 0..5 {
            let blocks = cap.fetch_as_pcapng().unwrap();
            for b in blocks {
                pcapng.append(b);
                packets_count += 1;
            }
        }

        pcapng.write_all(path).unwrap();

        let read_pcapng = PcapNg::read_all(path, pbo).unwrap();
        // interfaece info node
        assert_eq!(read_pcapng.blocks.len(), packets_count);
    }
    #[cfg(feature = "pcapng")]
    #[test]
    fn capture_pcapng_filter() {
        let path = "test_filter.pcapng";
        let pbo = PcapByteOrder::WiresharkDefault;
        // let valid_procotol = filter::valid_protocol();
        // println!("{:?}", valid_procotol);
        let filter = "host 192.168.5.2";

        let mut cap = Capture::new("ens33").unwrap();
        cap.set_filter(filter);

        let mut pcapng = cap.gen_pcapng_header(pbo).unwrap();
        for i in 0..5 {
            println!("i: {}", i);
            let block = cap.fetch_as_pcapng().unwrap();
            for b in block {
                pcapng.append(b);
            }
        }

        pcapng.write_all(path).unwrap();
    }
}

#[cfg(feature = "libpnet")]
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn capture_raw() {
        let mut cap = Capture::new("ens33").unwrap();
        cap.set_buffer_size(4096);
        for i in 0..5 {
            let packet_raw = cap.next_as_vec().unwrap();
            println!("fetch[{}], packets num: {}", i, packet_raw.len());
        }
    }
    #[cfg(feature = "pcap")]
    #[test]
    fn capture_pcap() {
        let path = "test_ens33.pcap";
        let pbo = PcapByteOrder::WiresharkDefault;

        let mut cap = Capture::new("ens33").unwrap();
        cap.set_buffer_size(4096);
        let mut pcap = cap.gen_pcap_header(pbo).unwrap();

        let mut packet_count = 0;
        for _ in 0..5 {
            let record = cap.next_as_pcap().unwrap();
            pcap.append(record);
            packet_count += 1;
        }
        println!("packet count: {}", packet_count);

        // write all capture data to test.pcap
        pcap.write_all(path).unwrap();

        let read_pcap = Pcap::read_all(path, pbo).unwrap();
        assert_eq!(read_pcap.records.len(), packet_count);
    }
    #[cfg(feature = "pcapng")]
    #[test]
    fn capture_pcapng() {
        let path = "test_ens33.pcapng";
        let pbo = PcapByteOrder::WiresharkDefault;

        let mut cap = Capture::new("ens33").unwrap();
        cap.set_buffer_size(4096);
        cap.set_timeout(1.0);
        cap.set_promiscuous(true);
        cap.set_snaplen(65535);

        let mut pcapng = cap.gen_pcapng_header(pbo).unwrap();

        // libpcap => 9
        // libpnet => 3
        println!("pcapng header len: {}", pcapng.blocks.len());

        let mut packets_count = pcapng.blocks.len();
        for _ in 0..5 {
            let block = cap.next_as_pcapng().unwrap();
            pcapng.append(block);
            packets_count += 1;
        }

        pcapng.write_all(path).unwrap();

        let read_pcapng = PcapNg::read_all(path, pbo).unwrap();
        // interfaece info node
        assert_eq!(read_pcapng.blocks.len(), packets_count);
    }
    #[cfg(feature = "pcapng")]
    #[test]
    fn capture_pcapng_filter() {
        let path = "test_filter.pcapng";
        let pbo = PcapByteOrder::WiresharkDefault;
        // let valid_procotol = filter::valid_protocol();
        // println!("{:?}", valid_procotol);
        let filter_str = "icmp and ip=192.168.5.2";

        let mut cap = Capture::new("ens33").unwrap();
        cap.set_filter(filter_str).unwrap();

        let mut pcapng = cap.gen_pcapng_header(pbo).unwrap();
        for i in 0..5 {
            println!("i: {}", i);
            let block = cap.next_as_pcapng().unwrap();
            pcapng.append(block);
        }

        pcapng.write_all(path).unwrap();
    }
}
