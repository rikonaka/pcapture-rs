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
use std::io::ErrorKind;
use std::result;
#[cfg(feature = "libpcap")]
use std::sync::mpsc::Receiver;
#[cfg(feature = "libpcap")]
use std::sync::mpsc::Sender;
#[cfg(feature = "libpcap")]
use std::sync::mpsc::channel;
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

#[cfg(feature = "libpnet")]
use crate::filter::Filter;
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

static DEFAULT_BUFFER_SIZE: usize = 4096;
static DEFAULT_TIMEOUT: f32 = 0.1;
static DEFAULT_TIMEOUT_MS: i32 = 1000;
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
    pub id: u32,
    pub device: Device,
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
    ///     let mut cap = Capture::new("ens33");
    ///     cap.filter(filter);
    ///     match cap.ready() {
    ///         Ok(_) => {
    ///             let mut pcapng = cap.gen_pcapng_header(pbo).unwrap();
    ///             for _ in 0..5 {
    ///                 let block = cap.next_as_pcapng().unwrap();
    ///                 pcapng.append(block);
    ///             }
    ///             pcapng.write_all(path).unwrap();
    ///         },
    ///         Err(e) => {
    ///             println!("capture error: {}", e);
    ///         }
    ///     }
    ///     
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
        let mut iface_id = 0;
        for interface in interfaces {
            if interface.name == name {
                iface_id = id;
            }
            let iface = Iface {
                id: id as u32,
                device: Device(interface),
            };
            ifaces.push(iface);
            id += 1;
        }

        Capture {
            name,
            buffer_size,
            timeout,
            snaplen,
            promisc,
            ifaces,
            iface_id,
            filter: None,
            pnet_rx: None,
        }
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
    pub fn filter(&mut self, filter: &str) -> Result<(), PcaptureError> {
        let filter = Filter::parser(filter)?;
        self.filter = filter;
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
        if self.iface_id < self.ifaces.len() {
            let iface = &self.ifaces[self.iface_id];
            let (_pnet_tx, pnet_rx) = match datalink::channel(&iface.device.0, config) {
                Ok(Ethernet(tx, rx)) => (tx, rx),
                Ok(_) => return Err(PcaptureError::UnhandledChannelType),
                Err(e) => return Err(PcaptureError::UnableCreateChannel { e: e.to_string() }),
            };

            self.pnet_rx = Some(pnet_rx);
            return Ok(());
        } else {
            Err(PcaptureError::UnableFoundInterface {
                i: self.name.to_string(),
            })
        }
    }
    /// Very low level next return call, no filter can be applied.
    pub fn next(&'_ mut self) -> Result<PacketData<'_>, PcaptureError> {
        let pnet_rx = match &mut self.pnet_rx {
            Some(pnet_rx) => pnet_rx,
            None => return Err(PcaptureError::UnableFoundChannel),
        };

        let data = pnet_rx.next()?; // sometimes here will return timeout error, and it should be ignore
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
    /// Capture the original data.
    /// ```rust
    /// use pcapture::Capture;
    ///
    /// fn main() {
    ///     let mut packets = Vec::new();
    ///     let mut cap = Capture::new("ens33");
    ///     match cap.ready() {
    ///         Ok(_) => {
    ///             for _ in 0..5 {
    ///                 let packet_raw = cap.next_as_vec().unwrap();
    ///                 packets.push(packet_raw)
    ///             }
    ///         },
    ///         Err(e) => {
    ///             println!("capture error: {}", e);
    ///         }
    ///     }
    ///     
    ///     cap.change_iface("ens38").unwrap();
    ///     match cap.ready() {
    ///         Ok(_) => {
    ///             for _ in 0..5 {
    ///                 let packet_raw = cap.next_as_vec().unwrap();
    ///                 packets.push(packet_raw)
    ///             }
    ///         },
    ///         Err(e) => {
    ///             println!("capture error: {}", e);
    ///         }
    ///     }
    /// }
    /// ```
    pub fn change_iface(&mut self, name: &'a str) -> Result<(), PcaptureError> {
        for (idx, i) in self.ifaces.iter().enumerate() {
            if i.device.0.name == name {
                self.iface_id = idx;
                self.name = name;
                return Ok(());
            }
        }
        Err(PcaptureError::UnableFoundInterface {
            i: name.to_string(),
        })
    }
    /// Capture the original data.
    /// ```rust
    /// use pcapture::Capture;
    ///
    /// fn main() {
    ///     let mut packets = Vec::new();
    ///     let mut cap = Capture::new("ens33");
    ///     cap.buffer_size(4096);
    ///     match cap.ready() {
    ///         Ok(_) => {
    ///             for _ in 0..5 {
    ///                 let packet_raw = cap.next_as_vec().unwrap();
    ///                 packets.push(packet_raw)
    ///             }
    ///         },
    ///         Err(e) => {
    ///             println!("capture error: {}", e);
    ///         }
    ///     }
    ///     
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
    #[cfg(feature = "pcapng")]
    pub fn next_as_pcapng(&mut self) -> Result<GeneralBlock, PcaptureError> {
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
                        let block = EnhancedPacketBlock::new(
                            packet_data.iface_id,
                            &packet_data.data,
                            snaplen,
                        )?;
                        let ret = GeneralBlock::EnhancedPacketBlock(block);
                        return Ok(ret);
                    }
                }
                None => {
                    let block =
                        EnhancedPacketBlock::new(packet_data.iface_id, &packet_data.data, snaplen)?;
                    let ret = GeneralBlock::EnhancedPacketBlock(block);
                    return Ok(ret);
                }
            }
        }
    }
}

#[cfg(feature = "libpcap")]
pub struct Capture<'a> {
    name: &'a str,
    buffer_size: usize,
    timeout_ms: i32,
    snaplen: i32,
    promisc: bool,
    // filter
    filter: Option<&'a str>,
    // all system ifaces
    ifaces: Vec<Iface>,
    // current used interface
    iface_id: usize,
    pcap_rx: Option<Receiver<PacketData<'a>>>,
    singal_tx: Option<Sender<bool>>,
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
    ///     // when the underlying layer is libpcap, the supported interface name is any.
    ///     let mut cap = Capture::new("ens33");
    ///     cap.filter(filter);
    ///     match cap.ready() {
    ///         Ok(_) => {
    ///             let mut pcapng = cap.gen_pcapng_header(pbo).unwrap();
    ///             for _ in 0..5 {
    ///                 let block = cap.next_as_pcapng().unwrap();
    ///                 pcapng.append(block);
    ///             }
    ///             pcapng.write_all(path).unwrap();
    ///         },
    ///         Err(e) => {
    ///             println!("capture error: {}", e);
    ///         }
    ///     }
    ///     
    /// }
    /// ```
    pub fn new(name: &'a str) -> Result<Capture<'a>, PcaptureError> {
        let devices = Libpcap::devices()?;
        let timeout_ms = DEFAULT_TIMEOUT_MS;
        let buffer_size = DEFAULT_BUFFER_SIZE;
        let snaplen = DETAULT_SNAPLEN as i32;
        let promisc = true;

        let mut ifaces = Vec::new();
        let mut id = 0;
        let mut iface_id = 0;
        for device in devices {
            if device.name == name {
                iface_id = id;
            }
            let iface = Iface {
                id: id as u32,
                device,
            };
            ifaces.push(iface);
            id += 1;
        }

        Ok(Capture {
            name,
            buffer_size,
            timeout_ms,
            snaplen,
            promisc,
            ifaces,
            iface_id,
            filter: None,
            pcap_rx: None,
            singal_tx: None,
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
    pub fn buffer_size(&mut self, buffer_size: usize) {
        self.buffer_size = buffer_size;
    }
    /// timeout as sec
    pub fn timeout(&mut self, timeout_ms: i32) {
        self.timeout_ms = timeout_ms;
    }
    pub fn promiscuous(&mut self, promiscuous: bool) {
        self.promisc = promiscuous;
    }
    pub fn snaplen(&mut self, snaplen: i32) {
        self.snaplen = snaplen;
    }
    pub fn filter(&mut self, filter: &'a str) {
        self.filter = Some(filter);
    }
    pub fn ready(&mut self) -> Result<(), PcaptureError> {
        let (packet_sender, packet_receiver) = channel();
        let (singal_sender, singal_receiver) = channel();

        let mut lp = Libpcap::new();
        let name = self.name;
        let snaplen = self.snaplen;
        let promisc = self.promisc;
        let timeout_ms = self.timeout_ms;
        let filter = self.filter;

        self.pcap_rx = Some(packet_receiver);
        self.singal_tx = Some(singal_sender);

        let _ = lp.ready(
            name,
            snaplen,
            promisc,
            timeout_ms,
            filter,
            packet_sender,
            singal_receiver,
        )?;

        Ok(())
    }
    pub fn stop(&self) -> Result<(), PcaptureError> {
        match &self.singal_tx {
            Some(singal_tx) => Libpcap::stop(singal_tx.clone()),
            None => Ok(()),
        }
    }
    /// Very low level next return call, no filter can be applied.
    pub fn next(&'_ mut self) -> Result<PacketData<'_>, PcaptureError> {
        let pnet_rx = match &mut self.pcap_rx {
            Some(pnet_rx) => pnet_rx,
            None => return Err(PcaptureError::UnableFoundChannel),
        };

        let data = pnet_rx.next()?; // sometimes here will return timeout error, and it should be ignore
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
    /// Capture the original data.
    /// ```rust
    /// use pcapture::Capture;
    ///
    /// fn main() {
    ///     let mut packets = Vec::new();
    ///     let mut cap = Capture::new("ens33");
    ///     match cap.ready() {
    ///         Ok(_) => {
    ///             for _ in 0..5 {
    ///                 let packet_raw = cap.next_as_vec().unwrap();
    ///                 packets.push(packet_raw)
    ///             }
    ///         },
    ///         Err(e) => {
    ///             println!("capture error: {}", e);
    ///         }
    ///     }
    ///     
    ///     cap.change_iface("ens38").unwrap();
    ///     match cap.ready() {
    ///         Ok(_) => {
    ///             for _ in 0..5 {
    ///                 let packet_raw = cap.next_as_vec().unwrap();
    ///                 packets.push(packet_raw)
    ///             }
    ///         },
    ///         Err(e) => {
    ///             println!("capture error: {}", e);
    ///         }
    ///     }
    /// }
    /// ```
    pub fn change_iface(&mut self, name: &'a str) -> Result<(), PcaptureError> {
        for (idx, i) in self.ifaces.iter().enumerate() {
            if i.device.0.name == name {
                self.iface_id = idx;
                self.name = name;
                return Ok(());
            }
        }
        Err(PcaptureError::UnableFoundInterface {
            i: name.to_string(),
        })
    }
    /// Capture the original data.
    /// ```rust
    /// use pcapture::Capture;
    ///
    /// fn main() {
    ///     let mut packets = Vec::new();
    ///     let mut cap = Capture::new("ens33");
    ///     cap.buffer_size(4096);
    ///     match cap.ready() {
    ///         Ok(_) => {
    ///             for _ in 0..5 {
    ///                 let packet_raw = cap.next_as_vec().unwrap();
    ///                 packets.push(packet_raw)
    ///             }
    ///         },
    ///         Err(e) => {
    ///             println!("capture error: {}", e);
    ///         }
    ///     }
    ///     
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
    #[cfg(feature = "pcapng")]
    pub fn next_as_pcapng(&mut self) -> Result<GeneralBlock, PcaptureError> {
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
                        let block = EnhancedPacketBlock::new(
                            packet_data.iface_id,
                            &packet_data.data,
                            snaplen,
                        )?;
                        let ret = GeneralBlock::EnhancedPacketBlock(block);
                        return Ok(ret);
                    }
                }
                None => {
                    let block =
                        EnhancedPacketBlock::new(packet_data.iface_id, &packet_data.data, snaplen)?;
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
        let mut cap = Capture::new("ens33");
        cap.buffer_size(4096);
        match cap.ready() {
            Ok(_) => {
                for _ in 0..5 {
                    let packet_raw = cap.next_as_vec().unwrap();
                    println!("packet len: {}", packet_raw.len());
                    packets.push(packet_raw);
                }
            }
            Err(e) => {
                println!("capture error: {}", e);
            }
        }
    }
    #[test]
    fn capture_change_iface() {
        let mut packets: Vec<Vec<u8>> = Vec::new();
        let mut cap = Capture::new("ens33");
        cap.buffer_size(4096);
        match cap.ready() {
            Ok(_) => {
                for _ in 0..5 {
                    let packet_raw = cap.next_as_vec().unwrap();
                    println!("packet len: {}", packet_raw.len());
                    packets.push(packet_raw);
                }
            }
            Err(e) => {
                println!("capture error: {}", e);
            }
        }

        cap.change_iface("lo").unwrap();
        match cap.ready() {
            Ok(_) => {
                for _ in 0..5 {
                    let packet_raw = cap.next_as_vec().unwrap();
                    println!("packet len: {}", packet_raw.len());
                    packets.push(packet_raw);
                }
            }
            Err(e) => {
                println!("capture error: {}", e);
            }
        }

        println!("packets len: {}", packets.len());
    }
    #[test]
    #[cfg(feature = "pcap")]
    fn capture_pcap() {
        let path = "test_ens33.pcap";
        let pbo = PcapByteOrder::WiresharkDefault;

        let mut cap = Capture::new("ens33");
        cap.buffer_size(4096);
        match cap.ready() {
            Ok(_) => {
                let mut pcap = cap.gen_pcap_header(pbo).unwrap();
                for _ in 0..5 {
                    let record = cap.next_as_pcap().unwrap();
                    pcap.append(record);
                }
                // write all capture data to test.pcap
                pcap.write_all(path).unwrap();

                let read_pcap = Pcap::read_all(path, pbo).unwrap();
                assert_eq!(read_pcap.records.len(), 5);
            }
            Err(e) => {
                println!("capture error: {}", e);
                return;
            }
        }
    }
    #[test]
    #[cfg(feature = "pcapng")]
    fn capture_pcapng() {
        let path = "test_ens33.pcapng";
        let pbo = PcapByteOrder::WiresharkDefault;

        let mut cap = Capture::new("ens33");
        cap.buffer_size(4096);
        cap.timeout(0.1);
        cap.promiscuous(true);
        cap.snaplen(65535);
        match cap.ready() {
            Ok(_) => {
                let mut pcapng = cap.gen_pcapng_header(pbo).unwrap();
                // println!("pcapng header len: {}", pcapng.blocks.len());
                for _ in 0..5 {
                    let block = cap.next_as_pcapng().unwrap();
                    pcapng.append(block);
                }

                pcapng.write_all(path).unwrap();

                let read_pcapng = PcapNg::read_all(path, pbo).unwrap();
                assert_eq!(read_pcapng.blocks.len(), 8);
            }
            Err(e) => {
                println!("capture error: {}", e);
            }
        }
    }
    #[test]
    #[cfg(feature = "pcapng")]
    fn capture_pcapng_filter() {
        let path = "test_filter.pcapng";
        let pbo = PcapByteOrder::WiresharkDefault;
        // let valid_procotol = filter::valid_protocol();
        // println!("{:?}", valid_procotol);
        let filter = "tcp and (addr=192.168.5.152 and port=80)";

        let mut cap = Capture::new("ens33");
        cap.filter(filter).unwrap();
        match cap.ready() {
            Ok(_) => {
                let mut pcapng = cap.gen_pcapng_header(pbo).unwrap();
                for i in 0..5 {
                    println!("i: {}", i);
                    let block = cap.next_as_pcapng().unwrap();
                    pcapng.append(block);
                }

                pcapng.write_all(path).unwrap();
            }
            Err(e) => {
                println!("capture error: {}", e);
            }
        }
    }
}
