#[repr(u32)]
#[derive(Debug, Clone)]
pub enum Network {
    Null = 0,
    Ethernet = 1,
    Fddi = 10,
    Raw = 101,
    Loop = 108,
    LinuxSll = 113,
    LinuxSll2 = 276,
    /// Raw IPv4; the packet begins with an IPv4 header.
    IPv4 = 228,
    /// Raw IPv6; the packet begins with an IPv6 header.
    IPv6 = 229,
    /// Linux netlink NETLINK NFLOG socket log messages.
    /// Use the [`pcap_nflog`] module to access content.
    Nflog = 239,
    /// Upper-layer protocol saves from Wireshark
    WiresharkUpperPdu = 252,
}

#[derive(Debug, Clone)]
pub struct PcapHeader {
    /// Magic number
    pub magic_number: u32,
    /// Major version number
    pub version_major: u16,
    /// Minor version number
    pub version_minor: u16,
    /// GMT to local correction
    pub thiszone: i32,
    /// Accuracy of timestamps
    pub sigfigs: u32,
    /// Max length of captured packets, in octets
    pub snaplen: u32,
    /// Data link type
    pub network: Network,
}

impl PcapHeader {
    pub fn init() -> PcapHeader {
        PcapHeader {
            magic_number: 0xa1b2_c3d4, // native order
            version_major: 2,
            version_minor: 4,
            thiszone: 0,
            sigfigs: 0,
            snaplen: 0,
            network: Network::Ethernet,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PcapRecord {
    /// Timestamp seconds
    pub ts_sec: u32,
    /// Timestamp microseconds
    pub ts_usec: u32,
    /// Number of octets of packet saved in file
    pub incl_len: u32,
    /// Actual length of packet
    pub orig_len: u32,
    /// Packet data
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Pcap {
    pub header: PcapHeader,
    pub record: Vec<PcapRecord>,
}

impl Pcap {
    pub fn init() {}
}
