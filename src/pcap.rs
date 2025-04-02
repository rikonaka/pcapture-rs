use bincode::Decode;
use bincode::Encode;
use serde::Deserialize;
use serde::Serialize;

#[repr(u32)]
#[derive(Debug, Clone, Deserialize, Serialize, Encode, Decode)]
pub enum LinkType {
    NULL = 0,
    ETHERNET = 1,
    AX25 = 3,
    IEEE8025 = 6,
    ARCNETBSD = 7,
    SLIP = 8,
    PPP = 9,
    FDDI = 10,
    PPPHDLC = 50,
    PPPETHER = 51,
    ATMRFC1483 = 100,
    RAW = 101,
    CHDLC = 104,
    IEEE80211 = 105,
    FRELAY = 107,
    LOOP = 108,
    LINUXSLL = 113,
    LTALK = 114,
    PFLOG = 117,
    IEEE80211PRISM = 119,
    IPOVERFC = 122,
    SUNATM = 123,
    IEEE80211RADIOTAP = 127,
    ARCNETLINUX = 129,
    APPLEIPOVERIEEE1394 = 138,
    MTP2WITHPHDR = 139,
    MTP2 = 140,
    MTP3 = 141,
    SCCP = 142,
    DOCSIS = 143,
    LINUXIRDA = 144,
    IEEE80211AVS = 163,
    BACNETMSTP = 165,
    PPPPPPD = 166,
    GPRSLLC = 169,
    GPFT = 170,
    GPFF = 171,
    LINUXLAPD = 177,
    MFR = 182,
    BLUETOOTHHCIH4 = 187,
    USBLINUX = 189,
    PPI = 192,
    IEEE802154WITHFCS = 195,
    SITA = 196,
    ERF = 197,
    BLUETOOTHHCIH4WITHPHDR = 201,
    AX25KISS = 202,
    LAPD = 203,
    PPPWITHDIR = 204,
    CHDLCWITHDIR = 205,
    FRELAYWITHDIR = 206,
    LAPBWITHDIR = 207,
    IPMBLINUX = 209,
    IEEE802154NONASKPHY = 215,
    USBLINUXMMAPPED = 220,
    FC2 = 224,
    FC2WITHFRAMEDELIMS = 225,
    IPNET = 226,
    CANSOCKETCAN = 227,
    IPV4 = 228,
    IPV6 = 229,
    IEEE802154NOFCS = 230,
    DBUS = 231,
    DVBCI = 235,
    MUX27010 = 236,
    STANAG5066DPDU = 237,
    NFLOG = 239,
    NETANALYZER = 240,
    NETANALYZERTRANSPARENT = 241,
    IPOIB = 242,
    MPEG2TS = 243,
    NG40 = 244,
    NFCLLCP = 245,
    INFINIBAND = 247,
    SCTP = 248,
    USBPCAP = 249,
    RTACSERIAL = 250,
    BLUETOOTHLELL = 251,
    WIRESHARKUPPERPDU = 252,
    NETLINK = 253,
    BLUETOOTHLINUXMONITOR = 254,
    BLUETOOTHBREDRBB = 255,
    BLUETOOTHLELLWITHPHDR = 256,
    PROFIBUSDL = 257,
    PKTAP = 258,
    EPON = 259,
    IPMIHPM2 = 260,
    ZWAVER1R2 = 261,
    ZWAVER3 = 262,
    WATTSTOPPERDLM = 263,
    ISO14443 = 264,
    RDS = 265,
    USBDARWIN = 266,
    SDLC = 268,
    LORATAP = 270,
    VSOCK = 271,
    NORDICBLE = 272,
    DOCSIS31XRA31 = 273,
    ETHERNETMPACKET = 274,
    DISPLAYPORTAUX = 275,
    LINUXSLL2 = 276,
    OPENVIZSLA = 278,
    EBHSCR = 279,
    VPPDISPATCH = 280,
    DSATAGBRCM = 281,
    DSATAGBRCMPREPEND = 282,
    IEEE802154TAP = 283,
    DSATAGDSA = 284,
    DSATAGEDSA = 285,
    ELEE = 286,
    WAVESERIAL = 287,
    USB20 = 288,
    ATSCALP = 289,
}

// pcap header format
// from https://www.ietf.org/archive/id/draft-gharris-opsawg-pcap-01.html
//
//                         1                   2                   3
//     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  0 |                          Magic Number                         |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  4 |          Major Version        |         Minor Version         |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  8 |                           Reserved1                           |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 12 |                           Reserved2                           |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 16 |                            SnapLen                            |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 20 | FCS |f|0 0 0 0 0 0 0 0 0 0 0 0|         LinkType              |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#[repr(C)]
#[derive(Debug, Clone, Deserialize, Serialize, Encode, Decode)]
pub struct PcapHeader {
    /// Magic Number (32 bits):
    /// An unsigned magic number, whose value is either the hexadecimal number 0xA1B2C3D4 or the hexadecimal number 0xA1B23C4D.
    /// If the value is 0xA1B2C3D4, time stamps in Packet Records (see Figure 2) are in seconds and microseconds;
    /// if it is 0xA1B23C4D, time stamps in Packet Records are in seconds and nanoseconds.
    pub magic_number: u32,
    /// Major Version (16 bits):
    /// An unsigned value, giving the number of the current major version of the format.
    /// The value for the current version of the format is 2.
    pub major_version: u16,
    /// Minor Version (16 bits):
    /// An unsigned value, giving the number of the current minor version of the format.
    /// The value is for the current version of the format is 4.
    pub minor_version: u16,
    /// Reserved1 (32 bits):
    /// Not used - SHOULD be filled with 0 by pcap file writers, and MUST be ignored by pcap file readers.
    reserved1: u32,
    /// Reserved2 (32 bits):
    /// Not used - SHOULD be filled with 0 by pcap file writers, and MUST be ignored by pcap file readers.
    reserved2: u32,
    /// SnapLen (32 bits):
    /// An unsigned value indicating the maximum number of octets captured from each packet.
    /// The portion of each packet that exceeds this value will not be stored in the file.
    pub snaplen: u32,
    /// Note: for wireshark, the Frame Cyclic Sequence (FCS) part is not used, and LinkType is 32 bits.
    /// LinkType (16 bits):
    /// A 16-bit unsigned value that defines the link layer type of packets in the file.
    /// This field is defined in the Section 8.1 IANA registry.
    pub linktype: LinkType,
}

impl Default for PcapHeader {
    fn default() -> Self {
        PcapHeader {
            // native order
            magic_number: 0xa1b2c3d4,
            major_version: 2,
            minor_version: 4,
            reserved1: 0,
            reserved2: 0,
            // init value, change when packet recv
            snaplen: 0,
            linktype: LinkType::ETHERNET,
        }
    }
}

//                         1                   2                   3
//     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  0 |                      Timestamp (Seconds)                      |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  4 |            Timestamp (Microseconds or nanoseconds)            |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  8 |                    Captured Packet Length                     |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 12 |                    Original Packet Length                     |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 16 /                                                               /
//    /                          Packet Data                          /
//    /                        variable length                        /
//    /                                                               /
//    +---------------------------------------------------------------+

#[repr(C)]
#[derive(Debug, Clone, Deserialize, Serialize, Encode, Decode)]
pub struct PcapRecord {
    /// Timestamp (Seconds) and Timestamp (Microseconds or nanoseconds):
    /// Seconds and fraction of a seconds values of a timestamp.
    pub ts_sec: u32,
    pub ts_usec: u32,
    /// Captured Packet Length (32 bits):
    /// An unsigned value that indicates the number of octets captured from the packet
    /// (i.e. the length of the Packet Data field).
    pub capt_len: u32,
    /// Original Packet Length (32 bits):
    /// An unsigned value that indicates the actual length of the packet when it was transmitted on the network.
    /// It can be different from the Captured Packet Length if the packet has been truncated by the capture process.
    pub orig_len: u32,
    /// Packet Data:
    /// The data coming from the network, including link-layer headers.
    /// The actual length of this field is Captured Packet Length.
    pub data: Vec<u8>,
}

impl PcapRecord {
    pub fn new(ts_sec: u32, ts_usec: u32, capt_len: u32, orig_len: u32, data: &[u8]) -> PcapRecord {
        PcapRecord {
            ts_sec,
            ts_usec,
            capt_len,
            orig_len,
            data: data.to_vec(),
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Deserialize, Serialize, Encode, Decode)]
pub struct Pcap {
    pub header: PcapHeader,
    pub record: Vec<PcapRecord>,
}

impl Pcap {
    pub fn append(&mut self, record: PcapRecord) {
        if record.data.len() as u32 > self.header.snaplen {
            self.header.snaplen = record.data.len() as u32;
        }
        self.record.push(record);
    }
    pub fn is_bigendian(&self) -> bool {
        if self.header.magic_number == 0xa1b2c3d4 {
            true
        } else {
            false
        }
    }
}

impl Default for Pcap {
    fn default() -> Self {
        Pcap {
            header: PcapHeader::default(),
            record: Vec::new(),
        }
    }
}
