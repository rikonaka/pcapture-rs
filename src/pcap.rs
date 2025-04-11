use bincode::Decode;
use bincode::Encode;
use byteorder::BigEndian;
use byteorder::LittleEndian;
use byteorder::ReadBytesExt;
use byteorder::WriteBytesExt;
use serde::Deserialize;
use serde::Serialize;
use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;
use strum_macros::EnumString;

use crate::DETAULT_WIRESHARK_MAX_LEN;
use crate::error::PcaptureError;

#[derive(Debug, Clone, Copy)]
pub enum PcapByteOrder {
    BigEndian,
    LittleEndian,
    WiresharkDefault, // LittleEndian
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, EnumString, EnumIter, Serialize, Deserialize, Encode, Decode)]
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

impl LinkType {
    pub fn to_u32(self) -> u32 {
        self as u32
    }
    pub fn from_u32(value: u32) -> Option<Self> {
        LinkType::iter().find(|&e| e as u32 == value)
    }
}

// File Header
// from https://www.ietf.org/archive/id/draft-gharris-opsawg-pcap-01.html#name-file-header
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
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct FileHeader {
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
    /// !!! Note: for wireshark, the Frame Cyclic Sequence (FCS) part is not used, and LinkType is 32 bits.
    /// LinkType (16 bits):
    /// A 16-bit unsigned value that defines the link layer type of packets in the file.
    /// This field is defined in the Section 8.1 IANA registry.
    pub linktype: LinkType,
}

impl Default for FileHeader {
    fn default() -> Self {
        FileHeader {
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

impl FileHeader {
    pub fn write(&self, fs: &mut File, pbo: PcapByteOrder) -> Result<(), PcaptureError> {
        match pbo {
            PcapByteOrder::LittleEndian | PcapByteOrder::WiresharkDefault => {
                fs.write_u32::<LittleEndian>(self.magic_number)?;
                fs.write_u16::<LittleEndian>(self.major_version)?;
                fs.write_u16::<LittleEndian>(self.minor_version)?;
                fs.write_u32::<LittleEndian>(self.reserved1)?;
                fs.write_u32::<LittleEndian>(self.reserved2)?;
                fs.write_u32::<LittleEndian>(self.snaplen)?;
                fs.write_u32::<LittleEndian>(self.linktype.to_u32())?;
            }
            PcapByteOrder::BigEndian => {
                fs.write_u32::<BigEndian>(self.magic_number)?;
                fs.write_u16::<BigEndian>(self.major_version)?;
                fs.write_u16::<BigEndian>(self.minor_version)?;
                fs.write_u32::<BigEndian>(self.reserved1)?;
                fs.write_u32::<BigEndian>(self.reserved2)?;
                fs.write_u32::<BigEndian>(self.snaplen)?;
                fs.write_u32::<BigEndian>(self.linktype.to_u32())?;
            }
        }
        Ok(())
    }
    pub fn read(fs: &mut File, pbo: PcapByteOrder) -> Result<FileHeader, PcaptureError> {
        match pbo {
            PcapByteOrder::LittleEndian | PcapByteOrder::WiresharkDefault => {
                let magic_number = fs.read_u32::<LittleEndian>()?;
                let major_version = fs.read_u16::<LittleEndian>()?;
                let minor_version = fs.read_u16::<LittleEndian>()?;
                let reserved1 = fs.read_u32::<LittleEndian>()?;
                let reserved2 = fs.read_u32::<LittleEndian>()?;
                let snaplen = fs.read_u32::<LittleEndian>()?;
                let linktype_value = fs.read_u32::<LittleEndian>()?;
                let linktype = match LinkType::from_u32(linktype_value) {
                    Some(l) => l,
                    None => {
                        return Err(PcaptureError::UnknownLinkType {
                            linktype: linktype_value,
                        });
                    }
                };
                Ok(FileHeader {
                    magic_number,
                    major_version,
                    minor_version,
                    reserved1,
                    reserved2,
                    snaplen,
                    linktype,
                })
            }
            PcapByteOrder::BigEndian => {
                let magic_number = fs.read_u32::<BigEndian>()?;
                let major_version = fs.read_u16::<BigEndian>()?;
                let minor_version = fs.read_u16::<BigEndian>()?;
                let reserved1 = fs.read_u32::<BigEndian>()?;
                let reserved2 = fs.read_u32::<BigEndian>()?;
                let snaplen = fs.read_u32::<BigEndian>()?;
                let linktype_value = fs.read_u32::<BigEndian>()?;
                let linktype = match LinkType::from_u32(linktype_value) {
                    Some(l) => l,
                    None => {
                        return Err(PcaptureError::UnknownLinkType {
                            linktype: linktype_value,
                        });
                    }
                };
                Ok(FileHeader {
                    magic_number,
                    major_version,
                    minor_version,
                    reserved1,
                    reserved2,
                    snaplen,
                    linktype,
                })
            }
        }
    }
}

// Packet Record
// from https://www.ietf.org/archive/id/draft-gharris-opsawg-pcap-01.html#name-packet-record
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
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct PacketRecord {
    /// Timestamp (Seconds) and Timestamp (Microseconds or nanoseconds):
    /// Seconds and fraction of a seconds values of a timestamp.
    pub ts_sec: u32,
    pub ts_usec: u32,
    /// Captured Packet Length (32 bits):
    /// An unsigned value that indicates the number of octets captured from the packet
    /// (i.e. the length of the Packet Data field).
    pub captured_packet_length: u32,
    /// Original Packet Length (32 bits):
    /// An unsigned value that indicates the actual length of the packet when it was transmitted on the network.
    /// It can be different from the Captured Packet Length if the packet has been truncated by the capture process.
    pub original_packet_length: u32,
    /// Packet Data:
    /// The data coming from the network, including link-layer headers.
    /// The actual length of this field is Captured Packet Length.
    pub packet_data: Vec<u8>,
}

impl PacketRecord {
    pub fn new(magic_number: u32, packet_data: &[u8]) -> Result<PacketRecord, PcaptureError> {
        let packet_slice = if packet_data.len() > DETAULT_WIRESHARK_MAX_LEN {
            &packet_data[..DETAULT_WIRESHARK_MAX_LEN]
        } else {
            packet_data
        };
        let dura = SystemTime::now().duration_since(UNIX_EPOCH)?;
        let (ts_sec, ts_usec) = if magic_number == 0xa1b2c3d4 {
            // u32 is pcap file struct defined data type, and in pcapng it will be u64
            let ts_sec = dura.as_secs() as u32;
            let ts_usec = dura.subsec_micros();
            (ts_sec, ts_usec)
        } else {
            let ts_sec = dura.as_secs() as u32;
            let ts_usec = dura.subsec_nanos();
            (ts_sec, ts_usec)
        };
        let captured_packet_length = packet_slice.len() as u32;
        let original_packet_length = packet_data.len() as u32;
        Ok(PacketRecord {
            ts_sec,
            ts_usec,
            captured_packet_length,
            original_packet_length,
            packet_data: packet_data.to_vec(),
        })
    }
    pub fn write(&self, fs: &mut File, pbo: PcapByteOrder) -> Result<(), PcaptureError> {
        match pbo {
            PcapByteOrder::LittleEndian | PcapByteOrder::WiresharkDefault => {
                fs.write_u32::<LittleEndian>(self.ts_sec)?;
                fs.write_u32::<LittleEndian>(self.ts_usec)?;
                fs.write_u32::<LittleEndian>(self.captured_packet_length)?;
                fs.write_u32::<LittleEndian>(self.original_packet_length)?;
                fs.write_all(&self.packet_data)?;
            }
            PcapByteOrder::BigEndian => {
                fs.write_u32::<BigEndian>(self.ts_sec)?;
                fs.write_u32::<BigEndian>(self.ts_usec)?;
                fs.write_u32::<BigEndian>(self.captured_packet_length)?;
                fs.write_u32::<BigEndian>(self.original_packet_length)?;
                fs.write_all(&self.packet_data)?;
            }
        }
        Ok(())
    }
    pub fn read(fs: &mut File, pbo: PcapByteOrder) -> Result<PacketRecord, PcaptureError> {
        let (ts_sec, ts_usec, captured_packet_length, original_packet_length) = match pbo {
            PcapByteOrder::LittleEndian | PcapByteOrder::WiresharkDefault => {
                let ts_sec = fs.read_u32::<LittleEndian>()?;
                let ts_usec = fs.read_u32::<LittleEndian>()?;
                let captured_packet_length = fs.read_u32::<LittleEndian>()?;
                let original_packet_length = fs.read_u32::<LittleEndian>()?;
                (
                    ts_sec,
                    ts_usec,
                    captured_packet_length,
                    original_packet_length,
                )
            }
            PcapByteOrder::BigEndian => {
                let ts_sec = fs.read_u32::<BigEndian>()?;
                let ts_usec = fs.read_u32::<BigEndian>()?;
                let captured_packet_length = fs.read_u32::<BigEndian>()?;
                let original_packet_length = fs.read_u32::<BigEndian>()?;
                (
                    ts_sec,
                    ts_usec,
                    captured_packet_length,
                    original_packet_length,
                )
            }
        };
        let mut data = vec![0u8; captured_packet_length as usize]; // read only capt_len length
        fs.read_exact(&mut data)?;
        Ok(PacketRecord {
            ts_sec,
            ts_usec,
            captured_packet_length,
            original_packet_length,
            packet_data: data,
        })
    }
}

#[repr(C)]
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct Pcap {
    pub header: FileHeader,
    pub records: Vec<PacketRecord>,
}

impl Pcap {
    pub fn append(&mut self, record: PacketRecord) {
        if record.packet_data.len() as u32 > self.header.snaplen {
            self.header.snaplen = record.packet_data.len() as u32;
        }
        self.records.push(record);
    }
    pub fn write_all(&self, path: &str, pbo: PcapByteOrder) -> Result<(), PcaptureError> {
        let mut fs = File::create(path)?;
        self.header.write(&mut fs, pbo)?;
        for r in &self.records {
            r.write(&mut fs, pbo)?;
        }
        Ok(())
    }
    pub fn read_all(path: &str, pbo: PcapByteOrder) -> Result<Pcap, PcaptureError> {
        let mut fs = File::open(path)?;
        let header = FileHeader::read(&mut fs, pbo)?;
        let mut record = Vec::new();
        loop {
            match PacketRecord::read(&mut fs, pbo) {
                Ok(r) => record.push(r),
                Err(_) => break,
            }
        }
        Ok(Pcap {
            header,
            records: record,
        })
    }
}

impl Default for Pcap {
    fn default() -> Self {
        Pcap {
            header: FileHeader::default(),
            records: Vec::new(),
        }
    }
}
