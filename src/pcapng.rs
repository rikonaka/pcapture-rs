use byteorder::BigEndian;
use byteorder::LittleEndian;
use byteorder::ReadBytesExt;
use byteorder::WriteBytesExt;
/// Pcapng is a very large protocol, here I only implement some structures necessary to save it for pcapng.
use pnet::datalink::NetworkInterface;
use pnet::ipnetwork::IpNetwork;
use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::process::Command;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;
use strum_macros::EnumString;
use subnetwork::SubnetworkNetmask;

use crate::PcapByteOrder;
use crate::PcaptureError;

const SIMPLE_PACKET_BLOCK_FIX_LENGTH: usize = 16;
const ENHANCED_PACKET_BLOCK_FIX_LENGTH: usize = 32;

#[repr(u16)]
#[derive(Debug, Clone, Copy, EnumString, EnumIter)]
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
    pub fn to_u16(self) -> u16 {
        self as u16
    }
    pub fn from_u16(value: u16) -> Option<Self> {
        LinkType::iter().find(|&e| e as u16 == value)
    }
}

//                      1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |      Option Code              |         Option Length         |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// /                       Option Value                            /
// /              variable length, padded to 32 bits               /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// /                                                               /
// /                 . . . other options . . .                     /
// /                                                               /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |   Option Code == opt_endofopt |   Option Length == 0          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#[derive(Debug, Clone)]
pub struct GeneralOption {
    // opt_comment = 1
    pub option_code: u16,
    pub option_length: u16,
    pub option_value: Vec<u8>,
}

impl GeneralOption {
    pub fn new(option_code: u16, option_value: &[u8]) -> GeneralOption {
        GeneralOption {
            option_code,
            option_length: option_value.len() as u16,
            option_value: padding_to_32(option_value),
        }
    }
    pub fn new_tail() -> GeneralOption {
        GeneralOption {
            // opt_endofopt = 0
            option_code: 0,
            option_length: 0,
            option_value: Vec::new(),
        }
    }
    pub fn write(&mut self, fs: &mut File, pbo: PcapByteOrder) -> Result<(), PcaptureError> {
        match pbo {
            PcapByteOrder::LittleEndian | PcapByteOrder::WiresharkDefault => {
                fs.write_u16::<LittleEndian>(self.option_code)?;
                fs.write_u16::<LittleEndian>(self.option_length)?;
                fs.write_all(&self.option_value)?;
            }
            PcapByteOrder::BigEndian => {
                fs.write_u16::<BigEndian>(self.option_code)?;
                fs.write_u16::<BigEndian>(self.option_length)?;
                fs.write_all(&self.option_value)?;
            }
        }
        Ok(())
    }
    pub fn read(fs: &mut File, pbo: PcapByteOrder) -> Result<GeneralOption, PcaptureError> {
        let (option_code, option_length) = match pbo {
            PcapByteOrder::LittleEndian | PcapByteOrder::WiresharkDefault => {
                let option_code = fs.read_u16::<LittleEndian>()?;
                let option_length = fs.read_u16::<LittleEndian>()?;
                (option_code, option_length)
            }
            PcapByteOrder::BigEndian => {
                let option_code = fs.read_u16::<BigEndian>()?;
                let option_length = fs.read_u16::<BigEndian>()?;
                (option_code, option_length)
            }
        };
        let padding_size = if option_length % 4 == 0 {
            0
        } else {
            4 - (option_length % 4)
        };
        let mut option_value = vec![0u8; (option_length + padding_size) as usize];
        fs.read_exact(&mut option_value)?;
        Ok(GeneralOption {
            option_code,
            option_length,
            option_value,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Options {
    options: Vec<GeneralOption>,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            options: Vec::new(),
        }
    }
}

impl Options {
    pub fn write(&mut self, fs: &mut File, pbo: PcapByteOrder) -> Result<(), PcaptureError> {
        for op in &mut self.options {
            op.write(fs, pbo)?;
        }
        Ok(())
    }
    pub fn read(fs: &mut File, pbo: PcapByteOrder) -> Result<Options, PcaptureError> {
        let mut options = Vec::new();
        loop {
            match GeneralOption::read(fs, pbo) {
                Ok(r) => {
                    let r_clone = r.clone();
                    options.push(r_clone);
                    if r.option_code == 0 {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        Ok(Options { options })
    }
}

// Section Header Block
// from https://www.ietf.org/archive/id/draft-tuexen-opsawg-pcapng-03.html#section_shb
//                         1                   2                   3
//     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  0 |                   Block Type = 0x0A0D0D0A                     |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  4 |                      Block Total Length                       |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  8 |                      Byte-Order Magic                         |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 12 |          Major Version        |         Minor Version         |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 16 |                                                               |
//    |                          Section Length                       |
//    |                                                               |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 24 /                                                               /
//    /                      Options (variable)                       /
//    /                                                               /
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |                      Block Total Length                       |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#[derive(Debug, Clone)]
pub struct SectionHeaderBlock {
    /// Block Type:
    /// The block type of the Section Header Block is the integer corresponding to the 4-char string "\n\r\r\n" (0x0A0D0D0A).
    pub block_type: u32,
    /// Block Total Length: total size of this block.
    pub block_total_length: u32,
    /// Byte-Order Magic (32 bits):
    /// An unsigned magic number, whose value is the hexadecimal number 0x1A2B3C4D.
    /// This number can be used to distinguish sections that have been saved on little-endian machines from the ones saved on big-endian machines, and to heuristically identify pcapng files.
    pub byte_order_magic: u32,
    /// Major Version (16 bits):
    /// An unsigned value, giving the number of the current major version of the format.
    /// The value for the current version of the format is 1.
    pub major_version: u16,
    /// Minor Version (16 bits):
    /// An unsigned value, giving the number of the current minor version of the format.
    /// The value for the current version of the format is 0.
    pub minor_version: u16,
    /// Section Length (64 bits):
    /// A signed value specifying the length in octets of the following section, excluding the Section Header Block itself.
    /// This field can be used to skip the section, for faster navigation inside large files.
    /// If the Section Length is -1 (0xFFFFFFFFFFFFFFFF), this means that the size of the section is not specified, and the only way to skip the section is to parse the blocks that it contains.
    /// Please note that if this field is valid (i.e. not negative), its value is always a multiple of 4, as all the blocks are aligned to and padded to 32-bit (4 octet) boundaries.
    /// Also, special care should be taken in accessing this field: since the alignment of all the blocks in the file is 32-bits, this field is not guaranteed to be aligned to a 64-bit boundary.
    /// This could be a problem on 64-bit processors.
    pub section_length: u32,
    /// Options:
    /// Optionally, a list of options (formatted according to the rules defined in Section 3.5) can be present.
    pub options: Options,
    pub block_total_length_2: u32,
}

fn padding_to_32(input: &[u8]) -> Vec<u8> {
    let mut ret = input.to_vec();
    while ret.len() % 4 != 0 {
        ret.push(0);
    }
    ret
}

impl Default for SectionHeaderBlock {
    fn default() -> Self {
        let sysinfo = SysInfo::init();
        // hardware
        let cpu_model_name = match sysinfo.cpu_model_name() {
            Ok(c) => c,
            Err(_) => String::from("get cpu model name error"), // ignore all error here
        };
        let hardware_option = GeneralOption::new(2, cpu_model_name.as_bytes());
        // os
        let system_name = match sysinfo.system_name() {
            Ok(c) => c,
            Err(_) => String::from("get system name failed"),
        };
        let os_option = GeneralOption::new(3, system_name.as_bytes());
        // name
        let app_name = String::from("pcapture-rs");
        let app_option = GeneralOption::new(4, app_name.as_bytes());
        // tail
        let tail_option = GeneralOption::new_tail();

        let options = Options {
            options: vec![hardware_option, os_option, app_option, tail_option],
        };
        SectionHeaderBlock {
            block_type: 0x0a0d0d0a,
            block_total_length: 0,
            byte_order_magic: 0x1a2b3c4d,
            major_version: 1,
            minor_version: 0,
            section_length: 0,
            options,
            block_total_length_2: 0,
        }
    }
}

impl SectionHeaderBlock {
    pub fn write(&mut self, fs: &mut File, pbo: PcapByteOrder) -> Result<(), PcaptureError> {
        match pbo {
            PcapByteOrder::LittleEndian | PcapByteOrder::WiresharkDefault => {
                fs.write_u32::<LittleEndian>(self.block_type)?;
                fs.write_u32::<LittleEndian>(self.block_total_length)?;
                fs.write_u32::<LittleEndian>(self.byte_order_magic)?;
                fs.write_u16::<LittleEndian>(self.major_version)?;
                fs.write_u16::<LittleEndian>(self.minor_version)?;
                fs.write_u32::<LittleEndian>(self.section_length)?;
                self.options.write(fs, pbo)?;
                fs.write_u32::<LittleEndian>(self.block_total_length_2)?;
            }
            PcapByteOrder::BigEndian => {
                fs.write_u32::<BigEndian>(self.block_type)?;
                fs.write_u32::<BigEndian>(self.block_total_length)?;
                fs.write_u32::<BigEndian>(self.byte_order_magic)?;
                fs.write_u16::<BigEndian>(self.major_version)?;
                fs.write_u16::<BigEndian>(self.minor_version)?;
                fs.write_u32::<BigEndian>(self.section_length)?;
                self.options.write(fs, pbo)?;
                fs.write_u32::<BigEndian>(self.block_total_length_2)?;
            }
        }
        Ok(())
    }
    pub fn read(fs: &mut File, pbo: PcapByteOrder) -> Result<SectionHeaderBlock, PcaptureError> {
        match pbo {
            PcapByteOrder::LittleEndian | PcapByteOrder::WiresharkDefault => {
                let block_type = fs.read_u32::<LittleEndian>()?;
                let block_total_length = fs.read_u32::<LittleEndian>()?;
                let byte_order_magic = fs.read_u32::<LittleEndian>()?;
                let major_version = fs.read_u16::<LittleEndian>()?;
                let minor_version = fs.read_u16::<LittleEndian>()?;
                let section_length = fs.read_u32::<LittleEndian>()?;
                let options = Options::read(fs, pbo)?;
                let block_total_length_2 = fs.read_u32::<LittleEndian>()?;
                Ok(SectionHeaderBlock {
                    block_type,
                    block_total_length,
                    byte_order_magic,
                    major_version,
                    minor_version,
                    section_length,
                    options,
                    block_total_length_2,
                })
            }
            PcapByteOrder::BigEndian => {
                let block_type = fs.read_u32::<BigEndian>()?;
                let block_total_length = fs.read_u32::<BigEndian>()?;
                let byte_order_magic = fs.read_u32::<BigEndian>()?;
                let major_version = fs.read_u16::<BigEndian>()?;
                let minor_version = fs.read_u16::<BigEndian>()?;
                let section_length = fs.read_u32::<BigEndian>()?;
                let options = Options::read(fs, pbo)?;
                let block_total_length_2 = fs.read_u32::<BigEndian>()?;
                Ok(SectionHeaderBlock {
                    block_type,
                    block_total_length,
                    byte_order_magic,
                    major_version,
                    minor_version,
                    section_length,
                    options,
                    block_total_length_2,
                })
            }
        }
    }
}

// Interface Description Block
// from https://www.ietf.org/archive/id/draft-tuexen-opsawg-pcapng-03.html#name-interface-description-block
//                        1                   2                   3
//     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  0 |                    Block Type = 0x00000001                    |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  4 |                      Block Total Length                       |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  8 |           LinkType            |           Reserved            |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 12 |                            SnapLen                            |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 16 /                                                               /
//    /                      Options (variable)                       /
//    /                                                               /
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |                      Block Total Length                       |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#[derive(Debug, Clone)]
pub struct InterfaceDescriptionBlock {
    /// Block Type:
    /// The block type of the Interface Description Block is 1.
    pub block_type: u32,
    /// Block Total Length: Total size of this block.
    pub block_total_length: u32,
    /// LinkType (16 bits):
    /// An unsigned value that defines the link layer type of this interface.
    pub linktype: LinkType,
    /// Reserved (16 bits): not used.
    reserved: u16,
    /// SnapLen (32 bits):
    /// An unsigned value indicating the maximum number of octets captured from each packet.
    /// The portion of each packet that exceeds this value will not be stored in the file.
    /// A value of zero indicates no limit.
    pub snaplen: u32,
    /// Options:
    /// Optionally, a list of option.
    pub options: Options,
    pub block_total_length_2: u32,
}

impl InterfaceDescriptionBlock {
    pub fn init(interface: NetworkInterface) -> Result<InterfaceDescriptionBlock, PcaptureError> {
        let mut general_option = Vec::new();
        // if_name
        let if_name = interface.name;
        let if_name_option = GeneralOption::new(2, if_name.as_bytes());
        general_option.push(if_name_option);
        // if_description
        let if_description = interface.description;
        let if_description_option = GeneralOption::new(3, if_description.as_bytes());
        general_option.push(if_description_option);
        // if_IPv4addr
        for ip in interface.ips {
            let op = match ip {
                IpNetwork::V4(ipv4) => {
                    // Examples: '192 168 1 1 255 255 255 0'
                    let netmask = SubnetworkNetmask::new(ipv4.prefix());
                    let netmask_ipv4 = netmask.to_ipv4()?;
                    let ip = ipv4.ip();
                    let mut data = ip.octets().to_vec();
                    data.extend_from_slice(&netmask_ipv4.octets());
                    let if_ipv4addr_option = GeneralOption::new(4, &data);
                    if_ipv4addr_option
                }
                IpNetwork::V6(ipv6) => {
                    // Example: 2001:0db8:85a3:08d3:1319:8a2e:0370:7344/64 is written (in hex) as '20 01 0d b8 85 a3 08 d3 13 19 8a 2e 03 70 73 44 40'
                    let ip = ipv6.ip();
                    let mut data = ip.octets().to_vec();
                    data.push(ipv6.prefix());
                    let if_ipv4addr_option = GeneralOption::new(5, &data);
                    if_ipv4addr_option
                }
            };
            general_option.push(op);
        }
        // if_MACaddr
        match interface.mac {
            Some(mac) => {
                // Example: '00 01 02 03 04 05'
                let if_macaddr_option = GeneralOption::new(6, &mac.octets());
                general_option.push(if_macaddr_option);
            }
            None => (),
        }
        // if_EUIaddr same as if_MACaddr and ignore
        // if_speed ignore
        // if_tsresol ignroe
        // if_tzone ignore
        // if_filter ignore
        // if_os ignore
        // if_fcslen ignore
        // if_tsoffset ignore
        // if_hardware ignore
        // if_txspeed ignore
        // if_rxspeed ignore

        let options = Options::default();
        Ok(InterfaceDescriptionBlock {
            block_type: 1,
            block_total_length: 0,
            linktype: LinkType::ETHERNET,
            reserved: 0,
            snaplen: 0,
            options,
            block_total_length_2: 0,
        })
    }
    pub fn write(&mut self, fs: &mut File, pbo: PcapByteOrder) -> Result<(), PcaptureError> {
        match pbo {
            PcapByteOrder::LittleEndian | PcapByteOrder::WiresharkDefault => {
                fs.write_u32::<LittleEndian>(self.block_type)?;
                fs.write_u32::<LittleEndian>(self.block_total_length)?;
                let linktype = self.linktype.to_u16();
                fs.write_u16::<LittleEndian>(linktype)?;
                fs.write_u16::<LittleEndian>(self.reserved)?;
                fs.write_u32::<LittleEndian>(self.snaplen)?;
                self.options.write(fs, pbo)?;
                fs.write_u32::<LittleEndian>(self.block_total_length_2)?;
            }
            PcapByteOrder::BigEndian => {
                fs.write_u32::<BigEndian>(self.block_type)?;
                fs.write_u32::<BigEndian>(self.block_total_length)?;
                let linktype = self.linktype.to_u16();
                fs.write_u16::<BigEndian>(linktype)?;
                fs.write_u16::<BigEndian>(self.reserved)?;
                fs.write_u32::<BigEndian>(self.snaplen)?;
                self.options.write(fs, pbo)?;
                fs.write_u32::<BigEndian>(self.block_total_length_2)?;
            }
        }
        Ok(())
    }
    pub fn read(
        fs: &mut File,
        pbo: PcapByteOrder,
    ) -> Result<InterfaceDescriptionBlock, PcaptureError> {
        match pbo {
            PcapByteOrder::LittleEndian | PcapByteOrder::WiresharkDefault => {
                let block_type = fs.read_u32::<LittleEndian>()?;
                let block_total_length = fs.read_u32::<LittleEndian>()?;
                let value = fs.read_u16::<LittleEndian>()?;
                let linktype = match LinkType::from_u16(value) {
                    Some(l) => l,
                    None => {
                        return Err(PcaptureError::UnknownLinkType {
                            linktype: value as u32,
                        });
                    }
                };
                let reserved = fs.read_u16::<LittleEndian>()?;
                let snaplen = fs.read_u32::<LittleEndian>()?;
                let options = Options::read(fs, pbo)?;
                let block_total_length_2 = fs.read_u32::<LittleEndian>()?;
                Ok(InterfaceDescriptionBlock {
                    block_type,
                    block_total_length,
                    linktype,
                    reserved,
                    snaplen,
                    options,
                    block_total_length_2,
                })
            }
            PcapByteOrder::BigEndian => {
                let block_type = fs.read_u32::<BigEndian>()?;
                let block_total_length = fs.read_u32::<BigEndian>()?;
                let value = fs.read_u16::<BigEndian>()?;
                let linktype = match LinkType::from_u16(value) {
                    Some(l) => l,
                    None => {
                        return Err(PcaptureError::UnknownLinkType {
                            linktype: value as u32,
                        });
                    }
                };
                let reserved = fs.read_u16::<BigEndian>()?;
                let snaplen = fs.read_u32::<BigEndian>()?;
                let options = Options::read(fs, pbo)?;
                let block_total_length_2 = fs.read_u32::<BigEndian>()?;
                Ok(InterfaceDescriptionBlock {
                    block_type,
                    block_total_length,
                    linktype,
                    reserved,
                    snaplen,
                    options,
                    block_total_length_2,
                })
            }
        }
    }
}

// Enhanced Packet Block
// from https://www.ietf.org/archive/id/draft-tuexen-opsawg-pcapng-03.html#name-enhanced-packet-block
//                         1                   2                   3
//     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  0 |                    Block Type = 0x00000006                    |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  4 |                      Block Total Length                       |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  8 |                         Interface ID                          |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 12 |                        Timestamp (High)                       |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 16 |                        Timestamp (Low)                        |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 20 |                    Captured Packet Length                     |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 24 |                    Original Packet Length                     |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 28 /                                                               /
//    /                          Packet Data                          /
//    /              variable length, padded to 32 bits               /
//    /                                                               /
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    /                                                               /
//    /                      Options (variable)                       /
//    /                                                               /
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |                      Block Total Length                       |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#[derive(Debug, Clone)]
pub struct EnhancedPacketBlock {
    /// Block Type: The block type of the Enhanced Packet Block is 6.
    pub block_type: u32,
    /// Block Total Length: total size of this block.
    pub block_total_length: u32,
    /// Interface ID (32 bits):
    /// An unsigned value that specifies the interface on which this packet was received or transmitted;
    /// The correct interface will be the one whose Interface Description Block is identified by the same number of this field.
    pub interface_id: u32,
    /// Timestamp (High) and Timestamp (Low):
    /// Upper 32 bits and lower 32 bits of a 64-bit timestamp.
    pub ts_high: u32,
    pub ts_low: u32,
    /// Captured Packet Length (32 bits):
    /// An unsigned value that indicates the number of octets captured from the packet (i.e. the length of the Packet Data field).
    pub captured_packet_length: u32,
    /// Original Packet Length (32 bits):
    /// An unsigned value that indicates the actual length of the packet when it was transmitted on the network.
    pub original_packet_length: u32,
    /// Packet Data: the data coming from the network, including link-layer headers.
    pub packet_data: Vec<u8>,
    /// Options: optionally, a list of options.
    pub options: Options,
    pub block_total_length_2: u32,
}

impl EnhancedPacketBlock {
    pub fn write(&mut self, fs: &mut File, pbo: PcapByteOrder) -> Result<(), PcaptureError> {
        match pbo {
            PcapByteOrder::LittleEndian | PcapByteOrder::WiresharkDefault => {
                fs.write_u32::<LittleEndian>(self.block_type)?;
                fs.write_u32::<LittleEndian>(self.block_total_length)?;
                fs.write_u32::<LittleEndian>(self.interface_id)?;
                fs.write_u32::<LittleEndian>(self.ts_high)?;
                fs.write_u32::<LittleEndian>(self.ts_low)?;
                fs.write_u32::<LittleEndian>(self.captured_packet_length)?;
                fs.write_u32::<LittleEndian>(self.original_packet_length)?;
                fs.write_all(&self.packet_data)?;
                self.options.write(fs, pbo)?;
                fs.write_u32::<LittleEndian>(self.block_total_length_2)?;
            }
            PcapByteOrder::BigEndian => {
                fs.write_u32::<BigEndian>(self.block_type)?;
                fs.write_u32::<BigEndian>(self.block_total_length)?;
                fs.write_u32::<BigEndian>(self.interface_id)?;
                fs.write_u32::<BigEndian>(self.ts_high)?;
                fs.write_u32::<BigEndian>(self.ts_low)?;
                fs.write_u32::<BigEndian>(self.captured_packet_length)?;
                fs.write_u32::<BigEndian>(self.original_packet_length)?;
                fs.write_all(&self.packet_data)?;
                self.options.write(fs, pbo)?;
                fs.write_u32::<BigEndian>(self.block_total_length_2)?;
            }
        }
        Ok(())
    }
    pub fn read(fs: &mut File, pbo: PcapByteOrder) -> Result<EnhancedPacketBlock, PcaptureError> {
        match pbo {
            PcapByteOrder::LittleEndian | PcapByteOrder::WiresharkDefault => {
                let block_type = fs.read_u32::<LittleEndian>()?;
                let block_total_length = fs.read_u32::<LittleEndian>()?;
                let interface_id = fs.read_u32::<LittleEndian>()?;
                let ts_high = fs.read_u32::<LittleEndian>()?;
                let ts_low = fs.read_u32::<LittleEndian>()?;
                let captured_packet_length = fs.read_u32::<LittleEndian>()?;
                let original_packet_length = fs.read_u32::<LittleEndian>()?;
                let padding_size = if captured_packet_length % 4 == 0 {
                    0
                } else {
                    4 - (captured_packet_length % 4)
                };
                let mut packet_data = vec![0u8; (captured_packet_length + padding_size) as usize];
                fs.read_exact(&mut packet_data)?;
                let options = Options::read(fs, pbo)?;
                let block_total_length_2 = fs.read_u32::<LittleEndian>()?;
                Ok(EnhancedPacketBlock {
                    block_type,
                    block_total_length,
                    interface_id,
                    ts_high,
                    ts_low,
                    captured_packet_length,
                    original_packet_length,
                    packet_data,
                    options,
                    block_total_length_2,
                })
            }
            PcapByteOrder::BigEndian => {
                let block_type = fs.read_u32::<BigEndian>()?;
                let block_total_length = fs.read_u32::<BigEndian>()?;
                let interface_id = fs.read_u32::<BigEndian>()?;
                let ts_high = fs.read_u32::<BigEndian>()?;
                let ts_low = fs.read_u32::<BigEndian>()?;
                let captured_packet_length = fs.read_u32::<BigEndian>()?;
                let original_packet_length = fs.read_u32::<BigEndian>()?;
                let padding_size = if captured_packet_length % 4 == 0 {
                    0
                } else {
                    4 - (captured_packet_length % 4)
                };
                let mut packet_data = vec![0u8; (captured_packet_length + padding_size) as usize];
                fs.read_exact(&mut packet_data)?;
                let options = Options::read(fs, pbo)?;
                let block_total_length_2 = fs.read_u32::<BigEndian>()?;
                Ok(EnhancedPacketBlock {
                    block_type,
                    block_total_length,
                    interface_id,
                    ts_high,
                    ts_low,
                    captured_packet_length,
                    original_packet_length,
                    packet_data,
                    options,
                    block_total_length_2,
                })
            }
        }
    }
}

// Simple Packet Block
// from https://www.ietf.org/archive/id/draft-tuexen-opsawg-pcapng-03.html#name-simple-packet-block
//                         1                   2                   3
//     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  0 |                    Block Type = 0x00000003                    |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  4 |                      Block Total Length                       |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  8 |                    Original Packet Length                     |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 12 /                                                               /
//    /                          Packet Data                          /
//    /              variable length, padded to 32 bits               /
//    /                                                               /
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |                      Block Total Length                       |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#[derive(Debug, Clone)]
pub struct SimplePacketBlock {
    pub block_type: u32,
    pub block_total_length: u32,
    pub original_packet_length: u32,
    pub packet_data: Vec<u8>,
    pub block_total_length_2: u32,
}

impl SimplePacketBlock {
    pub fn write(&mut self, fs: &mut File, pbo: PcapByteOrder) -> Result<(), PcaptureError> {
        match pbo {
            PcapByteOrder::LittleEndian | PcapByteOrder::WiresharkDefault => {
                fs.write_u32::<LittleEndian>(self.block_type)?;
                fs.write_u32::<LittleEndian>(self.block_total_length)?;
                fs.write_u32::<LittleEndian>(self.original_packet_length)?;
                fs.write_all(&self.packet_data)?;
                fs.write_u32::<LittleEndian>(self.block_total_length_2)?;
            }
            PcapByteOrder::BigEndian => {
                fs.write_u32::<BigEndian>(self.block_type)?;
                fs.write_u32::<BigEndian>(self.block_total_length)?;
                fs.write_u32::<BigEndian>(self.original_packet_length)?;
                fs.write_all(&self.packet_data)?;
                fs.write_u32::<BigEndian>(self.block_total_length_2)?;
            }
        }
        Ok(())
    }
    pub fn read(fs: &mut File, pbo: PcapByteOrder) -> Result<SimplePacketBlock, PcaptureError> {
        match pbo {
            PcapByteOrder::LittleEndian | PcapByteOrder::WiresharkDefault => {
                let block_type = fs.read_u32::<LittleEndian>()?;
                let block_total_length = fs.read_u32::<LittleEndian>()?;
                let original_packet_length = fs.read_u32::<LittleEndian>()?;
                let packet_data_len = block_total_length - 16;
                let mut packet_data = vec![0u8; (original_packet_length + padding_size) as usize];
                fs.read_exact(&mut packet_data)?;
                let block_total_length_2 = fs.read_u32::<LittleEndian>()?;
                Ok(SimplePacketBlock {
                    block_type,
                    block_total_length,
                    original_packet_length,
                    packet_data,
                    block_total_length_2,
                })
            }
            PcapByteOrder::BigEndian => {
                let block_type = fs.read_u32::<BigEndian>()?;
                let block_total_length = fs.read_u32::<BigEndian>()?;
                let interface_id = fs.read_u32::<BigEndian>()?;
                let ts_high = fs.read_u32::<BigEndian>()?;
                let ts_low = fs.read_u32::<BigEndian>()?;
                let captured_packet_length = fs.read_u32::<BigEndian>()?;
                let original_packet_length = fs.read_u32::<BigEndian>()?;
                let padding_size = if captured_packet_length % 4 == 0 {
                    0
                } else {
                    4 - (captured_packet_length % 4)
                };
                let mut packet_data = vec![0u8; (captured_packet_length + padding_size) as usize];
                fs.read_exact(&mut packet_data)?;
                let options = Options::read(fs, pbo)?;
                let block_total_length_2 = fs.read_u32::<BigEndian>()?;
                Ok(EnhancedPacketBlock {
                    block_type,
                    block_total_length,
                    interface_id,
                    ts_high,
                    ts_low,
                    captured_packet_length,
                    original_packet_length,
                    packet_data,
                    options,
                    block_total_length_2,
                })
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum GeneralBlockStructure {
    EnhancedPacketBlock(EnhancedPacketBlock),
    SimplePacketBlock(SimplePacketBlock),
}

#[derive(Debug, Clone)]
pub struct PcapNg {
    pub shb: SectionHeaderBlock,
    pub idb: InterfaceDescriptionBlock,
    pub flow: Vec<GeneralBlockStructure>,
}

impl PcapNg {
    pub fn init(interface: NetworkInterface) -> Result<PcapNg, PcaptureError> {
        Ok(PcapNg {
            shb: SectionHeaderBlock::default(),
            idb: InterfaceDescriptionBlock::init(interface)?,
            flow: Vec::new(),
        })
    }
    pub fn append(&mut self, block: GeneralBlockStructure) {
        self.flow.push(block);
    }
    pub fn write_all(&mut self, path: &str, pbo: PcapByteOrder) -> Result<(), PcaptureError> {
        let mut fs = File::create(path)?;
        self.shb.write(&mut fs, pbo)?;
        self.idb.write(&mut fs, pbo)?;
        for fl in &self.flow {
            fl.write(&mut fs, pbo)?;
        }
        Ok(())
    }
    pub fn read_all(path: &str, pbo: PcapByteOrder) -> Result<PcapNg, PcaptureError> {}
}

pub struct SysInfo {}

impl SysInfo {
    pub fn init() -> SysInfo {
        SysInfo {}
    }
    #[cfg(target_os = "linux")]
    pub fn cpu_model_name(&self) -> Result<String, PcaptureError> {
        let output = Command::new("cat").arg("/proc/cpuinfo").output()?;
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let lines: Vec<&str> = stdout.lines().map(|x| x.trim()).collect();
            for line in lines {
                if line.starts_with("model name") {
                    let line_split: Vec<&str> = line.split(":").map(|x| x.trim()).collect();
                    if line_split.len() == 2 {
                        let cpu_model_name = line_split[1];
                        return Ok(cpu_model_name.to_string());
                    }
                }
            }
        }
        Err(PcaptureError::GetSystemInfoError)
    }
    #[cfg(target_os = "windows")]
    pub fn cpu_model_name(&self) -> Result<String, PcaptureError> {
        let output = Command::new("wmic").args(["cpu", "get", "name"]).output()?;
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let lines: Vec<&str> = stdout.lines().map(|x| x.trim()).collect();
            if lines.len() >= 2 {
                let cpu_model_name = lines[1].to_string();
                return Ok(cpu_model_name);
            }
        }
        Err(PcaptureError::GetSystemInfoError)
    }
    #[cfg(target_os = "macos")]
    pub fn cpu_model_name(&self) -> Result<String, PcaptureError> {
        // cause I can not affords any expansive mac deivce...
        Ok(String::from("fake mac cpu model name"))
    }
    #[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd",))]
    pub fn cpu_model_name(&self) -> Result<String, PcaptureError> {
        let output = Command::new("sysctl").args(["-n", "hw.model"]).output()?;
        if output.status.success() {
            let cpu_model_name = String::from_utf8_lossy(&output.stdout);
            return Ok(cpu_model_name.to_string());
        }
        Err(PcaptureError::GetSystemInfoError)
    }
    #[cfg(any(
        target_os = "linux",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    ))]
    pub fn system_name(&self) -> Result<String, PcaptureError> {
        // bsd and linux use the same codes here
        let output = Command::new("uname").arg("-srv").output()?;
        if output.status.success() {
            let system_name = String::from_utf8_lossy(&output.stdout);
            return Ok(system_name.to_string());
        }
        Err(PcaptureError::GetSystemInfoError)
    }
    #[cfg(target_os = "windows")]
    pub fn system_name(&self) -> Result<String, PcaptureError> {
        let output = Command::new("wmic")
            .args(["os", "get", "Caption"])
            .output()?;
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let lines: Vec<&str> = stdout.lines().map(|x| x.trim()).collect();
            if lines.len() >= 2 {
                let system_name = lines[1];
                return Ok(system_name.to_string());
            }
        }
        Err(PcaptureError::GetSystemInfoError)
    }
    #[cfg(target_os = "macos")]
    pub fn system_name(&self) -> Result<String, PcaptureError> {
        // cause I can not affords any expansive mac deivce...
        Ok(String::from("fake mac system name"))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_sys_info() {
        let sys_info = SysInfo::init();
        let cpu_model_name = sys_info.cpu_model_name().unwrap();
        println!("model name: {}", cpu_model_name);
        let name = sys_info.system_name().unwrap();
        println!("model name: {}", name);
    }
}
