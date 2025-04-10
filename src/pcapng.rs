/// Pcapng is a very large protocol,
/// here I only implement some structures necessary to save it for pcapng.
use byteorder::BigEndian;
use byteorder::LittleEndian;
use byteorder::ReadBytesExt;
use byteorder::WriteBytesExt;
use pnet::datalink::NetworkInterface;
use pnet::ipnetwork::IpNetwork;
use std::fs::File;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;
use std::ops::Add;
use std::ops::Rem;
use std::ops::Sub;
use std::process::Command;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;
use strum_macros::EnumString;
use subnetwork::SubnetworkNetmask;

use crate::DETAULT_WIRESHARK_MAX_LEN;
use crate::PcapByteOrder;
use crate::PcaptureError;

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

#[repr(C)]
#[derive(Debug, Clone)]
pub struct GeneralOption {
    /// Option Type (16 bits):
    /// An unsigned value that contains the code that specifies the type of the current TLV record.
    pub option_code: u16,
    /// Option Length (16 bits):
    /// An unsigned value that contains the actual length of the following 'Option Value' field without the padding octets.
    pub option_length: u16,
    /// Option Value (variable length): The value of the given option, padded to a 32-bit boundary.
    pub option_value: Vec<u8>,
}

impl GeneralOption {
    pub fn new(option_code: u16, option_value: &[u8]) -> GeneralOption {
        GeneralOption {
            option_code,
            option_length: option_value.len() as u16,
            option_value: Utils::padding_to_32(option_value),
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
        let padding_size = Utils::calc_after_padding_size(option_length);
        let mut option_value = vec![0u8; padding_size as usize];
        fs.read_exact(&mut option_value)?;
        Ok(GeneralOption {
            option_code,
            option_length,
            option_value,
        })
    }
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct Options {
    pub options: Vec<GeneralOption>,
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
                    if r.option_code == 0 && r.option_length == 0 {
                        break;
                    }
                }
                Err(e) => return Err(e),
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

#[repr(C)]
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
        let mut shb = SectionHeaderBlock {
            block_type: 0x0a0d0d0a,
            block_total_length: 0,
            byte_order_magic: 0x1a2b3c4d,
            major_version: 1,
            minor_version: 0,
            section_length: 0,
            options,
            block_total_length_2: 0,
        };
        let shb_len = size_of_val(&shb) as u32;
        shb.block_total_length = shb_len;
        shb.block_total_length_2 = shb_len;
        shb
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

                let next_u32 = Utils::get_next_u32(fs, pbo)?;
                let options = if next_u32 == block_total_length {
                    // no options
                    Options::default()
                } else {
                    Options::read(fs, pbo)?
                };

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

                let next_u32 = Utils::get_next_u32(fs, pbo)?;
                let options = if next_u32 == block_total_length {
                    // no options
                    Options::default()
                } else {
                    Options::read(fs, pbo)?
                };

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

#[repr(C)]
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
    pub fn new(interface: NetworkInterface) -> Result<InterfaceDescriptionBlock, PcaptureError> {
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

        // use a tail to end the option struct
        general_option.push(GeneralOption::new_tail());
        let options = Options {
            options: general_option,
        };

        let mut idb = InterfaceDescriptionBlock {
            block_type: 0x01,
            block_total_length: 0,
            linktype: LinkType::ETHERNET,
            reserved: 0,
            snaplen: 0,
            options,
            block_total_length_2: 0,
        };
        let idb_len = size_of_val(&idb) as u32;
        idb.block_total_length = idb_len;
        idb.block_total_length_2 = idb_len;
        Ok(idb)
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

                let next_u32 = Utils::get_next_u32(fs, pbo)?;
                let options = if next_u32 == block_total_length {
                    // no options
                    Options::default()
                } else {
                    Options::read(fs, pbo)?
                };

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

                let next_u32 = Utils::get_next_u32(fs, pbo)?;
                let options = if next_u32 == block_total_length {
                    // no options
                    Options::default()
                } else {
                    Options::read(fs, pbo)?
                };

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

#[repr(C)]
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
    pub fn new(
        interface_id: u32,
        packet_data: &[u8],
    ) -> Result<EnhancedPacketBlock, PcaptureError> {
        let timestamp = PacketTimestamp::get()?;
        let pds = PacketData::parse(packet_data);
        let mut epb = EnhancedPacketBlock {
            block_type: 0x06,
            block_total_length: 0,
            interface_id,
            ts_high: timestamp.ts_high,
            ts_low: timestamp.ts_low,
            captured_packet_length: pds.captured_packet_length,
            original_packet_length: pds.original_packet_length,
            packet_data: pds.packet_data_slice,
            options: Options::default(),
            block_total_length_2: 0,
        };
        let epb_len = size_of_val(&epb) as u32;
        epb.block_total_length = epb_len;
        epb.block_total_length_2 = epb_len;
        Ok(epb)
    }
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

                // due to there has two uncertain value (packet data length and options length)
                let packet_data_len = Utils::calc_after_padding_size(captured_packet_length);
                let mut packet_data = vec![0u8; packet_data_len as usize];
                fs.read_exact(&mut packet_data)?;

                let next_u32 = Utils::get_next_u32(fs, pbo)?;
                let options = if next_u32 == block_total_length {
                    // no options
                    Options::default()
                } else {
                    Options::read(fs, pbo)?
                };

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

                // due to there has two uncertain value (packet data length and options length)
                let packet_data_len = Utils::calc_after_padding_size(captured_packet_length);
                let mut packet_data = vec![0u8; packet_data_len as usize];
                fs.read_exact(&mut packet_data)?;

                let next_u32 = Utils::get_next_u32(fs, pbo)?;
                let options = if next_u32 == block_total_length {
                    // no options
                    Options::default()
                } else {
                    Options::read(fs, pbo)?
                };

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

#[repr(C)]
#[derive(Debug, Clone)]
pub struct SimplePacketBlock {
    /// Block Type: The block type of the Simple Packet Block is 3.
    pub block_type: u32,
    /// Block Total Length: Total size of this block.
    pub block_total_length: u32,
    /// Original Packet Length (32 bits):
    /// An unsigned value indicating the actual length of the packet when it was transmitted on the network.
    pub original_packet_length: u32,
    /// Packet Data:
    /// The data coming from the network, including link-layer headers.
    pub packet_data: Vec<u8>,
    pub block_total_length_2: u32,
}

// block_type(4) + block_total_length(4) + original_packet_length(4) + block_total_length_2(4)
const SIMPLE_PACKET_BLOCK_FIX_LENGTH: u32 = 16;

impl SimplePacketBlock {
    pub fn new(packet_data: &[u8]) -> Result<SimplePacketBlock, PcaptureError> {
        let pds = PacketData::parse(packet_data);
        let mut spb = SimplePacketBlock {
            block_type: 0x03,
            block_total_length: 0,
            original_packet_length: pds.original_packet_length,
            packet_data: pds.packet_data_slice,
            block_total_length_2: 0,
        };
        let spb_len = size_of_val(&spb) as u32;
        spb.block_total_length = spb_len;
        spb.block_total_length_2 = spb_len;
        Ok(spb)
    }
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
                // very simple way to get the packet length
                let packet_data_len = block_total_length - SIMPLE_PACKET_BLOCK_FIX_LENGTH;
                let mut packet_data = vec![0u8; packet_data_len as usize];
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
                let original_packet_length = fs.read_u32::<BigEndian>()?;
                let packet_data_len = block_total_length - SIMPLE_PACKET_BLOCK_FIX_LENGTH;
                let mut packet_data = vec![0u8; packet_data_len as usize];
                fs.read_exact(&mut packet_data)?;
                let block_total_length_2 = fs.read_u32::<BigEndian>()?;
                Ok(SimplePacketBlock {
                    block_type,
                    block_total_length,
                    original_packet_length,
                    packet_data,
                    block_total_length_2,
                })
            }
        }
    }
}

// Packet Block (obsolete!)
// from https://www.ietf.org/archive/id/draft-tuexen-opsawg-pcapng-03.html#name-packet-block-obsolete
//                         1                   2                   3
//     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  0 |                    Block Type = 0x00000002                    |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  4 |                      Block Total Length                       |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  8 |         Interface ID          |          Drops Count          |
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

#[repr(C)]
#[derive(Debug, Clone)]
pub struct PacketBlock {
    /// Block Type: The block type of the Packet Block is 2.
    pub block_type: u32,
    /// Block Total Length: Total size of this block.
    pub block_total_length: u32,
    /// Interface ID:
    /// Specifies the interface this packet comes from;
    /// The correct interface will be the one whose Interface Description Block
    /// (within the current Section of the file) is identified by the same number of this field.
    pub interface_id: u16,
    /// Drops Count:
    /// A local drop counter.
    /// It specifies the number of packets lost (by the interface and the operating system) between this packet and the preceding one.
    pub drops_count: u16,
    /// Timestamp (High) and Timestamp (Low): Timestamp of the packet.
    pub ts_high: u32,
    pub ts_low: u32,
    /// Captured Packet Length: number of octets captured from the packet.
    pub captured_packet_length: u32,
    /// Original Packet Length (32 bits):
    /// An unsigned value indicating the actual length of the packet when it was transmitted on the network.
    pub original_packet_length: u32,
    /// Packet Data:
    /// The data coming from the network, including link-layer headers.
    pub packet_data: Vec<u8>,
    pub options: Options,
    /// Options: optionally, a list of options.
    pub block_total_length_2: u32,
}

/// The Packet Block is obsolete, and MUST NOT be used in new files.
/// Use the Enhanced Packet Block or Simple Packet Block instead.
/// This section is for historical reference only.
impl PacketBlock {
    /// Only implement the read function for obsolete struct.
    pub fn read(fs: &mut File, pbo: PcapByteOrder) -> Result<PacketBlock, PcaptureError> {
        match pbo {
            PcapByteOrder::LittleEndian | PcapByteOrder::WiresharkDefault => {
                let block_type = fs.read_u32::<LittleEndian>()?;
                let block_total_length = fs.read_u32::<LittleEndian>()?;
                let interface_id = fs.read_u16::<LittleEndian>()?;
                let drops_count = fs.read_u16::<LittleEndian>()?;
                let ts_high = fs.read_u32::<LittleEndian>()?;
                let ts_low = fs.read_u32::<LittleEndian>()?;
                let captured_packet_length = fs.read_u32::<LittleEndian>()?;
                let original_packet_length = fs.read_u32::<LittleEndian>()?;

                // due to there has two uncertain value (packet data length and options length)
                let packet_data_len = Utils::calc_after_padding_size(captured_packet_length);
                let mut packet_data = vec![0u8; packet_data_len as usize];
                fs.read_exact(&mut packet_data)?;

                let next_u32 = Utils::get_next_u32(fs, pbo)?;
                let options = if next_u32 == block_total_length {
                    // no options
                    Options::default()
                } else {
                    Options::read(fs, pbo)?
                };

                let block_total_length_2 = fs.read_u32::<LittleEndian>()?;
                Ok(PacketBlock {
                    block_type,
                    block_total_length,
                    interface_id,
                    drops_count,
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
                let interface_id = fs.read_u16::<BigEndian>()?;
                let drops_count = fs.read_u16::<BigEndian>()?;
                let ts_high = fs.read_u32::<BigEndian>()?;
                let ts_low = fs.read_u32::<BigEndian>()?;
                let captured_packet_length = fs.read_u32::<BigEndian>()?;
                let original_packet_length = fs.read_u32::<BigEndian>()?;

                let packet_data_len = Utils::calc_after_padding_size(captured_packet_length);
                let mut packet_data = vec![0u8; packet_data_len as usize];
                fs.read_exact(&mut packet_data)?;

                let next_u32 = Utils::get_next_u32(fs, pbo)?;
                let options = if next_u32 == block_total_length {
                    // no options
                    Options::default()
                } else {
                    Options::read(fs, pbo)?
                };

                let block_total_length_2 = fs.read_u32::<BigEndian>()?;
                Ok(PacketBlock {
                    block_type,
                    block_total_length,
                    interface_id,
                    drops_count,
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

#[repr(C)]
#[derive(Debug, Clone)]
pub struct Record {
    pub record_type: u16,
    pub record_value_length: u16,
    pub record_value: Vec<u8>,
}

impl Record {
    pub fn new(record_type: u16, record_value: &[u8]) -> Record {
        let record_value_length = record_value.len() as u16;
        Record {
            record_type,
            record_value_length,
            record_value: Utils::padding_to_32(record_value),
        }
    }
    pub fn new_tail() -> Record {
        // record_type: nrb_record_end (0)
        // record_value_length: 0
        Record {
            record_type: 0,
            record_value_length: 0,
            record_value: Vec::new(),
        }
    }
    pub fn write(&mut self, fs: &mut File, pbo: PcapByteOrder) -> Result<(), PcaptureError> {
        match pbo {
            PcapByteOrder::LittleEndian | PcapByteOrder::WiresharkDefault => {
                fs.write_u16::<LittleEndian>(self.record_type)?;
                fs.write_u16::<LittleEndian>(self.record_value_length)?;
                fs.write_all(&Utils::padding_to_32(&self.record_value))?;
            }
            PcapByteOrder::BigEndian => {
                fs.write_u16::<BigEndian>(self.record_type)?;
                fs.write_u16::<BigEndian>(self.record_value_length)?;
                fs.write_all(&Utils::padding_to_32(&self.record_value))?;
            }
        }
        Ok(())
    }
    pub fn read(fs: &mut File, pbo: PcapByteOrder) -> Result<Record, PcaptureError> {
        match pbo {
            PcapByteOrder::LittleEndian | PcapByteOrder::WiresharkDefault => {
                let record_type = fs.read_u16::<LittleEndian>()?;
                let record_value_length = fs.read_u16::<LittleEndian>()?;
                let padding_size = Utils::calc_after_padding_size(record_value_length);
                let mut record_value = vec![0u8; padding_size as usize];
                fs.read_exact(&mut record_value)?;
                Ok(Record {
                    record_type,
                    record_value_length,
                    record_value,
                })
            }
            PcapByteOrder::BigEndian => {
                let record_type = fs.read_u16::<BigEndian>()?;
                let record_value_length = fs.read_u16::<BigEndian>()?;
                let padding_size = Utils::calc_after_padding_size(record_value_length);
                let mut record_value = vec![0u8; padding_size as usize];
                fs.read_exact(&mut record_value)?;
                Ok(Record {
                    record_type,
                    record_value_length,
                    record_value,
                })
            }
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct Records {
    pub records: Vec<Record>,
}

impl Default for Records {
    fn default() -> Self {
        Records {
            records: Vec::new(),
        }
    }
}

impl Records {
    pub fn wirte(&mut self, fs: &mut File, pbo: PcapByteOrder) -> Result<(), PcaptureError> {
        for r in &mut self.records {
            r.write(fs, pbo)?;
        }
        Ok(())
    }
    pub fn read(fs: &mut File, pbo: PcapByteOrder) -> Result<Records, PcaptureError> {
        let mut records = Vec::new();
        loop {
            match Record::read(fs, pbo) {
                Ok(record) => {
                    let record_clone = record.clone();
                    records.push(record_clone);
                    if record.record_type == 0 && record.record_value_length == 0 {
                        break;
                    }
                }
                Err(e) => return Err(e),
            }
        }
        Ok(Records { records })
    }
}

// NameResolutionBlock
// from https://www.ietf.org/archive/id/draft-tuexen-opsawg-pcapng-03.html#name-name-resolution-block
//                         1                   2                   3
//     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  0 |                    Block Type = 0x00000004                    |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  4 |                      Block Total Length                       |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  8 |      Record Type              |      Record Value Length      |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 12 /                       Record Value                            /
//    /              variable length, padded to 32 bits               /
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    .                                                               .
//    .                  . . . other records . . .                    .
//    .                                                               .
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |  Record Type = nrb_record_end |   Record Value Length = 0     |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    /                                                               /
//    /                      Options (variable)                       /
//    /                                                               /
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |                      Block Total Length                       |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#[repr(C)]
#[derive(Debug, Clone)]
pub struct NameResolutionBlock {
    pub block_type: u32,
    pub block_total_length: u32,
    pub records: Records,
    pub options: Options,
    pub block_total_length_2: u32,
}

impl NameResolutionBlock {
    pub fn wirte(&mut self, fs: &mut File, pbo: PcapByteOrder) -> Result<(), PcaptureError> {
        match pbo {
            PcapByteOrder::LittleEndian | PcapByteOrder::WiresharkDefault => {
                fs.write_u32::<LittleEndian>(self.block_type)?;
                fs.write_u32::<LittleEndian>(self.block_total_length)?;
                self.records.wirte(fs, pbo)?;
                self.options.write(fs, pbo)?;
                fs.write_u32::<LittleEndian>(self.block_total_length_2)?;
            }
            PcapByteOrder::BigEndian => {
                fs.write_u32::<BigEndian>(self.block_type)?;
                fs.write_u32::<BigEndian>(self.block_total_length)?;
                self.records.wirte(fs, pbo)?;
                self.options.write(fs, pbo)?;
                fs.write_u32::<BigEndian>(self.block_total_length_2)?;
            }
        }
        Ok(())
    }
    pub fn read(fs: &mut File, pbo: PcapByteOrder) -> Result<NameResolutionBlock, PcaptureError> {
        match pbo {
            PcapByteOrder::LittleEndian | PcapByteOrder::WiresharkDefault => {
                let block_type = fs.read_u32::<LittleEndian>()?;
                let block_total_length = fs.read_u32::<LittleEndian>()?;
                let records = Records::read(fs, pbo)?;

                let next_32 = Utils::get_next_u32(fs, pbo)?;
                let options = if next_32 == block_total_length {
                    // no options
                    Options::default()
                } else {
                    let options = Options::read(fs, pbo)?;
                    options
                };

                let block_total_length_2 = fs.read_u32::<LittleEndian>()?;
                Ok(NameResolutionBlock {
                    block_type,
                    block_total_length,
                    records,
                    options,
                    block_total_length_2,
                })
            }
            PcapByteOrder::BigEndian => {
                let block_type = fs.read_u32::<BigEndian>()?;
                let block_total_length = fs.read_u32::<BigEndian>()?;
                let records = Records::read(fs, pbo)?;

                let next_32 = Utils::get_next_u32(fs, pbo)?;
                let options = if next_32 == block_total_length {
                    // no options
                    Options::default()
                } else {
                    let options = Options::read(fs, pbo)?;
                    options
                };

                let block_total_length_2 = fs.read_u32::<BigEndian>()?;
                Ok(NameResolutionBlock {
                    block_type,
                    block_total_length,
                    records,
                    options,
                    block_total_length_2,
                })
            }
        }
    }
}

// Interface Statistics Block
// from https://www.ietf.org/archive/id/draft-tuexen-opsawg-pcapng-03.html#name-interface-statistics-block
//                         1                   2                   3
//     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  0 |                   Block Type = 0x00000005                     |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  4 |                      Block Total Length                       |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  8 |                         Interface ID                          |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 12 |                        Timestamp (High)                       |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 16 |                        Timestamp (Low)                        |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 20 /                                                               /
//    /                      Options (variable)                       /
//    /                                                               /
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |                      Block Total Length                       |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#[repr(C)]
#[derive(Debug, Clone)]
pub struct InterfaceStatisticsBlock {
    pub block_type: u32,
    pub block_total_length: u32,
    pub interface_id: u32,
    pub ts_high: u32,
    pub ts_low: u32,
    pub options: Options,
    pub block_total_length_2: u32,
}

impl InterfaceStatisticsBlock {
    pub fn write(&mut self, fs: &mut File, pbo: PcapByteOrder) -> Result<(), PcaptureError> {
        match pbo {
            PcapByteOrder::LittleEndian | PcapByteOrder::WiresharkDefault => {
                fs.write_u32::<LittleEndian>(self.block_type)?;
                fs.write_u32::<LittleEndian>(self.block_total_length)?;
                fs.write_u32::<LittleEndian>(self.interface_id)?;
                fs.write_u32::<LittleEndian>(self.ts_high)?;
                fs.write_u32::<LittleEndian>(self.ts_low)?;
                self.options.write(fs, pbo)?;
                fs.write_u32::<LittleEndian>(self.block_total_length_2)?;
            }
            PcapByteOrder::BigEndian => {
                fs.write_u32::<BigEndian>(self.block_type)?;
                fs.write_u32::<BigEndian>(self.block_total_length)?;
                fs.write_u32::<BigEndian>(self.interface_id)?;
                fs.write_u32::<BigEndian>(self.ts_high)?;
                fs.write_u32::<BigEndian>(self.ts_low)?;
                self.options.write(fs, pbo)?;
                fs.write_u32::<BigEndian>(self.block_total_length_2)?;
            }
        }
        Ok(())
    }
    pub fn read(
        fs: &mut File,
        pbo: PcapByteOrder,
    ) -> Result<InterfaceStatisticsBlock, PcaptureError> {
        match pbo {
            PcapByteOrder::LittleEndian | PcapByteOrder::WiresharkDefault => {
                let block_type = fs.read_u32::<LittleEndian>()?;
                let block_total_length = fs.read_u32::<LittleEndian>()?;
                let interface_id = fs.read_u32::<LittleEndian>()?;
                let ts_high = fs.read_u32::<LittleEndian>()?;
                let ts_low = fs.read_u32::<LittleEndian>()?;

                let next_32 = Utils::get_next_u32(fs, pbo)?;
                let options = if next_32 == block_total_length {
                    // no options
                    Options::default()
                } else {
                    let options = Options::read(fs, pbo)?;
                    options
                };

                let block_total_length_2 = fs.read_u32::<LittleEndian>()?;
                Ok(InterfaceStatisticsBlock {
                    block_type,
                    block_total_length,
                    interface_id,
                    ts_high,
                    ts_low,
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

                let next_32 = Utils::get_next_u32(fs, pbo)?;
                let options = if next_32 == block_total_length {
                    // no options
                    Options::default()
                } else {
                    let options = Options::read(fs, pbo)?;
                    options
                };

                let block_total_length_2 = fs.read_u32::<BigEndian>()?;
                Ok(InterfaceStatisticsBlock {
                    block_type,
                    block_total_length,
                    interface_id,
                    ts_high,
                    ts_low,
                    options,
                    block_total_length_2,
                })
            }
        }
    }
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, EnumString, EnumIter)]
pub enum BlockType {
    SectionHeaderBlock = 0x0a0d0d0a,
    InterfaceDescriptionBlock = 0x01,
    PacketBlock = 0x02, // The document say it was 'obsolete!'
    SimplePacketBlock = 0x03,
    NameResolutionBlock = 0x04,
    InterfaceStatisticsBlock = 0x05,
    EnhancedPacketBlock = 0x06,
    CustomBlock = 0x00000bad,
    CustomBlock2 = 0x40000bad,
}

impl BlockType {
    pub fn to_u32(self) -> u32 {
        self as u32
    }
    pub fn from_u32(value: u32) -> Option<Self> {
        BlockType::iter().find(|&e| e as u32 == value)
    }
}

#[derive(Debug, Clone)]
pub enum GeneralBlockStructure {
    InterfaceDescriptionBlock(InterfaceDescriptionBlock),
    PacketBlock(PacketBlock),
    SimplePacketBlock(SimplePacketBlock),
    NameResolutionBlock(NameResolutionBlock),
    InterfaceStatisticsBlock(InterfaceStatisticsBlock),
    EnhancedPacketBlock(EnhancedPacketBlock),
    SectionHeaderBlock(SectionHeaderBlock),
    // CustomBlock(CustomBlock),
    // CustomBlock2(CustomBlock2),
}

impl GeneralBlockStructure {
    pub fn write(&mut self, fs: &mut File, pbo: PcapByteOrder) -> Result<(), PcaptureError> {
        match self {
            Self::InterfaceDescriptionBlock(b) => b.write(fs, pbo),
            Self::EnhancedPacketBlock(b) => b.write(fs, pbo),
            Self::SimplePacketBlock(b) => b.write(fs, pbo),
            Self::SectionHeaderBlock(b) => b.write(fs, pbo),
            Self::NameResolutionBlock(b) => b.wirte(fs, pbo),
            Self::InterfaceStatisticsBlock(b) => b.write(fs, pbo),
            Self::PacketBlock(_) => Err(PcaptureError::UnsupportedBlockType {
                blockname: String::from("Packet Block"),
            }), // do nothing just return an error
        }
    }
    pub fn read(fs: &mut File, pbo: PcapByteOrder) -> Result<GeneralBlockStructure, PcaptureError> {
        let block_type = Utils::get_block_type(fs, pbo)?;
        match block_type {
            BlockType::SectionHeaderBlock => {
                let shb = SectionHeaderBlock::read(fs, pbo)?;
                Ok(GeneralBlockStructure::SectionHeaderBlock(shb))
            }
            BlockType::InterfaceDescriptionBlock => {
                let idb = InterfaceDescriptionBlock::read(fs, pbo)?;
                Ok(GeneralBlockStructure::InterfaceDescriptionBlock(idb))
            }
            BlockType::EnhancedPacketBlock => {
                let epb = EnhancedPacketBlock::read(fs, pbo)?;
                Ok(GeneralBlockStructure::EnhancedPacketBlock(epb))
            }
            BlockType::SimplePacketBlock => {
                let spb = SimplePacketBlock::read(fs, pbo)?;
                Ok(GeneralBlockStructure::SimplePacketBlock(spb))
            }
            BlockType::PacketBlock => {
                let pb = PacketBlock::read(fs, pbo)?;
                Ok(GeneralBlockStructure::PacketBlock(pb))
            }
            BlockType::InterfaceStatisticsBlock => {
                let isb = InterfaceStatisticsBlock::read(fs, pbo)?;
                Ok(GeneralBlockStructure::InterfaceStatisticsBlock(isb))
            }
            BlockType::NameResolutionBlock => {
                let nrb = NameResolutionBlock::read(fs, pbo)?;
                Ok(GeneralBlockStructure::NameResolutionBlock(nrb))
            }
            BlockType::CustomBlock | BlockType::CustomBlock2 => {
                // useless, complete it later
                Err(PcaptureError::UnsupportedBlockType {
                    blockname: String::from("Custom Block"),
                })
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct PcapNg {
    pub blocks: Vec<GeneralBlockStructure>,
}

impl PcapNg {
    pub fn new(interface: NetworkInterface) -> Result<PcapNg, PcaptureError> {
        let shb = GeneralBlockStructure::SectionHeaderBlock(SectionHeaderBlock::default());
        let idb = GeneralBlockStructure::InterfaceDescriptionBlock(InterfaceDescriptionBlock::new(
            interface,
        )?);
        let blocks = vec![shb, idb];
        Ok(PcapNg { blocks })
    }
    pub fn append(&mut self, block: GeneralBlockStructure) {
        self.blocks.push(block);
    }
    pub fn write_all(&mut self, path: &str, pbo: PcapByteOrder) -> Result<(), PcaptureError> {
        let mut fs = File::create(path)?;
        for block in &mut self.blocks {
            block.write(&mut fs, pbo)?;
        }
        Ok(())
    }
    pub fn read_all(path: &str, pbo: PcapByteOrder) -> Result<PcapNg, PcaptureError> {
        let mut fs = File::open(path)?;
        let mut blocks = Vec::new();
        loop {
            let gbs = match GeneralBlockStructure::read(&mut fs, pbo) {
                Ok(gbs) => gbs,
                Err(_) => break,
            };
            blocks.push(gbs);
        }
        Ok(PcapNg { blocks })
    }
}

pub struct PacketData {
    pub packet_data_slice: Vec<u8>,
    pub captured_packet_length: u32,
    pub original_packet_length: u32,
}

impl PacketData {
    /// Cut the packet data with DETAULT_WIRESHARK_MAX_LEN then padding to 32
    fn parse(packet_data: &[u8]) -> PacketData {
        let packet_data_slice = if packet_data.len() > DETAULT_WIRESHARK_MAX_LEN {
            &packet_data[..DETAULT_WIRESHARK_MAX_LEN]
        } else {
            packet_data
        };
        let captured_packet_length = packet_data_slice.len() as u32;
        let original_packet_length = packet_data.len() as u32;
        PacketData {
            packet_data_slice: Utils::padding_to_32(packet_data_slice),
            captured_packet_length,
            original_packet_length,
        }
    }
}

pub struct PacketTimestamp {
    pub ts_high: u32,
    pub ts_low: u32,
}

impl PacketTimestamp {
    pub fn get() -> Result<PacketTimestamp, PcaptureError> {
        let now = SystemTime::now();
        let duration_since_epoch = now.duration_since(UNIX_EPOCH)?;
        let timestamp = duration_since_epoch.as_secs();
        let ts_high = (timestamp >> 32) as u32;
        let ts_low = (timestamp & 0xFFFFFFFF) as u32;
        Ok(PacketTimestamp { ts_high, ts_low })
    }
}

trait Zero: Rem<Output = Self> + Copy {
    fn zero() -> Self;
}

impl Zero for u16 {
    fn zero() -> Self {
        0
    }
}

impl Zero for u32 {
    fn zero() -> Self {
        0
    }
}

trait Four: Rem<Output = Self> + Copy {
    fn four() -> Self;
}

impl Four for u16 {
    fn four() -> Self {
        4
    }
}

impl Four for u32 {
    fn four() -> Self {
        4
    }
}

fn modulo<T: Rem>(a: T, b: T) -> T
where
    T: Rem<Output = T> + PartialEq + Zero,
{
    Rem::rem(a, b)
}

pub struct Utils;

impl Utils {
    pub fn padding_to_32(input: &[u8]) -> Vec<u8> {
        let mut ret = input.to_vec();
        while ret.len() % 4 != 0 {
            ret.push(0);
        }
        ret
    }
    /// Returns the actual size after data padding (only for u16 and u32).
    fn calc_after_padding_size<T: Zero + Four + PartialEq + Sub<Output = T> + Add<Output = T>>(
        length: T,
    ) -> T {
        if length == T::zero() {
            T::zero()
        } else {
            let remainder = modulo(length, T::four());
            let actual_size = length + T::four() - remainder;
            actual_size
        }
    }
    pub fn get_next_two_u16(
        fs: &mut File,
        pbo: PcapByteOrder,
    ) -> Result<(u16, u16), PcaptureError> {
        let (value1, value2) = match pbo {
            PcapByteOrder::LittleEndian | PcapByteOrder::WiresharkDefault => {
                let value1 = fs.read_u16::<LittleEndian>()?;
                let value2 = fs.read_u16::<LittleEndian>()?;
                (value1, value2)
            }
            PcapByteOrder::BigEndian => {
                let value1 = fs.read_u16::<BigEndian>()?;
                let value2 = fs.read_u16::<BigEndian>()?;
                (value1, value2)
            }
        };
        // seek back to block start position
        fs.seek(SeekFrom::Current(-4))?; // 2 * 16 bits = 32 bits = 4 bytes
        Ok((value1, value2))
    }
    pub fn get_next_u32(fs: &mut File, pbo: PcapByteOrder) -> Result<u32, PcaptureError> {
        let value = match pbo {
            PcapByteOrder::LittleEndian | PcapByteOrder::WiresharkDefault => {
                fs.read_u32::<LittleEndian>()?
            }
            PcapByteOrder::BigEndian => fs.read_u32::<BigEndian>()?,
        };
        // seek back to block start position
        fs.seek(SeekFrom::Current(-4))?; // 32 bits = 4 bytes
        Ok(value)
    }
    pub fn get_block_type(fs: &mut File, pbo: PcapByteOrder) -> Result<BlockType, PcaptureError> {
        let value = match pbo {
            PcapByteOrder::LittleEndian | PcapByteOrder::WiresharkDefault => {
                fs.read_u32::<LittleEndian>()?
            }
            PcapByteOrder::BigEndian => fs.read_u32::<BigEndian>()?,
        };
        // seek back to block start position
        fs.seek(SeekFrom::Current(-4))?; // 32 bits = 4 bytes

        match BlockType::from_u32(value) {
            Some(b) => Ok(b),
            None => Err(PcaptureError::UnknownBlockType { blocktype: value }),
        }
    }
}

pub struct SysInfo;

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
