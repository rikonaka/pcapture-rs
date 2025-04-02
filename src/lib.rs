use bincode;
use bincode::decode_from_std_read;
use bincode::encode_into_slice;
use bincode::encode_into_std_write;
use pcap::PcapRecord;
use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::ChannelType;
use pnet::datalink::Config;
use pnet::datalink::DataLinkReceiver;
use pnet::datalink::DataLinkSender;
use pnet::datalink::MacAddr;
use pnet::datalink::NetworkInterface;
use pnet::ipnetwork::IpNetwork;
use std::fs::File;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

pub mod error;
pub mod pcap;

use error::PcaptureError;
use pcap::Pcap;

static DEFAULT_BUFFER_SIZE: usize = 4096;
static DEFAULT_TIMEOUT: f32 = 1.0;
static DETAULT_WIRESHARK_MAX_LEN: usize = 262144;

#[derive(Debug)]
pub struct PcapFile {
    fs: File,
}

impl PcapFile {
    pub fn new(filename: &str) -> Result<PcapFile, PcaptureError> {
        let fs = File::create(filename)?;
        Ok(PcapFile { fs })
    }
    pub fn read(&mut self) -> Result<Pcap, PcaptureError> {
        let c = bincode::config::legacy();
        let pcap: Pcap = decode_from_std_read(&mut self.fs, c)?;
        Ok(pcap)
    }
    pub fn write(&mut self, pcap: Pcap) -> Result<usize, PcaptureError> {
        let c = bincode::config::legacy();
        let write_size = encode_into_std_write(pcap, &mut self.fs, c)?;
        Ok(write_size)
    }
}

#[derive(Debug, Clone)]
pub struct Device {
    pub name: String,
    pub desc: Option<String>,
    pub ips: Vec<IpNetwork>,
    pub mac: Option<MacAddr>,
}

impl Device {
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

pub struct Capture {
    config: Config,
    interface: NetworkInterface,
    tx: Box<dyn DataLinkSender>,
    rx: Box<dyn DataLinkReceiver>,
    pub pcap: Pcap,
}

impl Capture {
    pub fn new(iface_name: &str) -> Result<Capture, PcaptureError> {
        let interfaces = datalink::interfaces();
        for interface in interfaces {
            if interface.name == iface_name {
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
                let (tx, rx) = match datalink::channel(&interface, config) {
                    Ok(Ethernet(tx, rx)) => (tx, rx),
                    Ok(_) => return Err(PcaptureError::UnhandledChannelType),
                    Err(e) => return Err(PcaptureError::UnableCreateChannel { e: e.to_string() }),
                };
                let c = Capture {
                    config,
                    interface,
                    tx,
                    rx,
                    pcap: Pcap::default(),
                };
                return Ok(c);
            }
        }
        Err(PcaptureError::UnableFoundInterface {
            i: iface_name.to_string(),
        })
    }
    fn regen(&mut self) -> Result<(), PcaptureError> {
        let (tx, rx) = match datalink::channel(&self.interface, self.config) {
            Ok(Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => return Err(PcaptureError::UnhandledChannelType),
            Err(e) => return Err(PcaptureError::UnableCreateChannel { e: e.to_string() }),
        };
        self.tx = tx;
        self.rx = rx;
        Ok(())
    }
    pub fn buffer_size(&mut self, buffer_size: usize) -> Result<(), PcaptureError> {
        self.config.read_buffer_size = buffer_size;
        self.config.write_buffer_size = buffer_size;
        self.regen()
    }
    /// timeout as sec
    pub fn timeout(&mut self, timeout: f32) -> Result<(), PcaptureError> {
        let timeout_fix = Duration::from_secs_f32(timeout);
        self.config.read_timeout = Some(timeout_fix);
        self.config.write_timeout = Some(timeout_fix);
        self.regen()
    }
    pub fn promiscuous(&mut self, promiscuous: bool) -> Result<(), PcaptureError> {
        self.config.promiscuous = promiscuous;
        self.regen()
    }
    pub fn next(&mut self) -> Result<&[u8], PcaptureError> {
        match self.rx.next() {
            Ok(packet) => {
                let packet_slice = if packet.len() > DETAULT_WIRESHARK_MAX_LEN {
                    &packet[..DETAULT_WIRESHARK_MAX_LEN]
                } else {
                    packet
                };
                let dura = SystemTime::now().duration_since(UNIX_EPOCH)?;
                let ts_sec = dura.as_secs() as u32; // u32 is pcap file struct defined data type, and in pcapng it will be u64
                println!("ts_sec: {:X}", ts_sec);
                let ts_usec = dura.subsec_micros();
                let capt_len = packet_slice.len() as u32;
                let orig_len = packet.len() as u32;
                let pcap_record =
                    PcapRecord::new(ts_sec, ts_usec, capt_len, orig_len, packet_slice);

                /* test start */
                let mut dst = [0u8; 1024];
                let config = bincode::config::legacy();
                let _ = encode_into_slice(&pcap_record, &mut dst, config).unwrap();
                let hex_string: String = dst
                    .iter()
                    .map(|byte| format!("{:02x}", byte))
                    .collect::<Vec<String>>()
                    .join(" ");
                println!("{}", hex_string);
                /* test end */

                self.pcap.append(pcap_record);
                Ok(packet)
            }
            Err(e) => Err(PcaptureError::CapturePacketError { e: e.to_string() }),
        }
    }
    pub fn write_all(&mut self, filename: &str) -> Result<usize, PcaptureError> {
        let mut pcap_file = PcapFile::new(filename)?;
        pcap_file.write(self.pcap.clone())
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Deref;

    use super::*;
    use bincode::Encode;
    use bincode::encode_into_slice;
    #[test]
    fn test_interface() {
        let ni = datalink::interfaces();
        for n in ni {
            println!("{:?}", n);
        }
    }
    #[test]
    fn test_capture() {
        let mut cap = Capture::new("ens33").unwrap();
        for _ in 0..2 {
            match cap.next() {
                Ok(p) => println!("len [{}]", p.len()),
                Err(e) => eprintln!("{}", e),
            }
        }
        let size = cap.write_all("test.pcap").unwrap();
        println!("total write [{}] bytes", size);

        let data = cap.pcap.record;
        // println!(">>> magic_number: {:02X}", data.header.magic_number);
        // println!(">>> version_major: {:02X}", data.header.major_version);
        let mut dst = [0u8; 4096];
        let config = bincode::config::legacy();
        let _ = encode_into_slice(data, &mut dst, config).unwrap();
        let hex_string: String = dst
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect::<Vec<String>>()
            .join(" ");
        println!("{}", hex_string)
    }
    #[test]
    fn test_bincode() {
        // #[repr(C)]
        #[derive(Debug, Encode)]
        struct Test {
            a: u32,
            b: u16,
            c: u16,
        }
        let test = Test {
            a: 0xa1b2c3d4,
            b: 2,
            c: 4,
        };
        let mut dst = [0u8; 16];
        // let config = bincode::config::standard(); // this will add 'fc' in data begin
        let config = bincode::config::legacy();
        let _ = encode_into_slice(test, &mut dst, config).unwrap();
        let hex_string: String = dst
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect::<Vec<String>>()
            .join(" ");
        println!("{}", hex_string);
    }
    #[test]
    fn test_bincode2() {
        let mut dst = [0u8; 128];
        let pcap = Pcap::default();
        let config = bincode::config::legacy();
        let _ = encode_into_slice(pcap, &mut dst, config).unwrap();
        let hex_string: String = dst
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect::<Vec<String>>()
            .join(" ");
        println!("{}", hex_string);
    }
    #[test]
    fn test_bincode3() {
        let test: Vec<Vec<u8>> = vec![vec![1, 2, 3, 4], vec![5, 6, 7, 8]];
        let mut dst = [0u8; 32];
        let config = bincode::config::legacy();
        let _ = encode_into_slice(test, &mut dst, config).unwrap();
        let hex_string: String = dst
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect::<Vec<String>>()
            .join(" ");
        println!("{}", hex_string);
        // output:
        // 02 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 01 02 03 04 04 00 00 00 00 00 00 00 05 06 07 08

        let test: &[[u8; 4]] = &[[1, 2, 3, 4], [5, 6, 7, 8]];
        let mut dst = [0u8; 32];
        let config = bincode::config::legacy();
        let _ = encode_into_slice(test, &mut dst, config).unwrap();
        let hex_string: String = dst
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect::<Vec<String>>()
            .join(" ");
        println!("{}", hex_string);
        // output:
        // 02 00 00 00 00 00 00 00 01 02 03 04 05 06 07 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

        let test: &[u8; 8] = &[1, 2, 3, 4, 5, 6, 7, 8];
        let mut dst = [0u8; 32];
        let config = bincode::config::legacy();
        let _ = encode_into_slice(test, &mut dst, config).unwrap();
        let hex_string: String = dst
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect::<Vec<String>>()
            .join(" ");
        println!("{}", hex_string);
        // output:
        // 01 02 03 04 05 06 07 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

        let test: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let mut dst = [0u8; 32];
        let config = bincode::config::legacy();
        let _ = encode_into_slice(test, &mut dst, config).unwrap();
        let hex_string: String = dst
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect::<Vec<String>>()
            .join(" ");
        println!("{}", hex_string);
        // output:
        // 08 00 00 00 00 00 00 00 01 02 03 04 05 06 07 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

        let test: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let mut dst = [0u8; 32];
        let config = bincode::config::legacy();
        let _ = encode_into_slice(test, &mut dst, config).unwrap();
        let dst = &dst[8..];
        let hex_string: String = dst
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect::<Vec<String>>()
            .join(" ");
        println!("{}", hex_string);
        // output:
        // 01 02 03 04 05 06 07 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

        let test: Vec<[u8; 4]> = vec![[1, 2, 3, 4], [5, 6, 7, 8]];
        let mut dst = [0u8; 32];
        let config = bincode::config::legacy();
        let _ = encode_into_slice(test, &mut dst, config).unwrap();
        let hex_string: String = dst
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect::<Vec<String>>()
            .join(" ");
        println!("{}", hex_string);
        // output:
        // 02 00 00 00 00 00 00 00 01 02 03 04 05 06 07 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

        let test: Vec<[u8; 4]> = vec![[1, 2, 3, 4], [5, 6, 7, 8]];
        let mut dst = [0u8; 32];
        let config = bincode::config::standard();
        let _ = encode_into_slice(test, &mut dst, config).unwrap();
        let hex_string: String = dst
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect::<Vec<String>>()
            .join(" ");
        println!("{}", hex_string);
        // output:
        // 02 01 02 03 04 05 06 07 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

        let test: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let mut dst = [0u8; 32];
        let config = bincode::config::standard();
        let _ = encode_into_slice(test, &mut dst, config).unwrap();
        let hex_string: String = dst
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect::<Vec<String>>()
            .join(" ");
        println!("{}", hex_string);
        // output:
        // 08 01 02 03 04 05 06 07 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

        let test: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let test = test.deref();
        let mut dst = [0u8; 32];
        let config = bincode::config::standard();
        let _ = encode_into_slice(test, &mut dst, config).unwrap();
        let hex_string: String = dst
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect::<Vec<String>>()
            .join(" ");
        println!("{}", hex_string);
        // output:
        // 08 01 02 03 04 05 06 07 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

        let test: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let vec_ptr = test.as_ptr();
        let len = test.len();
        unsafe {
            let slice = std::slice::from_raw_parts(vec_ptr, len);
            let hex_string: String = slice
                .iter()
                .map(|byte| format!("{:02x}", byte))
                .collect::<Vec<String>>()
                .join(" ");
            println!("{}", hex_string);
        }
        // output:
        // 08 01 02 03 04 05 06 07 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    }
}
