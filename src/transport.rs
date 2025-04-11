use bincode;
use bincode::Decode;
use bincode::Encode;
use chrono::DateTime;
use chrono::Local;
use chrono::NaiveDate;
use chrono::Timelike;
use serde::Deserialize;
use serde::Serialize;
use std::fs::File;
use std::io::BufReader;
use std::io::Read;
use std::io::Write;
use std::net::TcpListener;
use std::net::TcpStream;

use crate::error::PcaptureError;
use crate::pcap::FileHeader;
use crate::pcap::PacketRecord;
use crate::pcap::PcapByteOrder;

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub enum PcapType {
    Header,
    Record,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct PcapTransport {
    pub p_type: PcapType,
    pub p_data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub enum PcapNgType {
    InterfaceDescriptionBlock,
    PacketBlock,
    SimplePacketBlock,
    NameResolutionBlock,
    InterfaceStatisticsBlock,
    EnhancedPacketBlock,
    SectionHeaderBlock,
    // CustomBlock,
    // CustomBlock2,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct PcapNgTransport {
    pub p_type: PcapNgType,
    pub p_data: Vec<u8>,
}

pub struct Client {
    stream: TcpStream,
}

impl Client {
    pub fn connect(url: &str, port: u16) -> Result<Client, PcaptureError> {
        let addr = format!("{}:{}", url, port);
        let stream = TcpStream::connect(addr)?;
        Ok(Client { stream })
    }
    /// Client only send data, not recv anything.
    pub fn send_pcap(&mut self, pcap_t: PcapTransport) -> Result<(), PcaptureError> {
        let config = bincode::config::standard();
        let encode_1 = bincode::encode_to_vec(pcap_t, config)?;
        let encode_len = encode_1.len() as u32;
        let encode_2 = encode_len.to_be_bytes(); // BigEndian on internet

        // first send 4 bytes length
        self.stream.write_all(&encode_2)?;
        // second send the data
        self.stream.write_all(&encode_1)?;
        Ok(())
    }
}

pub enum SplitRule {
    ByMin(u32),
    ByHour(DateTime<Local>),
    ByDay(DateTime<Local>),
    ByCount(usize),
    None, // default value, do not split the output file
}

impl Default for SplitRule {
    fn default() -> Self {
        Self::None
    }
}

static PCAPTURE_FILE_NAME: &str = "pcapture";

fn add_tail(input: &str, is_pcapng: bool) -> String {
    let mut input = input.to_string();
    if is_pcapng {
        input += ".pcapng";
    } else {
        input += ".pcap";
    }
    input
}

impl SplitRule {
    fn gen_filename_min(is_pcapng: bool, year: u32, day: u32, hour: u32, min: u32) -> String {
        let h = format!("{PCAPTURE_FILE_NAME}_{year}_{day}_{hour}_{min}");
        add_tail(&h, is_pcapng)
    }
    fn gen_filename_hour(is_pcapng: bool, year: u32, day: u32, hour: u32) -> String {
        let h = format!("{PCAPTURE_FILE_NAME}_{year}_{day}_{hour}");
        add_tail(&h, is_pcapng)
    }
    fn gen_filename_day(is_pcapng: bool, year: u32, day: u32) -> String {
        let h = format!("{PCAPTURE_FILE_NAME}_{year}_{day}");
        add_tail(&h, is_pcapng)
    }
}

pub struct Server {
    listener: TcpListener,
    fs: Option<File>,
    pbo: Option<PcapByteOrder>,
    split_rule: SplitRule,
}

impl Server {
    fn split_output(&mut self) -> Result<(), PcaptureError> {
        match self.split_rule {
            SplitRule::ByMin(last_min) => {
                let now = Local::now();
                let now_min = now.minute();
                if now_min > last_min {
                    let fs = File::open()?;
                }
            }
            _ => todo!(),
        }
    }
    pub fn listen() -> Result<Server, PcaptureError> {
        let listener = TcpListener::bind("127.0.0.1:4000")?;
        Ok(Server {
            listener,
            fs: None,
            pbo: None,
        })
    }
    pub fn set_output_path(&mut self, path: &str) -> Result<(), PcaptureError> {
        let fs = File::create(path)?;
        self.fs = Some(fs);
        Ok(())
    }
    pub fn set_pbo(&mut self, pbo: PcapByteOrder) {
        self.pbo = Some(pbo);
    }
    pub fn recv_pcap(&mut self) -> Result<(), PcaptureError> {
        for stream in self.listener.incoming() {
            let mut stream = stream?;
            let mut reader = BufReader::new(&mut stream);

            let mut len_buf = [0u8; 4];
            reader.read_exact(&mut len_buf)?;
            let recv_len = u32::from_be_bytes(len_buf) as usize;

            let mut buf = vec![0u8; recv_len];
            reader.read_exact(&mut buf)?;

            let config = bincode::config::standard();
            let decode: (PcapTransport, usize) = bincode::decode_from_slice(&buf, config)?;
            let (pcap_t, decode_len) = decode;
            if decode_len == recv_len {
                // it should equal
                match &mut self.fs {
                    Some(fs) => {
                        let pbo = match self.pbo {
                            Some(pbo) => pbo,
                            None => PcapByteOrder::WiresharkDefault,
                        };
                        match pcap_t.p_type {
                            PcapType::Header => {
                                let decode: (FileHeader, usize) =
                                    bincode::decode_from_slice(&pcap_t.p_data, config)?;
                                let (header, _) = decode;
                                header.write(fs, pbo)?;
                            }
                            PcapType::Record => {
                                let decode: (PacketRecord, usize) =
                                    bincode::decode_from_slice(&pcap_t.p_data, config)?;
                                let (record, _) = decode;
                                record.write(fs, pbo)?;
                            }
                        }
                    }
                    None => return Err(PcaptureError::FileDescriptorDoesNotExist),
                }
            } else {
                return Err(PcaptureError::RecvDataIncorrectError {
                    recv_len,
                    decode_len,
                });
            }
        }
        Ok(())
    }
}
