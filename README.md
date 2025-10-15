# pcapture-rs

A new generation of traffic capture library based on `libpnet`.

This library requires root permissions.

## Compared to pcap

### [pcap](https://crates.io/crates/pcap)

Why not use pcap to capture packets?

The `pcap` library does not support filters, which is easy to understand. In order to implement packet filtering, we have to implement these functions ourselves (it will be very uncomfortable to use).

The third is that you need to install additional libraries (`libpcap` & `libpcap-dev`) to use the `pcap` library.

When I used this library, I found that due to the frequent switching between kernel mode and user mode, using this library would cause high CPU usage. And I can't solve it 😓. For large-scale and high-performance situations, please use the `pcap` library.

## Platform

| Platform           | Note              |
| :----------------- | :---------------- |
| Linux              | supported         |
| Unix (*BSD, MacOS) | supported         |
| Windows            | supported (npcap) |

## Usage

```toml
pcapture = "^0"
```

Or

```toml
pcapture = { version = "^0", features = ["pcapng"] }
```

The `pcap` format only.

```toml
pcapture = { version = "^0", features = ["pcap"] }
```

## Examples

### Very simple way to capture the packets as pcapng format

```rust
use pcapture::PcapByteOrder;
use pcapture::Capture;
use pcapture::fs::pcapng::PcapNg; // for read pcapng file

fn main() {
    let path = "test.pcapng";
    let pbo = PcapByteOrder::WiresharkDefault;
    /// You must specify the interface, the 'all' option is not supported.
    let mut cap = Capture::new("ens33");
    // This step will generate the pcapng headers.
    let mut pcapng = cap.gen_pcapng_headers(pbo).unwrap();
    let x = pcapng.blocks.len();

    match cap.ready() {
        Ok(_) => {
            for _ in 0..5 {
                let block = cap.next_as_pcapng().unwrap();
                pcapng.append(block);
            }
            /// write all capture data to test.pcapng
            pcapng.write_all(path).unwrap();

            let read_pcapng = PcapNg::read_all(path, pbo).unwrap();
            /// By default, epb (EnhancedPacketBlock) is used to store data instead of spb (SimplePacketBlock).
            /// 1 shb (header) + x idb (interface infomation header) + 5 epb (traffic data)
            assert_eq!(read_pcapng.blocks.len(), 1 + x + 5);
        }
        Err(e) => println!("capture error: {}", e),
    }    
}
```

### And also the pcap format

Since pcap uses a 16-bit timestamp, it will be exhausted in 2038 (although it sounds far away), so it is recommended to use pcapng now.

```rust
use pcapture::PcapByteOrder;
use pcapture::Capture;
use pcapture::pcap::Pcap; // for read pcap file

fn main() {
    let path = "test.pcap";
    let pbo = PcapByteOrder::WiresharkDefault;

    let mut cap = Capture::new("ens33");
    let mut pcap = cap.gen_pcap_header(pbo).unwrap();

    match cap.ready() {
        Ok(_) => {
            for _ in 0..5 {
                let record = cap.next_as_pcap().unwrap();
                pcap.append(record);
            }
            /// write all capture data to test.pcap
            pcap.write_all(path).unwrap();

            let read_pcap = Pcap::read_all(path, pbo).unwrap();
            /// The pcap file format and the pcapng file have completely different structures.
            /// And pcap has only one file header,
            /// but pcapng can have various headers with different functions.
            /// 5 records, you can access the file header through 'read_pcap.header'.
            assert_eq!(read_pcap.records.len(), 5);
        }
        Err(e) => println!("capture error: {}", e),
    }
}
```

### And the most important filter features

I implemented a simple expression filter using the Shunting Yard algorithm.

```rust
use pcapture::PcapByteOrder;
use pcapture::Capture;

fn main() {
    let path = "test.pcapng";
    let pbo = PcapByteOrder::WiresharkDefault;
    /// Building filters is very simple and easy to understand.
    /// And support protocol filtering.
    let filter = "tcp and (ip=192.168.1.1 and port=80)";
    /// Only support this bracket '(' in expression, but 'AND' and 'OR' support both uppercase and lowercase.
    /// More examples:
    // let filter = "tcp and (ip=192.168.1.1 or port=80)";
    // let filter = "icmp and ip=192.168.1.1";
    // let filter = "!icmp and ip=192.168.1.1"; // ! means not include any icmp packet
    // let filter = "icmp and ip!=192.168.1.1"; // != means not include any packet which addr is 192.168.1.1
    /// Other valid values:
    /// [mac, srcmac, dstmac, ip, addr, srcip, srcaddr, dstip, dstaddr, port, srcport, dstport]
    /// Note: the expression ip=192.168.1.1 is equal to addr=192.168.1.1

    /// You can use the following code to print all supported protocols.
    // use pcapture::filter;
    // let valid_procotol = filter::valid_protocol();
    // println!("{:?}", valid_procotol);

    let mut cap = Capture::new("ens33");
    cap.filter(filter);
    let mut pcapng = cap.gen_pcapng_header(pbo).unwrap();

    match cap.ready() {
        Ok(_) => {
            for _ in 0..5 {
                let block = cap.next_as_pcapng().unwrap();
                pcapng.append(block);
            }
            /// write all capture data to test.pcapng
            pcapng.write_all(path).unwrap();
        }
        Err(e) => println!("capture error: {}", e),
    }  
}
```

### Sometimes you just wanna write the packet to the disk immediately

The above examples all store the captured packets in memory and then write them to disk at once use `write_all` function, but this is not acceptable in practice, because this will cause a lot of memory usage on the server.

```rust
use std::fs::File;
use pcapture::PcapByteOrder;
use pcapture::Capture;

fn main() {
    let path = "test.pcapng";
    let pbo = PcapByteOrder::WiresharkDefault;
    let fs = File::create(path).unwrap();

    let mut cap = Capture::new("ens33");
    let mut pcapng = cap.gen_pcapng_header(pbo).unwrap();
    /// Write the pcapng headers to disk.
    pcapng.write(fs).unwrap();

    match cap.ready() {
        Ok(_) => {
            for _ in 0..5 {
                let block = cap.next_as_pcapng().unwrap();
                /// Accept one and write one.
                block.write(fs, pbo).unwrap();
            }
        }
        Err(e) => println!("capture error: {}", e),
    }  
}
```
