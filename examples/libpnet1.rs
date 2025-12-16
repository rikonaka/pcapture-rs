use pcapture::Capture;
use pcapture::PcapByteOrder;
use pcapture::fs::pcapng::PcapNg; // for read pcapng file

#[cfg(unix)]
fn main() {
    let path = "test.pcapng";
    let pbo = PcapByteOrder::WiresharkDefault;
    // You must specify the interface, the 'all' option is not supported.
    #[cfg(target_os = "linux")]
    let mut cap = Capture::new("ens33").unwrap();
    #[cfg(target_os = "freebsd")]
    let mut cap = Capture::new("em0").unwrap();
    // This step will generate the pcapng headers.
    let mut pcapng = cap.gen_pcapng_header(pbo).unwrap();
    let h_len = pcapng.blocks.len();

    for _ in 0..5 {
        let block = cap.next_as_pcapng().unwrap();
        pcapng.append(block);
    }
    // write all capture packets to test.pcapng
    pcapng.write_all(path).unwrap();

    let read_pcapng = PcapNg::read_all(path, pbo).unwrap();
    // By default, epb (EnhancedPacketBlock) is used to store packets instead of spb (SimplePacketBlock).
    // 1 shb (header) + x idb (interface infomation header) + 5 epb (traffic data)
    // | ------------------- h_len ---------------------- | + | ------ 5 ------- |
    assert_eq!(read_pcapng.blocks.len(), h_len + 5);
}

#[cfg(windows)]
fn main() {
    let path = "test.pcapng";
    let pbo = PcapByteOrder::WiresharkDefault;
    // You must specify the interface, the 'all' option is not supported.
    let mut cap = Capture::new("\\Device\\NPF_{D98754DF-65FB-4A23-B6F1-8C386EACE452}").unwrap();
    // This step will generate the pcapng headers.
    let mut pcapng = cap.gen_pcapng_header(pbo).unwrap();
    let h_len = pcapng.blocks.len();

    for _ in 0..5 {
        let block = cap.next_as_pcapng().unwrap();
        pcapng.append(block);
    }
    // write all capture packets to test.pcapng
    pcapng.write_all(path).unwrap();

    let read_pcapng = PcapNg::read_all(path, pbo).unwrap();
    // By default, epb (EnhancedPacketBlock) is used to store packets instead of spb (SimplePacketBlock).
    // 1 shb (header) + x idb (interface infomation header) + 5 epb (traffic data)
    // | ------------------- h_len ---------------------- | + | ------ 5 ------- |
    assert_eq!(read_pcapng.blocks.len(), h_len + 5);
}
