use pcapture::Capture;
use pcapture::PcapByteOrder;
use pcapture::fs::pcapng::PcapNg; // for read pcapng file

pub fn test1() {
    let path = "test.pcapng";
    let pbo = PcapByteOrder::WiresharkDefault;
    // You must specify the interface, the 'all' option is not supported.
    let mut cap = Capture::new("ens33").unwrap();
    // This step will generate the pcapng headers.
    let mut pcapng = cap.gen_pcapng_header(pbo).unwrap();
    let h_len = pcapng.blocks.len();

    for _ in 0..5 {
        let block = cap.next_as_pcapng().unwrap();
        pcapng.append(block);
    }
    // write all capture data to test.pcapng
    pcapng.write_all(path).unwrap();

    let read_pcapng = PcapNg::read_all(path, pbo).unwrap();
    // By default, epb (EnhancedPacketBlock) is used to store data instead of spb (SimplePacketBlock).
    // 1 shb (header) + x idb (interface infomation header) + 5 epb (traffic data)
    // | ------------------- h_len ---------------------- | + | ------ 5 ------- |
    assert_eq!(read_pcapng.blocks.len(), h_len + 5);
}
