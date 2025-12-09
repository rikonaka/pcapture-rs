use pcapture::Capture;
use pcapture::PcapByteOrder;
use pcapture::fs::pcapng::PcapNg;

fn main() {
    let path = "test.pcapng";
    let pbo = PcapByteOrder::WiresharkDefault;
    // You must specify the interface, the 'all' option is not supported.
    let mut cap = Capture::new("ens33").unwrap();
    // BPF syntax filter
    cap.set_filter("tcp port 80");
    // This step will generate the pcapng headers.
    let mut pcapng = cap.gen_pcapng_header(pbo).unwrap();
    let h_len = pcapng.blocks.len();

    let mut i = 0;
    for _ in 0..5 {
        let blocks = cap.fetch_as_pcapng().unwrap();
        for b in blocks {
            pcapng.append(b);
            i += 1;
        }
    }
    // write all capture packets to test.pcapng
    pcapng.write_all(path).unwrap();

    let read_pcapng = PcapNg::read_all(path, pbo).unwrap();
    // By default, epb (EnhancedPacketBlock) is used to store data instead of spb (SimplePacketBlock).
    // 1 shb (header) + x idb (interface infomation header) + i epb (traffic data)
    // | ------------------- h_len ---------------------- | + | ------ i ------- |
    assert_eq!(read_pcapng.blocks.len(), h_len + i);
}
