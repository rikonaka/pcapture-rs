use pcapture::PcapByteOrder;
use pcapture::Capture;

pub fn test3() {
    let path = "test.pcapng";
    let pbo = PcapByteOrder::WiresharkDefault;
    // Building filters is very simple and easy to understand.
    // And support protocol filtering.
    let filter = "tcp and (ip=192.168.1.1 and port=80)";
    // Only support this bracket '(' in expression, but 'AND' and 'OR' support both uppercase and lowercase.
    // More examples:
    // let filter = "tcp and (ip=192.168.1.1 or port=80)";
    // let filter = "icmp and ip=192.168.1.1";
    // let filter = "!icmp and ip=192.168.1.1"; // ! means not include any icmp packet
    // let filter = "icmp and ip!=192.168.1.1"; // != means not include any packet which addr is 192.168.1.1
    // Other valid values:
    // [mac, srcmac, dstmac, ip, addr, srcip, srcaddr, dstip, dstaddr, port, srcport, dstport]
    // Note: the expression ip=192.168.1.1 is equal to addr=192.168.1.1

    // You can use the following code to print all supported protocols.
    // use pcapture::filter;
    // let valid_procotol = filter::valid_protocol();
    // println!("{:?}", valid_procotol);

    let mut cap = Capture::new("ens33").unwrap();
    cap.filter(filter).unwrap();
    let mut pcapng = cap.gen_pcapng_header(pbo).unwrap();

    for _ in 0..5 {
        let block = cap.next_as_pcapng().unwrap();
        pcapng.append(block);
    }
    // write all capture data to test.pcapng
    pcapng.write_all(path).unwrap();
}