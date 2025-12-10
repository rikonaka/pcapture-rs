use pcapture::PcapByteOrder;
use pcapture::Capture;
use pcapture::fs::pcap::Pcap; // for read pcap file

#[cfg(unix)]
fn main() {
    let path = "test.pcap";
    let pbo = PcapByteOrder::WiresharkDefault;

    let mut cap = Capture::new("ens33").unwrap();
    let mut pcap = cap.gen_pcap_header(pbo).unwrap();

    for _ in 0..5 {
        let record = cap.next_as_pcap().unwrap();
        pcap.append(record);
    }
    // write all capture packets to test.pcap
    pcap.write_all(path).unwrap();

    let read_pcap = Pcap::read_all(path, pbo).unwrap();
    // The pcap file format and the pcapng file have completely different structures.
    // And pcap has only one file header,
    // but pcapng can have various headers with different functions.
    // 5 records, you can access the file header through 'read_pcap.header'.
    assert_eq!(read_pcap.records.len(), 5);
}

#[cfg(windows)]
fn main() {
    let path = "test.pcap";
    let pbo = PcapByteOrder::WiresharkDefault;

    let mut cap = Capture::new("\\Device\\NPF_{D98754DF-65FB-4A23-B6F1-8C386EACE452}").unwrap();
    let mut pcap = cap.gen_pcap_header(pbo).unwrap();

    for _ in 0..5 {
        let record = cap.next_as_pcap().unwrap();
        pcap.append(record);
    }
    // write all capture packets to test.pcap
    pcap.write_all(path).unwrap();

    let read_pcap = Pcap::read_all(path, pbo).unwrap();
    // The pcap file format and the pcapng file have completely different structures.
    // And pcap has only one file header,
    // but pcapng can have various headers with different functions.
    // 5 records, you can access the file header through 'read_pcap.header'.
    assert_eq!(read_pcap.records.len(), 5);
}