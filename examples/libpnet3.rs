use pcapture::Capture;
use pcapture::PcapByteOrder;

#[cfg(unix)]
fn main() {
    let path = "test.pcapng";
    let pbo = PcapByteOrder::WiresharkDefault;
    // BPF syntax filter
    let filter = "tcp and (host 192.168.1.1 and port 80)";

    #[cfg(target_os = "linux")]
    let mut cap = Capture::new("ens33").unwrap();
    #[cfg(target_os = "freebsd")]
    let mut cap = Capture::new("em0").unwrap();
    cap.set_filter(filter).unwrap();
    let mut pcapng = cap.gen_pcapng_header(pbo).unwrap();

    for _ in 0..5 {
        let block = cap.next_as_pcapng().unwrap();
        pcapng.append(block);
    }
    // write all capture data to test.pcapng
    pcapng.write_all(path).unwrap();
}

#[cfg(windows)]
fn main() {
    let path = "test.pcapng";
    let pbo = PcapByteOrder::WiresharkDefault;
    // BPF syntax filter
    let filter = "tcp and (host 192.168.1.1 and port 80)";

    let mut cap = Capture::new("\\Device\\NPF_{D98754DF-65FB-4A23-B6F1-8C386EACE452}").unwrap();
    cap.set_filter(filter).unwrap();
    let mut pcapng = cap.gen_pcapng_header(pbo).unwrap();

    for _ in 0..5 {
        let block = cap.next_as_pcapng().unwrap();
        pcapng.append(block);
    }
    // write all capture data to test.pcapng
    pcapng.write_all(path).unwrap();
}
