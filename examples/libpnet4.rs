use pcapture::Capture;
use pcapture::PcapByteOrder;
use std::fs::File;

#[cfg(unix)]
fn main() {
    let path = "test.pcapng";
    let pbo = PcapByteOrder::WiresharkDefault;
    let mut fs = File::create(path).unwrap();

    #[cfg(target_os = "linux")]
    let mut cap = Capture::new("ens33").unwrap();
    #[cfg(target_os = "freebsd")]
    let mut cap = Capture::new("em0").unwrap();
    let pcapng = cap.gen_pcapng_header(pbo).unwrap();
    // Write the pcapng headers to disk.
    pcapng.write(&mut fs).unwrap();

    for _ in 0..5 {
        let block = cap.next_as_pcapng().unwrap();
        // Accept one and write one.
        block.write(&mut fs, pbo).unwrap();
    }
}

#[cfg(windows)]
fn main() {
    let path = "test.pcapng";
    let pbo = PcapByteOrder::WiresharkDefault;
    let mut fs = File::create(path).unwrap();

    let mut cap = Capture::new("\\Device\\NPF_{D98754DF-65FB-4A23-B6F1-8C386EACE452}").unwrap();
    let pcapng = cap.gen_pcapng_header(pbo).unwrap();
    // Write the pcapng headers to disk.
    pcapng.write(&mut fs).unwrap();

    for _ in 0..5 {
        let block = cap.next_as_pcapng().unwrap();
        // Accept one and write one.
        block.write(&mut fs, pbo).unwrap();
    }
}
