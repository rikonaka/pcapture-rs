use pcapture::Capture;
use pcapture::PcapByteOrder;
use std::fs::File;

fn main() {
    let path = "test.pcapng";
    let pbo = PcapByteOrder::WiresharkDefault;
    let mut fs = File::create(path).unwrap();

    let mut cap = Capture::new("ens33").unwrap();
    let pcapng = cap.gen_pcapng_header(pbo).unwrap();
    // Write the pcapng headers to disk.
    pcapng.write(&mut fs).unwrap();

    for _ in 0..5 {
        let block = cap.next_as_pcapng().unwrap();
        // Accept one and write one.
        block.write(&mut fs, pbo).unwrap();
    }
}
