#[cfg(unix)]
use pcapture::Capture;
#[cfg(unix)]
use pcapture::PcapByteOrder;

#[cfg(unix)]
fn main() {
    let pbo = PcapByteOrder::WiresharkDefault;
    // You must specify the interface, the 'all' option is not supported.
    #[cfg(target_os = "linux")]
    let mut cap = Capture::new("ens33").unwrap();
    // let mut cap = Capture::new("eth0").unwrap();
    #[cfg(target_os = "freebsd")]
    let mut cap = Capture::new("em0").unwrap();
    // BPF syntax filter
    cap.set_filter("arp");
    // This step will generate the pcapng headers.
    let mut pcapng = cap.gen_pcapng_header(pbo).unwrap();

    let mut i = 0;
    loop {
        let blocks = cap.fetch_as_pcapng().unwrap();
        for b in blocks {
            pcapng.append(b);
            i += 1;
        }
        println!("captured {} packets", i);
    }
}

#[cfg(windows)]
fn main() {
    println!("This example is disabled on Windows");
}
