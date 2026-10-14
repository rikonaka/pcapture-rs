//! Demonstrates `Capture::set_cbpf_filter`: a full pcap-filter expression, compiled by the `cbpf-rs` crate and attached directly to the kernel (`SO_ATTACH_FILTER`). 
//! 
//! Needs root (`CAP_NET_RAW`, for the raw socket `libpnet` opens) and Linux. Run on `lo`, so no
//! real NIC is needed - it sends its own test traffic from a background thread:
//!
//! ```text
//! sudo cargo run --example libpnet5 --features cbpf-filter
//! ```

use pcapture::Capture;
use pcapture::error::PcaptureError;
use std::io::ErrorKind;
use std::net::UdpSocket;
use std::thread;
use std::time::Duration;

const IFACE: &str = "lo";
const FILTER: &str = "udp port 9001";

fn main() {
    let mut cap = Capture::new(IFACE).expect("open capture");
    cap.set_cbpf_filter(FILTER).expect("compile and attach the cbpf-rs filter");
    println!("attached '{FILTER}' to the kernel via cbpf-rs\n");

    thread::spawn(|| {
        thread::sleep(Duration::from_millis(300));
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
        for port in [9000u16, 9001, 9002] {
            println!("sending a UDP packet to 127.0.0.1:{port}");
            sock.send_to(b"hello", ("127.0.0.1", port)).expect("send");
            thread::sleep(Duration::from_millis(100));
        }
    });

    println!("\nlistening on '{IFACE}' for 2s (filter: '{FILTER}')...\n");
    // `next_as_vec()` loops internally until a packet arrives, with no way to see a read timeout
    // from outside - so the deadline below is checked against the lower-level `next()` instead,
    // which does surface one.
    cap.set_timeout(0.2);
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let mut captured = 0usize;
    while std::time::Instant::now() < deadline {
        match cap.next() {
            Ok(packet) => {
                captured += 1;
                println!("captured: {} bytes (frame #{captured})", packet.data.len());
            }
            Err(PcaptureError::IOError(e)) if e.kind() == ErrorKind::TimedOut => continue,
            Err(e) => {
                eprintln!("read error: {e}");
                break;
            }
        }
    }

    println!("\n{captured} frame(s) reached userspace - every one should be the port-9001 packet");
}
