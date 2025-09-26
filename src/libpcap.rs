use std::os::raw::c_uchar;

#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
#[allow(unnecessary_transmutes)]
mod ffi {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

extern "C" fn packet_handler(
    _user: *mut c_uchar,
    h: *const ffi::pcap_pkthdr,
    bytes: *const c_uchar,
) {
    unsafe {
        let hdr = *h;
        println!("Got a packet! Length: {}", hdr.len);

        // let slice = std::slice::from_raw_parts(bytes, hdr.len as usize);
        // for b in slice.iter().take(16) {
        //     print!("{:02x} ", b);
        // }
        // println!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;
    #[test]
    fn test() {
        unsafe {
            let mut errbuf = [0i8; ffi::PCAP_ERRBUF_SIZE as usize];
            let mut alldevs: *mut ffi::pcap_if_t = std::ptr::null_mut();

            if ffi::pcap_findalldevs(&mut alldevs, errbuf.as_mut_ptr()) == -1 {
                eprintln!(
                    "Error in pcap_findalldevs: {}",
                    CStr::from_ptr(errbuf.as_ptr()).to_string_lossy()
                );
                return;
            }

            if alldevs.is_null() {
                eprintln!("No devices found");
                return;
            }

            // use the first dev as default dev
            let dev = (*alldevs).name;
            let name = CStr::from_ptr(dev).to_string_lossy();
            println!("First device name = {}", name);

            let mut net: ffi::bpf_u_int32 = 0;
            let mut mask: ffi::bpf_u_int32 = 0;

            if ffi::pcap_lookupnet(dev, &mut net, &mut mask, errbuf.as_mut_ptr()) == -1 {
                eprintln!(
                    "Couldn't get netmask for device {}: {}",
                    CStr::from_ptr(dev).to_string_lossy(),
                    CStr::from_ptr(errbuf.as_ptr()).to_string_lossy()
                );
                return;
            }

            let handle = ffi::pcap_open_live(
                dev,
                65535, // snaplen
                1,     // promisc
                1000,  // timeout ms
                errbuf.as_mut_ptr(),
            );
            if handle.is_null() {
                eprintln!(
                    "Couldn't open device: {}",
                    std::ffi::CStr::from_ptr(errbuf.as_ptr()).to_str().unwrap()
                );
                return;
            }

            let ret = ffi::pcap_dispatch(handle, -1, Some(packet_handler), std::ptr::null_mut());

            if ret < 0 {
                eprintln!("Error in pcap_dispatch: {}", ret);
            } else {
                println!("pcap_dispatch processed {} packets", ret);
            }

            // 4. 关闭
            ffi::pcap_freealldevs(alldevs);
            ffi::pcap_close(handle);
        }
    }
}
