use std::collections::VecDeque;
use std::ffi::CStr;
use std::ffi::CString;
use std::os::raw::c_uchar;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::Mutex;

use crate::error::PcaptureError;

#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
#[allow(unnecessary_transmutes)]
mod ffi {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

pub static PACKET_PIPE: LazyLock<Arc<Mutex<VecDeque<LibpcapData>>>> =
    LazyLock::new(|| Arc::new(Mutex::new(VecDeque::new())));

pub struct LibpcapData {
    pub data: Vec<u8>,
    pub tv_sec: i64,
    pub tv_usec: i64,
}

extern "C" fn packet_handler(
    _user: *mut c_uchar, // packet count
    hdr: *const ffi::pcap_pkthdr,
    bytes: *const c_uchar,
) {
    // if !user.is_null() {
    //     let user_ptr = user as *mut usize;
    //     unsafe {
    //         (*user_ptr) += 1;
    //     };
    // }

    let hdr = unsafe { *hdr };
    let slice = unsafe { std::slice::from_raw_parts(bytes, hdr.len as usize) };

    let data = LibpcapData {
        data: slice.to_vec(),
        tv_sec: hdr.ts.tv_sec,
        tv_usec: hdr.ts.tv_usec,
    };

    match PACKET_PIPE.lock() {
        Ok(mut pipe) => pipe.push_back(data),
        Err(e) => eprintln!("lock PIPE failed: {}", e),
    }
}

pub struct Libpcap {
    handle: *mut ffi::pcap,
    pub total: usize,
}

impl Drop for Libpcap {
    fn drop(&mut self) {
        unsafe {
            ffi::pcap_close(self.handle);
        }
    }
}

impl Libpcap {
    pub fn interfaces() -> Result<Vec<String>, PcaptureError> {
        let mut errbuf = [0i8; ffi::PCAP_ERRBUF_SIZE as usize];
        let mut alldevs: *mut ffi::pcap_if_t = std::ptr::null_mut();

        let findalldevs_result =
            unsafe { ffi::pcap_findalldevs(&mut alldevs, errbuf.as_mut_ptr()) };
        if findalldevs_result == -1 {
            let msg = format!("pcap_findalldevs error: {}", unsafe {
                CStr::from_ptr(errbuf.as_ptr()).to_string_lossy()
            });
            return Err(PcaptureError::LibpcapError { msg });
        }

        if alldevs.is_null() {
            let msg = String::from("no device found");
            return Err(PcaptureError::LibpcapError { msg });
        }

        let mut p = alldevs;
        let mut devices = Vec::new();
        while !p.is_null() {
            let device = unsafe { CStr::from_ptr((*p).name).to_string_lossy() };
            devices.push(device.to_string());
            p = unsafe { (*p).next };
        }

        unsafe {
            ffi::pcap_freealldevs(alldevs);
        }
        Ok(devices)
    }
    pub fn start(
        &mut self,
        iface: &str,
        snaplen: usize,
        promisc: bool,
        timeout_ms: usize,
        filter: Option<String>,
    ) -> Result<(), PcaptureError> {
        let mut errbuf = [0i8; ffi::PCAP_ERRBUF_SIZE as usize];
        let mut net: ffi::bpf_u_int32 = 0;
        let mut mask: ffi::bpf_u_int32 = 0;

        let iface_cstr = CString::new(iface)?;
        let iface_ptr = iface_cstr.as_ptr();

        let lookupnet_result =
            unsafe { ffi::pcap_lookupnet(iface_ptr, &mut net, &mut mask, errbuf.as_mut_ptr()) };
        if lookupnet_result == -1 {
            let msg = format!(
                "couldn't run pcap_lookupnet for device {}: {}",
                iface,
                unsafe { CStr::from_ptr(errbuf.as_ptr()).to_string_lossy() }
            );
            return Err(PcaptureError::LibpcapError { msg });
        }

        let promisc = if promisc { 1 } else { 0 };
        let handle = unsafe {
            ffi::pcap_open_live(
                iface_ptr,
                snaplen as i32,    // snaplen (suggest value: 65535)
                promisc,           // promisc (suggest value: 1)
                timeout_ms as i32, // timeout ms (suggest value: 1000)
                errbuf.as_mut_ptr(),
            )
        };

        if handle.is_null() {
            let msg = format!("couldn't open device {}: {}", iface, unsafe {
                std::ffi::CStr::from_ptr(errbuf.as_ptr()).to_string_lossy()
            });
            return Err(PcaptureError::LibpcapError { msg });
        }
        self.handle = handle;

        if let Some(filter) = filter {
            let mut bpf_program = ffi::bpf_program {
                bf_len: 0,
                bf_insns: std::ptr::null_mut(),
            };

            let filter_cstr = std::ffi::CString::new(filter)?;
            let netmask: u32 = 0;
            let compile_result = unsafe {
                ffi::pcap_compile(
                    handle,
                    &mut bpf_program,
                    filter_cstr.as_ptr(),
                    1, // optimize: true
                    netmask,
                )
            };
            if compile_result < 0 {
                let err_ptr = unsafe { ffi::pcap_geterr(handle) };
                let msg = format!("compile filter failed: {}", unsafe {
                    CStr::from_ptr(err_ptr).to_string_lossy()
                });
                return Err(PcaptureError::LibpcapError { msg });
            }

            let setfilter_result = unsafe { ffi::pcap_setfilter(handle, &mut bpf_program) };
            if setfilter_result < 0 {
                let err_ptr = unsafe { ffi::pcap_geterr(handle) };
                let msg = format!("set filter failed: {}", unsafe {
                    CStr::from_ptr(err_ptr).to_string_lossy()
                });
                unsafe {
                    ffi::pcap_freecode(&mut bpf_program);
                }
                return Err(PcaptureError::LibpcapError { msg });
            }
        }

        let user: *mut c_uchar = std::ptr::null_mut();
        // let user: *mut usize = &mut self.total;
        // let user = user as *mut c_uchar;

        loop {
            let ret = unsafe { ffi::pcap_dispatch(handle, -1, Some(packet_handler), user) };
            if ret < 0 {
                let msg = format!("pcap_dispatch error: {}", ret);
                return Err(PcaptureError::LibpcapError { msg });
            }

            self.total += ret as usize;
        }

        // auto close and free when struct droped
        // ffi::pcap_freealldevs(alldevs);
        // ffi::pcap_close(handle);
        // Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
