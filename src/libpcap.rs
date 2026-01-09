#[cfg(all(unix, feature = "libpcap"))]
use libc::AF_INET;
#[cfg(all(unix, feature = "libpcap"))]
use libc::AF_INET6;
#[cfg(all(feature = "libpcap", all(unix, not(target_os = "linux"))))]
use libc::AF_LINK;
#[cfg(all(feature = "libpcap", target_os = "linux"))]
use libc::AF_PACKET;
#[cfg(all(feature = "libpcap", all(unix, not(target_os = "linux"))))]
use libc::sockaddr_dl;
#[cfg(all(unix, feature = "libpcap"))]
use libc::sockaddr_in;
#[cfg(all(unix, feature = "libpcap"))]
use libc::sockaddr_in6;
#[cfg(all(feature = "libpcap", target_os = "linux"))]
use libc::sockaddr_ll;
#[cfg(all(unix, feature = "libpcap"))]
use std::ffi::CStr;
#[cfg(all(unix, feature = "libpcap"))]
use std::ffi::CString;
#[cfg(all(unix, feature = "libpcap"))]
use std::fmt;
#[cfg(all(unix, feature = "libpcap"))]
use std::net::IpAddr;
#[cfg(all(unix, feature = "libpcap"))]
use std::net::Ipv4Addr;
#[cfg(all(unix, feature = "libpcap"))]
use std::net::Ipv6Addr;
#[cfg(all(unix, feature = "libpcap"))]
use std::os::raw::c_uchar;
#[cfg(all(unix, feature = "libpcap"))]
use std::sync::mpsc::Sender;
#[cfg(all(unix, feature = "libpcap"))]
use std::sync::mpsc::channel;
#[cfg(all(unix, feature = "libpcap"))]
use std::time::Duration;

#[cfg(all(unix, feature = "libpcap"))]
use crate::Device;
#[cfg(all(unix, feature = "libpcap"))]
use crate::PacketData;
#[cfg(all(unix, feature = "libpcap"))]
use crate::error::PcaptureError;

/// This value controls the time it takes to retrieve a value from the mpsc queue.
/// Normally, it would return immediately when there is a value in the queue.
/// And this value is only used to determine when the queue is empty.
#[cfg(all(unix, feature = "libpcap"))]
const DEFAULT_RECV_TIMEOUT: f32 = 0.001;

#[cfg(all(unix, feature = "libpcap"))]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
#[allow(unnecessary_transmutes)]
#[allow(dead_code)]
mod ffi {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

#[cfg(all(unix, feature = "libpcap"))]
extern "C" fn packet_handler(
    user: *mut c_uchar, // packets sender
    hdr: *const ffi::pcap_pkthdr,
    bytes: *const c_uchar,
) {
    if !user.is_null() {
        let sender = unsafe { &mut *(user as *mut Sender<PacketData>) };

        let hdr = unsafe { *hdr };
        let slice = unsafe { std::slice::from_raw_parts(bytes, hdr.len as usize) };

        let tv_sec = hdr.ts.tv_sec as u64;
        let tv_usec = hdr.ts.tv_usec as u64;
        // if_tsresol = 6 (default)
        #[cfg(feature = "pcapng")]
        let ts64 = (tv_sec as u64) * 1_000_000 + (tv_usec as u64);
        #[cfg(feature = "pcapng")]
        let ts_high = (ts64 >> 32) as u32;
        #[cfg(feature = "pcapng")]
        let ts_low = (ts64 & 0xFFFF_FFFF) as u32;

        let packet_data = PacketData {
            data: slice,
            #[cfg(feature = "pcapng")]
            ts_high,
            #[cfg(feature = "pcapng")]
            ts_low,
            #[cfg(feature = "pcap")]
            ts_sec: tv_sec as u32,
            #[cfg(feature = "pcap")]
            ts_usec: tv_usec as u32,
        };

        match sender.send(packet_data) {
            Ok(_) => (),
            Err(e) => {
                eprintln!("packet_handler: send packet_data error: {}", e);
            }
        }
    } else {
        panic!("packet_handler: user ptr is null");
    }
}

#[cfg(all(unix, feature = "libpcap"))]
#[derive(Debug, Clone, Copy)]
pub struct MacAddr {
    data: [u8; 8], // the default MAC address returned by libpcap is 8 bits
    size: usize,
}

#[cfg(all(unix, feature = "libpcap"))]
impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mac = self.data[0..self.size].to_vec();
        let mac_vec: Vec<String> = mac.iter().map(|x| format!("{:02X}", x)).collect();
        let output = mac_vec.join(":");
        write!(f, "{}", output)
    }
}

#[cfg(all(unix, feature = "libpcap"))]
impl MacAddr {
    /// Returns the bytes value of the MAC address.
    pub fn to_bytes(&self) -> [u8; 6] {
        // The last two digits of the MAC address are reserved fields,
        // so only the first six digits are returned here.
        let mut bytes = [0; 6];
        bytes.copy_from_slice(&self.data[0..6]);
        bytes
    }
}

#[cfg(all(unix, feature = "libpcap"))]
#[derive(Debug, Clone, Copy)]
pub enum Addr {
    IpAddr(IpAddr),
    MacAddr(MacAddr),
}

#[cfg(all(unix, feature = "libpcap"))]
impl fmt::Display for Addr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let output = match self {
            Addr::IpAddr(ip) => format!("ip({})", ip),
            Addr::MacAddr(mac) => format!("mac({})", mac),
        };
        write!(f, "{}", output)
    }
}

#[cfg(all(unix, feature = "libpcap"))]
#[derive(Debug, Clone, Copy)]
pub struct Addresses {
    pub addr: Option<Addr>,
    pub netmask: Option<Addr>,
    pub broadaddr: Option<Addr>,
    pub dstaddr: Option<Addr>,
}

#[cfg(all(unix, feature = "libpcap"))]
impl fmt::Display for Addresses {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut values = Vec::new();
        if let Some(addr) = self.addr {
            values.push(format!("addr: {}", addr));
        }
        if let Some(netmask) = self.netmask {
            values.push(format!("netmask: {}", netmask));
        }
        if let Some(broadaddr) = self.broadaddr {
            values.push(format!("broadaddr: {}", broadaddr));
        }
        if let Some(dstaddr) = self.dstaddr {
            values.push(format!("dstaddr: {}", dstaddr));
        }

        let output = values.join(", ");
        write!(f, "{}", output)
    }
}

#[cfg(all(unix, feature = "libpcap"))]
#[derive(Debug, Clone, Copy)]
pub(crate) struct Libpcap {
    pub total_captured: usize,
    handle: *mut ffi::pcap,
    filter_enabled: bool,
    bpf_program: ffi::bpf_program,
}

#[cfg(all(unix, feature = "libpcap"))]
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum DispatchStatus {
    Timeout,
    Normal,
}

#[cfg(all(unix, feature = "libpcap"))]
impl Libpcap {
    pub(crate) fn new(
        name: &str,
        snaplen: i32,
        promisc: bool,
        timeout_ms: i32,
        filter: Option<String>,
    ) -> Result<Self, PcaptureError> {
        let mut errbuf = [0i8; ffi::PCAP_ERRBUF_SIZE as usize];
        let mut net: ffi::bpf_u_int32 = 0;
        let mut mask: ffi::bpf_u_int32 = 0;

        let iface_cstr = CString::new(name)?;
        let iface_ptr = iface_cstr.as_ptr();

        let lookupnet_result =
            unsafe { ffi::pcap_lookupnet(iface_ptr, &mut net, &mut mask, errbuf.as_mut_ptr()) };
        if lookupnet_result == -1 {
            let msg = format!(
                "couldn't run pcap_lookupnet for device {}: {}",
                name,
                unsafe { CStr::from_ptr(errbuf.as_ptr()).to_string_lossy() }
            );
            return Err(PcaptureError::LibpcapError { msg });
        }

        let promisc = if promisc { 1 } else { 0 };
        let handle = unsafe {
            ffi::pcap_open_live(
                iface_ptr,
                snaplen,    // snaplen (suggest value: 65535)
                promisc,    // promisc (suggest value: 1)
                timeout_ms, // timeout ms (suggest value: 1000)
                errbuf.as_mut_ptr(),
            )
        };

        if handle.is_null() {
            let msg = format!("couldn't open device {}: {}", name, unsafe {
                std::ffi::CStr::from_ptr(errbuf.as_ptr()).to_string_lossy()
            });
            return Err(PcaptureError::LibpcapError { msg });
        }

        let mut bpf_program = ffi::bpf_program {
            bf_len: 0,
            bf_insns: std::ptr::null_mut(),
        };
        let mut filter_enabled = false;

        if let Some(filter) = filter {
            filter_enabled = true;
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

        Ok(Self {
            total_captured: 0,
            handle,
            filter_enabled,
            bpf_program,
        })
    }
    fn sockaddr_parser(addr: *mut ffi::sockaddr) -> Option<Addr> {
        if addr.is_null() {
            None
        } else {
            let sa_family = unsafe { (*addr).sa_family };
            // println!("sa_family: {}", sa_family);
            match sa_family as i32 {
                AF_INET => {
                    // IPv4
                    let sa_in_ptr = addr as *const sockaddr_in;
                    let sa_in = unsafe { *sa_in_ptr };
                    let mut ip_bytes = sa_in.sin_addr.s_addr.to_be_bytes();
                    ip_bytes.reverse();
                    let ip = IpAddr::V4(Ipv4Addr::from(ip_bytes));
                    Some(Addr::IpAddr(ip))
                }
                AF_INET6 => {
                    // IPv6
                    let sa_in6_ptr = addr as *const sockaddr_in6;
                    let sa_in6 = unsafe { *sa_in6_ptr };
                    let ip_bytes = sa_in6.sin6_addr.s6_addr;
                    let ip = IpAddr::V6(Ipv6Addr::from(ip_bytes));
                    Some(Addr::IpAddr(ip))
                }
                #[cfg(target_os = "linux")]
                AF_PACKET => {
                    // Mac
                    let sa_ll_ptr = addr as *const sockaddr_ll;
                    let sa_ll = unsafe { *sa_ll_ptr };
                    let ll_bytes = sa_ll.sll_addr;
                    let size = if ll_bytes[6] == 0 && ll_bytes[7] == 0 {
                        6
                    } else {
                        8
                    };

                    let mac = MacAddr {
                        data: ll_bytes,
                        size,
                    };
                    Some(Addr::MacAddr(mac))
                }
                #[cfg(all(unix, not(target_os = "linux")))]
                AF_LINK => {
                    // Mac
                    let sdl_ptr = addr as *const sockaddr_dl;
                    let sa_dl = unsafe { *sdl_ptr };
                    let sdl_data = sa_dl.sdl_data;
                    let nlen = sa_dl.sdl_nlen as usize;
                    let alen = sa_dl.sdl_alen as usize;
                    let dl_slice = &sdl_data[nlen..nlen + alen];
                    let mut dl_bytes = [0u8; 8];
                    for (dst, src) in dl_bytes.iter_mut().zip(dl_slice.iter()) {
                        *dst = *src as u8;
                    }

                    let mac = MacAddr {
                        data: dl_bytes,
                        size: alen,
                    };
                    Some(Addr::MacAddr(mac))
                }
                _ => None,
            }
        }
    }
    pub(crate) fn devices() -> Result<Vec<Device>, PcaptureError> {
        let mut errbuf = [0i8; ffi::PCAP_ERRBUF_SIZE as usize];
        let mut alldevs: *mut ffi::pcap_if_t = std::ptr::null_mut();

        let findalldevs_result =
            unsafe { ffi::pcap_findalldevs(&mut alldevs, errbuf.as_mut_ptr()) };
        if findalldevs_result == -1 {
            let msg = format!("pcap_findalldevs error: {}", unsafe {
                CStr::from_ptr(errbuf.as_ptr()).to_string_lossy()
            });
            // eprintln!("{}", msg);
            // return Vec::new();
            let err = PcaptureError::LibpcapError { msg };
            return Err(err);
        }

        if alldevs.is_null() {
            let msg = String::from("no device found");
            // eprintln!("{}", msg);
            // return Vec::new();
            let err = PcaptureError::LibpcapError { msg };
            return Err(err);
        }

        let mut devices = Vec::new();

        while !alldevs.is_null() {
            let name = if unsafe { (*alldevs).name.is_null() } {
                // normally this will not be executed
                panic!("every device should have an name");
            } else {
                let name = unsafe { CStr::from_ptr((*alldevs).name).to_string_lossy() };
                name.to_string()
            };

            let description = if unsafe { (*alldevs).description.is_null() } {
                None
            } else {
                let description =
                    unsafe { CStr::from_ptr((*alldevs).description).to_string_lossy() };
                Some(description.to_string())
            };

            let mut libpcap_addresses = unsafe { (*alldevs).addresses };
            let mut addresses = Vec::new();

            while !libpcap_addresses.is_null() {
                let addr = unsafe { (*libpcap_addresses).addr };
                let rust_addr = Libpcap::sockaddr_parser(addr);

                let netmask = unsafe { (*libpcap_addresses).netmask };
                let rust_netmask = Libpcap::sockaddr_parser(netmask);

                let broadaddr = unsafe { (*libpcap_addresses).broadaddr };
                let rust_broadaddr = Libpcap::sockaddr_parser(broadaddr);

                let dstaddr = unsafe { (*libpcap_addresses).dstaddr };
                let rust_dstaddr = Libpcap::sockaddr_parser(dstaddr);

                let ads = Addresses {
                    addr: rust_addr,
                    netmask: rust_netmask,
                    broadaddr: rust_broadaddr,
                    dstaddr: rust_dstaddr,
                };
                addresses.push(ads);

                libpcap_addresses = unsafe { (*libpcap_addresses).next };
            }

            let device = Device {
                name,
                description,
                addresses,
            };

            devices.push(device);
            alldevs = unsafe { (*alldevs).next };
        }

        unsafe {
            ffi::pcap_freealldevs(alldevs);
        }
        Ok(devices)
    }
    fn dispatch(
        &mut self,
        packet_sender: Sender<PacketData>,
    ) -> Result<DispatchStatus, PcaptureError> {
        // let user: *mut c_uchar = std::ptr::null_mut();
        let sender_boxed = Box::new(packet_sender);
        let user_ptr = Box::into_raw(sender_boxed) as *mut c_uchar;

        let n = unsafe { ffi::pcap_dispatch(self.handle, -1, Some(packet_handler), user_ptr) };
        // let n = unsafe { ffi::pcap_loop(self.handle, -1, Some(packet_handler), user_ptr) };

        if n < 0 {
            let err_ptr = unsafe { ffi::pcap_geterr(self.handle) };
            let msg = format!("dispatch error: {}", unsafe {
                CStr::from_ptr(err_ptr).to_string_lossy()
            });
            return Err(PcaptureError::LibpcapError { msg });
        } else if n == 0 {
            // timeout
            return Ok(DispatchStatus::Timeout);
        }

        self.total_captured += n as usize;

        Ok(DispatchStatus::Normal)
    }
    /// This function returns all data packets received in the system cache,
    /// instead of returning one at a time.
    pub(crate) fn fetch(&mut self) -> Result<Vec<PacketData<'_>>, PcaptureError> {
        let timeout = Duration::from_secs_f32(DEFAULT_RECV_TIMEOUT);
        let (sender, receiver) = channel();
        let n = self.dispatch(sender)?;
        if n != DispatchStatus::Timeout {
            let mut ret = Vec::new();
            loop {
                if let Ok(packet_data) = receiver.recv_timeout(timeout) {
                    ret.push(packet_data);
                } else {
                    // the cached data has been completely retrieved
                    break;
                }
            }
            Ok(ret)
        } else {
            Ok(Vec::new())
        }
    }
    pub(crate) fn stop(&mut self) -> Result<(), PcaptureError> {
        unsafe {
            ffi::pcap_close(self.handle);
            if self.filter_enabled {
                ffi::pcap_freecode(&mut self.bpf_program);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[cfg(all(unix, feature = "libpcap"))]
mod tests {
    use super::*;
    #[test]
    fn test_interfaces() {
        let interfaces = Libpcap::devices().unwrap();
        for i in interfaces {
            println!("{}", i.name);
            println!("{:?}", i.description);
            for a in &i.addresses {
                println!("+ {}", a);
            }
            println!(">>>>>>>>>>>>>>>>>>>>>>>");
        }
    }
    #[test]
    fn test_recv() {
        let iface = "ens33";
        let snaplen = 65535;
        let promisc = true;
        let timeout_ms = 1000;
        // let filter = Some("host 192.168.5.2");
        let filter = None;

        let mut lp = Libpcap::new(iface, snaplen, promisc, timeout_ms, filter).unwrap();

        for i in 0..5 {
            let ret = lp.fetch().unwrap();
            println!("fetch[{}] - packets len {}", i, ret.len());
        }

        lp.stop().unwrap();
    }
}
