#[cfg(feature = "libpcap")]
use libc::AF_INET;
#[cfg(feature = "libpcap")]
use libc::AF_INET6;
#[cfg(all(feature = "libpcap", any(target_os = "freebsd", target_os = "macos")))]
use libc::AF_LINK;
#[cfg(all(feature = "libpcap", target_os = "linux"))]
use libc::AF_PACKET;
#[cfg(all(feature = "libpcap", any(target_os = "freebsd", target_os = "macos")))]
use libc::sockaddr_dl;
#[cfg(feature = "libpcap")]
use libc::sockaddr_in;
#[cfg(feature = "libpcap")]
use libc::sockaddr_in6;
#[cfg(feature = "libpcap")]
use libc::sockaddr_ll;
#[cfg(feature = "libpcap")]
use std::ffi::CStr;
#[cfg(feature = "libpcap")]
use std::ffi::CString;
#[cfg(feature = "libpcap")]
use std::fmt;
#[cfg(feature = "libpcap")]
use std::net::IpAddr;
#[cfg(feature = "libpcap")]
use std::net::Ipv4Addr;
#[cfg(feature = "libpcap")]
use std::net::Ipv6Addr;
#[cfg(feature = "libpcap")]
use std::os::raw::c_uchar;
#[cfg(feature = "libpcap")]
use std::sync::mpsc::Receiver;
#[cfg(feature = "libpcap")]
use std::sync::mpsc::Sender;
#[cfg(feature = "libpcap")]
use std::time::Duration;

#[cfg(feature = "libpcap")]
use crate::Device;
#[cfg(feature = "libpcap")]
use crate::PacketData;
#[cfg(feature = "libpcap")]
use crate::error::PcaptureError;

#[cfg(feature = "libpcap")]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
#[allow(unnecessary_transmutes)]
mod ffi {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

#[cfg(feature = "libpcap")]
extern "C" fn packet_handler(
    user: *mut c_uchar, // packet count
    hdr: *const ffi::pcap_pkthdr,
    bytes: *const c_uchar,
) {
    if !user.is_null() {
        let sender = unsafe { &mut *(user as *mut Sender<PacketData>) };

        let hdr = unsafe { *hdr };
        let slice = unsafe { std::slice::from_raw_parts(bytes, hdr.len as usize) };

        let tv_sec = hdr.ts.tv_sec;
        let tv_usec = hdr.ts.tv_usec;

        let packet_data = PacketData {
            data: slice,
            iface_id: 0, // fake id, assign with true value when recv from receiver
            tv_sec,
            tv_usec,
        };

        let _ = sender.send(packet_data);
    }
}

#[cfg(feature = "libpcap")]
#[derive(Debug, Clone, Copy)]
pub struct MacAddr {
    data: [u8; 8], // the default MAC address returned by libpcap is 8 bits
    size: usize,
}

#[cfg(feature = "libpcap")]
impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mac = self.data[0..self.size].to_vec();
        let mac_vec: Vec<String> = mac.iter().map(|x| format!("{:02X}", x)).collect();
        let output = mac_vec.join(":");
        write!(f, "{}", output)
    }
}

#[cfg(feature = "libpcap")]
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

#[cfg(feature = "libpcap")]
#[derive(Debug, Clone, Copy)]
pub enum Addr {
    IpAddr(IpAddr),
    MacAddr(MacAddr),
}

#[cfg(feature = "libpcap")]
impl fmt::Display for Addr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let output = match self {
            Addr::IpAddr(ip) => format!("ip({})", ip),
            Addr::MacAddr(mac) => format!("mac({})", mac),
        };
        write!(f, "{}", output)
    }
}

#[cfg(feature = "libpcap")]
#[derive(Debug, Clone, Copy)]
pub struct Addresses {
    pub addr: Option<Addr>,
    pub netmask: Option<Addr>,
    pub broadaddr: Option<Addr>,
    pub dstaddr: Option<Addr>,
}

#[cfg(feature = "libpcap")]
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

#[cfg(feature = "libpcap")]
#[derive(Debug, Clone)]
pub struct Libpcap {
    pub total_captured: usize,
    handle: *mut ffi::pcap,
    filter_enabled: bool,
    bpf_program: ffi::bpf_program,
}

#[cfg(feature = "libpcap")]
impl Libpcap {
    pub fn new() -> Libpcap {
        Libpcap {
            total_captured: 0,
            handle: std::ptr::null_mut(),
            filter_enabled: false,
            bpf_program: ffi::bpf_program {
                bf_len: 0,
                bf_insns: std::ptr::null_mut(),
            },
        }
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
                #[cfg(any(target_os = "freebsd", target_os = "macos"))]
                AF_LINK => {
                    // Mac
                    let sa_dl_ptr = addr as *const sockaddr_dl;
                    let sa_dl = *sa_dl_ptr;
                    let dl_bytes = sa_dl.sll_addr;
                    let mac = MacAddr(dl_bytes);
                    Some(Addr::MacAddr(mac))
                }
                _ => None,
            }
        }
    }
    pub fn devices() -> Vec<Device> {
        let mut errbuf = [0i8; ffi::PCAP_ERRBUF_SIZE as usize];
        let mut alldevs: *mut ffi::pcap_if_t = std::ptr::null_mut();

        let findalldevs_result =
            unsafe { ffi::pcap_findalldevs(&mut alldevs, errbuf.as_mut_ptr()) };
        if findalldevs_result == -1 {
            let msg = format!("pcap_findalldevs error: {}", unsafe {
                CStr::from_ptr(errbuf.as_ptr()).to_string_lossy()
            });
            eprintln!("{}", msg);
            return Vec::new();
        }

        if alldevs.is_null() {
            let msg = String::from("no device found");
            eprintln!("{}", msg);
            return Vec::new();
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
        devices
    }
    pub fn ready(
        &mut self,
        name: &str,
        snaplen: i32,
        promisc: bool,
        timeout_ms: i32,
        filter: Option<&str>,
    ) -> Result<(), PcaptureError> {
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

        self.handle = handle;
        self.filter_enabled = filter_enabled;
        self.bpf_program = bpf_program;

        Ok(())
    }
    pub fn next(&mut self, packet_sender: Sender<PacketData>) -> Result<(), PcaptureError> {
        // let user: *mut c_uchar = std::ptr::null_mut();
        let tx_boxed = Box::new(packet_sender);
        let user = Box::into_raw(tx_boxed) as *mut c_uchar;

        let packets = unsafe { ffi::pcap_dispatch(self.handle, -1, Some(packet_handler), user) };
        if packets < 0 {
            let msg = format!("pcap_dispatch error: {}", packets);
            return Err(PcaptureError::LibpcapError { msg });
        }

        self.total_captured += packets as usize;

        Ok(())
    }
    pub fn stop(&mut self) -> Result<(), PcaptureError> {
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
#[cfg(feature = "libpcap")]
mod tests {
    use super::*;
    use std::sync::mpsc::channel;
    #[test]
    fn test_interfaces() {
        let interfaces = Libpcap::devices();
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
    fn test_sender() {
        let iface = "ens33";
        let snaplen = 65535;
        let promisc = true;
        let timeout_ms = 1000;
        let filter = None;

        let (sender, receiver) = channel();
        let mut lp = Libpcap::new();

        lp.ready(iface, snaplen, promisc, timeout_ms, filter)
            .unwrap();

        for _ in 0..5 {
            let packet_data = lp.next(sender).unwrap();
            println!("packet_data len: {}", packet_data.data.len());
        }

        let _ = Libpcap::stop(tx);
    }
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
