use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::NetworkInterface;
use pnet::ipnetwork::IpNetwork;
use pnet::util::MacAddr;

pub mod error;

static DEFAULT_BUFFER_SIZE: usize = 4096;
static DEFAULT_TIMEOUT: f32 = 1.0;

#[derive(Debug, Clone)]
pub struct Device {
    pub name: String,
    pub desc: Option<String>,
    pub ips: Vec<IpNetwork>,
    pub mac: Option<MacAddr>,
}

impl Device {
    pub fn list() -> Vec<Device> {
        let ni = datalink::interfaces();
        let mut ret = Vec::new();
        for n in ni {
            let name = n.name;
            let desc = if n.description.len() > 0 {
                Some(n.description)
            } else {
                None
            };
            let mac = n.mac;
            let ips = n.ips;

            let d = Device {
                name,
                desc,
                mac,
                ips,
            };
            ret.push(d);
        }
        ret
    }
}

pub struct Capture {
    interface: NetworkInterface,
    buffer_size: usize,
    timeout: f32,
}

impl Capture {
    pub fn init(iface_name: &str) -> Option<Capture> {
        let ni = datalink::interfaces();
        for n in ni {
            if n.name == iface_name {
                let c = Capture {
                    interface: n,
                    buffer_size: DEFAULT_BUFFER_SIZE,
                    timeout: DEFAULT_TIMEOUT,
                };
                return Some(c);
            }
        }
        None
    }
    pub fn buffer_size(&mut self, buffer_size: usize) {
        self.buffer_size = buffer_size;
    }
    /// timeout as sec
    pub fn timeout(&mut self, timeout: f32) {
        self.timeout = timeout;
    }
}

pub fn capture(iface_name: &str) {
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .filter(|iface: &NetworkInterface| iface.name == iface_name)
        .next()
        .unwrap_or_else(|| panic!("No such network interface: {}", iface_name));

    let cfg = datalink::Config::default();
    let (_, mut rx) = match datalink::channel(&interface, cfg) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("packetdump: unhandled channel type"),
        Err(e) => panic!("packetdump: unable to create channel: {}", e),
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test() {
        let ni = datalink::interfaces();
        for n in ni {
            println!("{:?}", n);
        }
    }
}
