use pnet::datalink::MacAddr;
use pnet::packet::Packet;
use pnet::packet::ethernet::EtherType;
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ip::IpNextHeaderProtocol;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::sync::LazyLock;

use crate::PcaptureError;

#[derive(Debug, Clone, Copy)]
pub enum Protocol {
    Layer3(EtherType),
    Layer4(IpNextHeaderProtocol),
}

impl Protocol {
    fn convert(procotol: &str) -> Option<Self> {
        match PROCOTOL_NAME
            .iter()
            .position(|&x| x.to_lowercase() == procotol.to_lowercase())
        {
            Some(index) => Some(PROCOTOL_TYPE[index]),
            None => None,
        }
    }
}

static PROCOTOL_NAME: LazyLock<Vec<&str>> = LazyLock::new(|| {
    vec![
        "Ipv4",
        "Arp",
        "WakeOnLan",
        "Trill",
        "DECnet",
        "Rarp",
        "AppleTalk",
        "Aarp",
        "Ipx",
        "Qnx", // Qnx Qnet
        "Ipv6",
        "FlowControl",
        "CobraNet",
        "Mpls",
        "MplsMcast",
        "PppoeDiscovery",
        "PppoeSession",
        "Vlan",
        "PBridge",
        "Lldp",
        "PtpoE", // Precision Time Protocol (PTP) over Ethernet
        "Cfm",
        "QinQ",
        "Hopopt",
        "Icmp",
        "Igmp",
        "Ggp",
        "Ipv4encapsulation", // encapsulation
        "St",
        "Tcp",
        "Cbt",
        "Egp",
        "Igp",
        "BbnRccMon",
        "NvpII",
        "Pup",
        "Argus",
        "Emcon",
        "Xnet",
        "Chaos",
        "Udp",
        "Mux",
        "DcnMeas",
        "Hmp",
        "Prm",
        "XnsIdp",
        "Trunk1",
        "Trunk2",
        "Leaf1",
        "Leaf2",
        "Rdp",
        "Irtp",
        "IsoTp4",
        "Netblt",
        "MfeNsp",
        "MeritInp",
        "Dccp",
        "ThreePc",
        "Idpr",
        "Xtp",
        "Ddp",
        "IdprCmtp",
        "TpPlusPlus",
        "Il",
        "Ipv6encapsulation", // encapsulation
        "Sdrp",
        "Ipv6Route",
        "Ipv6Frag",
        "Idrp",
        "Rsvp",
        "Gre",
        "Dsr",
        "Bna",
        "Esp",
        "Ah",
        "INlsp",
        "Swipe",
        "Narp",
        "Mobile",
        "Tlsp",
        "Skip",
        "Icmpv6",
        "Ipv6NoNxt",
        "Ipv6Opts",
        "HostInternal",
        "Cftp",
        "LocalNetwork",
        "SatExpak",
        "Kryptolan",
        "Rvd",
        "Ippc",
        "DistributedFs",
        "SatMon",
        "Visa",
        "Ipcv",
        "Cpnx",
        "Cphb",
        "Wsn",
        "Pvp",
        "BrSatMon",
        "SunNd",
        "WbMon",
        "WbExpak",
        "IsoIp",
        "Vmtp",
        "SecureVmtp",
        "Vines",
        "TtpOrIptm",
        "NsfnetIgp",
        "Dgp",
        "Tcf",
        "Eigrp",
        "OspfigP",
        "SpriteRpc",
        "Larp",
        "Mtp",
        "Ax25",
        "IpIp",
        "Micp",
        "SccSp",
        "Etherip",
        "Encap",
        "PrivEncryption",
        "Gmtp",
        "Ifmp",
        "Pnni",
        "Pim",
        "Aris",
        "Scps",
        "Qnx2", // In order to distinguish it from the previous Qnx, Qnx is named Qnx2 here.
        "AN",
        "IpComp",
        "Snp",
        "CompaqPeer",
        "IpxInIp",
        "Vrrp",
        "Pgm",
        "ZeroHop",
        "L2tp",
        "Ddx",
        "Iatp",
        "Stp",
        "Srp",
        "Uti",
        "Smp",
        "Sm",
        "Ptp", // Performance Transparency Protocol
        "IsisOverIpv4",
        "Fire",
        "Crtp",
        "Crudp",
        "Sscopmce",
        "Iplt",
        "Sps",
        "Pipe",
        "Sctp",
        "Fc",
        "RsvpE2eIgnore",
        "MobilityHeader",
        "UdpLite",
        "MplsInIp",
        "Manet",
        "Hip",
        "Shim6",
        "Wesp",
        "Rohc",
        "Test1",
        "Test2",
        "Reserved",
    ]
});

static PROCOTOL_TYPE: LazyLock<Vec<Protocol>> = LazyLock::new(|| {
    vec![
        Protocol::Layer3(EtherTypes::Ipv4),
        Protocol::Layer3(EtherTypes::Arp),
        Protocol::Layer3(EtherTypes::WakeOnLan),
        Protocol::Layer3(EtherTypes::Trill),
        Protocol::Layer3(EtherTypes::DECnet),
        Protocol::Layer3(EtherTypes::Rarp),
        Protocol::Layer3(EtherTypes::AppleTalk),
        Protocol::Layer3(EtherTypes::Aarp),
        Protocol::Layer3(EtherTypes::Ipx),
        Protocol::Layer3(EtherTypes::Qnx),
        Protocol::Layer3(EtherTypes::Ipv6),
        Protocol::Layer3(EtherTypes::FlowControl),
        Protocol::Layer3(EtherTypes::CobraNet),
        Protocol::Layer3(EtherTypes::Mpls),
        Protocol::Layer3(EtherTypes::MplsMcast),
        Protocol::Layer3(EtherTypes::PppoeDiscovery),
        Protocol::Layer3(EtherTypes::PppoeSession),
        Protocol::Layer3(EtherTypes::Vlan),
        Protocol::Layer3(EtherTypes::PBridge),
        Protocol::Layer3(EtherTypes::Lldp),
        Protocol::Layer3(EtherTypes::Ptp),
        Protocol::Layer3(EtherTypes::Cfm),
        Protocol::Layer3(EtherTypes::QinQ),
        Protocol::Layer4(IpNextHeaderProtocols::Hopopt),
        Protocol::Layer4(IpNextHeaderProtocols::Icmp),
        Protocol::Layer4(IpNextHeaderProtocols::Igmp),
        Protocol::Layer4(IpNextHeaderProtocols::Ggp),
        Protocol::Layer4(IpNextHeaderProtocols::Ipv4), // encapsulation
        Protocol::Layer4(IpNextHeaderProtocols::St),
        Protocol::Layer4(IpNextHeaderProtocols::Tcp),
        Protocol::Layer4(IpNextHeaderProtocols::Cbt),
        Protocol::Layer4(IpNextHeaderProtocols::Egp),
        Protocol::Layer4(IpNextHeaderProtocols::Igp),
        Protocol::Layer4(IpNextHeaderProtocols::BbnRccMon),
        Protocol::Layer4(IpNextHeaderProtocols::NvpII),
        Protocol::Layer4(IpNextHeaderProtocols::Pup),
        Protocol::Layer4(IpNextHeaderProtocols::Argus),
        Protocol::Layer4(IpNextHeaderProtocols::Emcon),
        Protocol::Layer4(IpNextHeaderProtocols::Xnet),
        Protocol::Layer4(IpNextHeaderProtocols::Chaos),
        Protocol::Layer4(IpNextHeaderProtocols::Udp),
        Protocol::Layer4(IpNextHeaderProtocols::Mux),
        Protocol::Layer4(IpNextHeaderProtocols::DcnMeas),
        Protocol::Layer4(IpNextHeaderProtocols::Hmp),
        Protocol::Layer4(IpNextHeaderProtocols::Prm),
        Protocol::Layer4(IpNextHeaderProtocols::XnsIdp),
        Protocol::Layer4(IpNextHeaderProtocols::Trunk1),
        Protocol::Layer4(IpNextHeaderProtocols::Trunk2),
        Protocol::Layer4(IpNextHeaderProtocols::Leaf1),
        Protocol::Layer4(IpNextHeaderProtocols::Leaf2),
        Protocol::Layer4(IpNextHeaderProtocols::Rdp),
        Protocol::Layer4(IpNextHeaderProtocols::Irtp),
        Protocol::Layer4(IpNextHeaderProtocols::IsoTp4),
        Protocol::Layer4(IpNextHeaderProtocols::Netblt),
        Protocol::Layer4(IpNextHeaderProtocols::MfeNsp),
        Protocol::Layer4(IpNextHeaderProtocols::MeritInp),
        Protocol::Layer4(IpNextHeaderProtocols::Dccp),
        Protocol::Layer4(IpNextHeaderProtocols::ThreePc),
        Protocol::Layer4(IpNextHeaderProtocols::Idpr),
        Protocol::Layer4(IpNextHeaderProtocols::Xtp),
        Protocol::Layer4(IpNextHeaderProtocols::Ddp),
        Protocol::Layer4(IpNextHeaderProtocols::IdprCmtp),
        Protocol::Layer4(IpNextHeaderProtocols::TpPlusPlus),
        Protocol::Layer4(IpNextHeaderProtocols::Il),
        Protocol::Layer4(IpNextHeaderProtocols::Ipv6), // encapsulation
        Protocol::Layer4(IpNextHeaderProtocols::Sdrp),
        Protocol::Layer4(IpNextHeaderProtocols::Ipv6Route),
        Protocol::Layer4(IpNextHeaderProtocols::Ipv6Frag),
        Protocol::Layer4(IpNextHeaderProtocols::Idrp),
        Protocol::Layer4(IpNextHeaderProtocols::Rsvp),
        Protocol::Layer4(IpNextHeaderProtocols::Gre),
        Protocol::Layer4(IpNextHeaderProtocols::Dsr),
        Protocol::Layer4(IpNextHeaderProtocols::Bna),
        Protocol::Layer4(IpNextHeaderProtocols::Esp),
        Protocol::Layer4(IpNextHeaderProtocols::Ah),
        Protocol::Layer4(IpNextHeaderProtocols::INlsp),
        Protocol::Layer4(IpNextHeaderProtocols::Swipe),
        Protocol::Layer4(IpNextHeaderProtocols::Narp),
        Protocol::Layer4(IpNextHeaderProtocols::Mobile),
        Protocol::Layer4(IpNextHeaderProtocols::Tlsp),
        Protocol::Layer4(IpNextHeaderProtocols::Skip),
        Protocol::Layer4(IpNextHeaderProtocols::Icmpv6),
        Protocol::Layer4(IpNextHeaderProtocols::Ipv6NoNxt),
        Protocol::Layer4(IpNextHeaderProtocols::Ipv6Opts),
        Protocol::Layer4(IpNextHeaderProtocols::HostInternal),
        Protocol::Layer4(IpNextHeaderProtocols::Cftp),
        Protocol::Layer4(IpNextHeaderProtocols::LocalNetwork),
        Protocol::Layer4(IpNextHeaderProtocols::SatExpak),
        Protocol::Layer4(IpNextHeaderProtocols::Kryptolan),
        Protocol::Layer4(IpNextHeaderProtocols::Rvd),
        Protocol::Layer4(IpNextHeaderProtocols::Ippc),
        Protocol::Layer4(IpNextHeaderProtocols::DistributedFs),
        Protocol::Layer4(IpNextHeaderProtocols::SatMon),
        Protocol::Layer4(IpNextHeaderProtocols::Visa),
        Protocol::Layer4(IpNextHeaderProtocols::Ipcv),
        Protocol::Layer4(IpNextHeaderProtocols::Cpnx),
        Protocol::Layer4(IpNextHeaderProtocols::Cphb),
        Protocol::Layer4(IpNextHeaderProtocols::Wsn),
        Protocol::Layer4(IpNextHeaderProtocols::Pvp),
        Protocol::Layer4(IpNextHeaderProtocols::BrSatMon),
        Protocol::Layer4(IpNextHeaderProtocols::SunNd),
        Protocol::Layer4(IpNextHeaderProtocols::WbMon),
        Protocol::Layer4(IpNextHeaderProtocols::WbExpak),
        Protocol::Layer4(IpNextHeaderProtocols::IsoIp),
        Protocol::Layer4(IpNextHeaderProtocols::Vmtp),
        Protocol::Layer4(IpNextHeaderProtocols::SecureVmtp),
        Protocol::Layer4(IpNextHeaderProtocols::Vines),
        Protocol::Layer4(IpNextHeaderProtocols::TtpOrIptm),
        Protocol::Layer4(IpNextHeaderProtocols::NsfnetIgp),
        Protocol::Layer4(IpNextHeaderProtocols::Dgp),
        Protocol::Layer4(IpNextHeaderProtocols::Tcf),
        Protocol::Layer4(IpNextHeaderProtocols::Eigrp),
        Protocol::Layer4(IpNextHeaderProtocols::OspfigP),
        Protocol::Layer4(IpNextHeaderProtocols::SpriteRpc),
        Protocol::Layer4(IpNextHeaderProtocols::Larp),
        Protocol::Layer4(IpNextHeaderProtocols::Mtp),
        Protocol::Layer4(IpNextHeaderProtocols::Ax25),
        Protocol::Layer4(IpNextHeaderProtocols::IpIp),
        Protocol::Layer4(IpNextHeaderProtocols::Micp),
        Protocol::Layer4(IpNextHeaderProtocols::SccSp),
        Protocol::Layer4(IpNextHeaderProtocols::Etherip),
        Protocol::Layer4(IpNextHeaderProtocols::Encap),
        Protocol::Layer4(IpNextHeaderProtocols::PrivEncryption),
        Protocol::Layer4(IpNextHeaderProtocols::Gmtp),
        Protocol::Layer4(IpNextHeaderProtocols::Ifmp),
        Protocol::Layer4(IpNextHeaderProtocols::Pnni),
        Protocol::Layer4(IpNextHeaderProtocols::Pim),
        Protocol::Layer4(IpNextHeaderProtocols::Aris),
        Protocol::Layer4(IpNextHeaderProtocols::Scps),
        Protocol::Layer4(IpNextHeaderProtocols::Qnx),
        Protocol::Layer4(IpNextHeaderProtocols::AN),
        Protocol::Layer4(IpNextHeaderProtocols::IpComp),
        Protocol::Layer4(IpNextHeaderProtocols::Snp),
        Protocol::Layer4(IpNextHeaderProtocols::CompaqPeer),
        Protocol::Layer4(IpNextHeaderProtocols::IpxInIp),
        Protocol::Layer4(IpNextHeaderProtocols::Vrrp),
        Protocol::Layer4(IpNextHeaderProtocols::Pgm),
        Protocol::Layer4(IpNextHeaderProtocols::ZeroHop),
        Protocol::Layer4(IpNextHeaderProtocols::L2tp),
        Protocol::Layer4(IpNextHeaderProtocols::Ddx),
        Protocol::Layer4(IpNextHeaderProtocols::Iatp),
        Protocol::Layer4(IpNextHeaderProtocols::Stp),
        Protocol::Layer4(IpNextHeaderProtocols::Srp),
        Protocol::Layer4(IpNextHeaderProtocols::Uti),
        Protocol::Layer4(IpNextHeaderProtocols::Smp),
        Protocol::Layer4(IpNextHeaderProtocols::Sm),
        Protocol::Layer4(IpNextHeaderProtocols::Ptp), // Performance Transparency Protocol
        Protocol::Layer4(IpNextHeaderProtocols::IsisOverIpv4),
        Protocol::Layer4(IpNextHeaderProtocols::Fire),
        Protocol::Layer4(IpNextHeaderProtocols::Crtp),
        Protocol::Layer4(IpNextHeaderProtocols::Crudp),
        Protocol::Layer4(IpNextHeaderProtocols::Sscopmce),
        Protocol::Layer4(IpNextHeaderProtocols::Iplt),
        Protocol::Layer4(IpNextHeaderProtocols::Sps),
        Protocol::Layer4(IpNextHeaderProtocols::Pipe),
        Protocol::Layer4(IpNextHeaderProtocols::Sctp),
        Protocol::Layer4(IpNextHeaderProtocols::Fc),
        Protocol::Layer4(IpNextHeaderProtocols::RsvpE2eIgnore),
        Protocol::Layer4(IpNextHeaderProtocols::MobilityHeader),
        Protocol::Layer4(IpNextHeaderProtocols::UdpLite),
        Protocol::Layer4(IpNextHeaderProtocols::MplsInIp),
        Protocol::Layer4(IpNextHeaderProtocols::Manet),
        Protocol::Layer4(IpNextHeaderProtocols::Hip),
        Protocol::Layer4(IpNextHeaderProtocols::Shim6),
        Protocol::Layer4(IpNextHeaderProtocols::Wesp),
        Protocol::Layer4(IpNextHeaderProtocols::Rohc),
        Protocol::Layer4(IpNextHeaderProtocols::Test1),
        Protocol::Layer4(IpNextHeaderProtocols::Test2),
        Protocol::Layer4(IpNextHeaderProtocols::Reserved),
    ]
});

struct PacketMac {
    src_mac: MacAddr,
    dst_mac: MacAddr,
}

struct PacketIpv4Addr {
    src_ipv4: Ipv4Addr,
    dst_ipv4: Ipv4Addr,
}

struct PacketIpv6Addr {
    src_ipv6: Ipv6Addr,
    dst_ipv6: Ipv6Addr,
}

struct PacketPort {
    src_port: u16,
    dst_port: u16,
}

#[derive(Debug, Clone, Copy)]
pub enum FilterElem {
    SrcMac(MacAddr),
    DstMac(MacAddr),
    Mac(MacAddr),
    Broadcast,
    Multicast,
    SrcIp(IpAddr),
    DstIp(IpAddr),
    Ip(IpAddr),
    SrcNet(IpAddr, u8),
    DstNet(IpAddr, u8),
    Net(IpAddr, u8),
    SrcPort(u16),
    DstPort(u16),
    Port(u16),
    SrcPortRange(u16, u16),
    DstPortRange(u16, u16),
    PortRange(u16, u16),
    Protocol(Protocol),
    Others(bool),
}

impl FilterElem {
    fn get_mac(&self, packet: &[u8]) -> Option<PacketMac> {
        let ethernet_packet = match EthernetPacket::new(&packet) {
            Some(ethernet_packet) => ethernet_packet,
            None => {
                return None;
            }
        };
        Some(PacketMac {
            src_mac: ethernet_packet.get_source(),
            dst_mac: ethernet_packet.get_destination(),
        })
    }
    fn get_ipv4_addr(&self, packet: &[u8]) -> Option<PacketIpv4Addr> {
        let ethernet_packet = match EthernetPacket::new(&packet) {
            Some(ethernet_packet) => ethernet_packet,
            None => {
                return None;
            }
        };
        match ethernet_packet.get_ethertype() {
            EtherTypes::Ipv4 => match Ipv4Packet::new(ethernet_packet.payload()) {
                Some(ipv4_packet) => Some(PacketIpv4Addr {
                    src_ipv4: ipv4_packet.get_source(),
                    dst_ipv4: ipv4_packet.get_destination(),
                }),
                None => None,
            },
            _ => None,
        }
    }
    fn get_ipv6_addr(&self, packet: &[u8]) -> Option<PacketIpv6Addr> {
        let ethernet_packet = match EthernetPacket::new(&packet) {
            Some(ethernet_packet) => ethernet_packet,
            None => {
                return None;
            }
        };
        match ethernet_packet.get_ethertype() {
            EtherTypes::Ipv6 => match Ipv6Packet::new(ethernet_packet.payload()) {
                Some(ipv6_packet) => Some(PacketIpv6Addr {
                    src_ipv6: ipv6_packet.get_source(),
                    dst_ipv6: ipv6_packet.get_destination(),
                }),
                None => None,
            },
            _ => None,
        }
    }
    fn get_ipv4_tcp_udp_port(&self, packet: &[u8]) -> Option<PacketPort> {
        let ethernet_packet = match EthernetPacket::new(&packet) {
            Some(ethernet_packet) => ethernet_packet,
            None => {
                return None;
            }
        };
        match ethernet_packet.get_ethertype() {
            EtherTypes::Ipv4 => match Ipv4Packet::new(ethernet_packet.payload()) {
                Some(ipv4_packet) => match ipv4_packet.get_next_level_protocol() {
                    IpNextHeaderProtocols::Tcp => match TcpPacket::new(ipv4_packet.payload()) {
                        Some(tcp_packet) => Some(PacketPort {
                            src_port: tcp_packet.get_source(),
                            dst_port: tcp_packet.get_destination(),
                        }),
                        None => None,
                    },
                    IpNextHeaderProtocols::Udp => match UdpPacket::new(ipv4_packet.payload()) {
                        Some(udp_packet) => Some(PacketPort {
                            src_port: udp_packet.get_source(),
                            dst_port: udp_packet.get_destination(),
                        }),
                        None => None,
                    },
                    _ => None,
                },
                None => None,
            },
            EtherTypes::Ipv6 => match Ipv6Packet::new(ethernet_packet.payload()) {
                Some(ipv6_packet) => match ipv6_packet.get_next_header() {
                    IpNextHeaderProtocols::Tcp => match TcpPacket::new(ipv6_packet.payload()) {
                        Some(tcp_packet) => Some(PacketPort {
                            src_port: tcp_packet.get_source(),
                            dst_port: tcp_packet.get_destination(),
                        }),
                        None => None,
                    },
                    IpNextHeaderProtocols::Udp => match UdpPacket::new(ipv6_packet.payload()) {
                        Some(udp_packet) => Some(PacketPort {
                            src_port: udp_packet.get_source(),
                            dst_port: udp_packet.get_destination(),
                        }),
                        None => None,
                    },
                    _ => None,
                },
                None => None,
            },
            _ => None,
        }
    }
    fn get_layer3_protocol(&self, packet: &[u8]) -> Option<EtherType> {
        let ethernet_packet = match EthernetPacket::new(&packet) {
            Some(ethernet_packet) => ethernet_packet,
            None => {
                return None;
            }
        };
        Some(ethernet_packet.get_ethertype())
    }
    fn get_layer4_protocol(&self, packet: &[u8]) -> Option<IpNextHeaderProtocol> {
        let ethernet_packet = match EthernetPacket::new(&packet) {
            Some(ethernet_packet) => ethernet_packet,
            None => {
                return None;
            }
        };
        match ethernet_packet.get_ethertype() {
            EtherTypes::Ipv4 => match Ipv4Packet::new(ethernet_packet.payload()) {
                Some(ipv4_packet) => Some(ipv4_packet.get_next_level_protocol()),
                None => None,
            },
            EtherTypes::Ipv6 => match Ipv6Packet::new(ethernet_packet.payload()) {
                Some(ipv6_packet) => Some(ipv6_packet.get_next_header()),
                None => None,
            },
            _ => None,
        }
    }
    pub fn check(&self, packet_data: &[u8]) -> bool {
        match *self {
            FilterElem::SrcMac(mac) => match self.get_mac(packet_data) {
                Some(packet_mac) => {
                    if mac == packet_mac.src_mac {
                        true
                    } else {
                        false
                    }
                }
                None => false,
            },
            FilterElem::DstMac(mac) => match self.get_mac(packet_data) {
                Some(packet_mac) => {
                    if mac == packet_mac.dst_mac {
                        true
                    } else {
                        false
                    }
                }
                None => false,
            },
            FilterElem::Mac(mac) => match self.get_mac(packet_data) {
                Some(packet_mac) => {
                    if mac == packet_mac.src_mac || mac == packet_mac.dst_mac {
                        true
                    } else {
                        false
                    }
                }
                None => false,
            },
            FilterElem::Broadcast => match self.get_mac(packet_data) {
                Some(packet_mac) => packet_mac.dst_mac == MacAddr::broadcast(),
                None => false,
            },
            FilterElem::Multicast => match self.get_mac(packet_data) {
                Some(packet_mac) => {
                    let m = packet_mac.dst_mac;
                    let bytes = m.octets();
                    bytes[0] & 1 == 1 && m != MacAddr::broadcast()
                }
                None => false,
            },
            FilterElem::SrcIp(addr) => match addr {
                IpAddr::V4(ipv4_addr) => match self.get_ipv4_addr(packet_data) {
                    Some(packet_ipv4_addr) => {
                        if ipv4_addr == packet_ipv4_addr.src_ipv4 {
                            true
                        } else {
                            false
                        }
                    }
                    None => false,
                },
                IpAddr::V6(ipv6_addr) => match self.get_ipv6_addr(packet_data) {
                    Some(packet_ipv6_addr) => {
                        if ipv6_addr == packet_ipv6_addr.src_ipv6 {
                            true
                        } else {
                            false
                        }
                    }
                    None => false,
                },
            },
            FilterElem::DstIp(addr) => match addr {
                IpAddr::V4(ipv4_addr) => match self.get_ipv4_addr(packet_data) {
                    Some(packet_ipv4_addr) => {
                        if ipv4_addr == packet_ipv4_addr.dst_ipv4 {
                            true
                        } else {
                            false
                        }
                    }
                    None => false,
                },
                IpAddr::V6(ipv6_addr) => match self.get_ipv6_addr(packet_data) {
                    Some(packet_ipv6_addr) => {
                        if ipv6_addr == packet_ipv6_addr.dst_ipv6 {
                            true
                        } else {
                            false
                        }
                    }
                    None => false,
                },
            },
            FilterElem::Ip(addr) => match addr {
                IpAddr::V4(ipv4_addr) => match self.get_ipv4_addr(packet_data) {
                    Some(packet_ipv4_addr) => {
                        if ipv4_addr == packet_ipv4_addr.src_ipv4
                            || ipv4_addr == packet_ipv4_addr.dst_ipv4
                        {
                            true
                        } else {
                            false
                        }
                    }
                    None => false,
                },
                IpAddr::V6(ipv6_addr) => match self.get_ipv6_addr(packet_data) {
                    Some(packet_ipv6_addr) => {
                        if ipv6_addr == packet_ipv6_addr.src_ipv6
                            || ipv6_addr == packet_ipv6_addr.dst_ipv6
                        {
                            true
                        } else {
                            false
                        }
                    }
                    None => false,
                },
            },
            FilterElem::SrcNet(net_ip, prefix) => match net_ip {
                IpAddr::V4(net_v4) => match self.get_ipv4_addr(packet_data) {
                    Some(addrs) => ip_in_net_v4(addrs.src_ipv4, net_v4, prefix),
                    None => false,
                },
                IpAddr::V6(net_v6) => match self.get_ipv6_addr(packet_data) {
                    Some(addrs) => ip_in_net_v6(addrs.src_ipv6, net_v6, prefix),
                    None => false,
                },
            },
            FilterElem::DstNet(net_ip, prefix) => match net_ip {
                IpAddr::V4(net_v4) => match self.get_ipv4_addr(packet_data) {
                    Some(addrs) => ip_in_net_v4(addrs.dst_ipv4, net_v4, prefix),
                    None => false,
                },
                IpAddr::V6(net_v6) => match self.get_ipv6_addr(packet_data) {
                    Some(addrs) => ip_in_net_v6(addrs.dst_ipv6, net_v6, prefix),
                    None => false,
                },
            },
            FilterElem::Net(net_ip, prefix) => match net_ip {
                IpAddr::V4(net_v4) => match self.get_ipv4_addr(packet_data) {
                    Some(addrs) => {
                        ip_in_net_v4(addrs.src_ipv4, net_v4, prefix)
                            || ip_in_net_v4(addrs.dst_ipv4, net_v4, prefix)
                    }
                    None => false,
                },
                IpAddr::V6(net_v6) => match self.get_ipv6_addr(packet_data) {
                    Some(addrs) => {
                        ip_in_net_v6(addrs.src_ipv6, net_v6, prefix)
                            || ip_in_net_v6(addrs.dst_ipv6, net_v6, prefix)
                    }
                    None => false,
                },
            },
            FilterElem::SrcPort(port) => match self.get_ipv4_tcp_udp_port(packet_data) {
                Some(packet_port) => {
                    if port == packet_port.src_port {
                        true
                    } else {
                        false
                    }
                }
                None => false,
            },
            FilterElem::DstPort(port) => match self.get_ipv4_tcp_udp_port(packet_data) {
                Some(packet_port) => {
                    if port == packet_port.dst_port {
                        true
                    } else {
                        false
                    }
                }
                None => false,
            },
            FilterElem::Port(port) => match self.get_ipv4_tcp_udp_port(packet_data) {
                Some(packet_port) => {
                    if port == packet_port.src_port || port == packet_port.dst_port {
                        true
                    } else {
                        false
                    }
                }
                None => false,
            },
            FilterElem::SrcPortRange(start, end) => match self.get_ipv4_tcp_udp_port(packet_data) {
                Some(packet_port) => packet_port.src_port >= start && packet_port.src_port <= end,
                None => false,
            },
            FilterElem::DstPortRange(start, end) => match self.get_ipv4_tcp_udp_port(packet_data) {
                Some(packet_port) => packet_port.dst_port >= start && packet_port.dst_port <= end,
                None => false,
            },
            FilterElem::PortRange(start, end) => match self.get_ipv4_tcp_udp_port(packet_data) {
                Some(packet_port) => {
                    (packet_port.src_port >= start && packet_port.src_port <= end)
                        || (packet_port.dst_port >= start && packet_port.dst_port <= end)
                }
                None => false,
            },
            FilterElem::Protocol(protocol) => match protocol {
                Protocol::Layer3(layer3_protocol) => match self.get_layer3_protocol(packet_data) {
                    Some(p) => {
                        if p == layer3_protocol {
                            true
                        } else {
                            false
                        }
                    }
                    None => false,
                },
                Protocol::Layer4(layer4_protocol) => match self.get_layer4_protocol(packet_data) {
                    Some(p) => {
                        if p == layer4_protocol {
                            true
                        } else {
                            false
                        }
                    }
                    None => false,
                },
            },
            FilterElem::Others(b) => b, // others results store here
        }
    }
}

fn ip_in_net_v4(ip: Ipv4Addr, net: Ipv4Addr, prefix: u8) -> bool {
    let ip_u = u32::from(ip);
    let net_u = u32::from(net);
    let mask = if prefix == 0 {
        0u32
    } else {
        u32::MAX.checked_shl(32 - prefix as u32).unwrap_or(0)
    };
    (ip_u & mask) == (net_u & mask)
}

fn ip_in_net_v6(ip: Ipv6Addr, net: Ipv6Addr, prefix: u8) -> bool {
    let ip_u = u128::from_be_bytes(ip.octets());
    let net_u = u128::from_be_bytes(net.octets());
    let mask: u128 = if prefix == 0 {
        0
    } else {
        // create a mask with top `prefix` bits set
        (!0u128) << (128 - prefix as u32)
    };
    (ip_u & mask) == (net_u & mask)
}

pub fn valid_protocol() -> Vec<String> {
    let procotol_name = (*PROCOTOL_NAME).clone();
    let valid_procotol: Vec<String> = procotol_name
        .into_iter()
        .map(|x| x.to_lowercase())
        .collect();
    valid_procotol
}

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub enum Operator {
    And,
    Or,
    LeftBracket,
    // RightBracket,
    Not,
    Eq,
    Neq,
}

#[derive(Debug, Clone, Copy)]
pub enum ShuntingYardElem {
    Filter(FilterElem),
    Operator(Operator),
}

/// shunting yard alg.
#[derive(Debug, Clone)]
pub struct Filter {
    pub input_str: String,
    pub output_queue: Vec<ShuntingYardElem>,
}

#[cfg(feature = "debug")]
pub fn display_the_addr_and_port(packet_data: &[u8]) {
    let filter_elem = FilterElem::Others(true);
    if let Some(layer3_protocol) = filter_elem.get_layer3_protocol(packet_data) {
        if layer3_protocol == EtherTypes::Ipv4 {
            if let Some(addrs) = filter_elem.get_ipv4_addr(packet_data) {
                if let Some(layer4_protocol) = filter_elem.get_layer4_protocol(packet_data) {
                    if layer4_protocol == IpNextHeaderProtocols::Tcp {
                        if let Some(ports) = filter_elem.get_ipv4_tcp_udp_port(packet_data) {
                            println!(
                                "src: {}:{}, dst: {}:{}",
                                addrs.src_ipv4, ports.src_port, addrs.dst_ipv4, ports.dst_port
                            );
                        }
                    }
                }
            }
        }
    }
}

impl Filter {
    pub fn check(&self, packet_data: &[u8]) -> Result<bool, PcaptureError> {
        #[cfg(feature = "debug")]
        display_the_addr_and_port(packet_data);

        let mut output_queue_rev = self.output_queue.clone();
        output_queue_rev.reverse();
        let mut calc_queue = Vec::new();
        while let Some(sye) = output_queue_rev.pop() {
            match sye {
                ShuntingYardElem::Filter(f) => calc_queue.push(f),
                ShuntingYardElem::Operator(o) => match o {
                    Operator::Not => {
                        let f = match calc_queue.pop() {
                            Some(f) => f,
                            None => {
                                return Err(PcaptureError::IncompleteFilter {
                                    msg: String::from("operator NOT missing operand"),
                                });
                            }
                        };
                        let ret = !f.check(packet_data);
                        calc_queue.push(FilterElem::Others(ret));
                    }
                    Operator::And | Operator::Or => {
                        let f2 = match calc_queue.pop() {
                            Some(f) => f,
                            None => {
                                return Err(PcaptureError::IncompleteFilter {
                                    msg: String::from("binary operator missing right operand"),
                                });
                            }
                        };
                        let f1 = match calc_queue.pop() {
                            Some(f) => f,
                            None => {
                                return Err(PcaptureError::IncompleteFilter {
                                    msg: String::from("binary operator missing left operand"),
                                });
                            }
                        };
                        let ret = match o {
                            Operator::And => f1.check(packet_data) & f2.check(packet_data),
                            Operator::Or => f1.check(packet_data) | f2.check(packet_data),
                            _ => unreachable!(),
                        };
                        calc_queue.push(FilterElem::Others(ret));
                    }
                    Operator::LeftBracket => {}
                    Operator::Eq | Operator::Neq => {}
                },
            }
        }
        match calc_queue.pop() {
            Some(f) => match f {
                FilterElem::Others(b) => Ok(b),
                _ => Ok(f.check(packet_data)),
            },
            None => Ok(false),
        }
    }
    pub fn parser(input: &str) -> Result<Option<Self>, PcaptureError> {
        if input.len() == 0 {
            return Ok(None);
        }
        // Minimal BPF syntax:
        // - host <ip>, src host <ip>, dst host <ip>
        // - port <n>, src port <n>, dst port <n>
        // - protocols: tcp, udp, icmp, ip, arp, ipv6
        // - operators: and, or, not, parentheses

        #[derive(Debug, Clone, Copy, PartialEq)]
        enum TokOp {
            And,
            Or,
            Not,
            LParen,
        }

        fn prec(op: TokOp) -> i32 {
            match op {
                TokOp::Not => 3,
                TokOp::And => 2,
                TokOp::Or => 1,
                TokOp::LParen => 0,
            }
        }

        // tokenize by splitting whitespace and isolating parentheses
        let mut tokens = Vec::new();
        let mut buf = String::new();
        for ch in input.chars() {
            match ch {
                '(' | ')' | ' ' | '\t' | '\n' | '\r' => {
                    if !buf.is_empty() {
                        tokens.push(buf.clone());
                        buf.clear();
                    }
                    if ch == '(' || ch == ')' {
                        tokens.push(ch.to_string());
                    }
                }
                _ => buf.push(ch),
            }
        }
        if !buf.is_empty() {
            tokens.push(buf);
        }

        let mut output_queue: Vec<ShuntingYardElem> = Vec::new();
        let mut op_stack: Vec<TokOp> = Vec::new();

        let mut i = 0;
        while i < tokens.len() {
            let t = tokens[i].to_lowercase();
            match t.as_str() {
                // ether qualifiers
                "ether" => {
                    if i + 1 >= tokens.len() {
                        return Err(PcaptureError::IncompleteFilter {
                            msg: "ether requires a qualifier".into(),
                        });
                    }
                    let qual = tokens[i + 1].to_lowercase();
                    match qual.as_str() {
                        "src" => {
                            if i + 2 >= tokens.len() {
                                return Err(PcaptureError::IncompleteFilter {
                                    msg: "ether src requires a mac".into(),
                                });
                            }
                            let mac: MacAddr = match tokens[i + 2].parse() {
                                Ok(v) => v,
                                Err(e) => {
                                    return Err(PcaptureError::ValueError {
                                        parameter: tokens[i + 2].clone(),
                                        target: "MacAddr".into(),
                                        e: e.to_string(),
                                    });
                                }
                            };
                            output_queue.push(ShuntingYardElem::Filter(FilterElem::SrcMac(mac)));
                            i += 3;
                        }
                        "dst" => {
                            if i + 2 >= tokens.len() {
                                return Err(PcaptureError::IncompleteFilter {
                                    msg: "ether dst requires a mac".into(),
                                });
                            }
                            let mac: MacAddr = match tokens[i + 2].parse() {
                                Ok(v) => v,
                                Err(e) => {
                                    return Err(PcaptureError::ValueError {
                                        parameter: tokens[i + 2].clone(),
                                        target: "MacAddr".into(),
                                        e: e.to_string(),
                                    });
                                }
                            };
                            output_queue.push(ShuntingYardElem::Filter(FilterElem::DstMac(mac)));
                            i += 3;
                        }
                        "host" => {
                            if i + 2 >= tokens.len() {
                                return Err(PcaptureError::IncompleteFilter {
                                    msg: "ether host requires a mac".into(),
                                });
                            }
                            let mac: MacAddr = match tokens[i + 2].parse() {
                                Ok(v) => v,
                                Err(e) => {
                                    return Err(PcaptureError::ValueError {
                                        parameter: tokens[i + 2].clone(),
                                        target: "MacAddr".into(),
                                        e: e.to_string(),
                                    });
                                }
                            };
                            output_queue.push(ShuntingYardElem::Filter(FilterElem::Mac(mac)));
                            i += 3;
                        }
                        "broadcast" => {
                            output_queue.push(ShuntingYardElem::Filter(FilterElem::Broadcast));
                            i += 2;
                        }
                        "multicast" => {
                            output_queue.push(ShuntingYardElem::Filter(FilterElem::Multicast));
                            i += 2;
                        }
                        "proto" => {
                            if i + 2 >= tokens.len() {
                                return Err(PcaptureError::IncompleteFilter {
                                    msg: "ether proto requires a number".into(),
                                });
                            }
                            let tok = tokens[i + 2].to_lowercase();
                            // try numeric first (dec or hex)
                            if let Ok(v) = parse_u16_num(&tok) {
                                let et = EtherType(v);
                                output_queue.push(ShuntingYardElem::Filter(FilterElem::Protocol(
                                    Protocol::Layer3(et),
                                )));
                                i += 3;
                            } else {
                                // accept names like ip, ip6, arp, vlan
                                let et_opt = match tok.as_str() {
                                    "ip" => Some(EtherTypes::Ipv4),
                                    "ip6" | "ipv6" => Some(EtherTypes::Ipv6),
                                    _ => match Protocol::convert(&tok) {
                                        Some(Protocol::Layer3(et)) => Some(et),
                                        _ => None,
                                    },
                                };
                                if let Some(et) = et_opt {
                                    output_queue.push(ShuntingYardElem::Filter(
                                        FilterElem::Protocol(Protocol::Layer3(et)),
                                    ));
                                    i += 3;
                                } else {
                                    return Err(PcaptureError::IncompleteFilter {
                                        msg: format!("unsupported ether proto: {}", tok),
                                    });
                                }
                            }
                        }
                        _ => {
                            return Err(PcaptureError::IncompleteFilter {
                                msg: format!("unsupported ether qualifier: {}", qual),
                            });
                        }
                    }
                }
                "and" => {
                    let op = TokOp::And;
                    while let Some(top) = op_stack.last().cloned() {
                        if top != TokOp::LParen && prec(top) >= prec(op) {
                            match op_stack.pop().unwrap() {
                                TokOp::And => {
                                    output_queue.push(ShuntingYardElem::Operator(Operator::And))
                                }
                                TokOp::Or => {
                                    output_queue.push(ShuntingYardElem::Operator(Operator::Or))
                                }
                                TokOp::Not => {
                                    output_queue.push(ShuntingYardElem::Operator(Operator::Not))
                                }
                                TokOp::LParen => {}
                            }
                        } else {
                            break;
                        }
                    }
                    op_stack.push(op);
                    i += 1;
                }
                "or" => {
                    let op = TokOp::Or;
                    while let Some(top) = op_stack.last().cloned() {
                        if top != TokOp::LParen && prec(top) >= prec(op) {
                            match op_stack.pop().unwrap() {
                                TokOp::And => {
                                    output_queue.push(ShuntingYardElem::Operator(Operator::And))
                                }
                                TokOp::Or => {
                                    output_queue.push(ShuntingYardElem::Operator(Operator::Or))
                                }
                                TokOp::Not => {
                                    output_queue.push(ShuntingYardElem::Operator(Operator::Not))
                                }
                                TokOp::LParen => {}
                            }
                        } else {
                            break;
                        }
                    }
                    op_stack.push(op);
                    i += 1;
                }
                "not" => {
                    op_stack.push(TokOp::Not);
                    i += 1;
                }
                "(" => {
                    op_stack.push(TokOp::LParen);
                    i += 1;
                }
                ")" => {
                    // pop until LParen
                    while let Some(top) = op_stack.pop() {
                        if matches!(top, TokOp::LParen) {
                            break;
                        }
                        match top {
                            TokOp::And => {
                                output_queue.push(ShuntingYardElem::Operator(Operator::And))
                            }
                            TokOp::Or => {
                                output_queue.push(ShuntingYardElem::Operator(Operator::Or))
                            }
                            TokOp::Not => {
                                output_queue.push(ShuntingYardElem::Operator(Operator::Not))
                            }
                            TokOp::LParen => {}
                        }
                    }
                    i += 1;
                }
                // atoms
                "host" => {
                    if i + 1 >= tokens.len() {
                        return Err(PcaptureError::IncompleteFilter {
                            msg: "host requires an address".into(),
                        });
                    }
                    let addr_str = &tokens[i + 1];
                    let ip_addr: IpAddr = match addr_str.parse() {
                        Ok(v) => v,
                        Err(e) => {
                            return Err(PcaptureError::ValueError {
                                parameter: addr_str.clone(),
                                target: "IpAddr".into(),
                                e: e.to_string(),
                            });
                        }
                    };
                    output_queue.push(ShuntingYardElem::Filter(FilterElem::Ip(ip_addr)));
                    i += 2;
                }
                "src" => {
                    if i + 2 >= tokens.len() {
                        return Err(PcaptureError::IncompleteFilter {
                            msg: "src requires a qualifier and value".into(),
                        });
                    }
                    let qual = tokens[i + 1].to_lowercase();
                    match qual.as_str() {
                        "host" => {
                            let addr_str = &tokens[i + 2];
                            let ip_addr: IpAddr = match addr_str.parse() {
                                Ok(v) => v,
                                Err(e) => {
                                    return Err(PcaptureError::ValueError {
                                        parameter: addr_str.clone(),
                                        target: "IpAddr".into(),
                                        e: e.to_string(),
                                    });
                                }
                            };
                            output_queue.push(ShuntingYardElem::Filter(FilterElem::SrcIp(ip_addr)));
                            i += 3;
                        }
                        "net" => {
                            // src net <cidr> | src net <ip> mask <mask>
                            if i + 2 >= tokens.len() {
                                return Err(PcaptureError::IncompleteFilter {
                                    msg: "src net requires a value".into(),
                                });
                            }
                            let next = &tokens[i + 2];
                            if let Some((ip, prefix)) = parse_cidr(next)? {
                                output_queue
                                    .push(ShuntingYardElem::Filter(FilterElem::SrcNet(ip, prefix)));
                                i += 3;
                            } else if i + 4 < tokens.len() && tokens[i + 3].to_lowercase() == "mask"
                            {
                                let ip_str = next;
                                let mask_str = &tokens[i + 4];
                                let (ip, prefix) = parse_ip_mask(ip_str, mask_str)?;
                                output_queue
                                    .push(ShuntingYardElem::Filter(FilterElem::SrcNet(ip, prefix)));
                                i += 5;
                            } else {
                                return Err(PcaptureError::IncompleteFilter {
                                    msg: "unsupported src net syntax".into(),
                                });
                            }
                        }
                        "port" => {
                            let port_str = &tokens[i + 2];
                            let port: u16 = match port_str.parse() {
                                Ok(v) => v,
                                Err(e) => {
                                    return Err(PcaptureError::ValueError {
                                        parameter: port_str.clone(),
                                        target: "u16".into(),
                                        e: e.to_string(),
                                    });
                                }
                            };
                            output_queue.push(ShuntingYardElem::Filter(FilterElem::SrcPort(port)));
                            i += 3;
                        }
                        "portrange" => {
                            let range_str = &tokens[i + 2];
                            let (start, end) = parse_port_range(range_str)?;
                            output_queue.push(ShuntingYardElem::Filter(FilterElem::SrcPortRange(
                                start, end,
                            )));
                            i += 3;
                        }
                        _ => {
                            return Err(PcaptureError::IncompleteFilter {
                                msg: format!("unsupported src qualifier: {}", qual),
                            });
                        }
                    }
                }
                "dst" => {
                    if i + 2 >= tokens.len() {
                        return Err(PcaptureError::IncompleteFilter {
                            msg: "dst requires a qualifier and value".into(),
                        });
                    }
                    let qual = tokens[i + 1].to_lowercase();
                    match qual.as_str() {
                        "host" => {
                            let addr_str = &tokens[i + 2];
                            let ip_addr: IpAddr = match addr_str.parse() {
                                Ok(v) => v,
                                Err(e) => {
                                    return Err(PcaptureError::ValueError {
                                        parameter: addr_str.clone(),
                                        target: "IpAddr".into(),
                                        e: e.to_string(),
                                    });
                                }
                            };
                            output_queue.push(ShuntingYardElem::Filter(FilterElem::DstIp(ip_addr)));
                            i += 3;
                        }
                        "net" => {
                            if i + 2 >= tokens.len() {
                                return Err(PcaptureError::IncompleteFilter {
                                    msg: "dst net requires a value".into(),
                                });
                            }
                            let next = &tokens[i + 2];
                            if let Some((ip, prefix)) = parse_cidr(next)? {
                                output_queue
                                    .push(ShuntingYardElem::Filter(FilterElem::DstNet(ip, prefix)));
                                i += 3;
                            } else if i + 4 < tokens.len() && tokens[i + 3].to_lowercase() == "mask"
                            {
                                let ip_str = next;
                                let mask_str = &tokens[i + 4];
                                let (ip, prefix) = parse_ip_mask(ip_str, mask_str)?;
                                output_queue
                                    .push(ShuntingYardElem::Filter(FilterElem::DstNet(ip, prefix)));
                                i += 5;
                            } else {
                                return Err(PcaptureError::IncompleteFilter {
                                    msg: "unsupported dst net syntax".into(),
                                });
                            }
                        }
                        "port" => {
                            let port_str = &tokens[i + 2];
                            let port: u16 = match port_str.parse() {
                                Ok(v) => v,
                                Err(e) => {
                                    return Err(PcaptureError::ValueError {
                                        parameter: port_str.clone(),
                                        target: "u16".into(),
                                        e: e.to_string(),
                                    });
                                }
                            };
                            output_queue.push(ShuntingYardElem::Filter(FilterElem::DstPort(port)));
                            i += 3;
                        }
                        "portrange" => {
                            let range_str = &tokens[i + 2];
                            let (start, end) = parse_port_range(range_str)?;
                            output_queue.push(ShuntingYardElem::Filter(FilterElem::DstPortRange(
                                start, end,
                            )));
                            i += 3;
                        }
                        _ => {
                            return Err(PcaptureError::IncompleteFilter {
                                msg: format!("unsupported dst qualifier: {}", qual),
                            });
                        }
                    }
                }
                "port" => {
                    if i + 1 >= tokens.len() {
                        return Err(PcaptureError::IncompleteFilter {
                            msg: "port requires a number".into(),
                        });
                    }
                    let port_str = &tokens[i + 1];
                    let port: u16 = match port_str.parse() {
                        Ok(v) => v,
                        Err(e) => {
                            return Err(PcaptureError::ValueError {
                                parameter: port_str.clone(),
                                target: "u16".into(),
                                e: e.to_string(),
                            });
                        }
                    };
                    output_queue.push(ShuntingYardElem::Filter(FilterElem::Port(port)));
                    i += 2;
                }
                "portrange" => {
                    if i + 1 >= tokens.len() {
                        return Err(PcaptureError::IncompleteFilter {
                            msg: "portrange requires a-b".into(),
                        });
                    }
                    let range_str = &tokens[i + 1];
                    let (start, end) = parse_port_range(range_str)?;
                    output_queue.push(ShuntingYardElem::Filter(FilterElem::PortRange(start, end)));
                    i += 2;
                }
                // unqualified net
                "net" => {
                    if i + 1 >= tokens.len() {
                        return Err(PcaptureError::IncompleteFilter {
                            msg: "net requires a cidr or mask".into(),
                        });
                    }
                    let next = &tokens[i + 1];
                    if let Some((ip, prefix)) = parse_cidr(next)? {
                        output_queue.push(ShuntingYardElem::Filter(FilterElem::Net(ip, prefix)));
                        i += 2;
                    } else if i + 3 < tokens.len() && tokens[i + 2].to_lowercase() == "mask" {
                        let (ip, prefix) = parse_ip_mask(next, &tokens[i + 3])?;
                        output_queue.push(ShuntingYardElem::Filter(FilterElem::Net(ip, prefix)));
                        i += 4;
                    } else {
                        return Err(PcaptureError::IncompleteFilter {
                            msg: "unsupported net syntax".into(),
                        });
                    }
                }
                // vlan keyword (basic: matches VLAN EtherType)
                "vlan" => {
                    output_queue.push(ShuntingYardElem::Filter(FilterElem::Protocol(
                        Protocol::Layer3(EtherTypes::Vlan),
                    )));
                    i += 1;
                }
                // minimal protocol keywords
                "ip" => {
                    // support: ip src|dst <ip4>
                    if i + 2 < tokens.len()
                        && (tokens[i + 1].eq_ignore_ascii_case("src")
                            || tokens[i + 1].eq_ignore_ascii_case("dst"))
                    {
                        let side = tokens[i + 1].to_lowercase();
                        let addr_str = &tokens[i + 2];
                        let ip_addr: IpAddr = match addr_str.parse() {
                            Ok(v) => v,
                            Err(e) => {
                                return Err(PcaptureError::ValueError {
                                    parameter: addr_str.clone(),
                                    target: "IpAddr".into(),
                                    e: e.to_string(),
                                });
                            }
                        };
                        let v4 = match ip_addr {
                            IpAddr::V4(v) => v,
                            IpAddr::V6(_) => {
                                return Err(PcaptureError::IncompleteFilter {
                                    msg: "ip src/dst expects IPv4 address".into(),
                                });
                            }
                        };
                        output_queue.push(ShuntingYardElem::Filter(FilterElem::Protocol(
                            Protocol::Layer3(EtherTypes::Ipv4),
                        )));
                        match side.as_str() {
                            "src" => output_queue
                                .push(ShuntingYardElem::Filter(FilterElem::SrcIp(IpAddr::V4(v4)))),
                            _ => output_queue
                                .push(ShuntingYardElem::Filter(FilterElem::DstIp(IpAddr::V4(v4)))),
                        }
                        output_queue.push(ShuntingYardElem::Operator(Operator::And));
                        i += 3;
                    } else if i + 2 < tokens.len() && tokens[i + 1].eq_ignore_ascii_case("host") {
                        let addr_str = &tokens[i + 2];
                        let ip_addr: IpAddr = match addr_str.parse() {
                            Ok(v) => v,
                            Err(e) => {
                                return Err(PcaptureError::ValueError {
                                    parameter: addr_str.clone(),
                                    target: "IpAddr".into(),
                                    e: e.to_string(),
                                });
                            }
                        };
                        let v4 = match ip_addr {
                            IpAddr::V4(v) => v,
                            IpAddr::V6(_) => {
                                return Err(PcaptureError::IncompleteFilter {
                                    msg: "ip host expects IPv4 address".into(),
                                });
                            }
                        };
                        output_queue.push(ShuntingYardElem::Filter(FilterElem::Protocol(
                            Protocol::Layer3(EtherTypes::Ipv4),
                        )));
                        output_queue.push(ShuntingYardElem::Filter(FilterElem::Ip(IpAddr::V4(v4))));
                        output_queue.push(ShuntingYardElem::Operator(Operator::And));
                        i += 3;
                    } else if i + 1 < tokens.len() && tokens[i + 1].to_lowercase() == "proto" {
                        if i + 2 >= tokens.len() {
                            return Err(PcaptureError::IncompleteFilter {
                                msg: "ip proto requires a value".into(),
                            });
                        }
                        // push Layer3 IPv4 AND Layer4 proto
                        output_queue.push(ShuntingYardElem::Filter(FilterElem::Protocol(
                            Protocol::Layer3(EtherTypes::Ipv4),
                        )));
                        // parse next header
                        let nh_tok = tokens[i + 2].to_lowercase();
                        let nh = if let Ok(n) = nh_tok.parse::<u8>() {
                            IpNextHeaderProtocol(n)
                        } else if let Some(p) = Protocol::convert(&nh_tok) {
                            match p {
                                Protocol::Layer4(x) => x,
                                _ => {
                                    return Err(PcaptureError::IncompleteFilter {
                                        msg: "ip proto expects L4 value".into(),
                                    });
                                }
                            }
                        } else {
                            return Err(PcaptureError::IncompleteFilter {
                                msg: format!("unsupported ip proto: {}", nh_tok),
                            });
                        };
                        output_queue.push(ShuntingYardElem::Filter(FilterElem::Protocol(
                            Protocol::Layer4(nh),
                        )));
                        // insert implicit AND between the two
                        output_queue.push(ShuntingYardElem::Operator(Operator::And));
                        i += 3;
                    } else {
                        output_queue.push(ShuntingYardElem::Filter(FilterElem::Protocol(
                            Protocol::Layer3(EtherTypes::Ipv4),
                        )));
                        i += 1;
                    }
                }
                // ip6 with proto
                "ip6" | "ipv6" => {
                    // support: ip6 src|dst <ip6>
                    if i + 2 < tokens.len()
                        && (tokens[i + 1].eq_ignore_ascii_case("src")
                            || tokens[i + 1].eq_ignore_ascii_case("dst"))
                    {
                        let side = tokens[i + 1].to_lowercase();
                        let addr_str = &tokens[i + 2];
                        let ip_addr: IpAddr = match addr_str.parse() {
                            Ok(v) => v,
                            Err(e) => {
                                return Err(PcaptureError::ValueError {
                                    parameter: addr_str.clone(),
                                    target: "IpAddr".into(),
                                    e: e.to_string(),
                                });
                            }
                        };
                        let v6 = match ip_addr {
                            IpAddr::V6(v) => v,
                            IpAddr::V4(_) => {
                                return Err(PcaptureError::IncompleteFilter {
                                    msg: "ip6 src/dst expects IPv6 address".into(),
                                });
                            }
                        };
                        output_queue.push(ShuntingYardElem::Filter(FilterElem::Protocol(
                            Protocol::Layer3(EtherTypes::Ipv6),
                        )));
                        match side.as_str() {
                            "src" => output_queue
                                .push(ShuntingYardElem::Filter(FilterElem::SrcIp(IpAddr::V6(v6)))),
                            _ => output_queue
                                .push(ShuntingYardElem::Filter(FilterElem::DstIp(IpAddr::V6(v6)))),
                        }
                        output_queue.push(ShuntingYardElem::Operator(Operator::And));
                        i += 3;
                    } else if i + 2 < tokens.len() && tokens[i + 1].eq_ignore_ascii_case("host") {
                        let addr_str = &tokens[i + 2];
                        let ip_addr: IpAddr = match addr_str.parse() {
                            Ok(v) => v,
                            Err(e) => {
                                return Err(PcaptureError::ValueError {
                                    parameter: addr_str.clone(),
                                    target: "IpAddr".into(),
                                    e: e.to_string(),
                                });
                            }
                        };
                        let v6 = match ip_addr {
                            IpAddr::V6(v) => v,
                            IpAddr::V4(_) => {
                                return Err(PcaptureError::IncompleteFilter {
                                    msg: "ip6 host expects IPv6 address".into(),
                                });
                            }
                        };
                        output_queue.push(ShuntingYardElem::Filter(FilterElem::Protocol(
                            Protocol::Layer3(EtherTypes::Ipv6),
                        )));
                        output_queue.push(ShuntingYardElem::Filter(FilterElem::Ip(IpAddr::V6(v6))));
                        output_queue.push(ShuntingYardElem::Operator(Operator::And));
                        i += 3;
                    } else if i + 1 < tokens.len() && tokens[i + 1].to_lowercase() == "proto" {
                        if i + 2 >= tokens.len() {
                            return Err(PcaptureError::IncompleteFilter {
                                msg: "ip6 proto requires a value".into(),
                            });
                        }
                        output_queue.push(ShuntingYardElem::Filter(FilterElem::Protocol(
                            Protocol::Layer3(EtherTypes::Ipv6),
                        )));
                        let nh_tok = tokens[i + 2].to_lowercase();
                        let nh = if let Ok(n) = nh_tok.parse::<u8>() {
                            IpNextHeaderProtocol(n)
                        } else if let Some(p) = Protocol::convert(&nh_tok) {
                            match p {
                                Protocol::Layer4(x) => x,
                                _ => {
                                    return Err(PcaptureError::IncompleteFilter {
                                        msg: "ip6 proto expects L4 value".into(),
                                    });
                                }
                            }
                        } else {
                            return Err(PcaptureError::IncompleteFilter {
                                msg: format!("unsupported ip6 proto: {}", nh_tok),
                            });
                        };
                        output_queue.push(ShuntingYardElem::Filter(FilterElem::Protocol(
                            Protocol::Layer4(nh),
                        )));
                        output_queue.push(ShuntingYardElem::Operator(Operator::And));
                        i += 3;
                    } else {
                        // fall back to existing path below by treating as protocol token
                        if let Some(proto) = Protocol::convert(&t) {
                            output_queue
                                .push(ShuntingYardElem::Filter(FilterElem::Protocol(proto)));
                            i += 1;
                        } else {
                            return Err(PcaptureError::IncompleteFilter {
                                msg: format!("unsupported protocol: {}", t),
                            });
                        }
                    }
                }
                "arp" | "tcp" | "udp" | "icmp" => {
                    if let Some(proto) = Protocol::convert(&t) {
                        output_queue.push(ShuntingYardElem::Filter(FilterElem::Protocol(proto)));
                        i += 1;
                    } else {
                        // handle alias ip6 -> ipv6
                        return Err(PcaptureError::IncompleteFilter {
                            msg: format!("unsupported protocol: {}", t),
                        });
                    }
                }
                other => {
                    return Err(PcaptureError::IncompleteFilter {
                        msg: format!("unexpected token: {}", other),
                    });
                }
            }
        }

        // pop remaining operators
        while let Some(op) = op_stack.pop() {
            match op {
                TokOp::And => output_queue.push(ShuntingYardElem::Operator(Operator::And)),
                TokOp::Or => output_queue.push(ShuntingYardElem::Operator(Operator::Or)),
                TokOp::Not => output_queue.push(ShuntingYardElem::Operator(Operator::Not)),
                TokOp::LParen => {
                    return Err(PcaptureError::IncompleteFilter {
                        msg: "unbalanced parenthesis".into(),
                    });
                }
            }
        }

        Ok(Some(Self {
            input_str: input.to_string(),
            output_queue,
        }))
    }
}

fn parse_cidr(s: &str) -> Result<Option<(IpAddr, u8)>, PcaptureError> {
    if let Some((ip_part, prefix_part)) = s.split_once('/') {
        let ip: IpAddr = ip_part
            .parse::<IpAddr>()
            .map_err(|e: std::net::AddrParseError| PcaptureError::ValueError {
                parameter: ip_part.to_string(),
                target: "IpAddr".into(),
                e: e.to_string(),
            })?;
        let prefix: u8 = prefix_part
            .parse::<u8>()
            .map_err(|e: std::num::ParseIntError| PcaptureError::ValueError {
                parameter: prefix_part.to_string(),
                target: "u8".into(),
                e: e.to_string(),
            })?;
        Ok(Some((ip, prefix)))
    } else {
        Ok(None)
    }
}

fn parse_ip_mask(ip_str: &str, mask_str: &str) -> Result<(IpAddr, u8), PcaptureError> {
    let ip: IpAddr = ip_str
        .parse::<IpAddr>()
        .map_err(|e: std::net::AddrParseError| PcaptureError::ValueError {
            parameter: ip_str.to_string(),
            target: "IpAddr".into(),
            e: e.to_string(),
        })?;
    let mask_parsed = mask_str.parse::<IpAddr>();
    match ip {
        IpAddr::V4(ipv4) => match mask_parsed {
            Ok(IpAddr::V4(mask_v4)) => {
                let m = u32::from(mask_v4);
                // Count leading ones
                let prefix = m.leading_ones() as u8;
                // Validate mask is contiguous ones
                if m != (!0u32 << (32 - prefix as u32) & 0xFFFF_FFFF) {
                    return Err(PcaptureError::IncompleteFilter {
                        msg: "non-contiguous IPv4 mask".into(),
                    });
                }
                Ok((IpAddr::V4(ipv4), prefix))
            }
            Ok(IpAddr::V6(_)) => Err(PcaptureError::IncompleteFilter {
                msg: "mask form only supported for IPv4".into(),
            }),
            Err(_) => Err(PcaptureError::ValueError {
                parameter: mask_str.to_string(),
                target: "IpAddr".into(),
                e: "invalid mask".into(),
            }),
        },
        IpAddr::V6(_) => Err(PcaptureError::IncompleteFilter {
            msg: "mask form only supported for IPv4".into(),
        }),
    }
}

fn parse_port_range(s: &str) -> Result<(u16, u16), PcaptureError> {
    if let Some((a, b)) = s.split_once('-') {
        let start: u16 =
            a.parse::<u16>()
                .map_err(|e: std::num::ParseIntError| PcaptureError::ValueError {
                    parameter: a.to_string(),
                    target: "u16".into(),
                    e: e.to_string(),
                })?;
        let end: u16 =
            b.parse::<u16>()
                .map_err(|e: std::num::ParseIntError| PcaptureError::ValueError {
                    parameter: b.to_string(),
                    target: "u16".into(),
                    e: e.to_string(),
                })?;
        if start <= end {
            Ok((start, end))
        } else {
            Err(PcaptureError::IncompleteFilter {
                msg: "portrange start > end".into(),
            })
        }
    } else {
        Err(PcaptureError::IncompleteFilter {
            msg: "portrange requires a-b".into(),
        })
    }
}

fn parse_u16_num(s: &str) -> Result<u16, PcaptureError> {
    let v = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u16::from_str_radix(hex, 16).map_err(|e| PcaptureError::ValueError {
            parameter: s.to_string(),
            target: "u16".into(),
            e: e.to_string(),
        })?
    } else {
        s.parse::<u16>().map_err(|e| PcaptureError::ValueError {
            parameter: s.to_string(),
            target: "u16".into(),
            e: e.to_string(),
        })?
    };
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_filters_parser() {
        let exs = vec![
            "tcp and (host 192.168.1.1 and port 80)",
            "host 192.168.1.1",
            "not host 192.168.1.1",
            "host 192.168.1.1 and tcp",
            "not host 192.168.1.1 and tcp",
            "host 192.168.1.1 and port 80",
            "(host 192.168.1.1 and tcp) or port 80",
            "(host 192.168.1.1 and not tcp) or port 80",
            "src net 192.168.1.0/24 and portrange 80-8080",
            "dst net 2001:db8::/32 and udp",
            "net 10.0.0.0 mask 255.0.0.0 and not icmp",
            "ether broadcast",
            "ether multicast",
            "ether proto ip6",
            "ip host 192.168.1.2",
            "ip src 192.168.1.3",
            "ip6 host 2001:db8::1",
            "ip6 dst 2001:db8::2",
        ];
        // for unit test use
        for ex in exs {
            let filter = Filter::parser(ex).unwrap().unwrap();
            println!("{}", ex); // for test
            println!("{:?}", filter); // for test
        }
    }
    #[test]
    fn test_protocol() {
        assert_eq!(PROCOTOL_NAME.len(), PROCOTOL_TYPE.len());
        let mut uniq_procotol_name = Vec::new();
        for p in PROCOTOL_NAME.iter().map(|p| p.to_string()).into_iter() {
            if !uniq_procotol_name.contains(&p) {
                uniq_procotol_name.push(p);
            } else {
                println!("not unique value found: {}", p);
            }
        }
        assert_eq!(PROCOTOL_NAME.len(), uniq_procotol_name.len());
    }
    #[test]
    fn test_filter_with_data() {
        let packet_data_true = vec![
            0x0, 0xc, 0x29, 0x82, 0x7f, 0x58, 0x0, 0x50, 0x56, 0xc0, 0x0, 0x8, 0x8, 0x0, 0x45, 0x0,
            0x0, 0x34, 0xed, 0x3f, 0x40, 0x0, 0x80, 0x6, 0x81, 0x9a, 0xc0, 0xa8, 0x5, 0x1, 0xc0,
            0xa8, 0x5, 0x98, 0xd0, 0x4d, 0x0, 0x50, 0x6e, 0x85, 0x6d, 0xe6, 0x0, 0x0, 0x0, 0x0,
            0x80, 0x2, 0xff, 0xff, 0x36, 0x1d, 0x0, 0x0, 0x2, 0x4, 0x5, 0xb4, 0x1, 0x3, 0x3, 0x8,
            0x1, 0x1, 0x4, 0x2,
        ];

        let packet_data_false = vec![
            0x0, 0xc, 0x29, 0xec, 0xd0, 0x37, 0x0, 0x50, 0x56, 0xc0, 0x0, 0x8, 0x8, 0x0, 0x45, 0x0,
            0x0, 0xac, 0xc3, 0xfc, 0x40, 0x0, 0x80, 0x6, 0xaa, 0xfa, 0xc0, 0xa8, 0x5, 0x1, 0xc0,
            0xa8, 0x5, 0x3, 0xde, 0x18, 0x0, 0x16, 0xd, 0xe7, 0xbd, 0x2c, 0x84, 0xb6, 0x7b, 0xe7,
            0x50, 0x18, 0x7, 0xfc, 0xc, 0x1e, 0x0, 0x0, 0xf2, 0x82, 0x96, 0x24, 0x45, 0x2f, 0xcd,
            0x5b, 0x2c, 0x3b, 0xd5, 0x85, 0xd0, 0xff, 0x86, 0xbf, 0x94, 0x2c, 0x13, 0xf1, 0x80,
            0xc0, 0xfa, 0x24, 0x83, 0x5, 0x9e, 0x19, 0x12, 0xcc, 0x87, 0x29, 0x2e, 0x74, 0xbd,
            0xf3, 0xd0, 0x29, 0xb8, 0x5, 0x7b, 0xa1, 0x48, 0x1d, 0x46, 0x6, 0x0, 0xdc, 0xbd, 0xba,
            0xa7, 0x81, 0xbf, 0x3a, 0x9b, 0x24, 0x40, 0x3b, 0x69, 0x79, 0x54, 0x5d, 0x3e, 0xea,
            0xf6, 0xae, 0xa4, 0xc8, 0xbe, 0x99, 0xf8, 0x5b, 0xed, 0x8f, 0x24, 0x4f, 0x18, 0xd0,
            0x24, 0x8e, 0x8c, 0x28, 0x57, 0x63, 0xe3, 0x92, 0x25, 0xae, 0x5, 0xc8, 0x85, 0x8, 0xc,
            0x44, 0x7a, 0x59, 0x8b, 0xe0, 0x64, 0x63, 0x1a, 0x3f, 0x56, 0xbf, 0xa5, 0x81, 0x1e,
            0xfe, 0x47, 0x32, 0x8c, 0xe6, 0xe2, 0x47, 0x9c, 0xe9, 0xad, 0xb6, 0x5, 0xea, 0x76, 0x9,
            0x15, 0xe7, 0x9, 0xd3, 0x86, 0xa9, 0x3b, 0xc3, 0xf2, 0x9a,
        ];

        let filter = "tcp and (host 192.168.5.152 and port 80)";
        let filter = Filter::parser(filter).unwrap().unwrap();

        let check_true = filter.check(&packet_data_true).unwrap();
        let check_false = filter.check(&packet_data_false).unwrap();

        println!("check: {}", check_true);
        println!("check: {}", check_false);
    }
}
