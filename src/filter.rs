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
    fn convert(procotol: &str) -> Option<Protocol> {
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
pub enum Filter {
    SrcMac(MacAddr),
    DstMac(MacAddr),
    Mac(MacAddr),
    SrcAddr(IpAddr),
    DstAddr(IpAddr),
    Addr(IpAddr),
    SrcPort(u16),
    DstPort(u16),
    Port(u16),
    Protocol(Protocol),
    Others(bool),
}

impl Filter {
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
            Filter::SrcMac(mac) => match self.get_mac(packet_data) {
                Some(packet_mac) => {
                    if mac == packet_mac.src_mac {
                        true
                    } else {
                        false
                    }
                }
                None => false,
            },
            Filter::DstMac(mac) => match self.get_mac(packet_data) {
                Some(packet_mac) => {
                    if mac == packet_mac.dst_mac {
                        true
                    } else {
                        false
                    }
                }
                None => false,
            },
            Filter::Mac(mac) => match self.get_mac(packet_data) {
                Some(packet_mac) => {
                    if mac == packet_mac.src_mac || mac == packet_mac.dst_mac {
                        true
                    } else {
                        false
                    }
                }
                None => false,
            },
            Filter::SrcAddr(addr) => match addr {
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
            Filter::DstAddr(addr) => match addr {
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
            Filter::Addr(addr) => match addr {
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
            Filter::SrcPort(port) => match self.get_ipv4_tcp_udp_port(packet_data) {
                Some(packet_port) => {
                    if port == packet_port.src_port {
                        true
                    } else {
                        false
                    }
                }
                None => false,
            },
            Filter::DstPort(port) => match self.get_ipv4_tcp_udp_port(packet_data) {
                Some(packet_port) => {
                    if port == packet_port.dst_port {
                        true
                    } else {
                        false
                    }
                }
                None => false,
            },
            Filter::Port(port) => match self.get_ipv4_tcp_udp_port(packet_data) {
                Some(packet_port) => {
                    if port == packet_port.src_port || port == packet_port.dst_port {
                        true
                    } else {
                        false
                    }
                }
                None => false,
            },
            Filter::Protocol(protocol) => match protocol {
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
            Filter::Others(b) => b, // store others results
        }
    }
    pub fn parser(input: &str) -> Option<Filter> {
        // two styles:
        // ip=192.168.1.1
        // tcp
        if input.contains("=") {
            let input_split: Vec<&str> = input.split("=").map(|x| x.trim()).collect();
            if input_split.len() == 2 {
                // ip=192.168.1.1 => ['ip', '192.168.1.1']
                let filter_name = input_split[0].to_lowercase();
                let filter_parameter = input_split[1];
                match filter_name.as_str() {
                    "mac" | "srcmac" | "dstmac" => {
                        let mac: MacAddr = match filter_parameter.parse() {
                            Ok(i) => i,
                            Err(e) => panic!(
                                "convert [{}] to MacAddr struct failed: {}",
                                filter_parameter, e
                            ),
                        };
                        if filter_name == "mac" {
                            Some(Filter::Mac(mac))
                        } else if filter_name == "srcmac" {
                            Some(Filter::SrcMac(mac))
                        } else {
                            Some(Filter::DstMac(mac))
                        }
                    }
                    "ip" | "srcip" | "dstip" | "addr" | "srcaddr" | "dstaddr" => {
                        let ip_addr: IpAddr = match filter_parameter.parse() {
                            Ok(i) => i,
                            Err(e) => panic!(
                                "convert [{}] to IpAddr struct failed: {}",
                                filter_parameter, e
                            ),
                        };
                        if filter_name == "ip" || filter_name == "addr" {
                            Some(Filter::Addr(ip_addr))
                        } else if filter_name == "srcip" || filter_name == "srcaddr" {
                            Some(Filter::SrcAddr(ip_addr))
                        } else {
                            Some(Filter::DstAddr(ip_addr))
                        }
                    }
                    "port" | "srcport" | "dstport" => {
                        let port: u16 = match filter_parameter.parse() {
                            Ok(p) => p,
                            Err(e) => panic!("convert [{}] to u16 failed: {}", filter_parameter, e),
                        };
                        if filter_name == "port" {
                            Some(Filter::Port(port))
                        } else if filter_name == "srcport" {
                            Some(Filter::SrcPort(port))
                        } else {
                            Some(Filter::DstPort(port))
                        }
                    }
                    _ => None,
                }
            } else {
                None
            }
        } else {
            // protocol
            let procotol_name_lowcase: Vec<String> =
                PROCOTOL_NAME.iter().map(|x| x.to_lowercase()).collect();

            if procotol_name_lowcase.contains(&input.to_string()) {
                match Protocol::convert(input) {
                    Some(procotol) => Some(Filter::Protocol(procotol)),
                    None => None,
                }
            } else {
                None
            }
        }
    }
}

pub fn show_valid_protocol() -> Vec<String> {
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
}

#[derive(Debug, Clone, Copy)]
pub enum ShuntingYardElem {
    Filter(Filter),
    Operator(Operator),
}

/// shunting yard alg.
#[derive(Debug, Clone)]
pub struct Filters {
    pub output_queue: Vec<ShuntingYardElem>,
}

impl Filters {
    pub fn check(&self, packet_data: &[u8]) -> Result<bool, PcaptureError> {
        let mut output_queue_rev = self.output_queue.clone();
        output_queue_rev.reverse();
        let mut calc_queue = Vec::new();
        while let Some(sye) = output_queue_rev.pop() {
            match sye {
                ShuntingYardElem::Filter(f) => calc_queue.push(f),
                ShuntingYardElem::Operator(o) => {
                    let f1 = match calc_queue.pop() {
                        Some(f) => f,
                        None => {
                            return Err(PcaptureError::ShouldHaveValueError {
                                msg: String::from("the f1 should have value"),
                            });
                        }
                    };
                    let f2 = match calc_queue.pop() {
                        Some(f) => f,
                        None => {
                            return Err(PcaptureError::ShouldHaveValueError {
                                msg: String::from("the f2 should have value"),
                            });
                        }
                    };
                    match o {
                        Operator::And => {
                            let ret = f1.check(packet_data) & f2.check(packet_data);
                            calc_queue.push(Filter::Others(ret));
                        }
                        Operator::Or => {
                            let ret = f1.check(packet_data) | f2.check(packet_data);
                            calc_queue.push(Filter::Others(ret));
                        }
                        _ => (),
                    }
                }
            }
        }
        match calc_queue.pop() {
            Some(f) => match f {
                Filter::Others(b) => Ok(b),
                _ => Ok(f.check(packet_data)),
            },
            None => Ok(false),
        }
    }
    pub fn parser(input: &str) -> Filters {
        let mut output_queue: Vec<ShuntingYardElem> = Vec::new();
        let mut operator_stack: Vec<ShuntingYardElem> = Vec::new();
        let mut statement = String::new();

        let input_split: Vec<&str> = input.split(" ").filter(|&x| x.trim().len() > 0).collect();
        for s in input_split {
            match s {
                "and" => operator_stack.push(ShuntingYardElem::Operator(Operator::And)),
                "or" => operator_stack.push(ShuntingYardElem::Operator(Operator::Or)),
                _ => {
                    for ch in s.chars() {
                        if ch == '(' {
                            // '{' and '[' is illega chars
                            operator_stack.push(ShuntingYardElem::Operator(Operator::LeftBracket));
                        } else if ch == ')' {
                            while let Some(op) = operator_stack.pop() {
                                match op {
                                    ShuntingYardElem::Operator(o) => {
                                        if o == Operator::LeftBracket {
                                            break;
                                        } else {
                                            output_queue.push(op);
                                        }
                                    }
                                    _ => output_queue.push(op),
                                }
                            }
                        } else {
                            statement.push(ch);
                        }
                    }
                }
            }
            if statement.len() > 0 {
                match Filter::parser(&statement) {
                    Some(f) => output_queue.push(ShuntingYardElem::Filter(f)),
                    None => panic!("statemen [{}] parse failed", statement),
                };
                statement.clear();
            }
        }

        Filters { output_queue }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_filters_parser() {
        let exs = vec![
            "ip=192.168.1.1",
            "ip=192.168.1.1 and tcp",
            "ip=192.168.1.1 and port=80",
            "(ip=192.168.1.1 and tcp) or port=80",
        ];
        // for unit test use
        for e in exs {
            let filters = Protocol::convert(e);
            println!("{}", e); // for test
            println!("{:?}", filters); // for test
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
}
