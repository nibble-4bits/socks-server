use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use super::{AddressType, DestinationAddress, RESERVED, SOCKS_VERSION};

#[derive(Debug, Clone, Copy)]
pub enum Reply {
    Succeeded = 0,
    SocksServerFail,
    #[allow(unused)]
    ConnNotAllowed,
    #[allow(unused)]
    NetUnreachable,
    #[allow(unused)]
    HostUnreachable,
    ConnRefused,
    #[allow(unused)]
    TTLExpired,
    CmdNotSupported,
    AddrTypeNotSupported,
}

#[derive(Debug)]
pub struct ServerReply {
    pub version: u8,
    pub reply: Reply,
    pub reserved: u8,
    pub address_type: AddressType,
    pub bound_address: DestinationAddress,
    pub bound_port: u16,
}

impl ServerReply {
    pub fn new_successful_reply(sock_addr: SocketAddr) -> Self {
        let (address_type, bound_address) = match sock_addr.ip() {
            IpAddr::V4(v4_addr) => (AddressType::Ipv4, DestinationAddress::Ipv4(v4_addr)),
            IpAddr::V6(v6_addr) => (AddressType::Ipv6, DestinationAddress::Ipv6(v6_addr)),
        };

        Self {
            version: SOCKS_VERSION,
            reply: Reply::Succeeded,
            reserved: RESERVED,
            address_type,
            bound_address,
            bound_port: sock_addr.port(),
        }
    }

    pub fn new_unsuccessful_reply(reply: Reply) -> Self {
        Self {
            version: SOCKS_VERSION,
            reply,
            reserved: RESERVED,
            address_type: AddressType::Ipv4,
            bound_address: DestinationAddress::Ipv4(Ipv4Addr::new(0, 0, 0, 0)),
            bound_port: 0,
        }
    }

    // Raw packet has the following structure:
    // +----+-----+-------+------+----------+----------+
    // |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    // +----+-----+-------+------+----------+----------+
    // | 1  |  1  | X'00' |  1   | Variable |    2     |
    // +----+-----+-------+------+----------+----------+
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut packet = vec![
            self.version,
            self.reply as u8,
            self.reserved,
            self.address_type as u8,
        ];
        let port = u16::to_be_bytes(self.bound_port);

        match &self.bound_address {
            DestinationAddress::Ipv4(v4_addr) => {
                packet.extend_from_slice(v4_addr.octets().as_slice());
                packet.extend_from_slice(port.as_slice());
            }
            DestinationAddress::Ipv6(v6_addr) => {
                packet.extend_from_slice(v6_addr.octets().as_slice());
                packet.extend_from_slice(port.as_slice());
            }
            _ => {}
        };

        packet
    }
}
