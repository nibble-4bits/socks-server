use super::{AddressType, DestinationAddress, SOCKS_VERSION};

#[derive(Debug, Clone, Copy)]
pub enum Reply {
    Succeeded = 0,
    SocksServerFail,
    ConnNotAllowed,
    NetUnreachable,
    HostUnreachable,
    ConnRefused,
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
    pub fn new(
        reply: Reply,
        address_type: AddressType,
        bound_address: DestinationAddress,
        bound_port: u16,
    ) -> Self {
        Self {
            version: SOCKS_VERSION,
            reply,
            reserved: 0,
            address_type,
            bound_address,
            bound_port,
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
            DestinationAddress::DomainName(domain) => {
                packet.push(domain.len() as u8);
                packet.extend_from_slice(domain.as_bytes());
            }
        };

        packet
    }
}
