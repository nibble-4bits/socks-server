use num_derive::{FromPrimitive, ToPrimitive};
use std::{
    net::{Ipv4Addr, Ipv6Addr},
    process,
};

const SOCKS_VERSION: u8 = 5;

#[derive(Debug, FromPrimitive, ToPrimitive)]
pub enum AuthMethod {
    NoAuth,
    Gssapi,
    UserPassword,
    NoAcceptableMethod = 255,
}

#[derive(Debug)]
pub struct ClientHello {
    pub version: u8,
    pub methods: Vec<AuthMethod>,
}

impl ClientHello {
    // Raw packet has the following structure:
    // +----+----------+----------+
    // |VER | NMETHODS | METHODS  |
    // +----+----------+----------+
    // | 1  |    1     | 1 to 255 |
    // +----+----------+----------+
    pub fn new(raw_packet: &[u8]) -> Self {
        let version = raw_packet[0];
        let n_methods = raw_packet[1];

        let mut methods = Vec::with_capacity(n_methods as usize);
        for &method in &raw_packet[2..] {
            if let Some(method) = num_traits::FromPrimitive::from_u8(method) {
                methods.push(method);
            }
        }

        Self { version, methods }
    }
}

#[derive(Debug)]
pub struct ServerHello {
    pub version: u8,
    pub method: AuthMethod,
}

impl ServerHello {
    pub fn new(method: AuthMethod) -> Self {
        Self {
            version: SOCKS_VERSION,
            method,
        }
    }

    // Raw packet has the following structure:
    // +----+--------+
    // |VER | METHOD |
    // +----+--------+
    // | 1  |   1    |
    // +----+--------+
    pub fn as_bytes(&self) -> [u8; 2] {
        [
            self.version,
            num_traits::ToPrimitive::to_u8(&self.method).unwrap(),
        ]
    }
}

#[derive(Debug, FromPrimitive, ToPrimitive)]
pub enum AddressType {
    Ipv4 = 1,
    DomainName = 3,
    Ipv6 = 4,
}

#[derive(Debug)]
pub enum DestinationAddress {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    DomainName(String),
}

#[derive(Debug)]
pub struct ClientRequest {
    pub version: u8,
    pub command: u8,
    pub destination_addr: DestinationAddress,
    pub destination_port: u16,
}

impl ClientRequest {
    // Raw packet has the following structure:
    // +----+-----+-------+------+----------+----------+
    // |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    // +----+-----+-------+------+----------+----------+
    // | 1  |  1  | X'00' |  1   | Variable |    2     |
    // +----+-----+-------+------+----------+----------+
    pub fn new(raw_packet: &[u8]) -> Self {
        let version = raw_packet[0];
        let command = raw_packet[1];
        let _reserved = raw_packet[2];
        let address_type = raw_packet[3];

        let address_type = if let Some(addr_type) = num_traits::FromPrimitive::from_u8(address_type)
        {
            addr_type
        } else {
            eprintln!("Unrecognized address type {address_type}");
            process::exit(1);
        };

        let destination_addr = match address_type {
            AddressType::Ipv4 => {
                let mut octets = [0; 4];
                octets.copy_from_slice(&raw_packet[4..8]);

                DestinationAddress::Ipv4(Ipv4Addr::from(octets))
            }
            AddressType::Ipv6 => {
                let mut octets = [0; 16];
                octets.copy_from_slice(&raw_packet[4..20]);

                DestinationAddress::Ipv6(Ipv6Addr::from(octets))
            }
            AddressType::DomainName => {
                let domain_name_len = raw_packet[4] as usize;

                let domain =
                    String::from_utf8(raw_packet[5..domain_name_len + 5].to_vec()).unwrap();

                DestinationAddress::DomainName(domain)
            }
        };

        let destination_port: Vec<u8> = raw_packet.iter().rev().cloned().take(2).rev().collect();

        Self {
            version,
            command,
            destination_addr,
            destination_port: u16::from_be_bytes(destination_port.try_into().unwrap()),
        }
    }
}

// +----+-----+-------+------+----------+----------+
// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
// +----+-----+-------+------+----------+----------+
// | 1  |  1  | X'00' |  1   | Variable |    2     |
// +----+-----+-------+------+----------+----------+
#[derive(Debug)]
pub struct ServerReply {
    pub version: u8,
    pub reply: u8,
    pub reserved: u8,
    pub address_type: AddressType,
    pub bound_address: DestinationAddress,
    pub bound_port: u16,
}

impl ServerReply {
    pub fn new(
        reply: u8,
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

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut packet = vec![
            self.version,
            self.reply,
            self.reserved,
            num_traits::ToPrimitive::to_u8(&self.address_type).unwrap(),
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
