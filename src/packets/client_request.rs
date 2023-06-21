use std::net::{Ipv4Addr, Ipv6Addr};
use std::process;

use super::{AddressType, DestinationAddress};

#[derive(Debug)]
pub enum RequestCommand {
    Connect = 1,
    Bind,
    UdpAssociate,
}

impl TryFrom<u8> for RequestCommand {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(RequestCommand::Connect),
            2 => Ok(RequestCommand::Bind),
            3 => Ok(RequestCommand::UdpAssociate),
            _ => Err(()),
        }
    }
}

#[derive(Debug)]
pub struct ClientRequest {
    pub version: u8,
    pub command: RequestCommand,
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
        let command = if let Ok(cmd) = RequestCommand::try_from(command) {
            cmd
        } else {
            eprintln!("Unrecognized request command {command}");
            process::exit(1);
        };
        let _reserved = raw_packet[2];
        let address_type = raw_packet[3];

        let address_type = if let Ok(addr_type) = AddressType::try_from(address_type) {
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
