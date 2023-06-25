use std::net::{Ipv4Addr, Ipv6Addr};

pub const SOCKS_VERSION: u8 = 5;
const RESERVED: u8 = 0;

#[derive(Debug, Clone, Copy)]
pub enum AuthMethod {
    NoAuth,
    Gssapi,
    UserPassword,
    NoAcceptableMethod = 255,
}

impl TryFrom<u8> for AuthMethod {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(AuthMethod::NoAuth),
            1 => Ok(AuthMethod::Gssapi),
            2 => Ok(AuthMethod::UserPassword),
            255 => Ok(AuthMethod::NoAcceptableMethod),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum AddressType {
    Ipv4 = 1,
    DomainName = 3,
    Ipv6 = 4,
}

impl TryFrom<u8> for AddressType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(AddressType::Ipv4),
            3 => Ok(AddressType::DomainName),
            4 => Ok(AddressType::Ipv6),
            _ => Err(()),
        }
    }
}

#[derive(Debug)]
pub enum DestinationAddress {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    DomainName(String),
}

pub mod client_hello;
pub mod client_request;
pub mod errors;
pub mod server_hello;
pub mod server_reply;
