use super::errors::ClientHelloError;
use super::{AuthMethod, SOCKS_VERSION};

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
    pub fn new(raw_packet: &[u8]) -> Result<Self, ClientHelloError> {
        if raw_packet.len() < 3 {
            return Err(ClientHelloError::MalformedPacket);
        }

        let version = raw_packet[0];
        if version != SOCKS_VERSION {
            return Err(ClientHelloError::UnexpectedProtocolVersion(version));
        }

        let n_methods = raw_packet[1];
        if n_methods == 0 {
            return Err(ClientHelloError::MalformedPacket);
        }

        let mut methods = Vec::with_capacity(n_methods as usize);
        for &method in &raw_packet[2..] {
            if let Ok(method) = AuthMethod::try_from(method) {
                methods.push(method);
            }
        }

        Ok(Self { version, methods })
    }
}
