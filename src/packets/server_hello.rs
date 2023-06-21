use super::{AuthMethod, SOCKS_VERSION};

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
        [self.version, self.method as u8]
    }
}
