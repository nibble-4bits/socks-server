use super::AuthMethod;

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
            if let Ok(method) = AuthMethod::try_from(method) {
                methods.push(method);
            }
        }

        Self { version, methods }
    }
}
