#[derive(Debug)]
pub struct ServerUserPassResponse {
    version: u8,
    status: u8,
}

impl ServerUserPassResponse {
    pub fn new(is_success: bool) -> Self {
        Self {
            version: 1,
            status: !is_success as u8,
        }
    }

    // Raw packet has the following structure:
    // +----+--------+
    // |VER | STATUS |
    // +----+--------+
    // | 1  |   1    |
    // +----+--------+
    pub fn as_bytes(&self) -> [u8; 2] {
        [self.version, self.status]
    }
}
