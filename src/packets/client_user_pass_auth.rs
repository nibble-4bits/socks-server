use std::str;

#[derive(Debug)]
pub struct ClientUserPassAuth {
    pub version: u8,
    pub username: String,
    pub password: String,
}

impl ClientUserPassAuth {
    // Raw packet has the following structure:
    // +----+------+----------+------+----------+
    // |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
    // +----+------+----------+------+----------+
    // | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
    // +----+------+----------+------+----------+
    pub fn new(raw_packet: &[u8]) -> Self {
        let version = raw_packet[0];

        let username_len = raw_packet[1] as usize;
        let username = str::from_utf8(&raw_packet[2..username_len + 2])
            .unwrap()
            .to_string();

        let password_len = raw_packet[username_len + 2] as usize;
        let password =
            str::from_utf8(&raw_packet[username_len + 3..password_len + username_len + 3])
                .unwrap()
                .to_string();

        Self {
            version,
            username,
            password,
        }
    }
}
