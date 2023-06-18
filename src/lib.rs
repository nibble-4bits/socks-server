use num_derive::{FromPrimitive, ToPrimitive};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, TcpListener, TcpStream};
use std::{process, thread};

#[derive(Debug, FromPrimitive, ToPrimitive)]
enum AuthMethod {
    NoAuth,
    Gssapi,
    UserPassword,
}

// +----+----------+----------+
// |VER | NMETHODS | METHODS  |
// +----+----------+----------+
// | 1  |    1     | 1 to 255 |
// +----+----------+----------+
#[derive(Debug)]
struct ClientHello {
    version: u8,
    n_methods: u8,
    methods: Vec<AuthMethod>,
}

#[derive(Debug, FromPrimitive, ToPrimitive)]
enum AddressType {
    Ipv4 = 1,
    DomainName = 3,
    Ipv6 = 4,
}

#[derive(Debug)]
enum DestinationAddress {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    DomainName(String),
}

// +----+-----+-------+------+----------+----------+
// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
// +----+-----+-------+------+----------+----------+
// | 1  |  1  | X'00' |  1   | Variable |    2     |
// +----+-----+-------+------+----------+----------+
#[derive(Debug)]
struct ClientRequest {
    version: u8,
    command: u8,
    reserved: u8,
    address_type: AddressType,
    destination_addr: DestinationAddress,
    destination_port: u16,
}

pub struct SocksServer;

impl SocksServer {
    pub fn new() -> Self {
        SocksServer {}
    }

    pub fn listen(&self, port: i32) {
        let listener = TcpListener::bind(format!("0.0.0.0:{port}"))
            .expect("TCP listener should have been created");

        println!("Server listening on port: {}", port);

        loop {
            let (mut client_conn, remote) = listener
                .accept()
                .expect("Peer connection should have been accepted");

            println!("Accepted connection from {}", remote);

            let client_hello = self.read_client_hello(&mut client_conn);

            dbg!(&client_hello);

            self.send_server_hello(&mut client_conn, client_hello);

            let client_request = self.read_client_request(&mut client_conn);

            dbg!(&client_request);

            let remote_conn = self.send_server_reply(&mut client_conn, client_request);

            thread::spawn(|| {
                handle_packet_relay(client_conn, remote_conn);
            });
        }
    }

    fn read_client_hello(&self, stream: &mut TcpStream) -> ClientHello {
        let mut buf = [0; 2];
        stream.read_exact(&mut buf).unwrap();

        let [version, n_methods] = buf;

        let mut methods_buf = vec![0; n_methods as usize];
        stream.read_exact(&mut methods_buf).unwrap();

        let mut methods = Vec::with_capacity(n_methods as usize);
        for method in methods_buf {
            if let Some(method) = num_traits::FromPrimitive::from_u8(method) {
                methods.push(method);
            }
        }

        ClientHello {
            version,
            n_methods,
            methods,
        }
    }

    fn read_client_request(&self, stream: &mut TcpStream) -> ClientRequest {
        let mut buf = [0; 4];
        stream.read_exact(&mut buf).unwrap();

        let [version, command, reserved, address_type] = buf;

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
                stream.read_exact(&mut octets).unwrap();

                DestinationAddress::Ipv4(Ipv4Addr::from(octets))
            }
            AddressType::Ipv6 => {
                let mut octets = [0; 16];
                stream.read_exact(&mut octets).unwrap();

                DestinationAddress::Ipv6(Ipv6Addr::from(octets))
            }
            AddressType::DomainName => {
                let mut domain_name_len = [0];
                stream.read_exact(&mut domain_name_len).unwrap();

                let mut domain = vec![0; domain_name_len[0] as usize];
                stream.read_exact(&mut domain).unwrap();

                DestinationAddress::DomainName(String::from_utf8(domain).unwrap())
            }
        };

        let mut destination_port = [0; 2];
        stream.read_exact(&mut destination_port).unwrap();

        ClientRequest {
            version,
            command,
            reserved,
            address_type,
            destination_addr,
            destination_port: u16::from_be_bytes(destination_port),
        }
    }

    fn send_server_hello(&self, stream: &mut TcpStream, client_hello: ClientHello) {
        let buf = [5, 0];
        stream.write_all(&buf).unwrap();
    }

    fn send_server_reply(
        &self,
        stream: &mut TcpStream,
        client_request: ClientRequest,
    ) -> TcpStream {
        // +----+-----+-------+------+----------+----------+
        // |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
        // +----+-----+-------+------+----------+----------+
        // | 1  |  1  | X'00' |  1   | Variable |    2     |
        // +----+-----+-------+------+----------+----------+
        let remote_conn = match client_request.destination_addr {
            DestinationAddress::Ipv4(v4_addr) => {
                TcpStream::connect(format!("{}:{}", v4_addr, client_request.destination_port))
                    .unwrap()
            }
            DestinationAddress::Ipv6(v6_addr) => {
                TcpStream::connect(format!("{}:{}", v6_addr, client_request.destination_port))
                    .unwrap()
            }
            DestinationAddress::DomainName(domain) => {
                TcpStream::connect(format!("{}:{}", domain, client_request.destination_port))
                    .unwrap()
            }
        };

        let local_addr = remote_conn.local_addr().unwrap();
        let port = u16::to_be_bytes(local_addr.port());

        let buf = match local_addr.ip() {
            IpAddr::V4(ipv4) => {
                let ip = ipv4.octets();
                vec![5, 0, 0, 1, ip[0], ip[1], ip[2], ip[3], port[0], port[1]]
            }
            IpAddr::V6(ipv6) => {
                let ip = ipv6.octets();
                vec![
                    5, 0, 0, 4, ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7], ip[8],
                    ip[9], ip[10], ip[11], ip[12], ip[13], ip[14], ip[15], port[0], port[1],
                ]
            }
        };

        stream.write_all(&buf).unwrap();

        remote_conn
    }
}

fn handle_packet_relay(mut client_conn: TcpStream, mut remote_conn: TcpStream) {
    let mut client_conn_2 = client_conn.try_clone().unwrap();
    let mut remote_conn_2 = remote_conn.try_clone().unwrap();

    let client_to_remote = thread::spawn(move || loop {
        let mut buf = [0; 65535];
        let n = match client_conn.read(&mut buf) {
            Ok(s) => s,
            Err(e) => panic!("encountered IO error: {e}"),
        };

        if n == 0 {
            break;
        }

        remote_conn.write_all(&buf[..n]).unwrap();
    });

    let remote_to_client = thread::spawn(move || loop {
        let mut buf = [0; 65535];
        let n = match remote_conn_2.read(&mut buf) {
            Ok(s) => s,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                continue;
            }
            Err(e) => panic!("encountered IO error: {e}"),
        };

        if n == 0 {
            break;
        }

        client_conn_2.write_all(&buf[..n]).unwrap();
    });

    client_to_remote.join().unwrap();
    remote_to_client.join().unwrap();
}

impl Default for SocksServer {
    fn default() -> Self {
        SocksServer::new()
    }
}

// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[test]
//     fn it_works() {
//         let result = add(2, 2);
//         assert_eq!(result, 4);
//     }
// }
