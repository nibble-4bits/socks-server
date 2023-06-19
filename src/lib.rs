use std::io::{Read, Write};
use std::net::{IpAddr, Shutdown, TcpListener, TcpStream};
use std::thread;

mod packets;
use packets::{
    AddressType, AuthMethod, ClientHello, ClientRequest, DestinationAddress, ServerHello,
    ServerReply, SOCKS_VERSION,
};

pub struct SocksServer;

impl SocksServer {
    pub fn new() -> Self {
        SocksServer {}
    }

    fn read_client_hello(&self, stream: &mut TcpStream) -> ClientHello {
        let mut raw_packet = [0; 512];
        let n = stream.read(&mut raw_packet).unwrap();

        ClientHello::new(&raw_packet[..n])
    }

    fn send_server_hello(&self, stream: &mut TcpStream, client_hello: ClientHello) {
        if client_hello.version != SOCKS_VERSION {
            println!("Unrecognized SOCKS version {}", client_hello.version);

            stream.shutdown(Shutdown::Both).unwrap();

            return;
        }

        stream
            .write_all(&ServerHello::new(AuthMethod::NoAuth).as_bytes())
            .unwrap();
    }

    fn read_client_request(&self, stream: &mut TcpStream) -> ClientRequest {
        let mut raw_packet = [0; 512];
        let n = stream.read(&mut raw_packet).unwrap();

        ClientRequest::new(&raw_packet[..n])
    }

    fn send_server_reply(
        &self,
        stream: &mut TcpStream,
        client_request: ClientRequest,
    ) -> TcpStream {
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

        let buf = match local_addr.ip() {
            IpAddr::V4(v4_addr) => ServerReply::new(
                0,
                AddressType::Ipv4,
                DestinationAddress::Ipv4(v4_addr),
                local_addr.port(),
            )
            .as_bytes(),
            IpAddr::V6(v6_addr) => ServerReply::new(
                0,
                AddressType::Ipv6,
                DestinationAddress::Ipv6(v6_addr),
                local_addr.port(),
            )
            .as_bytes(),
        };

        stream.write_all(&buf).unwrap();

        remote_conn
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
            self.send_server_hello(&mut client_conn, client_hello);

            let client_request = self.read_client_request(&mut client_conn);
            let remote_conn = self.send_server_reply(&mut client_conn, client_request);

            thread::spawn(|| {
                handle_packet_relay(client_conn, remote_conn);
            });
        }
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
