use std::net::IpAddr;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::task;

mod packets;
use packets::client_hello::ClientHello;
use packets::client_request::ClientRequest;
use packets::server_hello::ServerHello;
use packets::server_reply::{Reply, ServerReply};
use packets::{AddressType, AuthMethod, DestinationAddress, SOCKS_VERSION};

pub struct SocksServer;

impl SocksServer {
    pub fn new() -> Self {
        SocksServer {}
    }

    pub async fn listen(&self, port: i32) {
        let listener = TcpListener::bind(format!("0.0.0.0:{port}"))
            .await
            .expect("TCP listener should have been created");

        println!("Server listening on port: {}", port);

        loop {
            let (client_conn, client_addr) = listener
                .accept()
                .await
                .expect("Peer connection should have been accepted");

            println!("Accepted connection from {}", client_addr);

            task::spawn(async {
                handle_connection(client_conn).await;
            });
        }
    }
}

impl Default for SocksServer {
    fn default() -> Self {
        SocksServer::new()
    }
}

async fn read_client_hello(stream: &mut TcpStream) -> ClientHello {
    let mut raw_packet = [0; 512];
    let n = stream.read(&mut raw_packet).await.unwrap();

    ClientHello::new(&raw_packet[..n])
}

async fn send_server_hello(stream: &mut TcpStream, client_hello: ClientHello) {
    if client_hello.version != SOCKS_VERSION {
        println!("Unrecognized SOCKS version {}", client_hello.version);

        stream.shutdown().await.unwrap();

        return;
    }

    stream
        .write_all(&ServerHello::new(AuthMethod::NoAuth).as_bytes())
        .await
        .unwrap();
}

async fn read_client_request(stream: &mut TcpStream) -> ClientRequest {
    let mut raw_packet = [0; 512];
    let n = stream.read(&mut raw_packet).await.unwrap();

    ClientRequest::new(&raw_packet[..n])
}

async fn send_server_reply(stream: &mut TcpStream, client_request: ClientRequest) -> TcpStream {
    let remote_conn = match client_request.destination_addr {
        DestinationAddress::Ipv4(v4_addr) => {
            TcpStream::connect(format!("{}:{}", v4_addr, client_request.destination_port))
                .await
                .unwrap()
        }
        DestinationAddress::Ipv6(v6_addr) => {
            TcpStream::connect(format!("{}:{}", v6_addr, client_request.destination_port))
                .await
                .unwrap()
        }
        DestinationAddress::DomainName(domain) => {
            TcpStream::connect(format!("{}:{}", domain, client_request.destination_port))
                .await
                .unwrap()
        }
    };

    let local_addr = remote_conn.local_addr().unwrap();

    let buf = match local_addr.ip() {
        IpAddr::V4(v4_addr) => ServerReply::new(
            Reply::Succeeded,
            AddressType::Ipv4,
            DestinationAddress::Ipv4(v4_addr),
            local_addr.port(),
        )
        .as_bytes(),
        IpAddr::V6(v6_addr) => ServerReply::new(
            Reply::Succeeded,
            AddressType::Ipv6,
            DestinationAddress::Ipv6(v6_addr),
            local_addr.port(),
        )
        .as_bytes(),
    };

    stream.write_all(&buf).await.unwrap();

    remote_conn
}

async fn handle_connection(mut client_conn: TcpStream) {
    let client_hello = read_client_hello(&mut client_conn).await;
    send_server_hello(&mut client_conn, client_hello).await;

    let client_request = read_client_request(&mut client_conn).await;
    let remote_conn = send_server_reply(&mut client_conn, client_request).await;

    handle_packet_relay(client_conn, remote_conn).await;
}

async fn relay_packets(mut src: OwnedReadHalf, mut dst: OwnedWriteHalf) {
    loop {
        let n = io::copy(&mut src, &mut dst).await.unwrap();

        if n == 0 {
            return;
        }
    }
}

async fn handle_packet_relay(client_conn: TcpStream, remote_conn: TcpStream) {
    let (client_conn_rx, client_conn_tx) = client_conn.into_split();
    let (remote_conn_rx, remote_conn_tx) = remote_conn.into_split();

    let client_to_remote =
        task::spawn(async { relay_packets(client_conn_rx, remote_conn_tx).await });
    let remote_to_client =
        task::spawn(async { relay_packets(remote_conn_rx, client_conn_tx).await });

    client_to_remote.await.unwrap();
    remote_to_client.await.unwrap();
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
