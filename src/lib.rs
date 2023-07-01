#![cfg_attr(feature = "unstable", feature(io_error_more))]

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::task;

mod packets;

use packets::client_user_pass_auth::ClientUserPassAuth;
use packets::errors::{
    ClientHelloError, ClientRequestError, ServerHelloError, ServerReplyError, UserPassAuthError,
};
use packets::server_hello::ServerHello;
use packets::server_reply::{Reply, ServerReply};
use packets::server_user_pass_response::ServerUserPassResponse;
pub use packets::AuthMethod;
use packets::DestinationAddress;
use packets::{client_hello::ClientHello, client_request::ClientRequest};

#[derive(Debug, Clone)]
pub struct AuthParams {
    pub logins: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct AuthSettings {
    pub method: AuthMethod,
    pub params: Option<AuthParams>,
}

pub struct SocksServer {
    auth_settings: AuthSettings,
}

impl SocksServer {
    pub fn new(auth_settings: AuthSettings) -> Self {
        SocksServer { auth_settings }
    }

    pub async fn listen(&self, ip: &str, port: u16) -> Result<(), io::Error> {
        let parsed_ip = ip
            .parse::<IpAddr>()
            .unwrap_or_else(|_| panic!("`{ip}` is not a valid IP address"));
        let bound_addr = SocketAddr::from((parsed_ip, port));
        let listener = TcpListener::bind(bound_addr).await?;

        println!("Server listening on port: {}", port);

        loop {
            let (client_conn, client_addr) = match listener.accept().await {
                Ok(result) => result,
                Err(e) => {
                    eprintln!("Error while attempting to accept client connection: {}", e);
                    continue;
                }
            };

            println!("Accepted connection from {}", client_addr);

            let auth_settings = self.auth_settings.clone();
            task::spawn(async {
                handle_connection(client_conn, auth_settings).await;
            });
        }
    }
}

impl Default for SocksServer {
    fn default() -> Self {
        SocksServer::new(AuthSettings {
            method: AuthMethod::NoAuth,
            params: None,
        })
    }
}

async fn read_client_hello(stream: &mut TcpStream) -> Result<ClientHello, ClientHelloError> {
    let mut raw_packet = [0; 512];
    let n = stream.read(&mut raw_packet).await?;

    let packet = ClientHello::new(&raw_packet[..n])?;

    Ok(packet)
}

async fn handle_user_pass_auth(
    stream: &mut TcpStream,
    auth_settings: AuthSettings,
) -> Result<(), UserPassAuthError> {
    let mut raw_packet = [0; 513];
    let n = stream.read(&mut raw_packet).await?;

    let packet = ClientUserPassAuth::new(&raw_packet[..n]);
    if let Some(params) = auth_settings.params {
        if let Some(s) = params.logins.get(&packet.username) {
            if *s == packet.password {
                let response_packet = ServerUserPassResponse::new(true);
                stream.write_all(&response_packet.as_bytes()).await?;
                return Ok(());
            }
        }
    }

    let response_packet = ServerUserPassResponse::new(false);
    stream.write_all(&response_packet.as_bytes()).await?;

    Err(UserPassAuthError::FailedAuth)
}

async fn send_server_hello(
    stream: &mut TcpStream,
    client_hello: ClientHello,
    auth_settings: AuthSettings,
) -> Result<(), ServerHelloError> {
    for method in client_hello.methods {
        if method == auth_settings.method {
            let buf = ServerHello::new(auth_settings.method).as_bytes();
            stream.write_all(&buf).await?;

            if auth_settings.method == AuthMethod::UserPassword {
                handle_user_pass_auth(stream, auth_settings).await?;
            }

            return Ok(());
        }
    }

    let buf = ServerHello::new(AuthMethod::NoAcceptableMethod).as_bytes();
    stream.write_all(&buf).await?;

    Err(ServerHelloError::NoAcceptableAuth)
}

async fn handle_client_request_error(stream: &mut TcpStream, error: &ClientRequestError) {
    use ClientRequestError::*;

    let reply_packet = match error {
        ErrUnsupportedBindCommand | ErrUnsupportedUDPAssociateCommand | ErrUnknownCommand => {
            ServerReply::new_unsuccessful_reply(Reply::CmdNotSupported)
        }
        ErrUnknownAddressType => ServerReply::new_unsuccessful_reply(Reply::AddrTypeNotSupported),
        _ => ServerReply::new_unsuccessful_reply(Reply::SocksServerFail),
    };

    stream.write_all(&reply_packet.as_bytes()).await.unwrap();
}

async fn handle_server_reply_error(stream: &mut TcpStream, error: &ServerReplyError) {
    use ServerReplyError::*;

    let reply_packet = match error {
        IoError(io_err) => match io_err.kind() {
            #[cfg(feature = "unstable")]
            io::ErrorKind::NetworkUnreachable => {
                ServerReply::new_unsuccessful_reply(Reply::NetUnreachable)
            }
            #[cfg(feature = "unstable")]
            io::ErrorKind::HostUnreachable => {
                ServerReply::new_unsuccessful_reply(Reply::HostUnreachable)
            }
            io::ErrorKind::ConnectionRefused => {
                ServerReply::new_unsuccessful_reply(Reply::ConnRefused)
            }
            _ => ServerReply::new_unsuccessful_reply(Reply::SocksServerFail),
        },
    };

    stream.write_all(&reply_packet.as_bytes()).await.unwrap();
}

async fn read_client_request(stream: &mut TcpStream) -> Result<ClientRequest, ClientRequestError> {
    let mut raw_packet = [0; 512];
    let n = stream.read(&mut raw_packet).await?;

    let packet = ClientRequest::new(&raw_packet[..n])?;

    Ok(packet)
}

async fn send_server_reply(
    stream: &mut TcpStream,
    client_request: ClientRequest,
) -> Result<TcpStream, ServerReplyError> {
    let remote_conn = match client_request.destination_addr {
        DestinationAddress::Ipv4(v4_addr) => {
            TcpStream::connect(format!("{}:{}", v4_addr, client_request.destination_port)).await?
        }
        DestinationAddress::Ipv6(v6_addr) => {
            TcpStream::connect(format!("{}:{}", v6_addr, client_request.destination_port)).await?
        }
        DestinationAddress::DomainName(domain) => {
            TcpStream::connect(format!("{}:{}", domain, client_request.destination_port)).await?
        }
    };

    let local_addr = remote_conn.local_addr()?;
    let buf = ServerReply::new_successful_reply(local_addr).as_bytes();

    stream.write_all(&buf).await?;

    Ok(remote_conn)
}

async fn handle_connection(mut client_conn: TcpStream, auth_settings: AuthSettings) {
    let client_hello = match read_client_hello(&mut client_conn).await {
        Ok(packet) => packet,
        Err(e) => {
            eprintln!("Error encountered: {}. Closing connection.", e);
            return;
        }
    };

    if let Err(e) = send_server_hello(&mut client_conn, client_hello, auth_settings).await {
        eprintln!("Error encountered: {}. Closing connection.", e);
        return;
    }

    let client_request = match read_client_request(&mut client_conn).await {
        Ok(packet) => packet,
        Err(e) => {
            eprintln!("Error encountered: {}. Closing connection.", e);
            handle_client_request_error(&mut client_conn, &e).await;
            return;
        }
    };
    let remote_conn = match send_server_reply(&mut client_conn, client_request).await {
        Ok(conn) => conn,
        Err(e) => {
            eprintln!("Error encountered: {}. Closing connection.", e);
            handle_server_reply_error(&mut client_conn, &e).await;
            return;
        }
    };

    handle_packet_relay(client_conn, remote_conn).await;
}

async fn relay_packets(mut src: OwnedReadHalf, mut dst: OwnedWriteHalf) {
    loop {
        let n = match io::copy(&mut src, &mut dst).await {
            Ok(bytes_read) => bytes_read,
            Err(_) => return,
        };

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
