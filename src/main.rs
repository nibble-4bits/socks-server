use socks_server::AuthMethod;
use socks_server::AuthSettings;
use socks_server::SocksServer;

const IP: &str = "0.0.0.0";
const PORT: u16 = 1080;

#[tokio::main]
async fn main() {
    let server = SocksServer::new(AuthSettings {
        method: AuthMethod::NoAuth,
        params: None,
    });

    if let Err(e) = server.listen(IP, PORT).await {
        eprintln!("Attempt to start listening failed: {}", e);
    }
}
