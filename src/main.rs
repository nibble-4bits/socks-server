use socks_server::SocksServer;

const PORT: i32 = 8888;

#[tokio::main]
async fn main() {
    let server = SocksServer::new();

    server.listen(PORT).await;
}
