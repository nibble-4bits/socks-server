use socks_server::SocksServer;

const PORT: i32 = 8888;

fn main() {
    let server = SocksServer::new();

    server.listen(PORT);
}
