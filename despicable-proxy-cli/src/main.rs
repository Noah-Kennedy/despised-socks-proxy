use std::net::{IpAddr, SocketAddr};
use despicable_socks5::tokio_server::{Socks5Server, Socks5ServerConfig};

use clap::Parser;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// IP address to serve on
    #[clap(long, group = "socks")]
    socks_ip: Option<IpAddr>,
    /// Port to serve on
    #[clap(long, requires = "socks")]
    socks_port: Option<u16>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::fmt().init();

    let args = Args::parse();

    if let Args { socks_ip: Some(ip), socks_port: Some(port), ..} = args {
        tracing::info!("Launching socks proxy");

        let config = Socks5ServerConfig {
            addr: SocketAddr::new(ip, port),
        };

        let server = Socks5Server::launch(config);

        server.acceptor.await.unwrap();
    }

    Ok(())
}
