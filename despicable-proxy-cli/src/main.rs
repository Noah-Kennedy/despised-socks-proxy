use anyhow::Context;

use std::net::{IpAddr, SocketAddr};

use clap::Parser;
use despicable_socks5::server::Greeter;
use either::Either;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

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

    if let Args {
        socks_ip: Some(ip),
        socks_port: Some(port),
        ..
    } = args
    {
        tracing::info!("Launching socks proxy");

        let addr = SocketAddr::new(ip, port);

        let listener = TcpListener::bind(addr).await?;

        loop {
            let (conn, _) = listener.accept().await?;
            tokio::spawn(handle_connection(conn));
        }
    }

    Ok(())
}

#[tracing::instrument]
async fn handle_connection(conn: TcpStream) {
    if let Err(error) = handle_connection_inner(conn).await {
        tracing::error!(?error, "Failed to handle connection");
    }
}

async fn handle_connection_inner(mut conn: TcpStream) -> anyhow::Result<()> {
    tracing::info!("New connection");

    let mut greeter = Greeter::new();
    let mut buf = [0; 1024];

    let (endpoint, mut data) = loop {
        let len = conn
            .read(&mut buf)
            .await
            .context("Error reading from client in greeting")?;

        match greeter.continue_greeting(&buf[..len]) {
            Either::Left(res) => break res,
            Either::Right(Some(out)) => {
                conn.write_all(out)
                    .await
                    .context("Failed to write data to client in greeting")?;
            }
            Either::Right(None) => {}
        }
    };

    tracing::info!(?endpoint, "Greeted connection");

    let mut outbound = match endpoint {
        Either::Left(addr) => TcpStream::connect(addr)
            .await
            .context("Failed to connect to socket")?,
        Either::Right((domain, port)) => TcpStream::connect((domain, port))
            .await
            .context("Failed to connect to domain")?,
    };

    let local_addr = outbound.local_addr()?;

    let bytes = match local_addr.ip() {
        IpAddr::V4(inner) => inner.octets().to_vec(),
        IpAddr::V6(inner) => inner.octets().to_vec(),
    };

    data.addr_mut().copy_from_slice(&bytes);
    data.set_port(local_addr.port());

    conn.write_all(data.0.as_ref())
        .await
        .context("Failed to respond to client with conn info")?;

    tracing::info!(?local_addr, "Connected");

    tokio::io::copy_bidirectional(&mut conn, &mut outbound)
        .await
        .context("Error in bidirectional copy")?;

    Ok(())
}
