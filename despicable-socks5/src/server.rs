use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::Context;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use crate::messages::{
    Connection, Greeting, ServerChoice, ATYP_DOMAIN, ATYP_V4, ATYP_V6,
    AUTH_METHODS_NO_AUTHENTICATION_REQUIRED, CMD_CONNECT, STATUS_ADDRESS_UNSUPPORTED,
    STATUS_COMMAND_UNSUPPORTED, STATUS_NOT_ALLOWED, STATUS_SUCCESS,
};

#[derive(Clone)]
pub struct Socks5ServerConfig {
    pub addr: SocketAddr,
}

pub struct Socks5Server {
    pub acceptor: JoinHandle<()>,
}

impl Socks5Server {
    pub fn launch(config: Socks5ServerConfig) -> Self {
        let acceptor = tokio::spawn(run_server(config));
        Self { acceptor }
    }
}

#[tracing::instrument(skip(config))]
async fn run_server(config: Socks5ServerConfig) {
    if let Err(error) = run_server_inner(config).await {
        tracing::error!(?error, "Error in socks5 server")
    }
}

async fn run_server_inner(config: Socks5ServerConfig) -> anyhow::Result<()> {
    let listener = TcpListener::bind(config.addr)
        .await
        .context("Failed to bind sock server")?;

    loop {
        let (connection, addr) = listener
            .accept()
            .await
            .context("Failed to accept new TCP connection")?;

        tokio::spawn(handle_connection(connection, addr));
    }
}

#[tracing::instrument(skip(stream))]
async fn handle_connection(stream: TcpStream, addr: SocketAddr) {
    let _ = addr;
    if let Err(error) = handle_connection_inner(stream).await {
        tracing::error!(?error, "Error in socks5 connection")
    }
}

async fn handle_connection_inner(mut stream: TcpStream) -> anyhow::Result<()> {
    let mut buf = [0; 1024];

    let len = stream
        .read(&mut buf)
        .await
        .context("Failed to read greeting")?;

    let greeting = Greeting(&buf[..len]);

    if !greeting.filter_for_method(AUTH_METHODS_NO_AUTHENTICATION_REQUIRED) {
        tracing::debug!("Client did not support no auth");
        let buf = [5, STATUS_NOT_ALLOWED];
        stream
            .write_all(&buf)
            .await
            .context("Failed to send not supported")?;

        return Ok(());
    }

    drop(greeting);

    let mut choice = ServerChoice(&mut buf);

    *choice.version_mut() = 5;
    *choice.method_mut() = AUTH_METHODS_NO_AUTHENTICATION_REQUIRED;

    drop(choice);

    stream
        .write_all(&buf[..2])
        .await
        .context("Failed to send choice")?;

    let len = stream.read(&mut buf).await.context("Failed to read auth")?;

    let mut connection = Connection(&mut buf[..len]);

    let cmd = *connection.cmd();

    if cmd != CMD_CONNECT {
        tracing::debug!(?cmd, "Client gave unsupported command");
        let buf = [5, STATUS_COMMAND_UNSUPPORTED];
        stream
            .write_all(&buf)
            .await
            .context("Failed to send not supported")?;

        return Ok(());
    }

    let addr = if *connection.atyp() == ATYP_V4 {
        let addr = connection.addr();
        IpAddr::V4(Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]))
    } else if *connection.atyp() == ATYP_V6 {
        let addr = connection.addr();
        let bytes: [u8; 16] = addr.try_into().unwrap();
        IpAddr::V6(Ipv6Addr::from(bytes))
    } else if *connection.atyp() == ATYP_DOMAIN {
        let name = String::from_utf8(connection.addr().to_vec())?;
        tokio::net::lookup_host(name).await?.next().unwrap().ip()
    } else {
        tracing::debug!(?cmd, "Client gave unsupported addr");
        let buf = [5, STATUS_ADDRESS_UNSUPPORTED];
        stream
            .write_all(&buf)
            .await
            .context("Failed to send not supported")?;

        return Ok(());
    };

    let socket_addr = SocketAddr::new(addr, connection.port());

    let mut outbound = TcpStream::connect(socket_addr).await?;

    *connection.status_mut() = STATUS_SUCCESS;
    *connection.version_mut() = 5;

    let local_addr = outbound.local_addr()?;

    let bytes = match local_addr.ip() {
        IpAddr::V4(inner) => inner.octets().to_vec(),
        IpAddr::V6(inner) => inner.octets().to_vec(),
    };

    connection.addr_mut().copy_from_slice(&bytes);
    connection.set_port(local_addr.port());

    stream.write(&buf[..len]).await?;

    tokio::io::copy_bidirectional(&mut outbound, &mut stream).await?;

    Ok(())
}
