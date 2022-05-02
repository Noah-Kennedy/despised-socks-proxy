use crate::messages::{
    Connection, Greeting, ATYP_DOMAIN, ATYP_V4, ATYP_V6, AUTH_METHODS_NO_AUTHENTICATION_REQUIRED,
    STATUS_NOT_ALLOWED, STATUS_SUCCESS,
};
use bytes::BytesMut;
use either::Either;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Debug)]
enum GreetingState {
    NewConnection,
    Authenticated,
}

pub struct Greeter {
    state: GreetingState,
    buf: BytesMut,
}

impl Greeter {
    pub fn new() -> Self {
        Self {
            state: GreetingState::NewConnection,
            buf: BytesMut::new(),
        }
    }
    pub fn continue_greeting<T>(
        &mut self,
        data: T,
    ) -> Either<(Either<SocketAddr, (String, u16)>, Connection<BytesMut>), Option<&'static [u8]>>
    where
        T: AsRef<[u8]>,
    {
        match self.state {
            GreetingState::NewConnection => {
                if self.buf.is_empty() {
                    let greeting = Greeting(&data);

                    if let Some(response) = handle_greeting(greeting) {
                        self.state = GreetingState::Authenticated;
                        Either::Right(Some(response))
                    } else {
                        self.buf.extend_from_slice(data.as_ref());
                        Either::Right(None)
                    }
                } else {
                    self.buf.extend_from_slice(data.as_ref());

                    let greeting = Greeting(&self.buf);

                    if let Some(response) = handle_greeting(greeting) {
                        self.buf.clear();
                        self.state = GreetingState::Authenticated;
                        Either::Right(Some(response))
                    } else {
                        Either::Right(None)
                    }
                }
            }
            GreetingState::Authenticated => {
                self.buf.extend_from_slice(data.as_ref());

                let mut conn = Connection(&mut self.buf);

                if let Some(response) = handle_connection(&mut conn) {
                    Either::Left((response, Connection(self.buf.split())))
                } else {
                    self.buf.extend_from_slice(data.as_ref());
                    Either::Right(None)
                }
            }
        }
    }
}

fn handle_greeting<T>(greeting: Greeting<T>) -> Option<&'static [u8]>
where
    T: AsRef<[u8]>,
{
    if !greeting.is_done() {
        None
    } else {
        if !greeting.filter_for_method(AUTH_METHODS_NO_AUTHENTICATION_REQUIRED) {
            tracing::debug!("Client did not support no auth");
            Some(&[5, STATUS_NOT_ALLOWED])
        } else {
            Some(&[5, AUTH_METHODS_NO_AUTHENTICATION_REQUIRED])
        }
    }
}

fn handle_connection<T>(connection: &mut Connection<T>) -> Option<Either<SocketAddr, (String, u16)>>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    if !connection.is_done() {
        None
    } else {
        let addr = if *connection.atyp() == ATYP_V4 {
            let addr = connection.addr();
            Either::Left(IpAddr::V4(Ipv4Addr::new(
                addr[0], addr[1], addr[2], addr[3],
            )))
        } else if *connection.atyp() == ATYP_V6 {
            let addr = connection.addr();
            let bytes: [u8; 16] = addr.try_into().unwrap();
            Either::Left(IpAddr::V6(Ipv6Addr::from(bytes)))
        } else if *connection.atyp() == ATYP_DOMAIN {
            let name = String::from_utf8(connection.addr().to_vec()).unwrap();
            Either::Right(name)
        } else {
            unimplemented!()
        };

        let addr = addr
            .map_left(|addr| SocketAddr::new(addr, connection.port()))
            .map_right(|domain| (domain, connection.port()));

        *connection.status_mut() = STATUS_SUCCESS;
        *connection.version_mut() = 5;

        connection.addr_mut().fill(0);
        connection.set_port(0);

        Some(addr)
    }
}
