pub const AUTH_METHODS_NO_AUTHENTICATION_REQUIRED: u8 = 0x00;
pub const AUTH_METHODS_GSSAPI: u8 = 0x01;
pub const AUTH_METHODS_USERNAME_PASSWORD: u8 = 0x02;
pub const AUTH_METHODS_NO_ACCEPTABLE_METHODS: u8 = 0xFF;

pub const CMD_CONNECT: u8 = 0x01;
pub const CMD_BIND: u8 = 0x02;
pub const CMD_UDP_ASSOCIATE: u8 = 0x03;

pub const STATUS_SUCCESS: u8 = 0x00;
pub const STATUS_SOCKS_FAIL: u8 = 0x01;
pub const STATUS_NOT_ALLOWED: u8 = 0x02;
pub const STATUS_NET_UNREACHABLE: u8 = 0x03;
pub const STATUS_HOST_UNREACHABLE: u8 = 0x04;
pub const STATUS_CONN_REFUSED: u8 = 0x05;
pub const STATUS_TTL_EXP: u8 = 0x06;
pub const STATUS_COMMAND_UNSUPPORTED: u8 = 0x07;
pub const STATUS_ADDRESS_UNSUPPORTED: u8 = 0x08;

pub const ATYP_V4: u8 = 0x01;
pub const ATYP_DOMAIN: u8 = 0x03;
pub const ATYP_V6: u8 = 0x04;

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Default, Hash)]
pub struct Greeting<B>(pub B);

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Default, Hash)]
pub struct ServerChoice<B>(pub B);

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Default, Hash)]
pub struct UsernamePasswordAuthRequest<B>(pub B);

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Default, Hash)]
pub struct Status<B>(pub B);

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Default, Hash)]
pub struct Connection<B>(pub B);

impl<B> Greeting<B>
where
    B: AsRef<[u8]>,
{
    #[inline]
    pub fn is_done(&self) -> bool {
        let slice = self.0.as_ref();
        slice.len() >= 2 && slice.len() - 2 >= slice[1] as usize
    }
    #[inline]
    pub fn version(&self) -> &u8 {
        &self.0.as_ref()[0]
    }
    #[inline]
    pub fn nmethods(&self) -> &u8 {
        &self.0.as_ref()[1]
    }
    #[inline]
    pub fn methods(&self) -> &[u8] {
        &self.0.as_ref()[2..]
    }
    #[inline]
    pub fn filter_for_method(&self, target: u8) -> bool {
        self.methods().iter().any(|b| *b == target)
    }
}

impl<B> ServerChoice<B>
where
    B: AsRef<[u8]>,
{
    #[inline]
    pub fn version(&self) -> &u8 {
        &self.0.as_ref()[0]
    }
    #[inline]
    pub fn method(&self) -> &u8 {
        &self.0.as_ref()[1]
    }
}

impl<B> ServerChoice<B>
where
    B: AsMut<[u8]>,
{
    #[inline]
    pub fn version_mut(&mut self) -> &mut u8 {
        &mut self.0.as_mut()[0]
    }
    #[inline]
    pub fn method_mut(&mut self) -> &mut u8 {
        &mut self.0.as_mut()[1]
    }
}

impl<B> UsernamePasswordAuthRequest<B>
where
    B: AsRef<[u8]>,
{
    #[inline]
    pub fn version(&self) -> &u8 {
        &self.0.as_ref()[0]
    }
    #[inline]
    pub fn ulen(&self) -> &u8 {
        &self.0.as_ref()[1]
    }
    #[inline]
    pub fn uname(&self) -> &[u8] {
        &self.0.as_ref()[2..2 + *self.ulen() as usize]
    }
    #[inline]
    pub fn plen(&self) -> &u8 {
        &self.0.as_ref()[2 + *self.ulen() as usize]
    }
    #[inline]
    pub fn password(&self) -> &[u8] {
        let offset = 3 + *self.ulen() as usize;
        &self.0.as_ref()[3 + *self.ulen() as usize..offset + *self.plen() as usize]
    }
}

impl<B> Status<B>
where
    B: AsRef<[u8]>,
{
    #[inline]
    pub fn version(&self) -> &u8 {
        &self.0.as_ref()[0]
    }
    #[inline]
    pub fn status(&self) -> &u8 {
        &self.0.as_ref()[1]
    }
}

impl<B> Status<B>
where
    B: AsMut<[u8]>,
{
    #[inline]
    pub fn version_mut(&mut self) -> &mut u8 {
        &mut self.0.as_mut()[0]
    }
    #[inline]
    pub fn status_mut(&mut self) -> &mut u8 {
        &mut self.0.as_mut()[1]
    }
}

impl<B> Connection<B>
where
    B: AsRef<[u8]>,
{
    #[inline]
    pub fn is_done(&self) -> bool {
        if self.0.as_ref().len() > 8 {
            let atyp = *self.atyp();

            let addr = self.addr();

            match atyp {
                ATYP_V4 => addr.len() >= 4,
                ATYP_V6 => addr.len() >= 16,
                ATYP_DOMAIN => {
                    if addr.len() > 0 {
                        let nlen = addr[0];

                        addr.len() > nlen as usize
                    } else {
                        false
                    }
                }
                _ => unimplemented!()
            }
        } else {
            false
        }
    }
    #[inline]
    pub fn version(&self) -> &u8 {
        &self.0.as_ref()[0]
    }
    #[inline]
    pub fn cmd(&self) -> &u8 {
        &self.0.as_ref()[1]
    }
    #[inline]
    pub fn rsv(&self) -> &u8 {
        &self.0.as_ref()[2]
    }
    #[inline]
    pub fn atyp(&self) -> &u8 {
        &self.0.as_ref()[3]
    }
    #[inline]
    pub fn addr(&self) -> &[u8] {
        let buf = self.0.as_ref();
        &buf[4..(buf.len() - 2)]
    }
    #[inline]
    pub fn port(&self) -> u16 {
        let buf = self.0.as_ref();
        u16::from_be_bytes([buf[buf.len() - 2], buf[buf.len() - 1]])
    }
}

impl<B> Connection<B>
where
    B: AsMut<[u8]>,
{
    #[inline]
    pub fn version_mut(&mut self) -> &mut u8 {
        &mut self.0.as_mut()[0]
    }
    #[inline]
    pub fn status_mut(&mut self) -> &mut u8 {
        &mut self.0.as_mut()[1]
    }
    #[inline]
    pub fn rsv_mut(&mut self) -> &mut u8 {
        &mut self.0.as_mut()[2]
    }
    #[inline]
    pub fn atyp_mut(&mut self) -> &mut u8 {
        &mut self.0.as_mut()[3]
    }
    #[inline]
    pub fn addr_mut(&mut self) -> &mut [u8] {
        let buf = self.0.as_mut();
        let len = buf.len();
        &mut buf[4..(len - 2)]
    }
    #[inline]
    pub fn set_port(&mut self, port: u16) {
        let len = self.0.as_mut().len();
        let bytes = port.to_be_bytes();
        self.0.as_mut()[len - 2] = bytes[0];
        self.0.as_mut()[len - 1] = bytes[1];
    }
}
