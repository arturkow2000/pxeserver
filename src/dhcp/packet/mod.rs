use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::fmt;
use std::io::{Cursor, Read};
use std::net::Ipv4Addr;

use byteorder::{NetworkEndian, ReadBytesExt};
use thiserror::Error;

pub use options::DhcpOption;

use super::id::Mac;

pub mod encode;
pub mod options;

#[derive(Error, Debug)]
pub enum Error {
    #[error("packet truncated")]
    Truncated,

    #[error("invalid hlen, expected {expected} got {got}")]
    InvalidHLen { expected: u8, got: u8 },

    #[error("invalid cookie: {0}.{1}.{2}.{3}")]
    InvalidCookie(u8, u8, u8, u8),

    #[error("invalid message type: {0}")]
    InvalidMessageType(u8),

    #[error("option type={tag} len={len} parse failed")]
    OptionParseFailed {
        tag: u8,
        len: u8,
        source: options::Error,
    },
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum BootpMessageType {
    Request = 1,
    Reply = 2,
}

impl TryFrom<u8> for BootpMessageType {
    type Error = u8;

    fn try_from(x: u8) -> Result<Self, Self::Error> {
        match x {
            1 => Ok(Self::Request),
            2 => Ok(Self::Reply),
            x => Err(x),
        }
    }
}

impl Into<u8> for BootpMessageType {
    fn into(self) -> u8 {
        self as u8
    }
}

impl fmt::Display for BootpMessageType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Request => "request",
                Self::Reply => "reply",
            }
        )
    }
}

pub struct Packet {
    pub bootp_message_type: BootpMessageType,
    pub htype: u8,
    pub hlen: u8,
    pub mac: Mac,
    pub hops: u8,
    pub xid: u32,
    pub secs: u16,
    pub flags: u16,
    pub ciaddr: Ipv4Addr,
    pub yiaddr: Ipv4Addr,
    pub siaddr: Ipv4Addr,
    pub giaddr: Ipv4Addr,
    pub server_name: Option<String>,
    pub boot_file_name: Option<String>,
    pub options: BTreeMap<u8, DhcpOption>,
}

impl Packet {
    pub fn parse(buf: &[u8]) -> Result<Self, Error> {
        let mut cursor = Cursor::new(buf);

        let bootp_message_type =
            BootpMessageType::try_from(cursor.read_u8().map_err(|_| Error::Truncated)?)
                .map_err(|x| Error::InvalidMessageType(x))?;

        let htype = cursor.read_u8().map_err(|_| Error::Truncated)?;
        let hlen = cursor.read_u8().map_err(|_| Error::Truncated)?;
        if hlen != 6 {
            return Err(Error::InvalidHLen {
                expected: 6,
                got: hlen,
            });
        }

        let hops = cursor.read_u8().map_err(|_| Error::Truncated)?;
        let xid = cursor
            .read_u32::<NetworkEndian>()
            .map_err(|_| Error::Truncated)?;
        let secs = cursor
            .read_u16::<NetworkEndian>()
            .map_err(|_| Error::Truncated)?;
        let flags = cursor
            .read_u16::<NetworkEndian>()
            .map_err(|_| Error::Truncated)?;

        let mut ciaddr = [0u8; 4];
        let mut yiaddr = [0u8; 4];
        let mut siaddr = [0u8; 4];
        let mut giaddr = [0u8; 4];

        cursor
            .read_exact(&mut ciaddr[..])
            .map_err(|_| Error::Truncated)?;
        cursor
            .read_exact(&mut yiaddr[..])
            .map_err(|_| Error::Truncated)?;
        cursor
            .read_exact(&mut siaddr[..])
            .map_err(|_| Error::Truncated)?;
        cursor
            .read_exact(&mut giaddr[..])
            .map_err(|_| Error::Truncated)?;

        let mut hardware_address = [0u8; 16];
        cursor
            .read_exact(&mut hardware_address[..])
            .map_err(|_| Error::Truncated)?;

        let ciaddr = Ipv4Addr::from(ciaddr);
        let yiaddr = Ipv4Addr::from(yiaddr);
        let siaddr = Ipv4Addr::from(siaddr);
        let giaddr = Ipv4Addr::from(giaddr);

        let hardware_address = Mac::from(hardware_address);

        let server_name = Self::parse_str(&mut cursor, 64)?;
        let boot_file_name = Self::parse_str(&mut cursor, 128)?;

        trace!("type = {}", bootp_message_type);
        trace!("htype = {}", htype);
        trace!("hlen = {}", hlen);
        trace!("hops = {}", hops);
        trace!("xid = {:x}", xid);
        trace!("secs = {}", secs);
        trace!("flags = {:x}", flags);
        trace!("ciaddr = {}", ciaddr);
        trace!("yiaddr = {}", yiaddr);
        trace!("siaddr = {}", siaddr);
        trace!("giaddr = {}", giaddr);
        trace!("mac = {}", hardware_address);
        trace!("server = {}", server_name.as_deref().unwrap_or("<NONE>"));
        trace!("file = {}", boot_file_name.as_deref().unwrap_or("<NONE>"));

        let options_len = buf.len() - cursor.position() as usize;
        trace!("options length = {}", options_len);

        let mut options: BTreeMap<u8, DhcpOption> = BTreeMap::new();
        if options_len > 0 {
            Self::parse_options(&mut cursor, &mut options, options_len)?;
        }

        Ok(Self {
            bootp_message_type,
            htype,
            hlen,
            mac: hardware_address,
            hops,
            xid,
            secs,
            flags,
            ciaddr,
            yiaddr,
            siaddr,
            giaddr,
            server_name,
            boot_file_name,
            options,
        })
    }

    fn parse_str(cursor: &mut Cursor<&[u8]>, len: usize) -> Result<Option<String>, Error> {
        let raw = cursor
            .get_ref()
            .get(cursor.position() as usize..cursor.position() as usize + len)
            .ok_or(Error::Truncated)?;

        cursor.set_position(cursor.position() + len as u64);

        if raw[0] == 0 {
            return Ok(None);
        }

        let terminator_offset = raw
            .iter()
            .copied()
            .enumerate()
            .find(|(x, _)| *x == 0)
            .map(|(i, _)| i)
            .unwrap_or(len);

        Ok(Some(
            String::from_utf8_lossy(&raw[..terminator_offset]).to_string(),
        ))
    }

    fn parse_options(
        cursor: &mut Cursor<&[u8]>,
        options: &mut BTreeMap<u8, DhcpOption>,
        mut left: usize,
    ) -> Result<(), Error> {
        // options always start at offset 236 from packet start
        debug_assert_eq!(cursor.position(), 236);

        let mut cookie = [0u8; 4];
        cursor
            .read_exact(&mut cookie)
            .map_err(|_| Error::Truncated)?;

        if &cookie[..] != &[99, 130, 83, 99][..] {
            return Err(Error::InvalidCookie(
                cookie[0], cookie[1], cookie[2], cookie[3],
            ));
        }

        while left > 0 {
            let tag = cursor.read_u8().map_err(|_| Error::Truncated)?;
            // padding
            if tag == 0 {
                left -= 1;
                continue;
            }

            // end of options field
            if tag == 255 {
                break;
            }

            let len = cursor.read_u8().map_err(|_| Error::Truncated)?;
            left -= 2;
            trace!("option tag={} len={}", tag, len);
            assert!(len as usize <= left);

            let data = &cursor.get_ref()
                [cursor.position() as usize..cursor.position() as usize + len as usize];
            cursor.set_position(cursor.position() + Into::<u64>::into(len));

            left -= Into::<usize>::into(len);

            options.insert(
                tag,
                DhcpOption::parse(tag, data).map_err(|source| Error::OptionParseFailed {
                    tag,
                    len,
                    source,
                })?,
            );
        }

        Ok(())
    }
}
