use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::io::{self, Write};
use std::net::Ipv4Addr;

use byteorder::{NetworkEndian, WriteBytesExt};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid message type len={len} type={type_raw:?}")]
    InvalidMessageType { len: u8, type_raw: Option<u8> },

    #[error("invalid IP address")]
    InvalidIpAddress,
}

pub const DHCP_SUBNET_MASK: u8 = 1;
// pub const DHCP_ROUTER_IP: u8 = 3;
pub const DHCP_MTU: u8 = 26;
pub const DHCP_REQUESTED_IP: u8 = 50;
pub const DHCP_LEASE_TIME: u8 = 51;
pub const DHCP_MESSAGE_TYPE: u8 = 53;
pub const DHCP_SERVER_ID: u8 = 54;
// pub const DHCP_PARAMETER_REQUEST_LIST: u8 = 55;
// pub const DHCP_MAXIMUM_DHCP_MESSAGE_SIZE: u8 = 57;
// pub const DHCP_VENDOR_CLASS_IDENTIFIER: u8 = 60;
pub const DHCP_CLIENT_IDENTIFIER: u8 = 61;
pub const DHCP_TFTP_SERVER_NAME: u8 = 66;
// pub const DHCP_USER_CLASS: u8 = 77;
// pub const DHCP_CLIENT_ARCHITECTURE: u8 = 93;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    Discover = 1,
    Offer = 2,
    Request = 3,
    Decline = 4,
    Ack = 5,
    Nak = 6,
    Release = 7,
    Inform = 8,
}

impl fmt::Display for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Discover => write!(f, "discover"),
            Self::Offer => write!(f, "offer"),
            Self::Request => write!(f, "request"),
            Self::Decline => write!(f, "decline"),
            Self::Ack => write!(f, "ack"),
            Self::Nak => write!(f, "nak"),
            Self::Release => write!(f, "release"),
            Self::Inform => write!(f, "inform"),
        }
    }
}

impl TryFrom<u8> for MessageType {
    type Error = u8;

    fn try_from(x: u8) -> Result<Self, Self::Error> {
        match x {
            1 => Ok(Self::Discover),
            2 => Ok(Self::Offer),
            3 => Ok(Self::Request),
            4 => Ok(Self::Decline),
            5 => Ok(Self::Ack),
            6 => Ok(Self::Nak),
            7 => Ok(Self::Release),
            8 => Ok(Self::Inform),
            x => Err(x),
        }
    }
}

impl Into<u8> for MessageType {
    fn into(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, Clone)]
pub enum DhcpOption {
    ByteArray(Vec<u8>),
    Ipv4Addr(Ipv4Addr),
    U16(u16),
    U32(u32),
    MessageType(MessageType),
    String(String),
}

impl DhcpOption {
    pub fn parse(tag: u8, data: &[u8]) -> Result<Self, Error> {
        match tag {
            DHCP_REQUESTED_IP | DHCP_SERVER_ID => {
                if data.len() == 4 {
                    Ok(Self::Ipv4Addr(Ipv4Addr::new(
                        data[0], data[1], data[2], data[3],
                    )))
                } else {
                    Err(Error::InvalidIpAddress)
                }
            }
            DHCP_MESSAGE_TYPE => {
                let len = data.len() as u8;
                if data.len() == 1 {
                    Ok(Self::MessageType(MessageType::try_from(data[0]).map_err(
                        |x| Error::InvalidMessageType {
                            len,
                            type_raw: Some(x),
                        },
                    )?))
                } else {
                    Err(Error::InvalidMessageType {
                        len,
                        type_raw: None,
                    })
                }
            }
            DHCP_CLIENT_IDENTIFIER => Ok(Self::ByteArray(data.to_vec())),
            _ => Ok(Self::ByteArray(data.to_vec())),
        }
    }

    pub fn len(&self) -> u8 {
        match self {
            Self::Ipv4Addr(_) => 4,
            Self::U16(_) => 2,
            Self::U32(_) => 4,
            Self::MessageType(_) => 1,
            Self::ByteArray(v) => TryInto::<u8>::try_into(v.len()).expect("array too big"),
            Self::String(v) => TryInto::<u8>::try_into(v.len()).expect("string too big"),
        }
    }

    pub fn encode(&self, writer: &mut dyn Write) -> io::Result<()> {
        match self {
            Self::Ipv4Addr(v) => writer.write_all(&v.octets()[..]),
            Self::U16(v) => writer.write_u16::<NetworkEndian>(*v),
            Self::U32(v) => writer.write_u32::<NetworkEndian>(*v),
            Self::MessageType(v) => writer.write_u8(Into::<u8>::into(*v)),
            Self::ByteArray(v) => writer.write_all(v.as_slice()),
            Self::String(v) => writer.write_all(v.as_bytes()),
        }
    }
}
