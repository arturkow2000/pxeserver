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
pub const DHCP_ROUTER_IP: u8 = 3;
pub const DHCP_REQUESTED_IP: u8 = 50;
pub const DHCP_LEASE_TIME: u8 = 51;
pub const DHCP_MESSAGE_TYPE: u8 = 53;
pub const DHCP_SERVER_ID: u8 = 54;
pub const DHCP_PARAMETER_REQUEST_LIST: u8 = 55;
pub const DHCP_MAXIMUM_DHCP_MESSAGE_SIZE: u8 = 57;
pub const DHCP_VENDOR_CLASS_IDENTIFIER: u8 = 60;
pub const DHCP_CLIENT_IDENTIFIER: u8 = 61;
pub const DHCP_TFTP_SERVER_NAME: u8 = 66;
pub const DHCP_USER_CLASS: u8 = 77;
pub const DHCP_CLIENT_ARCHITECTURE: u8 = 93;

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
    Unknown { tag: u8, data: Vec<u8> },
    SubnetMask(Ipv4Addr),
    RouterIp(Ipv4Addr),
    RequestedIp(Ipv4Addr),
    LeaseTime(u32),
    MessageType(MessageType),
    ServerId(Ipv4Addr),
    ClientIdentifier(Vec<u8>),
    TftpServerName(String),
}

impl DhcpOption {
    pub fn parse(tag: u8, data: &[u8]) -> Result<Self, Error> {
        match tag {
            DHCP_REQUESTED_IP => {
                if data.len() == 4 {
                    Ok(Self::RequestedIp(Ipv4Addr::new(
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
            DHCP_SERVER_ID => {
                if data.len() == 4 {
                    Ok(Self::ServerId(Ipv4Addr::new(
                        data[0], data[1], data[2], data[3],
                    )))
                } else {
                    Err(Error::InvalidIpAddress)
                }
            }
            DHCP_CLIENT_IDENTIFIER => Ok(Self::ClientIdentifier(data.to_vec())),
            _ => Ok(Self::Unknown {
                tag,
                data: data.to_vec(),
            }),
        }
    }

    /*pub fn required_alignment(&self) -> u8 {
        match self {
            Self::SubnetMask(_) => 4,
            Self::RequestedIp(_) => 4,
            Self::MessageType(_) => 0,
            Self::ServerId(_) => 4,
            Self::ClientIdentifier(_) => 0,
            Self::Unknown { .. } => 0,
        }
    }*/

    pub fn tag(&self) -> u8 {
        match self {
            Self::SubnetMask(_) => DHCP_SUBNET_MASK,
            Self::RouterIp(_) => DHCP_ROUTER_IP,
            Self::RequestedIp(_) => DHCP_REQUESTED_IP,
            Self::LeaseTime(_) => DHCP_LEASE_TIME,
            Self::MessageType(_) => DHCP_MESSAGE_TYPE,
            Self::ServerId(_) => DHCP_SERVER_ID,
            Self::ClientIdentifier(_) => DHCP_CLIENT_IDENTIFIER,
            Self::TftpServerName(_) => DHCP_TFTP_SERVER_NAME,
            Self::Unknown { tag, .. } => *tag,
        }
    }

    pub fn len(&self) -> u8 {
        match self {
            Self::SubnetMask(_) => 4,
            Self::RouterIp(_) => 4,
            Self::RequestedIp(_) => 4,
            Self::LeaseTime(_) => 4,
            Self::MessageType(_) => 1,
            Self::ServerId(_) => 4,
            Self::ClientIdentifier(id) => {
                TryInto::<u8>::try_into(id.len()).expect("client ID too big")
            }
            Self::TftpServerName(name) => {
                TryInto::<u8>::try_into(name.len()).expect("TFTP server name too big")
            }
            Self::Unknown { tag: _, data } => {
                TryInto::<u8>::try_into(data.len()).expect("data too big")
            }
        }
    }

    pub fn encode(&self, writer: &mut dyn Write) -> io::Result<()> {
        match self {
            Self::SubnetMask(mask) => writer.write_all(&mask.octets()[..]),
            Self::RouterIp(ip) => writer.write_all(&ip.octets()[..]),
            Self::RequestedIp(addr) => writer.write_all(&addr.octets()[..]),
            Self::LeaseTime(time) => writer.write_u32::<NetworkEndian>(*time),
            Self::MessageType(t) => writer.write_u8(Into::<u8>::into(*t)),
            Self::ServerId(addr) => writer.write_all(&addr.octets()[..]),
            Self::ClientIdentifier(id) => writer.write_all(id.as_slice()),
            Self::TftpServerName(name) => writer.write_all(name.as_bytes()),
            Self::Unknown { tag: _, data } => writer.write_all(data.as_slice()),
        }
    }
}
