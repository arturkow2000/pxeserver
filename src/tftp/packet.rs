use std::convert::{TryFrom, TryInto};
use std::io::{Cursor, Write};

use byteorder::{NetworkEndian, WriteBytesExt};

use super::error::{Error, Result};

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[allow(dead_code)]
#[repr(u16)]
pub enum TftpError {
    Other = 0,
    NotFound = 1,
    AccessDenied = 2,
    DiskFull = 3,
    IllegalOperation = 4,
    UnknownTid = 5,
    AlreadyExists = 6,
    NoSuchUser = 7,
}

impl TryFrom<u16> for TftpError {
    type Error = u16;

    fn try_from(code: u16) -> ::std::result::Result<Self, Self::Error> {
        match code {
            0 => Ok(Self::Other),
            1 => Ok(Self::NotFound),
            2 => Ok(Self::AccessDenied),
            3 => Ok(Self::DiskFull),
            4 => Ok(Self::IllegalOperation),
            5 => Ok(Self::UnknownTid),
            6 => Ok(Self::AlreadyExists),
            7 => Ok(Self::NoSuchUser),
            code => Err(code),
        }
    }
}

impl Into<u16> for TftpError {
    fn into(self) -> u16 {
        self as u16
    }
}

#[derive(Debug)]
pub enum Packet {
    RwRequest {
        write: bool,
        file: String,
    },
    Ack {
        block: u16,
    },
    Error {
        tag: TftpError,
        message: Option<String>,
    },
}

#[allow(dead_code)]
impl Packet {
    #[inline]
    pub fn ack(block: u16) -> Self {
        Self::Ack { block }
    }

    #[inline]
    pub fn error(tag: TftpError, message: Option<String>) -> Self {
        Self::Error { tag, message }
    }

    pub fn encode(&self) -> Vec<u8> {
        match self {
            // server never sends RRQ/WRQ to client, no need to support encoding it
            Self::RwRequest { .. } => panic!("attempting to encode RRQ/WRQ"),
            Self::Ack { block } => {
                // opcode + block number
                let packet_len = 2 + 2;
                let mut cursor = Cursor::new(Vec::with_capacity(packet_len));
                cursor.write_u16::<NetworkEndian>(4).unwrap();
                cursor.write_u16::<NetworkEndian>(*block).unwrap();

                let buf = cursor.into_inner();
                debug_assert_eq!(buf.len(), packet_len);

                buf
            }
            Self::Error { tag, message } => {
                // opcode + error_code + message + null byte
                let packet_len = 2 + 2 + message.as_deref().map_or(0, |x| x.len()) + 1;
                let mut cursor = Cursor::new(Vec::with_capacity(packet_len));
                cursor.write_u16::<NetworkEndian>(5).unwrap();
                cursor.write_u16::<NetworkEndian>(Into::into(*tag)).unwrap();
                if let Some(message) = message.as_deref() {
                    cursor.write_all(message.as_bytes()).unwrap();
                }
                cursor.write_u8(0).unwrap();

                let buf = cursor.into_inner();
                debug_assert_eq!(buf.len(), packet_len);

                buf
            }
        }
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        match buf
            .get(0..2)
            .map(|x| u16::from_be_bytes(TryInto::<[u8; 2]>::try_into(x).unwrap()))
            .ok_or(Error::InvalidPacket)?
        {
            opcode if opcode == 1 || opcode == 2 => {
                let write = opcode == 2;

                let t = buf[2..]
                    .iter()
                    .enumerate()
                    .find(|(_, &x)| x == 0)
                    .map(|(i, _)| i + 2)
                    .ok_or(Error::InvalidPacket)?;

                let file = String::from_utf8_lossy(&buf[2..t]).to_string();

                let t2 = buf
                    .get(t + 1..)
                    .ok_or(Error::InvalidPacket)?
                    .iter()
                    .enumerate()
                    .find(|(_, &x)| x == 0)
                    .map(|(i, _)| i + t + 1)
                    .ok_or(Error::InvalidPacket)?;

                let mode = String::from_utf8_lossy(&buf[t + 1..t2]).to_ascii_lowercase();
                if mode != "octet" {
                    return Err(Error::UnsupportedMode(mode));
                }

                Ok(Self::RwRequest { write, file })
            }
            4 => {
                let block = u16::from_be_bytes(
                    TryInto::<[u8; 2]>::try_into(buf.get(2..4).ok_or(Error::InvalidPacket)?)
                        .unwrap(),
                );
                Ok(Self::Ack { block })
            }
            5 => {
                let error_code = u16::from_be_bytes(
                    TryInto::<[u8; 2]>::try_into(buf.get(2..4).ok_or(Error::InvalidPacket)?)
                        .unwrap(),
                );
                let t = buf
                    .get(4..)
                    .ok_or(Error::InvalidPacket)?
                    .iter()
                    .enumerate()
                    .find(|(_, &x)| x == 0)
                    .map(|(i, _)| i + 4)
                    .ok_or(Error::InvalidPacket)?;

                let message = if t == 4 {
                    None
                } else {
                    Some(String::from_utf8_lossy(&buf[4..t]).to_string())
                };

                let tag = TftpError::try_from(error_code).unwrap_or_else(|_| {
                    warn!("unknown error code {}", error_code);
                    TftpError::Other
                });

                Ok(Self::Error { tag, message })
            }
            opcode => Err(Error::UnknownPacketType { opcode }),
        }
    }

    pub fn type_str(&self) -> &'static str {
        match self {
            Self::RwRequest { write, .. } => {
                if *write {
                    "write"
                } else {
                    "read"
                }
            }
            Self::Ack { .. } => "ack",
            Self::Error { .. } => "error",
        }
    }
}
