use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    IOError(#[from] ::std::io::Error),

    #[error("packet invalid")]
    InvalidPacket,

    #[error("unsupported mode: {0}")]
    UnsupportedMode(String),

    #[error("unknown packet type {opcode}")]
    UnknownPacketType {
        opcode: u16,
    },
}

pub type Result<T> = ::std::result::Result<T, Error>;
