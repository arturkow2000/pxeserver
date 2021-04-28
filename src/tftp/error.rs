use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    IOError(#[from] ::std::io::Error),

    #[error(transparent)]
    PathConversion(#[from] super::pathutils::Error),

    #[error("packet invalid")]
    InvalidPacket,

    #[error("unsupported mode: {0}")]
    UnsupportedMode(String),

    #[error("unknown packet type {opcode}")]
    UnknownPacketType { opcode: u16 },

    #[error("option {option} specified more than once")]
    DuplicateOption { option: String },

    #[error("invalid value \"{value}\" for {option}")]
    InvalidOptionValue { option: String, value: String },
}

pub type Result<T> = ::std::result::Result<T, Error>;
