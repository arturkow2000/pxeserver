use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    IOError(#[from] ::std::io::Error),

    #[error("packet parse failed: {0}")]
    PacketParseError(#[from] super::packet::Error),
}

pub type Result<T> = ::std::result::Result<T, Error>;
