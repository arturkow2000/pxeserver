use std::borrow::Cow;
use std::collections::HashMap;

use crate::tftp::{Error, Result};

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TftpOption {
    U32(u32),
}

impl TftpOption {
    pub fn decode_options(data: &[u8]) -> Result<HashMap<String, Self>> {
        let mut n = 0;
        let mut options = HashMap::new();
        let mut option_name: Option<Cow<str>> = None;

        loop {
            let d = &data[n..];
            if d.is_empty() {
                break;
            }

            let null_offset = d.iter().position(|&x| x == 0).ok_or(Error::InvalidPacket)?;
            n += null_offset + 1;

            if let Some(option_name) = option_name.take() {
                if let Some(option) = Self::decode_option(
                    &*option_name,
                    &*String::from_utf8_lossy(&d[..null_offset]),
                )? {
                    if options.get(&*option_name).is_none() {
                        options.insert(option_name.to_string(), option);
                    } else {
                        return Err(Error::DuplicateOption {
                            option: option_name.to_string(),
                        });
                    }
                }
            } else {
                option_name = Some(String::from_utf8_lossy(&d[..null_offset]))
            }
        }

        Ok(options)
    }

    fn decode_option(option_name: &str, option_value: &str) -> Result<Option<Self>> {
        match option_name {
            "blksize" => {
                let v = u32::from_str_radix(option_value, 10).map_err(|_| {
                    Error::InvalidOptionValue {
                        option: option_name.to_string(),
                        value: option_value.to_string(),
                    }
                })?;
                Ok(Some(Self::U32(v)))
            }
            "tsize" => {
                let v = u32::from_str_radix(option_value, 10).map_err(|_| {
                    Error::InvalidOptionValue {
                        option: option_name.to_string(),
                        value: option_value.to_string(),
                    }
                })?;
                Ok(Some(Self::U32(v)))
            }
            _ => {
                trace!(
                    "unhandled option \"{}\" value \"{}\"",
                    option_name,
                    option_value
                );
                Ok(None)
            }
        }
    }
}
