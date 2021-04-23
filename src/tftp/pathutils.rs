use std::path::{Component, Path};
use std::{iter, path::PathBuf};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("found forbidden character \"{ch}\" at {index}")]
    ForbiddenCharFound { ch: char, index: usize },

    #[error("invalid percent encoding \"%{c0}{c1}\" at {index}")]
    InvalidPercentEncoding { c0: char, c1: char, index: usize },

    #[error("found forbidden char (percent encoded) \"%{c0}{c1}\" ({}) at {index}")]
    ForbiddenPercentEncodedChar {
        c0: char,
        c1: char,
        index: usize,
        ch: char,
    },

    #[error("path sanitization failed")]
    SanitizationFailed,
}

pub type Result<T> = ::std::result::Result<T, Error>;

#[cfg(windows)]
const PATH_DELIMITER: char = '\\';

#[cfg(not(windows))]
const PATH_DELIMITER: char = '/';

// converts path from URL format to Unix or Windows format
// supports very basic paths
// any non-printable characters are forbidden
// all characters forbidden by Windows and macOS
// all forbidden here
// this simplifies code and makes it mostly platform independent
pub fn convert_path(path: &str) -> Result<PathBuf> {
    let mut string = String::with_capacity(path.len());

    let mut parsing_percent_encoding = false;
    let mut percent_location = 0;
    let mut hex_digits: [char; 2] = ['\x00', '\x00'];
    // true if previous character is slash, used to remove duplicated slashes
    let mut s = false;

    for (i, c) in path.chars().enumerate() {
        if is_forbidden_char(c) {
            return Err(Error::ForbiddenCharFound { ch: c, index: i });
        }

        if parsing_percent_encoding {
            let convert_now = if hex_digits[0] == '\x00' {
                hex_digits[0] = c;
                false
            } else {
                hex_digits[1] = c;
                true
            };

            if !is_hex_digit(c) {
                return Err(Error::InvalidPercentEncoding {
                    c0: hex_digits[0],
                    c1: hex_digits[1],
                    index: percent_location,
                });
            }

            if convert_now {
                parsing_percent_encoding = false;
                let decoded_char = hex_to_char(hex_digits);
                if decoded_char != ' ' && is_forbidden_char(decoded_char) {
                    return Err(Error::ForbiddenPercentEncodedChar {
                        c0: hex_digits[0],
                        c1: hex_digits[1],
                        index: percent_location,
                        ch: decoded_char,
                    });
                }
                string.push(decoded_char);
            }
        } else {
            if c != '/' {
                s = false;
            }

            match c {
                '%' => {
                    parsing_percent_encoding = true;
                    percent_location = i;
                    hex_digits[0] = '\x00';
                    hex_digits[1] = '\x00';
                }
                '/' => {
                    if !s {
                        string.push(PATH_DELIMITER);
                        s = true;
                    }
                }
                c => string.push(c),
            };
        }
    }

    Ok(PathBuf::from(string))
}

// see https://docs.microsoft.com/en-us/windows/win32/fileio/naming-a-file
// for info about forbidden stuff
fn is_forbidden_char(ch: char) -> bool {
    !ch.is_ascii_graphic()
        || ch == '\\'
        || ch == ':'
        || ch == '*'
        || ch == '?'
        || ch == '<'
        || ch == '>'
        || ch == '|'
}

fn is_hex_digit(ch: char) -> bool {
    match ch {
        '0'..='9' | 'a'..='f' | 'A'..='F' => true,
        _ => false,
    }
}

fn hex_to_char(chs: [char; 2]) -> char {
    let c = |c: char| -> u8 {
        match c {
            '0'..='9' => c as u8 - '0' as u8,
            'a'..='z' => c as u8 - 'a' as u8 + 10,
            'A'..='Z' => c as u8 - 'A' as u8 + 10,
            // already verified by is_hex_digit
            _ => unreachable!(),
        }
    };

    (c(chs[0]) * 16 + c(chs[1])) as char
}

pub fn encode_path_url(path: &Path) -> Result<String> {
    let mut encoded = String::new();
    encoded.push('/');

    for component in path.components() {
        match component {
            Component::RootDir => (),
            // TODO: percent-encode special characters like whitespace
            Component::Normal(x) => {
                encoded.extend(x.to_string_lossy().chars().chain(iter::once('/')))
            }
            // TODO: implement error handling
            _ => unimplemented!(),
        }
    }

    // remove trailing delimiter
    if encoded.chars().rev().next().unwrap_or('?') == '/' {
        encoded.pop().unwrap();
    }

    Ok(encoded)
}

pub fn append_path(root: &Path, path: &Path) -> Result<PathBuf> {
    let mut sanitized_path = PathBuf::new();

    for c in path.components() {
        match c {
            // does not occur in URL paths
            Component::Prefix(_) => return Err(Error::SanitizationFailed),
            Component::CurDir => (),
            Component::ParentDir => {
                sanitized_path.pop();
            }
            Component::RootDir => (),
            Component::Normal(n) => sanitized_path.push(n),
        }
    }

    Ok(root.join(sanitized_path))
}

#[cfg(test)]
mod tests {
    use super::{convert_path, hex_to_char, Error};

    #[test]
    fn test_hex_to_char() {
        assert_eq!(hex_to_char(['2', '0']), ' ');
        assert_eq!(hex_to_char(['3', '6']), '6');
        assert_eq!(hex_to_char(['4', 'a']), 'J');
        assert_eq!(hex_to_char(['4', 'A']), 'J');
        assert_eq!(hex_to_char(['5', 'E']), '^');
    }

    #[test]
    fn test_path_convert() {
        assert_eq!(
            convert_path("ldlinux.c32")
                .as_deref()
                .unwrap()
                .to_string_lossy(),
            "ldlinux.c32"
        );
        assert_eq!(
            convert_path("file%20with%20whitespaces")
                .as_deref()
                .unwrap()
                .to_string_lossy(),
            "file with whitespaces"
        );
        assert_eq!(
            convert_path("%70%45%52%63%65%6e%54%20%65%6E%43%4F%44%45%64")
                .as_deref()
                .unwrap()
                .to_string_lossy(),
            "pERcenT enCODEd"
        );

        // TODO: use assert_matches!
        // see https://github.com/rust-lang/rust/issues/82775

        // space must be percent encoded
        assert!(matches!(
            convert_path("path with forbidden char"),
            Err(Error::ForbiddenCharFound { ch: ' ', index: 4 })
        ));

        assert!(matches!(
            convert_path("%20test%04%20forbidden%20char"),
            Err(Error::ForbiddenPercentEncodedChar {
                c0: '0',
                c1: '4',
                ch: '\x04',
                index: 7
            })
        ));

        assert!(matches!(
            convert_path("0123%4gpf"),
            Err(Error::InvalidPercentEncoding {
                c0: '4',
                c1: 'g',
                index: 4
            })
        ));
    }

    #[cfg(windows)]
    #[test]
    fn test_path_convert_windows() {
        assert_eq!(
            convert_path("/path/to/file")
                .as_deref()
                .unwrap()
                .to_string_lossy(),
            "\\path\\to\\file"
        );

        // test slash deduplication
        assert_eq!(
            convert_path("//test///test2")
                .as_deref()
                .unwrap()
                .to_string_lossy(),
            "\\test\\test2"
        );
    }
}
