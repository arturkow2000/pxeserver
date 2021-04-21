use std::fmt;

#[repr(transparent)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Mac([u8; 16]);

impl Mac {
    pub fn get_raw(&self) -> &[u8; 16] {
        &self.0
    }
}

impl From<[u8; 16]> for Mac {
    fn from(x: [u8; 16]) -> Self {
        Self(x)
    }
}

impl fmt::Display for Mac {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for (i, &x) in self.0.iter().take(6).enumerate() {
            if i > 0 {
                write!(f, ":{:02X}", x)?;
            } else {
                write!(f, "{:02X}", x)?;
            }
        }

        Ok(())
    }
}

// Combined hardware address and DHCP client ID
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientId {
    pub mac: Mac,
    pub ext: Vec<u8>,
}

impl fmt::Display for ClientId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.ext.is_empty() {
            self.mac.fmt(f)
        } else {
            write!(f, "{}\\", self.mac)?;
            for (_i, &x) in self.ext.iter().enumerate() {
                write!(f, "{:02X}", x)?;
            }
            Ok(())
        }
    }
}
