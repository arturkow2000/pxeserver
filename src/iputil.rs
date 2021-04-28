use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

#[derive(Debug, Copy, Clone)]
pub struct Ipv4AddrAndMask {
    address: Ipv4Addr,
    mask_width: u8,
}

impl Ipv4AddrAndMask {
    #[inline]
    pub fn address(&self) -> Ipv4Addr {
        self.address
    }

    #[inline]
    pub fn mask_width(&self) -> u8 {
        self.mask_width
    }

    #[inline]
    pub fn mask_raw(&self) -> u32 {
        ((1 << self.mask_width) - 1) << (32 - self.mask_width)
    }

    #[inline]
    pub fn mask(&self) -> Ipv4Addr {
        Into::<Ipv4Addr>::into(self.mask_raw())
    }

    fn verify(&self) -> bool {
        Into::<u32>::into(self.address) & !self.mask_raw() == 0
    }
}

impl FromStr for Ipv4AddrAndMask {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut address: Ipv4Addr = Ipv4Addr::UNSPECIFIED;
        let mut mask_width = 0;

        for (i, s) in s.split('/').enumerate() {
            match i {
                0 => address = s.parse()?,
                1 => {
                    mask_width =
                        u8::from_str_radix(s, 10).map_err(|_| anyhow::Error::msg("invalid mask"))?
                }
                _ => bail!("invalid format"),
            }
        }

        if mask_width < 1 || mask_width > 30 {
            bail!("invalid mask");
        }

        let this = Ipv4AddrAndMask {
            address,
            mask_width,
        };

        if !this.verify() {
            bail!("invalid address/mask combination");
        }

        Ok(this)
    }
}

impl fmt::Display for Ipv4AddrAndMask {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}/{}", self.address, self.mask_width)
    }
}

pub fn belongs(address: Ipv4Addr, subnet: Ipv4Addr, subnet_mask: Ipv4Addr) -> bool {
    let address = Into::<u32>::into(address);
    let subnet = Into::<u32>::into(subnet);
    let subnet_mask = Into::<u32>::into(subnet_mask);

    assert_eq!(subnet & subnet_mask, subnet);

    address & subnet_mask == subnet
}
