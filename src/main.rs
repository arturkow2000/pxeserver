#[macro_use]
extern crate log;

#[macro_use]
extern crate anyhow;

use std::fmt;
use std::fs;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use clap::Clap;

mod dhcp;
mod iputil;
mod tftp;

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
    fn mask_raw(&self) -> u32 {
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

#[derive(Clap)]
pub struct Options {
    #[clap(short, long)]
    pub server_ip: Ipv4Addr,

    #[clap(long, about = "IP range start")]
    pub dhcp_ip_start: Ipv4Addr,

    #[clap(long, about = "IP range end")]
    pub dhcp_ip_end: Ipv4Addr,

    #[clap(long)]
    pub dhcp_subnet: Ipv4AddrAndMask,

    #[clap(short = 'r', long)]
    pub tftp_root: Option<PathBuf>,

    #[clap(index = 1)]
    pub loader: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut options: Options = Options::parse();
    options.tftp_root = if let Some(root) = options.tftp_root.as_deref() {
        Some(fs::canonicalize(root)?)
    } else {
        None
    };
    options.loader = fs::canonicalize(options.loader)?;

    let options = Arc::new(options);

    if !iputil::belongs(
        options.dhcp_ip_start,
        options.dhcp_subnet.address(),
        options.dhcp_subnet.mask(),
    ) {
        bail!(
            "{} does not belong to {}",
            options.dhcp_ip_start,
            options.dhcp_subnet
        );
    }

    if !iputil::belongs(
        options.dhcp_ip_end,
        options.dhcp_subnet.address(),
        options.dhcp_subnet.mask(),
    ) {
        bail!(
            "{} does not belong to {}",
            options.dhcp_ip_end,
            options.dhcp_subnet
        );
    }

    pretty_env_logger::init();

    let options0 = Arc::clone(&options);
    let options1 = Arc::clone(&options);

    let dhcp_server = tokio::spawn(async move { dhcp::start(&*options0).await });
    let tftp_server = tokio::spawn(async move { tftp::start(&*options1).await });
    let x = futures_util::join!(dhcp_server, tftp_server);
    x.0.unwrap();
    x.1.unwrap();

    Ok(())
}
