#[macro_use]
extern crate log;

#[macro_use]
extern crate anyhow;

use std::fs;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::{ArgGroup, Clap};
use futures_util::stream::FuturesUnordered;
use futures_util::StreamExt;
use iputil::Ipv4AddrAndMask;
use tokio::task::JoinHandle;

mod dhcp;
mod iputil;
mod tftp;

#[derive(Clap)]
#[clap(group =
    ArgGroup::new("dhcp")
        .required(false)
        .multiple(true)
        .requires_all(
            &[
                "dhcp-ip-start",
                "dhcp-ip-end",
                "dhcp-subnet"
            ])
)]
pub struct Options {
    #[clap(short, long)]
    pub server_ip: Ipv4Addr,

    #[clap(long, about = "IP range start", group = "dhcp")]
    pub dhcp_ip_start: Option<Ipv4Addr>,

    #[clap(long, about = "IP range end", group = "dhcp")]
    pub dhcp_ip_end: Option<Ipv4Addr>,

    #[clap(long, group = "dhcp")]
    pub dhcp_subnet: Option<Ipv4AddrAndMask>,

    #[clap(short = 'r', long)]
    pub tftp_root: Option<PathBuf>,

    #[clap(index = 1)]
    pub loader: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut options: Options = Options::parse();
    options.tftp_root = if let Some(root) = options.tftp_root.as_deref() {
        Some(fs::canonicalize(root).context("Failed to canonicalize root path")?)
    } else {
        None
    };
    options.loader =
        fs::canonicalize(options.loader).context("Failed to canonicalize loader path")?;

    let options = Arc::new(options);

    pretty_env_logger::init();

    let mut fut_list = FuturesUnordered::new();

    if options.dhcp_ip_start.is_some() {
        let fut = start_dhcp_server(Arc::clone(&options)).context("failed to spawn DHCP server")?;
        fut_list.push(fut);
    }

    fut_list.push(start_tftp_server(Arc::clone(&options)).context("failed to spawn TFTP server")?);

    while let Some(x) = fut_list.next().await {
        if let Err(e) = x {
            error!("{}", e)
        }
    }

    Ok(())
}

fn start_dhcp_server(options: Arc<Options>) -> anyhow::Result<JoinHandle<()>> {
    let dhcp_ip_start = options.dhcp_ip_start.unwrap();
    let dhcp_ip_end = options.dhcp_ip_end.unwrap();
    let dhcp_subnet = options.dhcp_subnet.unwrap();

    if !iputil::belongs(dhcp_ip_start, dhcp_subnet.address(), dhcp_subnet.mask()) {
        bail!("{} does not belong to {}", dhcp_ip_start, dhcp_subnet);
    }

    if !iputil::belongs(dhcp_ip_end, dhcp_subnet.address(), dhcp_subnet.mask()) {
        bail!("{} does not belong to {}", dhcp_ip_end, dhcp_subnet);
    }

    Ok(tokio::spawn(async move {
        dhcp::start(
            &*options,
            options.server_ip,
            dhcp_ip_start,
            dhcp_ip_end,
            dhcp_subnet,
        )
        .await
    }))
}

fn start_tftp_server(options: Arc<Options>) -> anyhow::Result<JoinHandle<()>> {
    Ok(tokio::spawn(async move {
        tftp::start(&*options).await;
    }))
}
