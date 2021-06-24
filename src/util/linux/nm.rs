use std::net::Ipv4Addr;

use anyhow::Result;
use futures_util::StreamExt;

pub type NetIfIndex = u32;

pub struct NetworkInterface {
    index: NetIfIndex,
    handle: rtnetlink::Handle,
}

impl NetworkInterface {
    pub async fn ip_address(&self) -> Result<Ipv4Addr> {
        /*if let Some(addr) = self.handle.address().get().set_link_index_filter(self.index).execute() {

        } else {
            bail!("IP address not set")
        }*/

        let fut = self
            .handle
            .address()
            .get()
            .set_link_index_filter(self.index)
            .execute();
        tokio::pin!(fut);
        for x in fut {}

        todo!()
    }
}

pub struct NetworkManager {
    handle: rtnetlink::Handle,
}

impl NetworkManager {
    pub async fn new() -> Result<Self> {
        let (c, handle, _) = rtnetlink::new_connection()?;
        tokio::spawn(c);

        Ok(Self { handle })
    }

    pub async fn get_interface(&mut self, name: String) -> Result<NetworkInterface> {
        if let Some(l) = self
            .handle
            .link()
            .get()
            .set_name_filter(name)
            .execute()
            .try_next()
            .await?
        {
            Ok(NetworkInterface {
                index: l.header.index,
                handle: self.handle.clone(),
            })
        } else {
            bail!("no such interface")
        }
    }
}
