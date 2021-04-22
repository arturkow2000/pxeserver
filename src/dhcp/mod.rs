use std::collections::BTreeMap;
use std::mem::MaybeUninit;
use std::net::Ipv4Addr;
use std::pin::Pin;
use std::time::{Duration, Instant};

use futures_util::task::{Context, Poll};
use tokio::io::ReadBuf;
use tokio::net::UdpSocket;
use tokio_stream::{Stream, StreamExt};

use crate::dhcp::id::Mac;
pub use error::{Error, Result};
use id::ClientId;
use packet::{
    options::{
        DhcpOption, MessageType, DHCP_CLIENT_IDENTIFIER, DHCP_LEASE_TIME, DHCP_MESSAGE_TYPE,
        DHCP_REQUESTED_IP, DHCP_SERVER_ID, DHCP_SUBNET_MASK, DHCP_TFTP_SERVER_NAME,
    },
    BootpMessageType, Packet,
};

mod error;
mod id;
mod packet;

const MAX_PACKET_SIZE: usize = 1024;

pub async fn start(options: &super::Options) {
    let socket = UdpSocket::bind((options.server_ip, 67)).await.unwrap();
    socket.set_broadcast(true).unwrap();

    let mask = options.dhcp_subnet.mask_raw();

    let ip_range_start = Into::<u32>::into(options.dhcp_ip_start) & !mask;
    let ip_range_end = Into::<u32>::into(options.dhcp_ip_end) & !mask;
    let ip_range_size = ip_range_end - ip_range_start + 1;

    let broadcast_ip = Ipv4Addr::from(Into::<u32>::into(options.dhcp_subnet.address) | !mask);

    debug!("server starting");
    debug!("server ip: {}", options.server_ip);
    debug!("server subnet: {}", options.dhcp_subnet);
    debug!(
        "IP range: {} - {} ({} IP addresses available)",
        ip_range_start, ip_range_end, ip_range_size
    );
    debug!("broadcast address: {}", broadcast_ip);

    Server {
        leases: BTreeMap::new(),
        pending: BTreeMap::new(),
        subnet_mask: options.dhcp_subnet.mask(),
        subnet_mask_width: options.dhcp_subnet.mask_width,
        subnet: options.dhcp_subnet.address(),
        broadcast_ip,
        ip_range_start,
        ip_range_end,
        server_ip: options.server_ip,
        tftp_boot_file: crate::tftp::boot_file_path_to_relative(
            options.boot_file.as_path(),
            options.tftp_root.as_deref(),
        ),
        lease_duration_secs: 3600,
    }
    .start(socket)
    .await
}

struct Server {
    leases: BTreeMap<Ipv4Addr, (ClientId, u32, Instant, Duration)>,
    pending: BTreeMap<Ipv4Addr, (ClientId, u32)>,
    subnet_mask: Ipv4Addr,
    subnet_mask_width: u8,
    subnet: Ipv4Addr,
    broadcast_ip: Ipv4Addr,
    ip_range_start: u32,
    ip_range_end: u32,
    server_ip: Ipv4Addr,
    tftp_boot_file: String,
    lease_duration_secs: u32,
}

impl Server {
    async fn start(mut self, socket: UdpSocket) {
        let mut stream = PacketStream { socket: &socket };
        while let Some(packet) = stream.next().await {
            match packet {
                Ok(packet) if packet.bootp_message_type == BootpMessageType::Request => {
                    if let Err(e) = self.process_packet(packet, &socket).await {
                        error!("{}", e);
                    }
                }
                Ok(packet) => error!("dropped {} packet", packet.bootp_message_type),
                Err(e) => error!("{}", e),
            }
        }
    }

    async fn process_packet(&mut self, packet: Packet, socket: &UdpSocket) -> anyhow::Result<()> {
        if self.filter_packet(&packet) {
            return Ok(());
        }

        let client_id_opt =
            packet
                .options
                .get(&DHCP_CLIENT_IDENTIFIER)
                .cloned()
                .map_or(Vec::new(), |x| {
                    if let DhcpOption::ClientIdentifier(x) = x {
                        x
                    } else {
                        Vec::new()
                    }
                });
        let client_id = ClientId {
            mac: packet.mac,
            ext: client_id_opt,
        };

        match packet.options.get(&DHCP_MESSAGE_TYPE) {
            Some(DhcpOption::MessageType(_t @ MessageType::Discover)) => {
                debug!("discover from {}", client_id);
                self.offer_ip_address(&packet, &client_id, socket).await;

                Ok(())
            }
            Some(DhcpOption::MessageType(_t @ MessageType::Request)) => {
                if let Some(DhcpOption::RequestedIp(requested_ip)) =
                    packet.options.get(&DHCP_REQUESTED_IP)
                {
                    if let Some(DhcpOption::ServerId(server_ip)) =
                        packet.options.get(&DHCP_SERVER_ID)
                    {
                        if *server_ip == self.server_ip {
                            if let Some((c, _)) = self.pending.get(requested_ip) {
                                if *c == client_id {
                                    self.send_ack(
                                        &socket,
                                        &client_id,
                                        packet.xid,
                                        *requested_ip,
                                        packet.mac,
                                    )
                                    .await;
                                    self.pending.remove_entry(requested_ip);
                                    self.leases.insert(
                                        *requested_ip,
                                        (
                                            client_id.clone(),
                                            packet.xid,
                                            Instant::now(),
                                            Duration::from_secs(Into::<u64>::into(
                                                self.lease_duration_secs,
                                            )),
                                        ),
                                    );
                                    info!(
                                        "{}/{} bound to {}",
                                        requested_ip, self.subnet_mask_width, client_id
                                    );
                                } else {
                                    self.send_nak(&socket, packet.xid, &client_id, packet.mac)
                                        .await;
                                }
                            } else {
                                self.send_nak(&socket, packet.xid, &client_id, packet.mac)
                                    .await;
                            }
                        } else {
                            // client requests IP from another DHCP server
                            // this automatically declines our offer
                            // see RFC 2131 section 3.1.4
                            if let Some((c, _)) = self.pending.get(requested_ip) {
                                if *c == client_id {
                                    self.pending.remove(requested_ip);
                                }
                            }
                        }

                        Ok(())
                    } else {
                        bail!("missing/invalid server id option")
                    }
                } else {
                    bail!("missing/invalid requested ip option")
                }
            }
            Some(DhcpOption::MessageType(t)) => bail!("unhandled message type {}", t),
            _ => bail!("message type not set"),
        }
    }

    fn filter_packet(&self, packet: &Packet) -> bool {
        if packet.server_name.is_some() {
            todo!();
        }

        if packet.giaddr != Ipv4Addr::new(0, 0, 0, 0) {
            // we don't support relay agents
            // all clients must be in same subnet
            warn!("filtered out packet with non-null relay agent address");
            return true;
        }

        false
    }

    async fn offer_ip_address(
        &mut self,
        request_packet: &Packet,
        client_id: &ClientId,
        socket: &UdpSocket,
    ) {
        let mut ip_to_offer: Option<Ipv4Addr>;

        // if same client sends multiple discover message offer same IP as before
        ip_to_offer = self
            .pending
            .iter()
            .find(|(_, (c, _))| c == client_id)
            .map(|(&ip, _)| ip);

        if ip_to_offer.is_none() {
            for (&ip, (_, _, allocation_time, lease_duration)) in self
                .leases
                .iter_mut()
                .filter(|(_, (cid, _, _, _))| cid == client_id)
            {
                // if lease expired extend it
                let now = Instant::now();
                if now.duration_since(*allocation_time) > *lease_duration {
                    *allocation_time = now;
                }

                ip_to_offer = Some(ip);
            }
        }

        if ip_to_offer.is_none() {
            ip_to_offer = self.find_free_ip_address(client_id);
        }

        if let Some(ip_to_offer) = ip_to_offer {
            info!(
                "offering {}/{} to {}",
                ip_to_offer, self.subnet_mask_width, client_id
            );
            self.pending
                .insert(ip_to_offer, (client_id.clone(), request_packet.xid));

            let mut options = BTreeMap::new();
            options.insert(
                DHCP_MESSAGE_TYPE,
                DhcpOption::MessageType(MessageType::Offer),
            );
            options.insert(DHCP_SUBNET_MASK, DhcpOption::SubnetMask(self.subnet_mask));
            options.insert(DHCP_SERVER_ID, DhcpOption::ServerId(self.server_ip));
            //options.insert(DHCP_ROUTER_IP, DhcpOption::RouterIp(self.server_ip));
            options.insert(
                DHCP_LEASE_TIME,
                DhcpOption::LeaseTime(self.lease_duration_secs),
            );
            // some PXE clients need this
            options.insert(
                DHCP_TFTP_SERVER_NAME,
                DhcpOption::TftpServerName(self.server_ip.to_string()),
            );

            let offer_packet = Packet {
                bootp_message_type: BootpMessageType::Reply,
                htype: 1,
                hlen: 6,
                hops: 0,
                xid: request_packet.xid,
                secs: 0,
                flags: 0,
                ciaddr: Ipv4Addr::UNSPECIFIED,
                yiaddr: ip_to_offer,
                siaddr: self.server_ip,
                giaddr: Ipv4Addr::UNSPECIFIED,
                mac: request_packet.mac,
                // FIXME
                server_name: Some("dhcp-pxe-server".to_string()),
                boot_file_name: Some(self.tftp_boot_file.clone()),
                options,
            };
            if let Err(e) = socket
                .send_to(offer_packet.encode().as_slice(), (self.broadcast_ip, 68))
                .await
            {
                error!("failed to send offer to {}: {}", client_id, e);
            }
        } else {
            warn!(
                "no more IP addresses available, cannot offer IP to {}",
                client_id
            )
        }
    }

    fn find_free_ip_address(&mut self, client_id: &ClientId) -> Option<Ipv4Addr> {
        for n in self.ip_range_start..=self.ip_range_end {
            let mut ip = Into::<u32>::into(self.subnet);
            ip |= n;
            let ip = Into::<Ipv4Addr>::into(ip);
            if self.is_ip_available(ip, client_id) {
                return Some(ip);
            }
        }

        None
    }

    fn is_ip_available(&mut self, ip: Ipv4Addr, _client_id: &ClientId) -> bool {
        if let Some((_, _, allocation_time, lease_duration)) = self.leases.get(&ip) {
            if Instant::now().duration_since(*allocation_time) > *lease_duration {
                self.leases.remove(&ip);
                true
            } else {
                false
            }
        } else if let Some((c, _)) = self.pending.get(&ip) {
            // FIXME: pending requests never expire
            false
        } else {
            true
        }
    }

    async fn send_nak(&self, socket: &UdpSocket, xid: u32, client_id: &ClientId, mac: Mac) {
        let mut options = BTreeMap::new();
        options.insert(DHCP_MESSAGE_TYPE, DhcpOption::MessageType(MessageType::Nak));

        let packet = Packet {
            bootp_message_type: BootpMessageType::Reply,
            htype: 1,
            hlen: 6,
            hops: 0,
            xid,
            secs: 0,
            flags: 0,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: self.server_ip,
            giaddr: Ipv4Addr::UNSPECIFIED,
            mac,
            // FIXME
            server_name: Some("dhcp-pxe-server".to_string()),
            boot_file_name: Some("BOOT.COM".to_string()),
            options,
        };
        if let Err(e) = socket
            .send_to(packet.encode().as_slice(), (self.broadcast_ip, 68))
            .await
        {
            error!("failed to send NAK to {}: {}", client_id, e);
        }
    }

    async fn send_ack(
        &self,
        socket: &UdpSocket,
        client_id: &ClientId,
        xid: u32,
        ip_address: Ipv4Addr,
        mac: Mac,
    ) {
        let mut options = BTreeMap::new();
        options.insert(DHCP_MESSAGE_TYPE, DhcpOption::MessageType(MessageType::Ack));
        options.insert(DHCP_SUBNET_MASK, DhcpOption::SubnetMask(self.subnet_mask));
        options.insert(DHCP_SERVER_ID, DhcpOption::ServerId(self.server_ip));
        options.insert(
            DHCP_LEASE_TIME,
            DhcpOption::LeaseTime(self.lease_duration_secs),
        );
        // some PXE clients need this
        options.insert(
            DHCP_TFTP_SERVER_NAME,
            DhcpOption::TftpServerName(self.server_ip.to_string()),
        );

        let packet = Packet {
            bootp_message_type: BootpMessageType::Reply,
            htype: 1,
            hlen: 6,
            hops: 0,
            xid,
            secs: 0,
            flags: 0,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: ip_address,
            siaddr: self.server_ip,
            giaddr: Ipv4Addr::UNSPECIFIED,
            mac,
            // TODO
            server_name: Some("dhcp-pxe-server".to_string()),
            boot_file_name: Some(self.tftp_boot_file.clone()),
            options,
        };
        if let Err(e) = socket
            .send_to(packet.encode().as_slice(), (self.broadcast_ip, 68))
            .await
        {
            error!("failed to send ACK to {}: {}", client_id, e);
        }
    }
}

struct PacketStream<'a> {
    socket: &'a UdpSocket,
}

impl<'a> Stream for PacketStream<'a> {
    type Item = Result<Packet>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut buf: [u8; MAX_PACKET_SIZE] = unsafe { MaybeUninit::uninit().assume_init() };
        let mut rb = ReadBuf::new(&mut buf);

        match self.socket.poll_recv(cx, &mut rb) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => {
                Poll::Ready(Some(Packet::parse(rb.filled()).map_err(|e| Error::from(e))))
            }
            Poll::Ready(Err(x)) => Poll::Ready(Some(Err(Error::from(x)))),
        }
    }
}
