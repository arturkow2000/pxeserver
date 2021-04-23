use std::fs::canonicalize;
use std::io;
use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::time::Duration;

use futures_util::task::{Context, Poll};
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncReadExt, ReadBuf};
use tokio::net::UdpSocket;
use tokio_stream::{Stream, StreamExt};

use error::{Error, Result};
use packet::{Packet, TftpError};

mod error;
mod packet;
mod pathutils;

const MAX_PACKET_SIZE: usize = 1024;

pub async fn start(options: &super::Options) {
    let socket = UdpSocket::bind((options.server_ip, 69)).await.unwrap();
    socket.set_broadcast(true).unwrap();

    debug!("server starting");

    // TODO: improve error handling
    let root = options.tftp_root.clone();
    if let Some(root) = root.as_deref() {
        debug!("root: {}", root.display());
    }

    let loader = canonicalize(options.loader.as_path()).unwrap();
    let loader_relative = loader_path_to_relative(loader.as_path(), root.as_deref());

    debug!("loader: {} ({})", loader.display(), loader_relative);

    Server {
        server_ip: options.server_ip,
        root,
        loader,
        loader_relative,
        // TODO: allow setting these from command line
        retries: 5,
        timeout: Duration::from_secs(3),
    }
    .main(socket)
    .await
}

pub fn loader_path_to_relative(loader: &Path, root: Option<&Path>) -> String {
    if let Some(root) = root {
        // TODO: improve error handling
        let relative = loader.strip_prefix(root).unwrap();
        pathutils::encode_path_url(relative).unwrap()
    } else {
        // if no root was specified
        // we build fake root
        // and put loader as PAYLOAD.BIN
        "PAYLOAD.BIN".to_string()
    }
}

struct Server {
    server_ip: Ipv4Addr,
    root: Option<PathBuf>,
    loader: PathBuf,
    // path relative to root in URL format
    loader_relative: String,
    retries: u32,
    timeout: Duration,
}

impl Server {
    async fn main(self, socket: UdpSocket) {
        let mut stream = PacketStream { socket: &socket };

        while let Some(r) = stream.next().await {
            match r {
                Ok((client_addr, packet)) => {
                    match packet {
                        Packet::RwRequest { write, file } => {
                            match self.establish_connection(client_addr).await {
                                Ok((tid, s)) => {
                                    if write {
                                        // we don't support write
                                        Self::reply(
                                            &s,
                                            &Packet::error(
                                                TftpError::AccessDenied,
                                                Some(
                                                    "write operations are not supported"
                                                        .to_string(),
                                                ),
                                            ),
                                        )
                                        .await;
                                    } else {
                                        self.handle_read_request(tid, s, file).await;
                                    }
                                }
                                Err(e) => error!(
                                    "failed to establish connection with {}: {}",
                                    client_addr, e
                                ),
                            }
                        }
                        // TODO: warn about ignored packets
                        _ => warn!(
                            "ignored packet type {} from {}",
                            packet.type_str(),
                            client_addr
                        ),
                    }
                }
                Err(e) => error!("{}", e),
            }
        }
    }

    async fn open_file_1(&self, root: &Path, file: &str) -> anyhow::Result<File> {
        let path = pathutils::convert_path(file)
            .map(|path| pathutils::append_path(root, path.as_path()))??;

        trace!("{} => {}", file, path.display());

        Ok(OpenOptions::new()
            .read(true)
            .write(false)
            .open(path.as_path())
            .await?)
    }

    async fn open_file_2(&self, file: &Path) -> anyhow::Result<File> {
        Ok(OpenOptions::new()
            .read(true)
            .write(false)
            .open(file)
            .await?)
    }

    async fn handle_read_request(&self, _tid: u16, socket: UdpSocket, file_name: String) {
        trace!("client requests {}", file_name);

        match if let Some(root) = self.root.as_deref() {
            self.open_file_1(root, file_name.as_str()).await
        } else {
            if file_name.as_str() != "PAYLOAD.BIN" {
                Self::reply(&socket, &Packet::error(TftpError::NotFound, None)).await;
                return;
            } else {
                self.open_file_2(self.loader.as_path()).await
            }
        } {
            Ok(file) => {
                TransferHandler {
                    retries: self.retries,
                    timeout: self.timeout,
                    file,
                    socket,
                    // TODO: support other block sizes
                    block_size: 512,
                }
                .spawn();
            }
            Err(e) => {
                error!("failed to open {}: {}", file_name, e);
                Self::reply(&socket, &Packet::error(TftpError::NotFound, None)).await;
            }
        }
    }

    async fn reply(s: &UdpSocket, packet: &Packet) {
        if let Err(e) = s.send(packet.encode().as_slice()).await {
            error!("send failed: {}", e)
        }
    }

    async fn establish_connection(&self, client_addr: SocketAddr) -> io::Result<(u16, UdpSocket)> {
        let tid = Self::select_tid();
        let socket = UdpSocket::bind((self.server_ip, tid)).await?;
        socket.connect(client_addr).await?;

        Ok((tid, socket))
    }

    fn select_tid() -> u16 {
        rand::random()
    }
}

struct PacketStream<'a> {
    socket: &'a UdpSocket,
}

impl<'a> Stream for PacketStream<'a> {
    type Item = Result<(SocketAddr, Packet)>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut buf: [MaybeUninit<u8>; MAX_PACKET_SIZE] = [MaybeUninit::uninit(); MAX_PACKET_SIZE];
        let mut rb = ReadBuf::uninit(&mut buf[..]);

        match self.socket.poll_recv_from(cx, &mut rb) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(saddr)) => match Packet::decode(rb.filled()) {
                Ok(packet) => Poll::Ready(Some(Ok((saddr, packet)))),
                Err(e) => Poll::Ready(Some(Err(e))),
            },
            Poll::Ready(Err(e)) => Poll::Ready(Some(Err(Error::from(e)))),
        }
    }
}

struct TransferHandler {
    retries: u32,
    timeout: Duration,
    file: File,
    socket: UdpSocket,
    block_size: usize,
}

impl TransferHandler {
    fn spawn(mut self) {
        tokio::spawn(async move {
            if let Err(e) = self.transfer_file().await {
                error!("file transfer failed: {}", e);
            }
        });
    }

    async fn transfer_file(&mut self) -> io::Result<()> {
        // buffer for data packet, size = data block size + header (opcode + block number)
        let mut buffer = Vec::with_capacity(self.block_size + 4);
        unsafe { buffer.set_len(self.block_size + 4) };

        // buffer for ack packet
        let mut buffer2: [u8; 32] = unsafe { MaybeUninit::uninit().assume_init() };

        let mut current_block: u16 = 1;
        let mut send_packet: bool;
        let mut retries: u32;

        buffer[..2].copy_from_slice(&3u16.to_be_bytes()[..]);

        if let Some(file_size) = Self::get_file_size(&self.file).await {
            debug!(
                "transferring file size={} block_size={} num_blocks={}",
                file_size,
                self.block_size,
                file_size / self.block_size as u64
            );
        }

        loop {
            buffer[2..4].copy_from_slice(&current_block.to_be_bytes()[..]);

            let n = self.file.read(&mut buffer[4..]).await?;
            let is_last = n != self.block_size;

            retries = self.retries;
            send_packet = true;
            loop {
                if retries == 0 {
                    error!("file transfer timed out after {} retries", self.retries);
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "block transfer timed out",
                    ));
                }

                tokio::select! {
                    _ = tokio::time::sleep(self.timeout) => {
                        send_packet = true;
                        retries -= 1;
                    }
                    _ = self.socket.send(&buffer[..]), if send_packet => {
                        send_packet = false;
                    }
                    result = self.socket.recv(&mut buffer2[..]) => {
                        let n = result?;
                        if Self::is_ack_packet(&buffer2[..n], current_block) {
                            break;
                        }
                    }
                }
            }

            if is_last {
                self.terminate(current_block + 1).await?;
                info!("file transfer complete");
                break;
            }

            current_block += 1;
        }

        Ok(())
    }

    async fn get_file_size(file: &File) -> Option<u64> {
        file.metadata().await.ok().map(|x| x.len())
    }

    fn is_ack_packet(buffer: &[u8], current_block: u16) -> bool {
        match Packet::decode(buffer) {
            Ok(packet) => {
                if let Packet::Ack { block } = packet {
                    if block == current_block {
                        return true;
                    }
                }
            }
            Err(e) => warn!("packet decode error during file transfer: {}", e),
        }

        false
    }

    async fn terminate(&self, block_number: u16) -> io::Result<()> {
        let packet: &[u8] = &[
            3u16.to_be_bytes()[0],
            3u16.to_be_bytes()[1],
            block_number.to_be_bytes()[0],
            block_number.to_be_bytes()[1],
        ];
        let mut buffer2: [u8; 32] = unsafe { MaybeUninit::uninit().assume_init() };

        let mut retries = self.retries;
        let mut send_packet = true;
        loop {
            if retries == 0 {
                error!("file transfer timed out after {} retries", self.retries);
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "block transfer timed out",
                ));
            }

            tokio::select! {
                _ = tokio::time::sleep(self.timeout) => {
                    send_packet = true;
                    retries -= 1;
                }
                _= self.socket.send(&packet[..]), if send_packet => {
                    send_packet = false;
                }
                result = self.socket.recv(&mut buffer2[..]) => {
                    let n = result?;
                    if Self::is_ack_packet(&buffer2[..n], block_number) {
                        return Ok(());
                    }
                }
            }
        }
    }
}
