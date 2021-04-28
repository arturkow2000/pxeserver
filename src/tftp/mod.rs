use std::collections::HashMap;
use std::fs::canonicalize;
use std::io;
use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use futures_util::task::{Context, Poll};
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncReadExt, ReadBuf};
use tokio::net::UdpSocket;
use tokio_stream::{Stream, StreamExt};

use error::{Error, Result};
use packet::{Packet, TftpError, TftpOption};

mod error;
mod packet;
mod pathutils;

const MAX_PACKET_SIZE: usize = 1024;
const TFTP_DEFAULT_BLOCK_SIZE: u32 = 512;
// at least iPXE fails if block number is greater than 8192
// TODO: verify maximum block count allowed by RFC
const MAX_BLOCK_COUNT: u32 = 8192;
// Maximum size of data block
// equals to MTU - IP header size - UDP header size - TFTP header size
// assuming MTU = 1500
//const MAX_BLOCK_SIZE: u32 = 1408;

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
                        Packet::RwRequest {
                            write,
                            file,
                            options,
                        } => {
                            self.handle_rw_request(client_addr, write, file, options)
                                .await;
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

    async fn handle_rw_request(
        &self,
        client_addr: SocketAddr,
        write: bool,
        file_name: String,
        options: HashMap<String, TftpOption>,
    ) {
        match self.establish_connection(client_addr).await {
            Ok((tid, socket)) => {
                if write {
                    // we don't support write
                    Self::reply(
                        &socket,
                        &Packet::error(
                            TftpError::AccessDenied,
                            Some("write operations are not supported".to_string()),
                        ),
                    )
                    .await;
                } else {
                    match self.open_file(file_name.as_str(), write).await {
                        Ok(file) => {
                            info!("commencing {} transfer (ID {})", file_name, tid);

                            let can_negotiate = !options.is_empty();
                            let (block_size, can_negotiate) =
                                if let Some(opt) = options.get("blksize") {
                                    let TftpOption::U32(size) = opt;
                                    (*size, true)
                                } else {
                                    (TFTP_DEFAULT_BLOCK_SIZE, false)
                                };

                            let send_tsize = options.get("tsize").is_some();

                            self.handle_read_request(
                                tid,
                                socket,
                                file_name,
                                file,
                                block_size,
                                can_negotiate,
                                can_negotiate,
                                send_tsize,
                            )
                            .await;
                        }
                        Err(e) => {
                            error!("transfer ID {} failed to open {}: {}", tid, file_name, e);
                            Self::reply(&socket, &Packet::error(TftpError::NotFound, None)).await;
                        }
                    }
                }
            }
            Err(e) => error!("failed to establish connection with {}: {}", client_addr, e),
        }
    }

    async fn open_file(&self, file: &str, write: bool) -> Result<File> {
        // FIXME: workaround to prevent value from dropping
        let mut _t = None;

        let path = if let Some(root) = self.root.as_deref() {
            _t = Some(
                pathutils::convert_path(file)
                    .map(|path| pathutils::append_path(root, path.as_path()))??,
            );
            _t.as_deref().unwrap()
        } else {
            if file == "PAYLOAD.BIN" {
                self.loader.as_path()
            } else {
                return Err(Error::from(io::Error::new(
                    io::ErrorKind::NotFound,
                    "file not found",
                )));
            }
        };

        Ok(OpenOptions::new()
            .read(!write)
            .write(write)
            .open(path)
            .await?)
    }

    async fn handle_read_request(
        &self,
        tid: u16,
        socket: UdpSocket,
        file_name: String,
        file: File,
        block_size: u32,
        can_negotiate: bool,
        can_negotiate_block_size: bool,
        send_tsize: bool,
    ) {
        let file_len = file.metadata().await.ok().map(|x| x.len());

        if can_negotiate {
            self.negotiate(
                &socket,
                if can_negotiate_block_size {
                    Some(block_size)
                } else {
                    None
                },
                if send_tsize { file_len } else { None },
            )
            .await;
        }

        TransferHandler {
            retries: self.retries,
            timeout: self.timeout,
            file_name,
            file,
            socket,
            block_size: block_size as usize,
            tid,
        }
        .spawn();
    }

    async fn negotiate(&self, socket: &UdpSocket, block_size: Option<u32>, tsize: Option<u64>) {
        let mut encoded: Vec<u8> = Vec::new();
        encoded.extend_from_slice(&6u16.to_be_bytes()[..]); // opcode
        if let Some(block_size) = block_size {
            encoded.extend_from_slice(b"blksize\x00");
            encoded.extend_from_slice(block_size.to_string().as_bytes());
            encoded.push(0);
        }
        if let Some(tsize) = tsize {
            encoded.extend_from_slice(b"tsize\x00");
            encoded.extend_from_slice(tsize.to_string().as_bytes());
            encoded.push(0);
        }

        if encoded.len() == 2 {
            encoded.push(0);
        }

        socket.send(encoded.as_slice()).await.unwrap();
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
    file_name: String,
    file: File,
    socket: UdpSocket,
    block_size: usize,
    tid: u16,
}

impl TransferHandler {
    fn spawn(mut self) {
        tokio::spawn(async move {
            let start = Instant::now();
            if let Err(e) = self.transfer_file().await {
                error!(
                    "transfer ID {} of {} failed: {}",
                    self.tid, self.file_name, e
                );
            } else {
                info!(
                    "transfer ID {} of {} done after {} s",
                    self.tid,
                    self.file_name,
                    Instant::now().duration_since(start).as_secs()
                );
            }
        });
    }

    async fn transfer_file(&mut self) -> anyhow::Result<()> {
        //let mut header: [u8; 4] = [0, 6, 0, 0];

        // buffer for outgoing data packet, size = data block size + header (opcode + block number)
        let mut buffer_out: Vec<u8> = Vec::new();
        buffer_out.resize(self.block_size + 4, 0);

        // buffer for incoming packet, used by send_data
        // declared here to prevent reinitializing array on every call to send_data
        //
        // seems like there is no simple way to read from socket into uninitialized array
        // MaybeUninit::uninit() is not an option as recv() takes reference to u8 not MaybeUninit<u8>
        // converting MaybeUninit<T> into T prior to initialization is instant UB.
        // see
        // https://doc.rust-lang.org/std/mem/union.MaybeUninit.html
        // https://www.ralfj.de/blog/2019/07/14/uninit.html
        let mut buffer_in: [u8; 32] = [0; 32];

        let mut current_block: u16 = 1;

        loop {
            buffer_out[..2].copy_from_slice(&3u16.to_be_bytes()[..]);
            buffer_out[2..4].copy_from_slice(&current_block.to_be_bytes()[..]);

            let n = self
                .file
                .read(&mut buffer_out[4..])
                .await
                .context("failed to read from file")?;

            self.send_data(current_block, &buffer_out[..n + 4], &mut buffer_in[..])
                .await?;

            if n != self.block_size {
                // last block sent
                break;
            }

            current_block += 1;
        }

        Ok(())
    }

    async fn send_data(
        &self,
        current_block: u16,
        data: &[u8],
        in_buffer: &mut [u8],
    ) -> anyhow::Result<()> {
        let mut left_retries = self.retries;

        let mut interval = tokio::time::interval(self.timeout);
        while left_retries > 0 {
            tokio::select! {
                _ = interval.tick() => {
                    self.socket.send(data).await
                        .context("failed to write to socket")?;

                    left_retries -= 1;
                }
                result = self.socket.recv(in_buffer) => {
                    let total_read = result?;
                    if Self::is_ack_packet(&in_buffer[..total_read], current_block) {
                        return Ok(());
                    }
                }
            };
        }

        bail!("timed out");
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
}
