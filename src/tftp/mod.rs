use std::collections::BTreeMap;
use std::convert::TryInto;
use std::io::{self, Cursor, Read, Write};
use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::time::Duration;

use byteorder::{NetworkEndian, WriteBytesExt};
use futures_util::stream::FuturesUnordered;
use futures_util::task::{Context, Poll};
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncReadExt, ReadBuf};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio_stream::{Stream, StreamExt};

use error::{Error, Result};

mod error;

const MAX_PACKET_SIZE: usize = 1024;

pub async fn start(options: &super::Options) {
    let socket = UdpSocket::bind((options.server_ip, 69)).await.unwrap();
    socket.set_broadcast(true).unwrap();

    Server {
        server_ip: options.server_ip,
        root: options.tftp_root.clone(),
        boot_file_path: options.boot_file.clone(),
        boot_file_path_relative: boot_file_path_to_relative(
            options.boot_file.as_path(),
            options.tftp_root.as_deref(),
        ),
        retries: 5,
        timeout: Duration::from_secs(3),
    }
    .main(socket)
    .await
}

pub fn boot_file_path_to_relative(boot_file: &Path, tftp_root: Option<&Path>) -> String {
    // TODO: support TFTP root
    if tftp_root.is_some() {
        unimplemented!("TFTP root is not supported yet");
    } else {
        "PAYLOAD.BIN".to_string()
    }
}

struct Server {
    server_ip: Ipv4Addr,
    root: Option<PathBuf>,
    boot_file_path: PathBuf,
    // path relative to root
    boot_file_path_relative: String,
    retries: u32,
    timeout: Duration,
}

impl Server {
    async fn main(self, socket: UdpSocket) {
        let mut stream = PacketStream { socket: &socket };

        // TODO: currently we don't support setting root directory
        // we can serve only file, specified by boot_file option
        if self.root.is_some() {
            panic!("TFTP root is not supported yet");
        }

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

    async fn handle_read_request(&self, tid: u16, socket: UdpSocket, file_name: String) {
        let retries = self.retries;
        let timeout = self.timeout;

        if self.root.is_some() {
            unimplemented!("TFTP root is not supported");
        } else {
            if file_name != "PAYLOAD.BIN" {
                Self::reply(&socket, &Packet::error(TftpError::NotFound, None)).await;
            }

            match OpenOptions::new()
                .read(true)
                .write(false)
                .open(self.boot_file_path.as_path())
                .await
            {
                Ok(file) => {
                    TransferHandler {
                        retries,
                        timeout,
                        file,
                        socket,
                        // TODO: support other block sizes
                        block_size: 512,
                    }
                    .spawn();
                }
                Err(e) => {
                    error!("failed to open {}: {}", self.boot_file_path.display(), e);
                    Self::reply(&socket, &Packet::error(TftpError::NotFound, None)).await;
                }
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

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[allow(dead_code)]
#[repr(u16)]
enum TftpError {
    Other = 0,
    NotFound = 1,
    AccessDenied = 2,
    DiskFull = 3,
    IllegalOperation = 4,
    UnknownTid = 5,
    AlreadyExists = 6,
    NoSuchUser = 7,
}

impl Into<u16> for TftpError {
    fn into(self) -> u16 {
        self as u16
    }
}

#[derive(Debug)]
enum Packet {
    RwRequest {
        write: bool,
        file: String,
    },
    Ack {
        block: u16,
    },
    Error {
        tag: TftpError,
        message: Option<String>,
    },
}

#[allow(dead_code)]
impl Packet {
    #[inline]
    fn ack(block: u16) -> Self {
        Self::Ack { block }
    }

    #[inline]
    fn error(tag: TftpError, message: Option<String>) -> Self {
        Self::Error { tag, message }
    }

    fn encode(&self) -> Vec<u8> {
        match self {
            // server never sends RRQ/WRQ to client, no need to support encoding it
            Self::RwRequest { .. } => panic!("attempting to encode RRQ/WRQ"),
            Self::Ack { block } => {
                // opcode + block number
                let packet_len = 2 + 2;
                let mut cursor = Cursor::new(Vec::with_capacity(packet_len));
                cursor.write_u16::<NetworkEndian>(4).unwrap();
                cursor.write_u16::<NetworkEndian>(*block).unwrap();

                let buf = cursor.into_inner();
                debug_assert_eq!(buf.len(), packet_len);

                buf
            }
            Self::Error { tag, message } => {
                // opcode + error_code + message + null byte
                let packet_len = 2 + 2 + message.as_deref().map_or(0, |x| x.len()) + 1;
                let mut cursor = Cursor::new(Vec::with_capacity(packet_len));
                cursor.write_u16::<NetworkEndian>(5).unwrap();
                cursor.write_u16::<NetworkEndian>(Into::into(*tag)).unwrap();
                if let Some(message) = message.as_deref() {
                    cursor.write_all(message.as_bytes()).unwrap();
                }
                cursor.write_u8(0).unwrap();

                let buf = cursor.into_inner();
                debug_assert_eq!(buf.len(), packet_len);

                buf
            }
        }
    }

    fn decode(buf: &[u8]) -> Result<Self> {
        match buf
            .get(0..2)
            .map(|x| u16::from_be_bytes(TryInto::<[u8; 2]>::try_into(x).unwrap()))
            .ok_or(Error::InvalidPacket)?
        {
            opcode if opcode == 1 || opcode == 2 => {
                let write = opcode == 2;

                let t = buf[2..]
                    .iter()
                    .enumerate()
                    .find(|(_, &x)| x == 0)
                    .map(|(i, _)| i + 2)
                    .ok_or(Error::InvalidPacket)?;

                let file = String::from_utf8_lossy(&buf[2..t]).to_string();

                let t2 = buf
                    .get(t + 1..)
                    .ok_or(Error::InvalidPacket)?
                    .iter()
                    .enumerate()
                    .find(|(_, &x)| x == 0)
                    .map(|(i, _)| i + t + 1)
                    .ok_or(Error::InvalidPacket)?;

                let mode = String::from_utf8_lossy(&buf[t + 1..t2]).to_ascii_lowercase();
                if mode != "octet" {
                    return Err(Error::UnsupportedMode(mode));
                }

                Ok(Self::RwRequest { write, file })
            }
            4 => {
                let block = u16::from_be_bytes(
                    TryInto::<[u8; 2]>::try_into(buf.get(2..4).ok_or(Error::InvalidPacket)?)
                        .unwrap(),
                );
                Ok(Self::Ack { block })
            }
            _ => todo!(),
        }
    }

    fn type_str(&self) -> &'static str {
        match self {
            Self::RwRequest { write, .. } => {
                if *write {
                    "write"
                } else {
                    "read"
                }
            }
            Self::Ack { .. } => "ack",
            Self::Error { .. } => "error",
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
                        // TODO: handle error
                        let packet = Packet::decode(&buffer2[..n]).unwrap();
                        if let Packet::Ack { block } = packet {
                            if block == current_block {
                                break;
                            }
                        }
                    }
                }
            }

            if n != self.block_size {
                // last block transferred, we are done
                // don't wait for ACK

                // seems like we have to send empty block if total payload size is than block size
                // or client won't boot

                // TODO: client does not ACK last packet so we can not know whether packet did arrive
                // should resend packet few times increase chance that client gets it
                if current_block == 1 {
                    buffer[2..4].copy_from_slice(&(current_block + 1).to_be_bytes()[..]);
                    self.socket.send(&buffer[..4]).await?;
                }

                break;
            }

            current_block += 1;
        }

        Ok(())
    }

    async fn get_file_size(file: &File) -> Option<u64> {
        file.metadata().await.ok().map(|x| x.len())
    }
}
