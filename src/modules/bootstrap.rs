use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

const IO_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerReport {
    pub addr: SocketAddr,
    pub known_peers: Vec<SocketAddr>,
    pub connected_peers: Vec<SocketAddr>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerEntry {
    pub addr: SocketAddr,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub uptime_seconds: i64,
    pub stable: bool,
    pub known_peers: Vec<SocketAddr>,
    pub connected_peers: Vec<SocketAddr>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeersResponse {
    pub requester_stable: bool,
    pub requester_effective_addr: SocketAddr,
    pub entries: Vec<PeerEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum Message {
    Report(PeerReport),
    Peers(PeersResponse),
}

pub async fn report_and_get_peers(
    server: SocketAddr,
    report: PeerReport,
) -> Result<(Vec<PeerEntry>, bool, SocketAddr)> {
    let mut stream = timeout(IO_TIMEOUT, TcpStream::connect(server)).await??;
    write_message(&mut stream, &Message::Report(report)).await?;

    match read_message(&mut stream).await? {
        Message::Peers(res) => Ok((res.entries, res.requester_stable, res.requester_effective_addr)),
        _ => Ok((Vec::new(), false, server)),
    }
}

async fn write_message(stream: &mut TcpStream, msg: &Message) -> Result<()> {
    let bytes = bincode::serialize(msg)?;
    let len = bytes.len() as u32;
    timeout(IO_TIMEOUT, stream.write_u32_le(len)).await??;
    timeout(IO_TIMEOUT, stream.write_all(&bytes)).await??;
    timeout(IO_TIMEOUT, stream.flush()).await??;
    Ok(())
}

async fn read_message(stream: &mut TcpStream) -> Result<Message> {
    let len = timeout(IO_TIMEOUT, stream.read_u32_le()).await?? as usize;
    let mut buf = vec![0u8; len];
    timeout(IO_TIMEOUT, stream.read_exact(&mut buf)).await??;
    Ok(bincode::deserialize::<Message>(&buf)?)
}
