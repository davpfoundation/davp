use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerReport {
    pub addr: SocketAddr,
    pub known_peers: Vec<SocketAddr>,
    pub connected_peers: Vec<SocketAddr>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerEntry {
    pub addr: SocketAddr,
    pub last_seen: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub known_peers: Vec<SocketAddr>,
    pub connected_peers: Vec<SocketAddr>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum Message {
    Report(PeerReport),
    Peers(Vec<PeerEntry>),
}

pub async fn report_and_get_peers(server: SocketAddr, report: PeerReport) -> Result<Vec<PeerEntry>> {
    let mut stream = timeout(Duration::from_millis(200), TcpStream::connect(server)).await??;
    write_message(&mut stream, &Message::Report(report)).await?;

    match read_message(&mut stream).await? {
        Message::Peers(list) => Ok(list),
        _ => Ok(Vec::new()),
    }
}

async fn write_message(stream: &mut TcpStream, msg: &Message) -> Result<()> {
    let bytes = bincode::serialize(msg)?;
    let len = bytes.len() as u32;
    timeout(Duration::from_millis(200), stream.write_u32_le(len)).await??;
    timeout(Duration::from_millis(200), stream.write_all(&bytes)).await??;
    timeout(Duration::from_millis(200), stream.flush()).await??;
    Ok(())
}

async fn read_message(stream: &mut TcpStream) -> Result<Message> {
    let len = timeout(Duration::from_millis(200), stream.read_u32_le()).await?? as usize;
    let mut buf = vec![0u8; len];
    timeout(Duration::from_millis(200), stream.read_exact(&mut buf)).await??;
    Ok(bincode::deserialize::<Message>(&buf)?)
}
