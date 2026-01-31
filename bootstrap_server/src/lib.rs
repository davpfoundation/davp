use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tokio::sync::watch;
use tokio::time::{interval, timeout};

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

#[derive(Debug, Clone)]
struct PeerState {
    last_seen: DateTime<Utc>,
    known_peers: Vec<SocketAddr>,
    connected_peers: Vec<SocketAddr>,
}

#[derive(Clone)]
pub struct CntServerHandle {
    peers: Arc<RwLock<HashMap<SocketAddr, PeerState>>>,
    ttl: Duration,
}

impl CntServerHandle {
    pub async fn entries(&self) -> Vec<PeerEntry> {
        build_peer_entries(&self.peers, self.ttl).await
    }
}

pub async fn run_server(bind: SocketAddr, ttl_seconds: i64) -> Result<()> {
    let (_tx, rx) = watch::channel(false);
    run_server_with_shutdown(bind, ttl_seconds, rx).await
}

pub async fn start_server_with_shutdown(
    bind: SocketAddr,
    ttl_seconds: i64,
    shutdown: watch::Receiver<bool>,
) -> Result<CntServerHandle> {
    let ttl = Duration::seconds(ttl_seconds.max(5));

    let peers: Arc<RwLock<HashMap<SocketAddr, PeerState>>> = Arc::new(RwLock::new(HashMap::new()));
    let listener = TcpListener::bind(bind).await?;

    let accept_peers = Arc::clone(&peers);
    let mut accept_shutdown = shutdown.clone();
    tokio::spawn(async move {
        loop {
            if *accept_shutdown.borrow() {
                break;
            }

            let accept_res = tokio::select! {
                _ = accept_shutdown.changed() => {
                    continue;
                }
                res = listener.accept() => res,
            };

            let (stream, _) = match accept_res {
                Ok(v) => v,
                Err(_) => break,
            };

            let peers = Arc::clone(&accept_peers);
            tokio::spawn(async move {
                let _ = handle_client(stream, peers, ttl).await;
            });
        }
    });

    let prune_peers = Arc::clone(&peers);
    let mut prune_shutdown = shutdown.clone();
    tokio::spawn(async move {
        let mut tick = interval(std::time::Duration::from_secs(1));
        loop {
            if *prune_shutdown.borrow() {
                break;
            }
            tokio::select! {
                _ = prune_shutdown.changed() => {
                    continue;
                }
                _ = tick.tick() => {
                    prune_expired(&prune_peers, ttl).await;
                }
            }
        }
    });

    Ok(CntServerHandle { peers, ttl })
}

pub async fn run_server_with_shutdown(
    bind: SocketAddr,
    ttl_seconds: i64,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let _handle = start_server_with_shutdown(bind, ttl_seconds, shutdown.clone()).await?;

    loop {
        if *shutdown.borrow() {
            break;
        }
        let _ = shutdown.changed().await;
    }

    Ok(())
}

async fn handle_client(
    mut stream: TcpStream,
    peers: Arc<RwLock<HashMap<SocketAddr, PeerState>>>,
    ttl: Duration,
) -> Result<()> {
    let msg: Message = read_message(&mut stream).await?;

    match msg {
        Message::Report(report) => {
            let now = Utc::now();
            {
                let mut map = peers.write().await;
                map.insert(
                    report.addr,
                    PeerState {
                        last_seen: now,
                        known_peers: report.known_peers,
                        connected_peers: report.connected_peers,
                    },
                );

                let inferred = map
                    .get(&report.addr)
                    .map(|st| (st.known_peers.clone(), st.connected_peers.clone()))
                    .unwrap_or_default();

                for p in inferred.0.into_iter().chain(inferred.1.into_iter()) {
                    if p == report.addr {
                        continue;
                    }
                    map.entry(p)
                        .and_modify(|st| {
                            st.last_seen = now;
                        })
                        .or_insert(PeerState {
                            last_seen: now,
                            known_peers: Vec::new(),
                            connected_peers: Vec::new(),
                        });
                }
            }

            let list = build_peer_entries(&peers, ttl).await;
            write_message(&mut stream, &Message::Peers(list)).await?;
        }
        Message::Peers(_) => {}
    }

    Ok(())
}

async fn build_peer_entries(
    peers: &Arc<RwLock<HashMap<SocketAddr, PeerState>>>,
    ttl: Duration,
) -> Vec<PeerEntry> {
    let now = Utc::now();
    let mut out = Vec::new();

    let map = peers.read().await;
    for (addr, st) in map.iter() {
        let expires_at = st.last_seen + ttl;
        if expires_at <= now {
            continue;
        }
        out.push(PeerEntry {
            addr: *addr,
            last_seen: st.last_seen,
            expires_at,
            known_peers: st.known_peers.clone(),
            connected_peers: st.connected_peers.clone(),
        });
    }

    out.sort_by_key(|p| p.expires_at);
    out
}

async fn prune_expired(peers: &Arc<RwLock<HashMap<SocketAddr, PeerState>>>, ttl: Duration) {
    let now = Utc::now();
    let mut expired = Vec::new();

    {
        let map = peers.read().await;
        for (addr, st) in map.iter() {
            if st.last_seen + ttl <= now {
                expired.push(*addr);
            }
        }
    }

    if !expired.is_empty() {
        let mut map = peers.write().await;
        for addr in expired {
            map.remove(&addr);
        }
    }
}


async fn write_message(stream: &mut TcpStream, msg: &Message) -> Result<()> {
    let bytes = bincode::serialize(msg)?;
    let len = bytes.len() as u32;
    timeout(std::time::Duration::from_millis(200), stream.write_u32_le(len)).await??;
    timeout(std::time::Duration::from_millis(200), stream.write_all(&bytes)).await??;
    timeout(std::time::Duration::from_millis(200), stream.flush()).await??;
    Ok(())
}

async fn read_message(stream: &mut TcpStream) -> Result<Message> {
    let len = timeout(std::time::Duration::from_millis(200), stream.read_u32_le()).await?? as usize;
    let mut buf = vec![0u8; len];
    timeout(std::time::Duration::from_millis(200), stream.read_exact(&mut buf)).await??;
    Ok(bincode::deserialize::<Message>(&buf)?)
}
