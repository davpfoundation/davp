use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch, RwLock};
use tokio::time::{timeout, Duration};

use crate::modules::asset::Proof;
use crate::modules::certification::PublishedProof;
use crate::modules::hash::AssetHash;
use crate::modules::net_utils::is_invalid_peer_addr;
use crate::modules::storage::Storage;
use crate::modules::verification::verify_proof;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const TARGET_OUTBOUND_SESSIONS: usize = 8;
const OUTBOUND_DIAL_TICK: Duration = Duration::from_secs(2);

#[derive(Clone, Debug)]
pub struct NodeConfig {
    pub bind_addr: SocketAddr,
    pub advertise_addr: Arc<Mutex<SocketAddr>>,
    pub peers: Arc<RwLock<Vec<SocketAddr>>>,
    pub peer_graph: Arc<RwLock<HashMap<SocketAddr, Vec<SocketAddr>>>>,
    pub last_inbound: Arc<Mutex<Option<Instant>>>,
}

type SessionMap = HashMap<SocketAddr, mpsc::UnboundedSender<Message>>;

static PEER_SESSIONS: OnceLock<Arc<RwLock<SessionMap>>> = OnceLock::new();

fn peer_sessions() -> &'static Arc<RwLock<SessionMap>> {
    PEER_SESSIONS.get_or_init(|| Arc::new(RwLock::new(HashMap::new())))
}

pub async fn connected_session_peers() -> Vec<SocketAddr> {
    let m = peer_sessions().read().await;
    m.keys().copied().collect()
}

pub async fn fetch_published_proof_from_peers(
    peers: &[SocketAddr],
    verification_id: &str,
) -> Result<Option<PublishedProof>> {
    for peer in peers {
        if let Ok(Some(published)) = request_published_proof(*peer, verification_id).await {
            return Ok(Some(published));
        }
    }
    Ok(None)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerConnections {
    pub addr: SocketAddr,
    pub connected_peers: Vec<SocketAddr>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum Message {
    PushProof(Proof),
    PushPublishedProof(PublishedProof),
    GetProof {
        verification_id: String,
    },
    ProofResponse {
        proof: Option<Proof>,
    },
    GetPublishedProof {
        verification_id: String,
    },
    PublishedProofResponse {
        published: Option<PublishedProof>,
    },
    GetIdsByHash {
        asset_hash: AssetHash,
    },
    IdsByHashResponse {
        verification_ids: Vec<String>,
    },
    Ping {
        from: SocketAddr,
        known_peers: Vec<SocketAddr>,
        connections: Vec<PeerConnections>,
    },
    Pong {
        observed_addr: SocketAddr,
        known_peers: Vec<SocketAddr>,
        connections: Vec<PeerConnections>,
    },
}

pub async fn run_node(storage: Storage, config: NodeConfig) -> Result<()> {
    let listener = TcpListener::bind(config.bind_addr).await?;
    let storage = Arc::new(storage);
    let advertise_addr = Arc::clone(&config.advertise_addr);
    let peers = config.peers;
    let peer_graph = config.peer_graph;
    let last_inbound = config.last_inbound;
    let local_bind = config.bind_addr;

    {
        let storage = Arc::clone(&storage);
        let peers = Arc::clone(&peers);
        let peer_graph = Arc::clone(&peer_graph);
        let advertise_addr = Arc::clone(&advertise_addr);
        tokio::spawn(async move {
            maintain_outbound_sessions(local_bind, advertise_addr, storage, peers, peer_graph, None)
                .await;
        });
    }

    loop {
        let (stream, remote_addr) = listener.accept().await?;

        if let Ok(mut g) = last_inbound.lock() {
            *g = Some(Instant::now());
        }

        let storage = Arc::clone(&storage);
        let peers = Arc::clone(&peers);
        let peer_graph = Arc::clone(&peer_graph);
        let last_inbound = Arc::clone(&last_inbound);

        tokio::spawn(async move {
            let _ = handle_connection(
                local_bind,
                stream,
                remote_addr,
                None,
                storage,
                peers,
                peer_graph,
                last_inbound,
            )
            .await;
        });
    }
}

async fn request_published_proof(
    peer: SocketAddr,
    verification_id: &str,
) -> Result<Option<PublishedProof>> {
    let mut stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(peer)).await??;
    write_message(
        &mut stream,
        &Message::GetPublishedProof {
            verification_id: verification_id.to_string(),
        },
    )
    .await?;

    match read_message(&mut stream).await? {
        Message::PublishedProofResponse { published } => Ok(published),
        _ => Ok(None),
    }
}

pub async fn run_node_with_shutdown(
    storage: Storage,
    config: NodeConfig,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let listener = TcpListener::bind(config.bind_addr).await?;
    let storage = Arc::new(storage);
    let advertise_addr = Arc::clone(&config.advertise_addr);
    let peers = config.peers;
    let peer_graph = config.peer_graph;
    let last_inbound = config.last_inbound;
    let local_bind = config.bind_addr;

    {
        let storage = Arc::clone(&storage);
        let peers = Arc::clone(&peers);
        let peer_graph = Arc::clone(&peer_graph);
        let advertise_addr = Arc::clone(&advertise_addr);
        let shutdown_rx = shutdown.clone();
        tokio::spawn(async move {
            maintain_outbound_sessions(
                local_bind,
                advertise_addr,
                storage,
                peers,
                peer_graph,
                Some(shutdown_rx),
            )
            .await;
        });
    }

    loop {
        if *shutdown.borrow() {
            break;
        }

        let accept_res = tokio::select! {
            _ = shutdown.changed() => {
                continue;
            }
            res = listener.accept() => res,
        };

        let (stream, remote_addr) = accept_res?;

        if let Ok(mut g) = last_inbound.lock() {
            *g = Some(Instant::now());
        }

        let storage = Arc::clone(&storage);
        let peers = Arc::clone(&peers);
        let peer_graph = Arc::clone(&peer_graph);
        let last_inbound = Arc::clone(&last_inbound);

        tokio::spawn(async move {
            let _ = handle_connection(
                local_bind,
                stream,
                remote_addr,
                None,
                storage,
                peers,
                peer_graph,
                last_inbound,
            )
            .await;
        });
    }

    Ok(())
}

pub async fn replicate_proof(proof: &Proof, peers: &[SocketAddr]) {
    for peer in peers {
        let _ = send_message(*peer, &Message::PushProof(proof.clone())).await;
    }
}

pub async fn replicate_published_proof(published: &PublishedProof, peers: &[SocketAddr]) {
    for peer in peers {
        let _ = send_message(*peer, &Message::PushPublishedProof(published.clone())).await;
        let _ = send_message(*peer, &Message::PushProof(published.proof.clone())).await;
    }
}

async fn handle_connection(
    local_bind: SocketAddr,
    stream: TcpStream,
    observed_remote: SocketAddr,
    peer_hint: Option<SocketAddr>,
    storage: Arc<Storage>,
    peers: Arc<RwLock<Vec<SocketAddr>>>,
    peer_graph: Arc<RwLock<HashMap<SocketAddr, Vec<SocketAddr>>>>,
    _last_inbound: Arc<Mutex<Option<Instant>>>,
) -> Result<()> {
    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
    let session_peer: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(peer_hint));

    let initial_peer = session_peer.lock().ok().and_then(|g| *g);
    if let Some(peer) = initial_peer {
        let mut m = peer_sessions().write().await;
        m.insert(peer, tx.clone());
    }

    let (mut reader, mut writer) = stream.into_split();

    let writer_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if let Err(e) = write_message(&mut writer, &msg).await {
                println!(
                    "P2P: writer_task write_message error: {}",
                    e
                );
                break;
            }
        }
    });

    loop {
        let msg = match read_message(&mut reader).await {
            Ok(v) => v,
            Err(e) => {
                println!(
                    "P2P: inbound read_message error (local_bind={}, observed_remote={}): {}",
                    local_bind, observed_remote, e
                );
                break;
            }
        };

        let _ = handle_incoming_message(
            local_bind,
            observed_remote,
            msg,
            &tx,
            Arc::clone(&session_peer),
            Arc::clone(&storage),
            Arc::clone(&peers),
            Arc::clone(&peer_graph),
        )
        .await;
    }

    let final_peer = session_peer.lock().ok().and_then(|g| *g);
    if let Some(peer) = final_peer {
        let mut m = peer_sessions().write().await;
        m.remove(&peer);
    }
    writer_task.abort();
    Ok(())
}

async fn handle_incoming_message(
    local_bind: SocketAddr,
    observed_remote: SocketAddr,
    msg: Message,
    tx: &mpsc::UnboundedSender<Message>,
    session_peer: Arc<Mutex<Option<SocketAddr>>>,
    storage: Arc<Storage>,
    peers: Arc<RwLock<Vec<SocketAddr>>>,
    peer_graph: Arc<RwLock<HashMap<SocketAddr, Vec<SocketAddr>>>>,
) -> Result<()> {
    let sender_key = session_peer.lock().ok().and_then(|g| *g);
    match msg {
        Message::PushProof(proof) => {
            verify_proof(&proof, None)?;
            if !storage.contains(&proof.verification_id) {
                storage.store_proof(&proof)?;
                let mut connected = connected_session_peers().await;
                if let Some(sender) = sender_key {
                    connected.retain(|p| *p != sender);
                } else {
                    connected.retain(|p| *p != observed_remote);
                }
                replicate_proof(&proof, &connected).await;
            }
        }
        Message::PushPublishedProof(published) => {
            verify_proof(&published.proof, None)?;
            if storage.contains(&published.proof.verification_id) {
                let _ = storage.store_published_proof(&published);
            } else {
                storage.store_published_proof(&published)?;
                let mut connected = connected_session_peers().await;
                if let Some(sender) = sender_key {
                    connected.retain(|p| *p != sender);
                } else {
                    connected.retain(|p| *p != observed_remote);
                }
                replicate_published_proof(&published, &connected).await;
            }
        }
        Message::GetProof { verification_id } => {
            let proof = if storage.contains(&verification_id) {
                Some(storage.retrieve_proof(&verification_id)?)
            } else {
                None
            };
            let _ = tx.send(Message::ProofResponse { proof });
        }
        Message::GetPublishedProof { verification_id } => {
            let published = if storage.contains(&verification_id) {
                Some(storage.retrieve_published_proof(&verification_id)?)
            } else {
                None
            };
            let _ = tx.send(Message::PublishedProofResponse { published });
        }
        Message::GetIdsByHash { asset_hash } => {
            let verification_ids = storage.lookup_by_hash(&asset_hash).unwrap_or_default();
            let _ = tx.send(Message::IdsByHashResponse { verification_ids });
        }
        Message::Ping {
            from,
            known_peers,
            connections,
        } => {
            println!(
                "P2P: received Ping (local_bind={}, observed_remote={}, from={})",
                local_bind, observed_remote, from
            );
            // For inbound connections, the remote TCP socket address uses an ephemeral source
            // port. If the peer's advertised `from` address is not routable (e.g. RFC1918)
            // or doesn't match the observed public IP, fall back to the observed socket addr
            // so we can still push data back over this established connection.
            let session_key = if !is_invalid_peer_addr(from) && from.ip() == observed_remote.ip() {
                from
            } else {
                observed_remote
            };

            let mut register: Option<SocketAddr> = None;
            if let Ok(mut g) = session_peer.lock() {
                if g.is_none() {
                    *g = Some(session_key);
                    register = Some(session_key);
                }
            }
            if let Some(peer) = register {
                let mut m = peer_sessions().write().await;
                m.insert(peer, tx.clone());
            }

            if !is_invalid_peer_addr(from) {
                merge_peers(&peers, from, &known_peers).await;
            }
            merge_graph(&peer_graph, &connections).await;
            {
                let mut g = peer_graph.write().await;
                let entry = g.entry(local_bind).or_default();
                if !entry.contains(&session_key) {
                    entry.push(session_key);
                }
            }
            let peers_snapshot = peers.read().await.clone();
            let graph_snapshot = snapshot_graph(&peer_graph).await;
            let _ = tx.send(Message::Pong {
                observed_addr: observed_remote,
                known_peers: peers_snapshot,
                connections: graph_snapshot,
            });
            println!(
                "P2P: queued Pong (local_bind={}, observed_remote={}, session_key={})",
                local_bind, observed_remote, session_key
            );
        }
        Message::Pong { .. } => {}
        Message::ProofResponse { .. }
        | Message::PublishedProofResponse { .. }
        | Message::IdsByHashResponse { .. } => {}
    }

    Ok(())
}

async fn maintain_outbound_sessions(
    local_bind: SocketAddr,
    advertise_addr: Arc<Mutex<SocketAddr>>,
    storage: Arc<Storage>,
    peers: Arc<RwLock<Vec<SocketAddr>>>,
    peer_graph: Arc<RwLock<HashMap<SocketAddr, Vec<SocketAddr>>>>,
    mut shutdown: Option<watch::Receiver<bool>>,
) {
    const MAX_NEW_DIALS_PER_TICK: usize = 2;
    const BACKOFF_INITIAL_SECS: u64 = 2;
    const BACKOFF_MAX_SECS: u64 = 60;

    let mut tick = tokio::time::interval(OUTBOUND_DIAL_TICK);
    let mut backoff: HashMap<SocketAddr, (Instant, u64)> = HashMap::new();
    loop {
        if let Some(rx) = shutdown.as_ref() {
            if *rx.borrow() {
                break;
            }
        }

        if let Some(rx) = shutdown.as_mut() {
            tokio::select! {
                _ = tick.tick() => {}
                _ = rx.changed() => { continue; }
            }
        } else {
            tick.tick().await;
        }

        let current_connected = {
            let m = peer_sessions().read().await;
            m.len()
        };

        if current_connected >= TARGET_OUTBOUND_SESSIONS {
            continue;
        }

        let self_advertised = advertise_addr
            .lock()
            .ok()
            .map(|g| *g)
            .unwrap_or(local_bind);

        let peers_snapshot = peers.read().await.clone();
        let connections_snapshot = snapshot_graph(&peer_graph).await;

        let now = Instant::now();
        let mut dial_peers: Vec<SocketAddr> = peers_snapshot
            .iter()
            .copied()
            .filter(|peer| {
                if *peer == local_bind {
                    return false;
                }
                if *peer == self_advertised {
                    return false;
                }
                if is_invalid_peer_addr(*peer) {
                    return false;
                }
                if let Some((next_ok, _)) = backoff.get(peer) {
                    if *next_ok > now {
                        return false;
                    }
                }
                true
            })
            .collect();

        dial_peers.sort();

        let mut attempted: usize = 0;
        for peer in dial_peers.into_iter() {
            if peer == local_bind {
                continue;
            }
            if peer == self_advertised {
                continue;
            }
            if is_invalid_peer_addr(peer) {
                continue;
            }

            let already = {
                let m = peer_sessions().read().await;
                m.contains_key(&peer)
            };
            if already {
                continue;
            }

            if attempted >= MAX_NEW_DIALS_PER_TICK {
                break;
            }
            attempted = attempted.saturating_add(1);

            let mut stream = match timeout(CONNECT_TIMEOUT, TcpStream::connect(peer)).await {
                Ok(Ok(s)) => s,
                _ => {
                    let delay = backoff
                        .get(&peer)
                        .map(|(_, d)| (d.saturating_mul(2)).min(BACKOFF_MAX_SECS))
                        .unwrap_or(BACKOFF_INITIAL_SECS);
                    backoff.insert(peer, (Instant::now() + Duration::from_secs(delay), delay));
                    continue;
                }
            };

            let from = advertise_addr
                .lock()
                .ok()
                .map(|g| *g)
                .unwrap_or(local_bind);

            if write_message(
                &mut stream,
                &Message::Ping {
                    from,
                    known_peers: peers_snapshot.clone(),
                    connections: connections_snapshot.clone(),
                },
            )
            .await
            .is_err()
            {
                let delay = backoff
                    .get(&peer)
                    .map(|(_, d)| (d.saturating_mul(2)).min(BACKOFF_MAX_SECS))
                    .unwrap_or(BACKOFF_INITIAL_SECS);
                backoff.insert(peer, (Instant::now() + Duration::from_secs(delay), delay));
                continue;
            }

            match read_message(&mut stream).await {
                Ok(Message::Pong { .. }) => {
                    backoff.remove(&peer);
                }
                _ => {
                    let delay = backoff
                        .get(&peer)
                        .map(|(_, d)| (d.saturating_mul(2)).min(BACKOFF_MAX_SECS))
                        .unwrap_or(BACKOFF_INITIAL_SECS);
                    backoff.insert(peer, (Instant::now() + Duration::from_secs(delay), delay));
                    continue;
                }
            }

            {
                let mut g = peer_graph.write().await;
                let entry = g.entry(local_bind).or_default();
                if !entry.contains(&peer) {
                    entry.push(peer);
                }
            }

            let storage2 = Arc::clone(&storage);
            let peers2 = Arc::clone(&peers);
            let peer_graph2 = Arc::clone(&peer_graph);
            tokio::spawn(async move {
                let _ = handle_connection(
                    local_bind,
                    stream,
                    peer,
                    Some(peer),
                    storage2,
                    peers2,
                    peer_graph2,
                    Arc::new(Mutex::new(None)),
                )
                .await;
            });

            let now_connected = {
                let m = peer_sessions().read().await;
                m.len()
            };
            if now_connected >= TARGET_OUTBOUND_SESSIONS {
                break;
            }
        }
    }
}

pub async fn fetch_proof_from_peers(
    peers: &[SocketAddr],
    verification_id: &str,
) -> Result<Option<Proof>> {
    for peer in peers {
        if let Ok(Some(proof)) = request_proof(*peer, verification_id).await {
            return Ok(Some(proof));
        }
    }
    Ok(None)
}

pub async fn fetch_ids_by_hash_from_peers(
    peers: &[SocketAddr],
    asset_hash: &AssetHash,
) -> Result<Vec<String>> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();

    for peer in peers {
        if let Ok(ids) = request_ids_by_hash(*peer, asset_hash).await {
            for id in ids {
                if seen.insert(id.clone()) {
                    out.push(id);
                }
            }
        }
    }

    Ok(out)
}

pub async fn ping_peer(
    peer: SocketAddr,
    from: SocketAddr,
    known_peers: Vec<SocketAddr>,
    connections: Vec<PeerConnections>,
) -> Result<(Vec<SocketAddr>, Vec<PeerConnections>, SocketAddr)> {
    let mut stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(peer)).await??;
    write_message(
        &mut stream,
        &Message::Ping {
            from,
            known_peers,
            connections,
        },
    )
    .await?;

    match read_message(&mut stream).await? {
        Message::Pong {
            observed_addr,
            known_peers,
            connections,
        } => Ok((known_peers, connections, observed_addr)),
        _ => Ok((Vec::new(), Vec::new(), peer)),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PingPeerStage {
    Connect,
    WritePing,
    ReadPong,
    InvalidResponse,
}

#[derive(Debug, Clone)]
pub struct PingPeerDetailedError {
    pub stage: PingPeerStage,
    pub message: String,
}

pub async fn ping_peer_detailed(
    peer: SocketAddr,
    from: SocketAddr,
    known_peers: Vec<SocketAddr>,
    connections: Vec<PeerConnections>,
) -> std::result::Result<(Vec<SocketAddr>, Vec<PeerConnections>, SocketAddr), PingPeerDetailedError> {
    let mut stream = match timeout(CONNECT_TIMEOUT, TcpStream::connect(peer)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            return Err(PingPeerDetailedError {
                stage: PingPeerStage::Connect,
                message: format!("{}", e),
            });
        }
        Err(e) => {
            return Err(PingPeerDetailedError {
                stage: PingPeerStage::Connect,
                message: format!("{}", e),
            });
        }
    };

    if let Err(e) = write_message(
        &mut stream,
        &Message::Ping {
            from,
            known_peers,
            connections,
        },
    )
    .await
    {
        return Err(PingPeerDetailedError {
            stage: PingPeerStage::WritePing,
            message: format!("{}", e),
        });
    }

    let msg = match read_message(&mut stream).await {
        Ok(m) => m,
        Err(e) => {
            return Err(PingPeerDetailedError {
                stage: PingPeerStage::ReadPong,
                message: format!("{}", e),
            });
        }
    };

    match msg {
        Message::Pong {
            observed_addr,
            known_peers,
            connections,
        } => Ok((known_peers, connections, observed_addr)),
        _ => Err(PingPeerDetailedError {
            stage: PingPeerStage::InvalidResponse,
            message: "not a pong".to_string(),
        }),
    }
}

async fn request_proof(peer: SocketAddr, verification_id: &str) -> Result<Option<Proof>> {
    let mut stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(peer)).await??;
    write_message(
        &mut stream,
        &Message::GetProof {
            verification_id: verification_id.to_string(),
        },
    )
    .await?;

    match read_message(&mut stream).await? {
        Message::ProofResponse { proof } => Ok(proof),
        _ => Ok(None),
    }
}

async fn request_ids_by_hash(peer: SocketAddr, asset_hash: &AssetHash) -> Result<Vec<String>> {
    let mut stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(peer)).await??;
    write_message(
        &mut stream,
        &Message::GetIdsByHash {
            asset_hash: asset_hash.clone(),
        },
    )
    .await?;

    match read_message(&mut stream).await? {
        Message::IdsByHashResponse { verification_ids } => Ok(verification_ids),
        _ => Ok(Vec::new()),
    }
}

async fn send_message(peer: SocketAddr, msg: &Message) -> Result<()> {
    if let Some(tx) = peer_sessions().read().await.get(&peer).cloned() {
        if tx.send(msg.clone()).is_ok() {
            return Ok(());
        }
        let mut m = peer_sessions().write().await;
        m.remove(&peer);
    }

    let mut stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(peer)).await??;
    write_message(&mut stream, msg).await?;
    Ok(())
}

async fn write_message<W: AsyncWriteExt + Unpin>(stream: &mut W, msg: &Message) -> Result<()> {
    let bytes = bincode::serialize(msg)?;
    let len = bytes.len() as u32;
    timeout(IO_TIMEOUT, stream.write_u32_le(len)).await??;
    timeout(IO_TIMEOUT, stream.write_all(&bytes)).await??;
    timeout(IO_TIMEOUT, stream.flush()).await??;
    Ok(())
}

async fn read_message<R: AsyncReadExt + Unpin>(stream: &mut R) -> Result<Message> {
    let len = timeout(IO_TIMEOUT, stream.read_u32_le()).await?? as usize;
    let mut buf = vec![0u8; len];
    timeout(IO_TIMEOUT, stream.read_exact(&mut buf)).await??;
    Ok(bincode::deserialize::<Message>(&buf)?)
}

async fn merge_peers(
    peers: &Arc<RwLock<Vec<SocketAddr>>>,
    from: SocketAddr,
    additional: &[SocketAddr],
) {
    let mut all = peers.write().await;
    if !all.contains(&from) && !is_invalid_peer_addr(from) {
        all.push(from);
    }
    for p in additional {
        if !all.contains(p) && !is_invalid_peer_addr(*p) {
            all.push(*p);
        }
    }
}

async fn merge_graph(
    graph: &Arc<RwLock<HashMap<SocketAddr, Vec<SocketAddr>>>>,
    updates: &[PeerConnections],
) {
    let mut g = graph.write().await;
    for pc in updates {
        let entry = g.entry(pc.addr).or_default();
        for p in pc.connected_peers.iter().copied() {
            if !entry.contains(&p) {
                entry.push(p);
            }
        }
    }
}

async fn snapshot_graph(
    graph: &Arc<RwLock<HashMap<SocketAddr, Vec<SocketAddr>>>>,
) -> Vec<PeerConnections> {
    let g = graph.read().await;
    g.iter()
        .map(|(addr, connected_peers)| PeerConnections {
            addr: *addr,
            connected_peers: connected_peers.clone(),
        })
        .collect()
}
