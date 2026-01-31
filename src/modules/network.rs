use crate::modules::asset::Proof;
use crate::modules::hash::AssetHash;
use crate::modules::storage::Storage;
use crate::modules::verification::verify_proof;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tokio::sync::watch;
use tokio::time::{timeout, Duration};

#[derive(Clone, Debug)]
pub struct NodeConfig {
    pub bind_addr: SocketAddr,
    pub peers: Arc<RwLock<Vec<SocketAddr>>>,
    pub peer_graph: Arc<RwLock<HashMap<SocketAddr, Vec<SocketAddr>>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerConnections {
    pub addr: SocketAddr,
    pub connected_peers: Vec<SocketAddr>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum Message {
    PushProof(Proof),
    GetProof { verification_id: String },
    ProofResponse { proof: Option<Proof> },
    GetIdsByHash { asset_hash: AssetHash },
    IdsByHashResponse { verification_ids: Vec<String> },
    Ping { from: SocketAddr, known_peers: Vec<SocketAddr>, connections: Vec<PeerConnections> },
    Pong { known_peers: Vec<SocketAddr>, connections: Vec<PeerConnections> },
}

pub async fn run_node(storage: Storage, config: NodeConfig) -> Result<()> {
    let listener = TcpListener::bind(config.bind_addr).await?;
    let storage = Arc::new(storage);
    let peers = config.peers;
    let peer_graph = config.peer_graph;

    loop {
        let (stream, _) = listener.accept().await?;
        let storage = Arc::clone(&storage);
        let peers = Arc::clone(&peers);
        let peer_graph = Arc::clone(&peer_graph);

        tokio::spawn(async move {
            let _ = handle_connection(stream, storage, peers, peer_graph).await;
        });
    }
}

pub async fn run_node_with_shutdown(
    storage: Storage,
    config: NodeConfig,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let listener = TcpListener::bind(config.bind_addr).await?;
    let storage = Arc::new(storage);
    let peers = config.peers;
    let peer_graph = config.peer_graph;

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

        let (stream, _) = accept_res?;
        let storage = Arc::clone(&storage);
        let peers = Arc::clone(&peers);
        let peer_graph = Arc::clone(&peer_graph);

        tokio::spawn(async move {
            let _ = handle_connection(stream, storage, peers, peer_graph).await;
        });
    }

    Ok(())
}

pub async fn replicate_proof(proof: &Proof, peers: &[SocketAddr]) {
    for peer in peers {
        let _ = send_message(*peer, &Message::PushProof(proof.clone())).await;
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    storage: Arc<Storage>,
    peers: Arc<RwLock<Vec<SocketAddr>>>,
    peer_graph: Arc<RwLock<HashMap<SocketAddr, Vec<SocketAddr>>>>,
) -> Result<()> {
    let msg = read_message(&mut stream).await?;

    match msg {
        Message::PushProof(proof) => {
            verify_proof(&proof, None)?;
            if !storage.contains(&proof.verification_id) {
                storage.store_proof(&proof)?;
                let peers_snapshot = peers.read().await.clone();
                replicate_proof(&proof, &peers_snapshot).await;
            }
        }
        Message::GetProof { verification_id } => {
            let proof = if storage.contains(&verification_id) {
                Some(storage.retrieve_proof(&verification_id)?)
            } else {
                None
            };
            write_message(&mut stream, &Message::ProofResponse { proof }).await?;
        }
        Message::GetIdsByHash { asset_hash } => {
            let verification_ids = storage.lookup_by_hash(&asset_hash).unwrap_or_default();
            write_message(
                &mut stream,
                &Message::IdsByHashResponse {
                    verification_ids,
                },
            )
            .await?;
        }
        Message::Ping { from, known_peers, connections } => {
            merge_peers(&peers, from, &known_peers).await;
            merge_graph(&peer_graph, &connections).await;
            let peers_snapshot = peers.read().await.clone();
            let graph_snapshot = snapshot_graph(&peer_graph).await;
            write_message(
                &mut stream,
                &Message::Pong {
                    known_peers: peers_snapshot,
                    connections: graph_snapshot,
                },
            )
            .await?;
        }
        Message::ProofResponse { .. } | Message::IdsByHashResponse { .. } => {}
        Message::Pong { .. } => {}
    }

    Ok(())
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
) -> Result<(Vec<SocketAddr>, Vec<PeerConnections>)> {
    let mut stream = timeout(Duration::from_millis(200), TcpStream::connect(peer)).await??;
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
        Message::Pong { known_peers, connections } => Ok((known_peers, connections)),
        _ => Ok((Vec::new(), Vec::new())),
    }
}

async fn request_proof(peer: SocketAddr, verification_id: &str) -> Result<Option<Proof>> {
    let mut stream = timeout(Duration::from_millis(200), TcpStream::connect(peer)).await??;
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
    let mut stream = timeout(Duration::from_millis(200), TcpStream::connect(peer)).await??;
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
    let mut stream = timeout(Duration::from_millis(200), TcpStream::connect(peer)).await??;
    write_message(&mut stream, msg).await?;
    Ok(())
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

async fn merge_peers(peers: &Arc<RwLock<Vec<SocketAddr>>>, from: SocketAddr, additional: &[SocketAddr]) {
    let mut all = peers.write().await;
    if !all.contains(&from) {
        all.push(from);
    }
    for p in additional {
        if !all.contains(p) {
            all.push(*p);
        }
    }
}

async fn merge_graph(graph: &Arc<RwLock<HashMap<SocketAddr, Vec<SocketAddr>>>>, updates: &[PeerConnections]) {
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

async fn snapshot_graph(graph: &Arc<RwLock<HashMap<SocketAddr, Vec<SocketAddr>>>>) -> Vec<PeerConnections> {
    let g = graph.read().await;
    g.iter()
        .map(|(addr, connected_peers)| PeerConnections {
            addr: *addr,
            connected_peers: connected_peers.clone(),
        })
        .collect()
}
