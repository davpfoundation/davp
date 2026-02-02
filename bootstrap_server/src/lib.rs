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

const STABLE_AFTER: Duration = Duration::minutes(15);

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
    pub entries: Vec<PeerEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum Message {
    Report(PeerReport),
    Peers(PeersResponse),
}

#[derive(Debug, Clone)]
struct PeerState {
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    stable: bool,
    reported: bool,
    active_inferred: bool,
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
        build_peer_entries(&self.peers, self.ttl, true).await
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

            // Prune first so "first client when CNT is empty" works even with stale entries.
            prune_expired(&peers, ttl).await;

            let requester_stable;
            {
                let mut map = peers.write().await;

                // Stability is server-authoritative and based on server-measured uptime only.
                // Do not assign stable immediately on insert.
                let stable_on_insert = false;

                let mut should_infer_from_gossip = false;
                let mut inferred_known: Vec<SocketAddr> = Vec::new();
                let mut inferred_connected: Vec<SocketAddr> = Vec::new();

                {
                    let entry = map.entry(report.addr).or_insert_with(|| PeerState {
                        first_seen: now,
                        last_seen: now,
                        stable: stable_on_insert,
                        reported: true,
                        active_inferred: true,
                        known_peers: Vec::new(),
                        connected_peers: Vec::new(),
                    });

                    entry.reported = true;
                    entry.last_seen = now;

                    // Gate gossip uploads: only stable clients can update known/connected lists.
                    // Also treat empty lists as presence-only so a stable client can query its
                    // stable status without wiping previously stored gossip.
                    if entry.stable && !(report.known_peers.is_empty() && report.connected_peers.is_empty()) {
                        entry.known_peers = report.known_peers;
                        entry.connected_peers = report.connected_peers;
                        should_infer_from_gossip = true;
                        inferred_known = entry.known_peers.clone();
                        inferred_connected = entry.connected_peers.clone();
                    }
                }

                // Stable clients can refresh/insert inferred peers so non-CNT nodes propagate via CNT.
                // Inferred peers are marked as reported=false so they never participate in stable election.
                if should_infer_from_gossip {
                    // Only refresh TTL for inferred peers that are CURRENTLY connected.
                    // Known peers should not keep inferred peers alive forever.
                    for p in inferred_connected.into_iter() {
                        if p == report.addr {
                            continue;
                        }

                        map.entry(p)
                            .and_modify(|st| {
                                if !st.reported {
                                    st.last_seen = now;
                                }
                            })
                            .or_insert(PeerState {
                                first_seen: now,
                                last_seen: now,
                                stable: false,
                                reported: false,
                                active_inferred: true,
                                known_peers: Vec::new(),
                                connected_peers: Vec::new(),
                            });
                    }

                    // Still insert inferred known peers for discovery, but do NOT refresh their TTL.
                    for p in inferred_known.into_iter() {
                        if p == report.addr {
                            continue;
                        }

                        map.entry(p).or_insert(PeerState {
                            first_seen: now,
                            last_seen: now,
                            stable: false,
                            reported: false,
                            active_inferred: false,
                            known_peers: Vec::new(),
                            connected_peers: Vec::new(),
                        });
                    }
                }

                elect_stable_if_needed(&mut map, now);

                requester_stable = map.get(&report.addr).map(|st| st.stable).unwrap_or(false);
            }

            let list = build_peer_entries(&peers, ttl, requester_stable).await;
            write_message(
                &mut stream,
                &Message::Peers(PeersResponse {
                    requester_stable,
                    entries: list,
                }),
            )
            .await?;
        }
        Message::Peers(_) => {}
    }

    Ok(())
}

fn elect_stable_if_needed(map: &mut HashMap<SocketAddr, PeerState>, now: DateTime<Utc>) {
    if map.is_empty() {
        return;
    }

    // If we already have a stable peer that has reached the stable-after threshold,
    // keep it to avoid unnecessary churn.
    if map
        .values()
        .any(|st| st.reported && st.stable && (now - st.first_seen) >= STABLE_AFTER)
    {
        return;
    }

    for st in map.values_mut() {
        st.stable = false;
    }

    if !map.values().any(|st| st.reported) {
        return;
    }

    // Deterministic election:
    // - oldest first_seen wins
    // - tie-breaker: lowest SocketAddr
    // Prefer peers that have reached STABLE_AFTER. If none have, still elect a bootstrap
    // stable among all reported peers so there's always at least one stable.
    let elect = |require_stable_after: bool| -> Option<SocketAddr> {
        let mut selected: Option<SocketAddr> = None;
        let mut selected_first_seen: Option<DateTime<Utc>> = None;

        for (addr, st) in map.iter() {
            if !st.reported {
                continue;
            }
            if require_stable_after && (now - st.first_seen) < STABLE_AFTER {
                continue;
            }

            match (selected, selected_first_seen) {
                (None, None) => {
                    selected = Some(*addr);
                    selected_first_seen = Some(st.first_seen);
                }
                (Some(cur_addr), Some(cur_seen)) => {
                    if st.first_seen < cur_seen || (st.first_seen == cur_seen && *addr < cur_addr) {
                        selected = Some(*addr);
                        selected_first_seen = Some(st.first_seen);
                    }
                }
                _ => {}
            }
        }

        selected
    };

    let selected = elect(true).or_else(|| elect(false));

    if let Some(addr) = selected {
        if let Some(st) = map.get_mut(&addr) {
            st.stable = true;
        }
    }
}

async fn build_peer_entries(
    peers: &Arc<RwLock<HashMap<SocketAddr, PeerState>>>,
    ttl: Duration,
    include_gossip: bool,
) -> Vec<PeerEntry> {
    let now = Utc::now();
    let mut out = Vec::new();

    let map = peers.read().await;
    for (addr, st) in map.iter() {
        if !st.reported && !st.active_inferred {
            continue;
        }
        let expires_at = st.last_seen + ttl;
        if expires_at <= now {
            continue;
        }
        let uptime_seconds = (now - st.first_seen).num_seconds().max(0);
        out.push(PeerEntry {
            addr: *addr,
            first_seen: st.first_seen,
            last_seen: st.last_seen,
            expires_at,
            uptime_seconds,
            stable: st.stable,
            known_peers: if include_gossip { st.known_peers.clone() } else { Vec::new() },
            connected_peers: if include_gossip { st.connected_peers.clone() } else { Vec::new() },
        });
    }

    // Keep ordering stable across heartbeats. Sorting by expires_at/last_seen causes
    // the list to constantly reshuffle due to timing races.
    out.sort_by(|a, b| b.first_seen.cmp(&a.first_seen).then_with(|| a.addr.cmp(&b.addr)));
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
