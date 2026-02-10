use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::sync::watch;
use tokio::sync::Mutex;
use tokio::sync::RwLock;
use tokio::time::{interval, timeout};

use futures::StreamExt;
use libp2p::core::upgrade;
use libp2p::gossipsub::{Behaviour as Gossipsub, Config as GossipsubConfig, Event as GossipsubEvent, IdentTopic as Topic, MessageAuthenticity};
use libp2p::identify::{Behaviour as Identify, Config as IdentifyConfig};
use libp2p::noise;
use libp2p::swarm::{NetworkBehaviour, Swarm, SwarmEvent};
use libp2p::{identity, tcp, yamux, Multiaddr, PeerId, Transport};
use std::future::Future;
use std::pin::Pin;

const STABLE_AFTER: Duration = Duration::minutes(15);
const MAX_MESSAGE_BYTES: usize = 64 * 1024;
const MAX_GOSSIP_LIST_LEN: usize = 512;
const MAX_TRACKED_PEERS: usize = 50_000;
const MAX_CONCURRENT_CONNECTIONS: usize = 512;
const RATE_LIMIT_WINDOW: Duration = Duration::seconds(60);
const MAX_REPORTS_PER_WINDOW: u32 = 120;
const MAX_RATE_LIMIT_IPS: usize = 20_000;
const IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

const DAVP_PROOF_TOPIC: &str = "davp.proofs.v1";

fn push_log(logs: &Arc<Mutex<VecDeque<String>>>, line: String) {
    const MAX_LINES: usize = 500;
    let logs = Arc::clone(logs);
    tokio::spawn(async move {
        let mut l = logs.lock().await;
        if l.len() >= MAX_LINES {
            let to_drop = (l.len() + 1).saturating_sub(MAX_LINES);
            for _ in 0..to_drop {
                let _ = l.pop_front();
            }
        }
        l.push_back(line);
    });
}

fn rewrite_192_168_to_public_ip(addr: SocketAddr, public_ip: Option<IpAddr>) -> SocketAddr {
    let Some(public_ip) = public_ip else {
        return addr;
    };
    match addr.ip() {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            if o[0] == 192 && o[1] == 168 {
                SocketAddr::new(public_ip, addr.port())
            } else {
                addr
            }
        }
        IpAddr::V6(_) => addr,
    }
}

#[derive(Clone)]
struct TokioExecutor;

impl libp2p::swarm::Executor for TokioExecutor {
    fn exec(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        let _ = tokio::spawn(future);
    }
}

#[derive(NetworkBehaviour)]
#[behaviour(out_event = "HubEvent")]
struct HubBehaviour {
    identify: Identify,
    gossipsub: Gossipsub,
}

#[allow(clippy::large_enum_variant)]
enum HubEvent {
    Identify(libp2p::identify::Event),
    Gossipsub(GossipsubEvent),
}

impl From<libp2p::identify::Event> for HubEvent {
    fn from(e: libp2p::identify::Event) -> Self {
        HubEvent::Identify(e)
    }
}

impl From<GossipsubEvent> for HubEvent {
    fn from(e: GossipsubEvent) -> Self {
        HubEvent::Gossipsub(e)
    }
}

pub async fn run_p2p_hub(bind: SocketAddr, shutdown: &mut watch::Receiver<bool>) -> Result<()> {
    let id_keys = identity::Keypair::generate_ed25519();
    let peer_id = PeerId::from(id_keys.public());

    let noise_config = noise::Config::new(&id_keys).map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let transport = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true))
        .upgrade(upgrade::Version::V1)
        .authenticate(noise_config)
        .multiplex(yamux::Config::default())
        .boxed();

    let identify = Identify::new(IdentifyConfig::new("davp-hub/0.1".into(), id_keys.public()));

    let gs_cfg = GossipsubConfig::default();
    let mut gossipsub = Gossipsub::new(MessageAuthenticity::Signed(id_keys.clone()), gs_cfg)
        .map_err(|e| anyhow::anyhow!(e))?;
    let topic = Topic::new(DAVP_PROOF_TOPIC);
    gossipsub.subscribe(&topic).map_err(|e| anyhow::anyhow!(e.to_string()))?;

    let behaviour = HubBehaviour { identify, gossipsub };
    let mut swarm = Swarm::new(
        transport,
        behaviour,
        peer_id,
        libp2p::swarm::Config::with_executor(TokioExecutor),
    );

    let listen: Multiaddr = format!("/ip4/{}/tcp/{}", bind.ip(), bind.port()).parse()?;
    Swarm::listen_on(&mut swarm, listen)?;

    loop {
        if *shutdown.borrow() {
            break;
        }

        tokio::select! {
            _ = shutdown.changed() => {},
            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        println!("P2P hub listening on {address}");
                    }
                    SwarmEvent::Behaviour(HubEvent::Gossipsub(GossipsubEvent::Message { message, .. })) => {
                        // No-op: gossipsub will forward to peers; we just act as a rendezvous point.
                        let _ = message;
                    }
                    _ => {}
                }
            }
        }
    }

    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerReport {
    pub addr: SocketAddr,
    #[serde(default)]
    pub upnp_enabled: bool,
    pub known_peers: Vec<SocketAddr>,
    pub connected_peers: Vec<SocketAddr>,
}

fn is_unroutable_socket_addr(a: SocketAddr) -> bool {
    a.port() == 0 || is_unroutable_ip(a.ip())
}

fn is_unroutable_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_loopback() || v4.is_unspecified() {
                return true;
            }
            // CGNAT 100.64.0.0/10
            if v4.octets()[0] == 100 {
                let b = v4.octets()[1];
                if (64..=127).contains(&b) {
                    return true;
                }
            }
            // RFC1918
            if v4.octets()[0] == 10 {
                return true;
            }
            if v4.octets()[0] == 172 {
                let b = v4.octets()[1];
                if (16..=31).contains(&b) {
                    return true;
                }
            }
            if v4.octets()[0] == 192 && v4.octets()[1] == 168 {
                return true;
            }
            // Link-local 169.254.0.0/16
            if v4.octets()[0] == 169 && v4.octets()[1] == 254 {
                return true;
            }
            // Broadcast 255.255.255.255
            v4 == Ipv4Addr::BROADCAST
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() || v6.is_unspecified() {
                return true;
            }
            let seg0 = v6.segments()[0];
            // Unique local: fc00::/7
            if (seg0 & 0xfe00) == 0xfc00 {
                return true;
            }
            // Link-local unicast: fe80::/10
            if (seg0 & 0xffc0) == 0xfe80 {
                return true;
            }
            false
        }
    }
}

async fn is_rate_limited(
    rate_limits: &Arc<RwLock<HashMap<IpAddr, RateLimitState>>>,
    ip: IpAddr,
    now: DateTime<Utc>,
) -> bool {
    let mut map = rate_limits.write().await;
    if map.len() > MAX_RATE_LIMIT_IPS {
        map.retain(|_, st| (now - st.window_start) < Duration::seconds(RATE_LIMIT_WINDOW.num_seconds() * 2));
    }
    if map.len() >= MAX_RATE_LIMIT_IPS && !map.contains_key(&ip) {
        return true;
    }
    let st = map
        .entry(ip)
        .or_insert(RateLimitState {
            window_start: now,
            count: 0,
        });
    if now - st.window_start >= RATE_LIMIT_WINDOW {
        st.window_start = now;
        st.count = 0;
    }
    st.count = st.count.saturating_add(1);
    st.count > MAX_REPORTS_PER_WINDOW
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

#[derive(Debug, Clone)]
struct PeerState {
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    stable: bool,
    reported: bool,
    upnp_enabled: bool,
    active_inferred: bool,
    known_peers: Vec<SocketAddr>,
    connected_peers: Vec<SocketAddr>,
}

#[derive(Debug, Clone)]
struct RateLimitState {
    window_start: DateTime<Utc>,
    count: u32,
}

#[derive(Clone)]
pub struct CntServerHandle {
    peers: Arc<RwLock<HashMap<SocketAddr, PeerState>>>,
    ttl: Duration,
    logs: Arc<Mutex<VecDeque<String>>>,
}

impl CntServerHandle {
    pub async fn entries(&self) -> Vec<PeerEntry> {
        build_peer_entries(&self.peers, self.ttl, true).await
    }

    pub async fn logs(&self) -> Vec<String> {
        let l = self.logs.lock().await;
        l.iter().cloned().collect()
    }
}

pub async fn run_server(bind: SocketAddr, ttl_seconds: i64) -> Result<()> {
    let (_tx, rx) = watch::channel(false);
    run_server_with_shutdown(bind, ttl_seconds, rx, false, None).await
}

pub async fn start_server_with_shutdown(
    bind: SocketAddr,
    ttl_seconds: i64,
    shutdown: watch::Receiver<bool>,
    allow_loopback: bool,
    public_ip: Option<IpAddr>,
) -> Result<CntServerHandle> {
    let ttl = Duration::seconds(ttl_seconds.max(5));

    let peers: Arc<RwLock<HashMap<SocketAddr, PeerState>>> = Arc::new(RwLock::new(HashMap::new()));
    let logs: Arc<Mutex<VecDeque<String>>> = Arc::new(Mutex::new(VecDeque::new()));
    let rate_limits: Arc<RwLock<HashMap<IpAddr, RateLimitState>>> =
        Arc::new(RwLock::new(HashMap::new()));
    let conn_limit = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
    let listener = TcpListener::bind(bind).await?;

    let accept_peers = Arc::clone(&peers);
    let accept_conn_limit = Arc::clone(&conn_limit);
    let accept_rate_limits = Arc::clone(&rate_limits);
    let accept_logs = Arc::clone(&logs);
    let mut accept_shutdown = shutdown.clone();
    let allow_loopback_cfg = allow_loopback;
    let public_ip_cfg = public_ip;
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

            let (stream, remote_addr) = match accept_res {
                Ok(v) => v,
                Err(_) => break,
            };

            let peers = Arc::clone(&accept_peers);
            let rate_limits = Arc::clone(&accept_rate_limits);
            let logs = Arc::clone(&accept_logs);
            let permit = match Arc::clone(&accept_conn_limit).acquire_owned().await {
                Ok(p) => p,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let _permit = permit;
                let _ = handle_client(
                    stream,
                    remote_addr,
                    peers,
                    rate_limits,
                    logs,
                    ttl,
                    allow_loopback_cfg,
                    public_ip_cfg,
                )
                .await;
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

    Ok(CntServerHandle { peers, ttl, logs })
}

pub async fn run_server_with_shutdown(
    bind: SocketAddr,
    ttl_seconds: i64,
    mut shutdown: watch::Receiver<bool>,
    allow_loopback: bool,
    public_ip: Option<IpAddr>,
) -> Result<()> {
    let _handle =
        start_server_with_shutdown(bind, ttl_seconds, shutdown.clone(), allow_loopback, public_ip)
            .await?;

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
    remote_addr: SocketAddr,
    peers: Arc<RwLock<HashMap<SocketAddr, PeerState>>>,
    rate_limits: Arc<RwLock<HashMap<IpAddr, RateLimitState>>>,
    logs: Arc<Mutex<VecDeque<String>>>,
    ttl: Duration,
    allow_loopback: bool,
    public_ip: Option<IpAddr>,
) -> Result<()> {
    let msg: Message = read_message(&mut stream).await?;

    match msg {
        Message::Report(report) => {
            let now = Utc::now();

            let mut effective_addr = rewrite_192_168_to_public_ip(report.addr, public_ip);
            if is_unroutable_socket_addr(effective_addr) {
                let port = effective_addr.port();
                let remote_ip = remote_addr.ip();
                // If the reported address is unroutable (like 0.0.0.0 or 127.0.0.1),
                // we try to use the remote IP we observed, unless that's also unroutable.
                // However, if allow_loopback is true, we allow using the loopback IP.
                if port != 0 && (!is_unroutable_ip(remote_ip) || (allow_loopback && remote_ip.is_loopback())) {
                    effective_addr = rewrite_192_168_to_public_ip(SocketAddr::new(remote_ip, port), public_ip);
                }
            }

            // Never accept unroutable/self-referential addresses into the public directory.
            // This prevents accidental pollution of CNT World with 127.0.0.1 / RFC1918 / link-local.
            let allow_this_unroutable = allow_loopback && (effective_addr.ip().is_loopback() || is_unroutable_ip(effective_addr.ip()));
            if is_unroutable_socket_addr(effective_addr) && !allow_this_unroutable {
                push_log(
                    &logs,
                    format!(
                        "CNT: rejecting unroutable report from {} (effective_addr={})",
                        remote_addr, effective_addr
                    ),
                );
                write_message(
                    &mut stream,
                    &Message::Peers(PeersResponse {
                        requester_stable: false,
                        requester_effective_addr: effective_addr,
                        entries: build_peer_entries(&peers, ttl, false).await,
                    }),
                )
                .await?;
                return Ok(());
            }

            let remote_ip = remote_addr.ip();
            if is_rate_limited(&rate_limits, remote_ip, now).await {
                let requester_stable = {
                    let map = peers.read().await;
                    map.get(&effective_addr).map(|st| st.stable).unwrap_or(false)
                };
                let list = build_peer_entries(&peers, ttl, requester_stable).await;
                write_message(
                    &mut stream,
                    &Message::Peers(PeersResponse {
                        requester_stable,
                        requester_effective_addr: effective_addr,
                        entries: list,
                    }),
                )
                .await?;
                return Ok(());
            }

            // Prune first so "first client when CNT is empty" works even with stale entries.
            prune_expired(&peers, ttl).await;

            let requester_stable;
            {
                let mut map = peers.write().await;

                let allow_gossip = {
                    let had_stable = map.values().any(|st| st.reported && st.stable);
                    let was_stable = map.get(&effective_addr).map(|st| st.stable).unwrap_or(false);
                    was_stable || !had_stable
                };

                let (known_peers, connected_peers) = if allow_gossip {
                    (
                        report
                            .known_peers
                            .into_iter()
                            .take(MAX_GOSSIP_LIST_LEN)
                            .map(|a| rewrite_192_168_to_public_ip(a, public_ip))
                            .filter(|a| !is_unroutable_socket_addr(*a))
                            .collect::<Vec<_>>(),
                        report
                            .connected_peers
                            .into_iter()
                            .take(MAX_GOSSIP_LIST_LEN)
                            .map(|a| rewrite_192_168_to_public_ip(a, public_ip))
                            .filter(|a| !is_unroutable_socket_addr(*a))
                            .collect::<Vec<_>>(),
                    )
                } else {
                    (Vec::new(), Vec::new())
                };

                // Prevent unbounded memory growth from arbitrary addresses.
                if map.len() >= MAX_TRACKED_PEERS && !map.contains_key(&effective_addr) {
                    return Ok(());
                }

                // Stability is server-authoritative and based on server-measured uptime only.
                // Do not assign stable immediately on insert.
                let stable_on_insert = false;

                let mut should_infer_from_gossip = false;
                let mut inferred_known: Vec<SocketAddr> = Vec::new();
                let mut inferred_connected: Vec<SocketAddr> = Vec::new();

                {
                    let entry = map.entry(effective_addr).or_insert_with(|| PeerState {
                        first_seen: now,
                        last_seen: now,
                        stable: stable_on_insert,
                        reported: true,
                        upnp_enabled: report.upnp_enabled,
                        active_inferred: true,
                        known_peers: Vec::new(),
                        connected_peers: Vec::new(),
                    });

                    entry.reported = true;
                    entry.last_seen = now;
                    entry.upnp_enabled = report.upnp_enabled;

                    // Treat empty lists as presence-only so a client can query its stable status
                    // without wiping previously stored gossip.
                    if !(known_peers.is_empty() && connected_peers.is_empty()) {
                        entry.known_peers = known_peers;
                        entry.connected_peers = connected_peers;
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
                        if p == effective_addr {
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
                                upnp_enabled: false,
                                active_inferred: true,
                                known_peers: Vec::new(),
                                connected_peers: Vec::new(),
                            });
                    }

                    // Still insert inferred known peers for discovery, but do NOT refresh their TTL.
                    for p in inferred_known.into_iter() {
                        if p == effective_addr {
                            continue;
                        }

                        map.entry(p).or_insert(PeerState {
                            first_seen: now,
                            last_seen: now,
                            stable: false,
                            reported: false,
                            upnp_enabled: false,
                            active_inferred: false,
                            known_peers: Vec::new(),
                            connected_peers: Vec::new(),
                        });
                    }
                }

                elect_stable_if_needed(&mut map, now);

                requester_stable = map.get(&effective_addr).map(|st| st.stable).unwrap_or(false);
                push_log(
                    &logs,
                    format!(
                        "CNT: accepted report from {} (effective_addr={}), total_peers={}",
                        remote_addr,
                        effective_addr,
                        map.len()
                    ),
                );
            }

            let list = build_peer_entries(&peers, ttl, requester_stable).await;
            write_message(
                &mut stream,
                &Message::Peers(PeersResponse {
                    requester_stable,
                    requester_effective_addr: effective_addr,
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

    // Stable peers must be UPnP-enabled (eligible for inbound reachability).
    let any_eligible = map.values().any(|st| st.reported && st.upnp_enabled);
    if !any_eligible {
        for st in map.values_mut() {
            st.stable = false;
        }
        return;
    }

    // If we already have a stable peer that has reached the stable-after threshold,
    // keep it to avoid unnecessary churn.
    if map
        .values()
        .any(|st| {
            st.reported
                && st.upnp_enabled
                && st.stable
                && (now - st.first_seen) >= STABLE_AFTER
        })
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
            if !st.reported || !st.upnp_enabled {
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
            known_peers: if include_gossip {
                st.known_peers.clone()
            } else {
                Vec::new()
            },
            connected_peers: if include_gossip {
                st.connected_peers.clone()
            } else {
                Vec::new()
            },
        });
    }

    // Keep ordering stable across heartbeats. Sorting by expires_at/last_seen causes
    // the list to constantly reshuffle due to timing races.
    out.sort_by(|a, b| {
        b.first_seen
            .cmp(&a.first_seen)
            .then_with(|| a.addr.cmp(&b.addr))
    });
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
    timeout(
        IO_TIMEOUT,
        stream.write_u32_le(len),
    )
    .await??;
    timeout(
        IO_TIMEOUT,
        stream.write_all(&bytes),
    )
    .await??;
    timeout(IO_TIMEOUT, stream.flush()).await??;
    Ok(())
}

async fn read_message(stream: &mut TcpStream) -> Result<Message> {
    let len = timeout(IO_TIMEOUT, stream.read_u32_le()).await?? as usize;
    if len == 0 || len > MAX_MESSAGE_BYTES {
        return Err(anyhow::anyhow!("invalid message length"));
    }
    let mut buf = vec![0u8; len];
    timeout(
        IO_TIMEOUT,
        stream.read_exact(&mut buf),
    )
    .await??;
    Ok(bincode::deserialize::<Message>(&buf)?)
}
