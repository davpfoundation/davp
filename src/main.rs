use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use clap::{Parser, Subcommand};
use davp::modules::asset::create_proof_from_bytes;
use davp::modules::bootstrap::{report_and_get_peers, PeerReport};
use davp::modules::metadata::{AssetType, Metadata};
use davp::modules::network::{ping_peer, replicate_proof, run_node, NodeConfig, PeerConnections};
use davp::modules::storage::Storage;
use davp::modules::verification::verify_proof;
use davp::KeypairBytes;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Parser, Debug)]
#[command(name = "davp")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Keygen,

    Create {
        #[arg(long)]
        file: PathBuf,

        #[arg(long)]
        keypair_base64: String,

        #[arg(long, default_value = "other")]
        asset_type: String,

        #[arg(long, default_value_t = false)]
        ai_assisted: bool,

        #[arg(long)]
        description: Option<String>,

        #[arg(long)]
        tags: Option<Vec<String>>,

        #[arg(long)]
        parent_verification_id: Option<String>,

        #[arg(long, default_value = "davp_storage")]
        storage_dir: PathBuf,

        #[arg(long)]
        replicate_to: Option<Vec<SocketAddr>>,
    },

    Verify {
        #[arg(long)]
        verification_id: String,

        #[arg(long)]
        file: Option<PathBuf>,

        #[arg(long, default_value = "davp_storage")]
        storage_dir: PathBuf,
    },

    Node {
        #[arg(long)]
        bind: SocketAddr,

        #[arg(long, default_value = "davp_storage")]
        storage_dir: PathBuf,

        #[arg(long)]
        peers: Option<Vec<SocketAddr>>,

        #[arg(long)]
        bootstrap_server: Option<SocketAddr>,

        #[arg(long, default_value_t = 10)]
        max_peers: usize,
    },
}

fn parse_asset_type(s: &str) -> Result<AssetType> {
    match s.to_ascii_lowercase().as_str() {
        "text" => Ok(AssetType::Text),
        "code" => Ok(AssetType::Code),
        "image" => Ok(AssetType::Image),
        "video" => Ok(AssetType::Video),
        "other" => Ok(AssetType::Other),
        _ => Err(anyhow!("unknown asset_type")),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Keygen => {
            let keypair = KeypairBytes::generate();
            let pubkey = keypair.public_key_bytes()?;

            println!("keypair_base64={}", keypair.to_base64());
            println!("public_key_base64={}", STANDARD.encode(pubkey));
            Ok(())
        }
        Commands::Create {
            file,
            keypair_base64,
            asset_type,
            ai_assisted,
            description,
            tags,
            parent_verification_id,
            storage_dir,
            replicate_to,
        } => {
            let bytes = std::fs::read(file)?;
            let kp = KeypairBytes::from_base64(&keypair_base64)?;
            let at = parse_asset_type(&asset_type)?;
            let metadata = Metadata::new(tags, description, parent_verification_id);

            let proof = create_proof_from_bytes(&bytes, at, ai_assisted, metadata, &kp)?;

            let storage = Storage::new(storage_dir);
            storage.store_proof(&proof)?;

            if let Some(peers) = replicate_to {
                replicate_proof(&proof, &peers).await;
            }

            println!("verification_id={}", proof.verification_id);
            Ok(())
        }
        Commands::Verify {
            verification_id,
            file,
            storage_dir,
        } => {
            let storage = Storage::new(storage_dir);
            let proof = storage.retrieve_proof(&verification_id)?;

            let content = match file {
                Some(path) => Some(std::fs::read(path)?),
                None => None,
            };

            verify_proof(&proof, content.as_deref())?;
            println!("valid");
            Ok(())
        }
        Commands::Node {
            bind,
            storage_dir,
            peers,
            bootstrap_server,
            max_peers,
        } => {
            let storage = Storage::new(storage_dir);
            let peers_arc: Arc<RwLock<Vec<SocketAddr>>> = Arc::new(RwLock::new(peers.unwrap_or_default()));
            let peer_graph: Arc<RwLock<HashMap<SocketAddr, Vec<SocketAddr>>>> =
                Arc::new(RwLock::new(HashMap::new()));

            if let Some(server) = bootstrap_server {
                let peers_for_task = Arc::clone(&peers_arc);
                let peer_graph_for_task = Arc::clone(&peer_graph);
                tokio::spawn(async move {
                    let mut tick = tokio::time::interval(std::time::Duration::from_millis(100));
                    let mut cnt_report_tick = tokio::time::interval(std::time::Duration::from_secs(5));
                    loop {
                        tokio::select! {
                            _ = tick.tick() => {
                                // peer gossip fast path
                                let snapshot = peers_for_task.read().await.clone();
                                let connections_snapshot: Vec<PeerConnections> = {
                                    let g = peer_graph_for_task.read().await;
                                    g.iter()
                                        .map(|(addr, connected_peers)| PeerConnections {
                                            addr: *addr,
                                            connected_peers: connected_peers.clone(),
                                        })
                                        .collect()
                                };

                                let mut join_set = tokio::task::JoinSet::new();
                                for peer in snapshot.iter().copied() {
                                    if peer == bind {
                                        continue;
                                    }
                                    let known = snapshot.clone();
                                    let conn = connections_snapshot.clone();
                                    join_set.spawn(async move { (peer, ping_peer(peer, bind, known, conn).await) });
                                }

                                let mut connected = Vec::new();
                                let mut dead = Vec::new();
                                let mut any_connected = false;
                                let mut newly_discovered = Vec::new();
                                let mut conn_updates: Vec<PeerConnections> = Vec::new();

                                while let Some(join_res) = join_set.join_next().await {
                                    match join_res {
                                        Ok((peer, Ok((peer_list, conn_graph)))) => {
                                            connected.push(peer);
                                            any_connected = true;

                                            for p in peer_list {
                                                if p == bind {
                                                    continue;
                                                }
                                                if !newly_discovered.contains(&p) {
                                                    newly_discovered.push(p);
                                                }
                                            }

                                            if !conn_graph.is_empty() {
                                                conn_updates.extend(conn_graph);
                                            }
                                        }
                                        Ok((peer, Err(_))) => {
                                            dead.push(peer);
                                        }
                                        Err(_) => {}
                                    }
                                }

                                if !conn_updates.is_empty() {
                                    let mut g = peer_graph_for_task.write().await;
                                    for pc in conn_updates {
                                        let entry = g.entry(pc.addr).or_default();
                                        for p in pc.connected_peers {
                                            if !entry.contains(&p) {
                                                entry.push(p);
                                            }
                                        }
                                    }
                                }

                                if !dead.is_empty() {
                                    let mut set = peers_for_task.write().await;
                                    set.retain(|p| !dead.contains(p));
                                    let mut g = peer_graph_for_task.write().await;
                                    for d in dead.iter().copied() {
                                        g.remove(&d);
                                    }
                                    for peers in g.values_mut() {
                                        peers.retain(|p| !dead.contains(p));
                                    }
                                }

                                if !newly_discovered.is_empty() {
                                    let mut set = peers_for_task.write().await;
                                    for p in newly_discovered {
                                        if !set.contains(&p) {
                                            set.push(p);
                                        }
                                    }
                                }

                                {
                                    let mut g = peer_graph_for_task.write().await;
                                    g.insert(bind, connected.clone());
                                }
                            }
                            _ = cnt_report_tick.tick() => {
                                // report to CNT every 5s
                                let snapshot = peers_for_task.read().await.clone();
                                let connections_snapshot: Vec<PeerConnections> = {
                                    let g = peer_graph_for_task.read().await;
                                    g.iter()
                                        .map(|(addr, connected_peers)| PeerConnections {
                                            addr: *addr,
                                            connected_peers: connected_peers.clone(),
                                        })
                                        .collect()
                                };

                                let connected = {
                                    let g = peer_graph_for_task.read().await;
                                    g.get(&bind).cloned().unwrap_or_default()
                                };

                                let report = PeerReport {
                                    addr: bind,
                                    known_peers: snapshot,
                                    connected_peers: connected,
                                };

                                if let Ok(entries) = report_and_get_peers(server, report).await {
                                    let mut set = peers_for_task.write().await;
                                    let now = chrono::Utc::now();
                                    for e in entries {
                                        let expires_in = (e.expires_at - now).num_seconds();
                                        println!(
                                            "bootstrap_peer={} last_seen={} expires_in={}s connected={} known={}",
                                            e.addr,
                                            e.last_seen.to_rfc3339(),
                                            expires_in,
                                            e.connected_peers.len(),
                                            e.known_peers.len()
                                        );

                                        if e.addr == bind {
                                            continue;
                                        }
                                        if !set.contains(&e.addr) {
                                            set.push(e.addr);
                                        }
                                    }
                                }
                            }
                        }
                    }
                });
            }

            let config = NodeConfig {
                bind_addr: bind,
                peers: peers_arc,
                peer_graph,
            };

            run_node(storage, config).await
        }
    }
}
