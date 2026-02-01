use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use clap::{Parser, Subcommand};
use davp::modules::asset::create_proof_from_bytes;
use davp::modules::bootstrap::{report_and_get_peers, PeerReport};
use davp::modules::certification::PublishedProof;
use davp::modules::issuer_certificate::{
    DEFAULT_CERTS_URL, IssuerCertificationStatus, fetch_certificate_bundle, fetch_certificates,
    parse_certificates_json, verify_issuer_certificate,
};
use davp::modules::metadata::{AssetType, Metadata};
use davp::modules::network::{ping_peer, replicate_published_proof, replicate_proof, run_node, NodeConfig, PeerConnections};
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

        #[arg(long)]
        issuer_certificate_id: Option<String>,

        #[arg(long, default_value = "davp_storage")]
        storage_dir: PathBuf,

        #[arg(long)]
        replicate_to: Option<Vec<SocketAddr>>,
    },

    Verify {
        #[arg(long, alias = "verification_id")]
        verification_id: String,

        #[arg(long, alias = "file")]
        file: Option<PathBuf>,

        #[arg(long, alias = "ca_public_key_base64")]
        ca_public_key_base64: Option<String>,

        #[arg(long, alias = "ca_keypair_base64")]
        ca_keypair_base64: Option<String>,

        #[arg(long, alias = "certs_url", default_value = DEFAULT_CERTS_URL)]
        certs_url: String,

        #[arg(long, alias = "certs_file")]
        certs_file: Option<PathBuf>,

        #[arg(long, alias = "certs_json")]
        certs_json: Option<String>,

        #[arg(long, alias = "certs_json_base64")]
        certs_json_base64: Option<String>,

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
            issuer_certificate_id,
            storage_dir,
            replicate_to,
        } => {
            let bytes = std::fs::read(file)?;
            let kp = KeypairBytes::from_base64(&keypair_base64)?;
            let at = parse_asset_type(&asset_type)?;
            let metadata = Metadata::new(tags, description, parent_verification_id);

            let proof = create_proof_from_bytes(&bytes, at, ai_assisted, metadata, &kp)?;

            let storage = Storage::new(storage_dir);
            let published = PublishedProof {
                proof: proof.clone(),
                issuer_certificate_id,
            };
            storage.store_published_proof(&published)?;

            if let Some(peers) = replicate_to {
                if published.issuer_certificate_id.is_some() {
                    replicate_published_proof(&published, &peers).await;
                } else {
                    replicate_proof(&proof, &peers).await;
                }
            }

            println!("verification_id={}", proof.verification_id);
            println!(
                "creator_public_key_base64={}",
                STANDARD.encode(proof.creator_public_key)
            );
            println!("signature_base64={}", STANDARD.encode(proof.signature.0));
            if let Some(id) = published.issuer_certificate_id.as_deref() {
                println!("issuer_certificate_id={}", id);
            }
            Ok(())
        }
        Commands::Verify {
            verification_id,
            file,
            ca_public_key_base64,
            ca_keypair_base64,
            certs_url,
            certs_file,
            certs_json,
            certs_json_base64,
            storage_dir,
        } => {
            let storage = Storage::new(storage_dir);
            let published = storage.retrieve_published_proof(&verification_id)?;

            let content = match file {
                Some(path) => Some(std::fs::read(path)?),
                None => None,
            };

            verify_proof(&published.proof, content.as_deref())?;
            println!("valid");
            println!("verification_id={}", published.proof.verification_id);
            println!(
                "creator_public_key_base64={}",
                STANDARD.encode(published.proof.creator_public_key)
            );
            println!(
                "signature_base64={}",
                STANDARD.encode(published.proof.signature.0)
            );

            let debug_cert = std::env::var("DAVP_CERT_DEBUG")
                .ok()
                .is_some_and(|v| v.trim() == "1" || v.trim().eq_ignore_ascii_case("true"));
            match published.issuer_certificate_id.as_deref() {
                Some(id) => {
                    println!("issuer_certificate_id={}", id);

                    // CA key source precedence:
                    // 1) CLI/env override
                    // 2) cert bundle ca_public_key_base64
                    let ca_pk_override_b64 = ca_public_key_base64
                        .as_deref()
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(|s| s.to_string())
                        .or_else(|| std::env::var("DAVP_CA_PUBLIC_KEY_BASE64").ok());

                    let ca_pk: Option<[u8; 32]> = if let Some(b64) = ca_pk_override_b64 {
                        let ca_pk_bytes = match STANDARD.decode(b64.trim()) {
                            Ok(b) => b,
                            Err(e) => {
                                if debug_cert {
                                    eprintln!("issuer_cert_debug: CA public key base64 decode failed: {}", e);
                                }
                                println!("unverified issuer");
                                return Ok(());
                            }
                        };
                        let ca_pk_len = ca_pk_bytes.len();
                        match ca_pk_bytes.as_slice().try_into() {
                            Ok(a) => Some(a),
                            Err(_) => {
                                if debug_cert {
                                    eprintln!(
                                        "issuer_cert_debug: CA public key must be 32 bytes, got {} bytes",
                                        ca_pk_len
                                    );
                                }
                                None
                            }
                        }
                    } else {
                        let bundle = match fetch_certificate_bundle(&certs_url).await {
                            Ok(b) => b,
                            Err(e) => {
                                if debug_cert {
                                    eprintln!("issuer_cert_debug: failed to fetch cert bundle: {:#}", e);
                                }
                                println!("unverified issuer");
                                return Ok(());
                            }
                        };

                        if debug_cert {
                            eprintln!(
                                "issuer_cert_debug: bundle.ca_public_key_base64 present={}",
                                bundle.ca_public_key_base64.as_deref().map(str::trim).filter(|s| !s.is_empty()).is_some()
                            );
                        }

                        match bundle.ca_public_key_base64.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                            Some(b64) => {
                                match STANDARD.decode(b64) {
                                    Ok(bytes) => bytes.as_slice().try_into().ok(),
                                    Err(e) => {
                                        if debug_cert {
                                            eprintln!("issuer_cert_debug: bundle CA public key base64 decode failed: {}", e);
                                        }
                                        None
                                    }
                                }
                            }
                            None => None,
                        }
                    };

                    let Some(ca_pk) = ca_pk else {
                        if debug_cert {
                            eprintln!("issuer_cert_debug: no CA public key available (need bundle.ca_public_key_base64 or override)");
                        }
                        println!("unverified issuer");
                        return Ok(());
                    };

                        let status = (|| async {
                            let certs = if let Some(b64) = &certs_json_base64 {
                                if debug_cert {
                                    eprintln!("issuer_cert_debug: loading certificates from --certs_json_base64");
                                }
                                let bytes = STANDARD.decode(b64.trim()).map_err(|e| {
                                    anyhow!("failed to base64-decode certs_json_base64: {}", e)
                                })?;
                                let json = String::from_utf8(bytes)
                                    .map_err(|e| anyhow!("certs_json_base64 is not valid utf8: {}", e))?;
                                parse_certificates_json(&json)?
                            } else if let Some(json) = &certs_json {
                                if debug_cert {
                                    eprintln!("issuer_cert_debug: loading certificates from --certs_json (inline)");
                                }
                                parse_certificates_json(json)?
                            } else if let Some(path) = &certs_file {
                                if debug_cert {
                                    eprintln!(
                                        "issuer_cert_debug: attempting to read certs_file {}",
                                        path.to_string_lossy()
                                    );
                                    if let Ok(abs) = std::fs::canonicalize(path) {
                                        eprintln!(
                                            "issuer_cert_debug: certs_file canonical path {}",
                                            abs.to_string_lossy()
                                        );
                                    }
                                }
                                let json = std::fs::read_to_string(path).map_err(|e| {
                                    anyhow!(
                                        "failed to read certs_file {}: {}",
                                        path.to_string_lossy(),
                                        e
                                    )
                                })?;
                                parse_certificates_json(&json)?
                            } else {
                                fetch_certificates(&certs_url).await?
                            };
                            if debug_cert {
                                if certs_json_base64.is_some() {
                                    eprintln!("issuer_cert_debug: certificates source=certs_json_base64");
                                } else if certs_json.is_some() {
                                    eprintln!("issuer_cert_debug: certificates source=certs_json");
                                } else if let Some(path) = &certs_file {
                                    eprintln!("issuer_cert_debug: loaded certificates from file {}", path.to_string_lossy());
                                } else {
                                    eprintln!("issuer_cert_debug: fetched certificates from {}", certs_url);
                                }
                                eprintln!("issuer_cert_debug: certificate count={}", certs.len());
                                for (i, c) in certs.iter().take(5).enumerate() {
                                    eprintln!("issuer_cert_debug: cert[{}].certificate_id={}", i, c.certificate_id);
                                }
                            }
                            let found = certs
                                .iter()
                                .any(|c| c.certificate_id.trim() == id.trim());

                            if debug_cert {
                                if let Some(cert) = certs.iter().find(|c| c.certificate_id.trim() == id.trim()) {
                                    if let Some(kp_b64) = ca_keypair_base64
                                        .as_deref()
                                        .map(str::trim)
                                        .filter(|s| !s.is_empty())
                                        .map(|s| s.to_string())
                                        .or_else(|| std::env::var("DAVP_CA_KEYPAIR_BASE64").ok())
                                    {
                                        use davp::modules::issuer_certificate::{
                                            issuer_certificate_signing_payload_bytes,
                                            issuer_certificate_signing_payload_bytes_legacy,
                                        };
                                        use davp::modules::signature::{sign, KeypairBytes};

                                        match KeypairBytes::from_base64(&kp_b64) {
                                            Ok(kp) => {
                                                if let Ok(pk) = kp.public_key_bytes() {
                                                    eprintln!(
                                                        "issuer_cert_debug: CA public key derived from keypair = {}",
                                                        STANDARD.encode(pk)
                                                    );
                                                }
                                                let expected_current = issuer_certificate_signing_payload_bytes(cert)
                                                    .and_then(|bytes| sign(&bytes, &kp))
                                                    .map(|sig| STANDARD.encode(sig.0));
                                                let expected_legacy = issuer_certificate_signing_payload_bytes_legacy(cert)
                                                    .and_then(|bytes| sign(&bytes, &kp))
                                                    .map(|sig| STANDARD.encode(sig.0));

                                                let cert_sig = cert.ca_signature.trim();
                                                let matches_current = expected_current.as_deref().is_ok_and(|s| s == cert_sig);
                                                let matches_legacy = expected_legacy.as_deref().is_ok_and(|s| s == cert_sig);

                                                if matches_current {
                                                    eprintln!("issuer_cert_debug: ca_signature matches recomputed signature (current payload format)");
                                                }
                                                if matches_legacy {
                                                    eprintln!("issuer_cert_debug: ca_signature matches recomputed signature (legacy payload format)");
                                                }

                                                if !matches_current && !matches_legacy {
                                                    eprintln!("issuer_cert_debug: ca_signature MISMATCH");
                                                    if let Ok(s) = &expected_current {
                                                        eprintln!("issuer_cert_debug: expected_ca_signature_current={}", s);
                                                    }
                                                    if let Ok(s) = &expected_legacy {
                                                        eprintln!("issuer_cert_debug: expected_ca_signature_legacy={}", s);
                                                    }
                                                    eprintln!("issuer_cert_debug: cert_ca_signature={}", cert_sig);
                                                }
                                            }
                                            Err(e) => {
                                                eprintln!("issuer_cert_debug: invalid CA keypair base64: {:#}", e);
                                            }
                                        }
                                    }
                                }
                            }

                            let res = verify_issuer_certificate(
                                &certs,
                                id,
                                &published.proof.creator_public_key,
                                &ca_pk,
                                chrono::Utc::now(),
                            );
                            Ok::<(bool, IssuerCertificationStatus), anyhow::Error>((found, res?))
                        })()
                        .await;

                        match status {
                            Ok((_, IssuerCertificationStatus::Certified { organization_name })) => {
                                println!("certified issuer");
                                println!("organization_name={}", organization_name);
                            }
                            Ok((found, IssuerCertificationStatus::Unverified)) => {
                                if debug_cert {
                                    if found {
                                        eprintln!("issuer_cert_debug: certificate found but issuer_public_key does not match proof.creator_public_key");
                                    } else {
                                        eprintln!("issuer_cert_debug: certificate_id not found in certs.json (possible CDN cache / wrong URL / cert not published)");
                                    }
                                }
                                println!("unverified issuer");
                            }
                            Err(e) => {
                                if debug_cert {
                                    eprintln!("issuer_cert_debug: certificate verification failed: {:#}", e);
                                }
                                println!("unverified issuer");
                            }
                        }
                }
                None => {
                    println!("unverified issuer");
                }
            }
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
                    let mut cnt_report_tick = tokio::time::interval(std::time::Duration::from_secs(2));
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
