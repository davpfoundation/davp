use anyhow::Result;
use base64::Engine as _;
use davp::modules::asset::create_proof_from_bytes;
use davp::modules::hash::blake3_hash_bytes;
use davp::modules::bootstrap::{report_and_get_peers, PeerEntry, PeerReport};
use davp::modules::metadata::{AssetType, Metadata};
use davp::modules::network::{
    fetch_ids_by_hash_from_peers, fetch_proof_from_peers, replicate_proof,
    run_node_with_shutdown, NodeConfig, PeerConnections, ping_peer,
};
use davp_bootstrap_server::run_server_with_shutdown;
use davp::modules::storage::Storage;
use davp::modules::verification::verify_proof;
use davp::KeypairBytes;
use eframe::egui;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::sync::watch;
use tokio::sync::RwLock;

fn main() -> Result<()> {
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size(egui::vec2(980.0, 720.0)),
        ..Default::default()
    };
    eframe::run_native(
        "davp",
        native_options,
        Box::new(|_cc| Box::new(DavpApp::default())),
    )
    .map_err(|e| anyhow::anyhow!(e.to_string()))?;

    Ok(())
}

struct DavpApp {
    tab: Tab,

    storage_dir: String,

    peers: String,

    cnt_server: String,
    start_cnt_server: bool,
    cnt_bind: String,
    cnt_ttl_seconds: i64,
    cnt_enabled: bool,

    node_bind: String,
    max_peers: usize,
    run_node_enabled: bool,

    networking_started: bool,

    peers_arc: Arc<RwLock<Vec<SocketAddr>>>,
    peer_graph: Arc<RwLock<HashMap<SocketAddr, Vec<SocketAddr>>>>,
    bootstrap_entries: Arc<Mutex<Vec<PeerEntry>>>,
    reachable_peers: Arc<Mutex<Vec<SocketAddr>>>,
    tasks_started: bool,

    node_shutdown_tx: Option<watch::Sender<bool>>,
    sync_shutdown_tx: Option<watch::Sender<bool>>,
    cnt_server_shutdown_tx: Option<watch::Sender<bool>>,
    cnt_enabled_tx: Option<watch::Sender<bool>>,

    rt: tokio::runtime::Runtime,

    // key management
    keypair_base64: String,
    public_key_base64: String,

    // create
    create_file_path: String,
    create_asset_type: String,
    create_ai_assisted: bool,
    create_description: String,
    create_tags: String,
    create_parent_verification_id: String,
    created_verification_id: String,

    // verify
    verify_verification_id: String,
    verify_file_path: String,
    verify_status: String,

    last_error: String,

    manual_connect_open: bool,
    manual_connect_addr: String,
}

impl Default for DavpApp {
    fn default() -> Self {
        let peers_arc: Arc<RwLock<Vec<SocketAddr>>> = Arc::new(RwLock::new(Vec::new()));
        let peer_graph: Arc<RwLock<HashMap<SocketAddr, Vec<SocketAddr>>>> = Arc::new(RwLock::new(HashMap::new()));
        Self {
            tab: Tab::default(),
            storage_dir: "davp_storage".to_string(),
            peers: "".to_string(),
            cnt_server: "127.0.0.1:9100".to_string(),
            start_cnt_server: true,
            cnt_bind: "127.0.0.1:9100".to_string(),
            cnt_ttl_seconds: 5,
            cnt_enabled: true,
            node_bind: "127.0.0.1:9002".to_string(),
            max_peers: 10,
            run_node_enabled: true,
            networking_started: false,
            peers_arc: Arc::clone(&peers_arc),
            peer_graph: Arc::clone(&peer_graph),
            bootstrap_entries: Arc::new(Mutex::new(Vec::new())),
            reachable_peers: Arc::new(Mutex::new(Vec::new())),
            tasks_started: false,
            node_shutdown_tx: None,
            sync_shutdown_tx: None,
            cnt_server_shutdown_tx: None,
            cnt_enabled_tx: None,
            rt: tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("tokio runtime"),

            keypair_base64: String::new(),
            public_key_base64: String::new(),

            create_file_path: String::new(),
            create_asset_type: "other".to_string(),
            create_ai_assisted: false,
            create_description: String::new(),
            create_tags: String::new(),
            create_parent_verification_id: String::new(),
            created_verification_id: String::new(),

            verify_verification_id: String::new(),
            verify_file_path: String::new(),
            verify_status: String::new(),

            last_error: String::new(),

            manual_connect_open: false,
            manual_connect_addr: String::new(),
        }
    }
}

#[derive(Default, Clone, Copy, PartialEq, Eq)]
enum Tab {
    #[default]
    Create,
    Verify,
    Keygen,
}

impl eframe::App for DavpApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.tab, Tab::Create, "Create");
                ui.selectable_value(&mut self.tab, Tab::Verify, "Verify");
                ui.selectable_value(&mut self.tab, Tab::Keygen, "Keygen");
            });

            ui.separator();
            ui.horizontal(|ui| {
                if !self.networking_started {
                    if ui.button("Start networking").clicked() {
                        self.networking_started = true;
                    }
                } else {
                    if ui.button("Disconnect network").clicked() {
                        self.stop_network();
                    }
                }
                ui.label(format!("Network: {}", if self.networking_started { "running" } else { "stopped" }));

                if self.networking_started {
                    let before = self.cnt_enabled;
                    ui.checkbox(&mut self.cnt_enabled, "Use CNT tracker");
                    if self.cnt_enabled != before {
                        if let Some(tx) = &self.cnt_enabled_tx {
                            let _ = tx.send(self.cnt_enabled);
                        }

                        if !self.cnt_enabled {
                            if let Ok(mut g) = self.bootstrap_entries.lock() {
                                g.clear();
                            }
                        }
                    }
                }

                if ui.button("Connect manually").clicked() {
                    self.manual_connect_open = true;
                }
            });

            egui::CollapsingHeader::new("Network settings")
                .default_open(true)
                .show(ui, |ui| {
                    ui.add_enabled_ui(!self.networking_started, |ui| {
                        ui.horizontal(|ui| {
                            ui.label("Node bind:");
                            ui.text_edit_singleline(&mut self.node_bind);
                            ui.label("Max peers:");
                            ui.add(egui::DragValue::new(&mut self.max_peers).clamp_range(1..=100));
                            ui.checkbox(&mut self.run_node_enabled, "Run node");
                        });

                        ui.horizontal(|ui| {
                            ui.label("CNT server (tracker):");
                            ui.text_edit_singleline(&mut self.cnt_server);
                        });

                        ui.horizontal(|ui| {
                            ui.label("Local CNT server:");
                            ui.label("Bind:");
                            ui.text_edit_singleline(&mut self.cnt_bind);
                            ui.label("TTL (s):");
                            ui.add(egui::DragValue::new(&mut self.cnt_ttl_seconds).clamp_range(5..=600));
                        });

                        ui.horizontal(|ui| {
                            ui.checkbox(&mut self.cnt_enabled, "Use CNT tracker (optional)");
                        });

                        ui.horizontal(|ui| {
                            ui.label("Manual seed peers (comma host:port):");
                            ui.text_edit_singleline(&mut self.peers);
                            if ui.button("Apply").clicked() {
                                match parse_peers(&self.peers) {
                                    Ok(list) => {
                                        let peers_arc = Arc::clone(&self.peers_arc);
                                        let _ = self.rt.block_on(async move {
                                            *peers_arc.write().await = list;
                                        });
                                    }
                                    Err(e) => self.last_error = e,
                                }
                            }
                            if ui.button("Sync").clicked() {
                                let peers_arc = Arc::clone(&self.peers_arc);
                                let snapshot = self
                                    .rt
                                    .block_on(async move { peers_arc.read().await.clone() });
                                self.peers = snapshot
                                    .iter()
                                    .map(|p| p.to_string())
                                    .collect::<Vec<_>>()
                                    .join(",");
                            }
                        });
                    });
                });

            egui::CollapsingHeader::new("Storage settings")
                .default_open(false)
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label("Storage dir:");
                        ui.text_edit_singleline(&mut self.storage_dir);
                        if ui.button("Browse").clicked() {
                            if let Some(path) = rfd::FileDialog::new().pick_folder() {
                                self.storage_dir = path.to_string_lossy().to_string();
                            }
                        }
                    });
                });
        });

        let mut manual_connect_do_connect = false;
        let mut manual_connect_do_cancel = false;
        if self.manual_connect_open {
            egui::Window::new("Connect manually")
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.label("Peer address (host:port):");
                    ui.text_edit_singleline(&mut self.manual_connect_addr);

                    ui.horizontal(|ui| {
                        if ui.button("Connect").clicked() {
                            manual_connect_do_connect = true;
                        }
                        if ui.button("Cancel").clicked() {
                            manual_connect_do_cancel = true;
                        }
                    });
                });
        }

        if manual_connect_do_connect {
            match self.connect_manual_peer() {
                Ok(()) => {
                    self.manual_connect_addr.clear();
                    self.manual_connect_open = false;
                }
                Err(e) => self.last_error = e,
            }
        }

        if manual_connect_do_cancel {
            self.manual_connect_open = false;
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            if self.networking_started {
                self.ensure_background_tasks();
            }

            let known_peers_snapshot = {
                let peers_arc = Arc::clone(&self.peers_arc);
                self.rt
                    .block_on(async move { peers_arc.read().await.clone() })
            };

            let graph_snapshot = {
                let peer_graph = Arc::clone(&self.peer_graph);
                self.rt
                    .block_on(async move { peer_graph.read().await.clone() })
            };
            let reachable_snapshot = self
                .reachable_peers
                .lock()
                .map(|g| g.clone())
                .unwrap_or_default();

            let entries = self
                .bootstrap_entries
                .lock()
                .map(|g| g.clone())
                .unwrap_or_default();

            ui.separator();
            ui.horizontal(|ui| {
                ui.label(format!("Known peers: {}", known_peers_snapshot.len()));
                ui.label(format!("Reachable peers: {}", reachable_snapshot.len()));
                ui.label(format!("CNT peers: {}", entries.len()));
                ui.label(format!("CNT tracker: {}", if self.cnt_enabled { "enabled" } else { "disabled" }));
            });

            egui::CollapsingHeader::new("Reachable peers (ping OK)")
                .default_open(true)
                .show(ui, |ui| {
                    for p in reachable_snapshot {
                        ui.monospace(p.to_string());
                    }
                });

            egui::CollapsingHeader::new("Known peers (cached list)")
                .default_open(false)
                .show(ui, |ui| {
                    for p in known_peers_snapshot {
                        ui.monospace(p.to_string());
                    }
                });

            egui::CollapsingHeader::new("Connection graph (gossip)")
                .default_open(false)
                .show(ui, |ui| {
                    let mut keys: Vec<_> = graph_snapshot.keys().copied().collect();
                    keys.sort_by_key(|k| k.to_string());
                    for k in keys {
                        let mut peers = graph_snapshot.get(&k).cloned().unwrap_or_default();
                        peers.sort_by_key(|p| p.to_string());
                        ui.monospace(format!(
                            "{} -> {}",
                            k,
                            peers
                                .iter()
                                .map(|p| p.to_string())
                                .collect::<Vec<_>>()
                                .join(",")
                        ));
                    }
                });

            if !entries.is_empty() {
                egui::CollapsingHeader::new("CNT peers (tracker list)")
                    .default_open(false)
                    .show(ui, |ui| {
                        let now = chrono::Utc::now();
                        for e in entries {
                            let expires_in = (e.expires_at - now).num_seconds();
                            ui.monospace(format!(
                                "{} last_seen={} expires_in={}s reported_connected={} reported_known={} ",
                                e.addr,
                                e.last_seen.to_rfc3339(),
                                expires_in,
                                e.connected_peers.len(),
                                e.known_peers.len()
                            ));
                        }
                    });
            }

            if !self.last_error.is_empty() {
                ui.add_space(4.0);
                ui.colored_label(egui::Color32::RED, &self.last_error);
                if ui.button("Clear error").clicked() {
                    self.last_error.clear();
                }
                ui.separator();
            }

            match self.tab {
                Tab::Create => self.ui_create(ui),
                Tab::Verify => self.ui_verify(ui),
                Tab::Keygen => self.ui_keygen(ui),
            }
        });
    }
}

impl DavpApp {
    fn stop_cnt_server(&mut self) {
        if let Some(tx) = self.cnt_server_shutdown_tx.take() {
            let _ = tx.send(true);
        }
    }

    fn connect_manual_peer(&mut self) -> std::result::Result<(), String> {
        let addr: SocketAddr = self
            .manual_connect_addr
            .trim()
            .parse()
            .map_err(|_| "invalid peer address".to_string())?;

        let bind: SocketAddr = self
            .node_bind
            .trim()
            .parse()
            .map_err(|_| "invalid node bind".to_string())?;

        let peers_arc = Arc::clone(&self.peers_arc);
        let peer_graph = Arc::clone(&self.peer_graph);

        let ping_res = self.rt.block_on(async move {
            {
                let mut peers = peers_arc.write().await;
                if !peers.contains(&addr) {
                    peers.push(addr);
                }
            }

            let snapshot = peers_arc.read().await.clone();
            let connections_snapshot: Vec<PeerConnections> = {
                let g = peer_graph.read().await;
                g.iter()
                    .map(|(addr, connected_peers)| PeerConnections {
                        addr: *addr,
                        connected_peers: connected_peers.clone(),
                    })
                    .collect()
            };

            ping_peer(addr, bind, snapshot, connections_snapshot).await
        });

        let (peer_list, conn_graph) = ping_res
            .map_err(|_| "could not reach peer (ping failed)".to_string())?;

        if !peer_list.is_empty() {
            let peers_arc = Arc::clone(&self.peers_arc);
            let _ = self.rt.block_on(async move {
                let mut peers = peers_arc.write().await;
                for p in peer_list {
                    if p == bind {
                        continue;
                    }
                    if !peers.contains(&p) {
                        peers.push(p);
                    }
                }
            });
        }

        if !conn_graph.is_empty() {
            let peer_graph = Arc::clone(&self.peer_graph);
            let _ = self.rt.block_on(async move {
                let mut g = peer_graph.write().await;
                for pc in conn_graph {
                    let entry = g.entry(pc.addr).or_default();
                    for p in pc.connected_peers {
                        if !entry.contains(&p) {
                            entry.push(p);
                        }
                    }
                }
            });
        }

        if let Ok(mut g) = self.reachable_peers.lock() {
            if !g.contains(&addr) {
                g.push(addr);
            }
        }

        let peers_arc = Arc::clone(&self.peers_arc);
        let snapshot = self
            .rt
            .block_on(async move { peers_arc.read().await.clone() });
        self.peers = snapshot
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",");

        Ok(())
    }

    fn stop_network(&mut self) {
        if let Some(tx) = self.sync_shutdown_tx.take() {
            let _ = tx.send(true);
        }
        if let Some(tx) = self.node_shutdown_tx.take() {
            let _ = tx.send(true);
        }

        if let Some(tx) = self.cnt_enabled_tx.take() {
            let _ = tx.send(false);
        }

        if let Some(tx) = self.cnt_server_shutdown_tx.take() {
            let _ = tx.send(true);
        }

        self.tasks_started = false;
        self.networking_started = false;

        if let Ok(mut g) = self.bootstrap_entries.lock() {
            g.clear();
        }
        if let Ok(mut g) = self.reachable_peers.lock() {
            g.clear();
        }
    }

    fn ensure_background_tasks(&mut self) {
        if self.tasks_started {
            return;
        }

        if !self.networking_started {
            return;
        }

        let bind: SocketAddr = match self.node_bind.parse() {
            Ok(v) => v,
            Err(_) => return,
        };

        let peers_arc = Arc::clone(&self.peers_arc);
        let peer_graph = Arc::clone(&self.peer_graph);
        let bootstrap_entries = Arc::clone(&self.bootstrap_entries);
        let reachable_peers = Arc::clone(&self.reachable_peers);

        if self.start_cnt_server {
            let cnt_bind: SocketAddr = match self.cnt_bind.parse() {
                Ok(v) => v,
                Err(_) => return,
            };
            let ttl = self.cnt_ttl_seconds;

            let (cnt_server_shutdown_tx, cnt_server_shutdown_rx) = watch::channel(false);
            self.cnt_server_shutdown_tx = Some(cnt_server_shutdown_tx);
            self.rt.spawn(async move {
                let _ = run_server_with_shutdown(cnt_bind, ttl, cnt_server_shutdown_rx).await;
            });
        }

        let cnt_server: SocketAddr = match self.cnt_server.parse() {
            Ok(v) => v,
            Err(_) => return,
        };
        let max_peers = self.max_peers;

        let (sync_shutdown_tx, mut sync_shutdown_rx) = watch::channel(false);
        self.sync_shutdown_tx = Some(sync_shutdown_tx);

        let (node_shutdown_tx, node_shutdown_rx) = watch::channel(false);
        self.node_shutdown_tx = Some(node_shutdown_tx);

        let (cnt_enabled_tx, cnt_enabled_rx) = watch::channel(self.cnt_enabled);
        self.cnt_enabled_tx = Some(cnt_enabled_tx);

        if self.run_node_enabled {
            let storage = Storage::new(self.storage_dir.clone());
            let config = NodeConfig {
                bind_addr: bind,
                peers: Arc::clone(&peers_arc),
                peer_graph: Arc::clone(&peer_graph),
            };

            self.rt.spawn(async move {
                let _ = run_node_with_shutdown(storage, config, node_shutdown_rx).await;
            });
        }

        self.rt.spawn(async move {
            let cnt_enabled = *cnt_enabled_rx.borrow();
            let _ = sync_network_once(
                bind,
                max_peers,
                Arc::clone(&peers_arc),
                Arc::clone(&peer_graph),
                cnt_server,
                Arc::clone(&bootstrap_entries),
                Arc::clone(&reachable_peers),
                cnt_enabled,
                false, // cnt_report_only
            )
            .await;

            let mut tick = tokio::time::interval(std::time::Duration::from_millis(100));
            let mut cnt_report_tick = tokio::time::interval(std::time::Duration::from_secs(5));
            loop {
                if *sync_shutdown_rx.borrow() {
                    break;
                }

                tokio::select! {
                    _ = sync_shutdown_rx.changed() => {
                        continue;
                    }
                    _ = tick.tick() => {
                        let cnt_enabled = *cnt_enabled_rx.borrow();
                        let _ = sync_network_once(
                            bind,
                            max_peers,
                            Arc::clone(&peers_arc),
                            Arc::clone(&peer_graph),
                            cnt_server,
                            Arc::clone(&bootstrap_entries),
                            Arc::clone(&reachable_peers),
                            cnt_enabled,
                            false, // skip_cnt_report
                        )
                        .await;
                    }
                    _ = cnt_report_tick.tick() => {
                        let cnt_enabled = *cnt_enabled_rx.borrow();
                        if cnt_enabled {
                            let _ = sync_network_once(
                                bind,
                                max_peers,
                                Arc::clone(&peers_arc),
                                Arc::clone(&peer_graph),
                                cnt_server,
                                Arc::clone(&bootstrap_entries),
                                Arc::clone(&reachable_peers),
                                cnt_enabled,
                                true, // cnt_report_only
                            )
                            .await;
                        }
                    }
                }
            }
        });

        self.tasks_started = true;
    }

    fn ui_keygen(&mut self, ui: &mut egui::Ui) {
        ui.heading("Keygen");
        ui.add_space(8.0);

        if ui.button("Generate new keypair").clicked() {
            match self.keygen() {
                Ok(()) => {}
                Err(e) => self.last_error = e,
            }
        }

        ui.add_space(8.0);
        ui.label("Keypair (base64) - keep private:");
        ui.text_edit_multiline(&mut self.keypair_base64);

        ui.label("Public key (base64) - shareable:");
        ui.text_edit_multiline(&mut self.public_key_base64);
    }

    fn ui_create(&mut self, ui: &mut egui::Ui) {
        ui.heading("Create Proof");
        ui.add_space(8.0);

        ui.horizontal(|ui| {
            ui.label("File:");
            ui.text_edit_singleline(&mut self.create_file_path);
            if ui.button("Browse").clicked() {
                if let Some(path) = rfd::FileDialog::new().pick_file() {
                    self.create_file_path = path.to_string_lossy().to_string();
                }
            }
        });

        ui.horizontal(|ui| {
            ui.label("Asset type:");
            ui.text_edit_singleline(&mut self.create_asset_type);
            if self.create_asset_type.is_empty() {
                self.create_asset_type = "other".to_string();
            }
        });

        ui.checkbox(&mut self.create_ai_assisted, "AI assisted");

        ui.label("Description:");
        ui.text_edit_multiline(&mut self.create_description);

        ui.label("Tags (comma-separated):");
        ui.text_edit_singleline(&mut self.create_tags);

        ui.label("Parent verification_id (optional):");
        ui.text_edit_singleline(&mut self.create_parent_verification_id);

        ui.add_space(8.0);
        ui.label("Keypair (base64):");
        ui.text_edit_multiline(&mut self.keypair_base64);

        ui.add_space(8.0);
        if ui.button("Create proof").clicked() {
            match self.create_proof() {
                Ok(()) => {}
                Err(e) => self.last_error = e,
            }
        }

        if !self.created_verification_id.is_empty() {
            ui.separator();
            ui.label("Created verification_id:");
            ui.monospace(&self.created_verification_id);
        }
    }

    fn ui_verify(&mut self, ui: &mut egui::Ui) {
        ui.heading("Verify Proof");
        ui.add_space(8.0);

        ui.label("verification_id:");
        ui.text_edit_singleline(&mut self.verify_verification_id);

        ui.horizontal(|ui| {
            ui.label("File (optional):");
            ui.text_edit_singleline(&mut self.verify_file_path);
            if ui.button("Browse").clicked() {
                if let Some(path) = rfd::FileDialog::new().pick_file() {
                    self.verify_file_path = path.to_string_lossy().to_string();
                }
            }
        });

        if ui.button("Verify").clicked() {
            match self.verify() {
                Ok(()) => {}
                Err(e) => self.last_error = e,
            }
        }

        ui.add_space(6.0);
        ui.label("Tip: leave verification_id empty to verify by file only (it will compute hash and search peers/local index).");

        if !self.verify_status.is_empty() {
            ui.separator();
            ui.label("Status:");
            ui.monospace(&self.verify_status);
        }
    }

    fn keygen(&mut self) -> std::result::Result<(), String> {
        let keypair = KeypairBytes::generate();
        let pubkey = keypair.public_key_bytes().map_err(|e| e.to_string())?;

        self.keypair_base64 = keypair.to_base64();
        self.public_key_base64 = base64::engine::general_purpose::STANDARD.encode(pubkey);
        Ok(())
    }

    fn create_proof(&mut self) -> std::result::Result<(), String> {
        let file_path = PathBuf::from(self.create_file_path.trim());
        let bytes = std::fs::read(file_path).map_err(|e| e.to_string())?;

        let kp = KeypairBytes::from_base64(self.keypair_base64.trim()).map_err(|e| e.to_string())?;
        let asset_type = parse_asset_type(&self.create_asset_type)?;

        let tags = parse_tags(&self.create_tags);
        let description = if self.create_description.trim().is_empty() {
            None
        } else {
            Some(self.create_description.trim().to_string())
        };
        let parent_verification_id = if self.create_parent_verification_id.trim().is_empty() {
            None
        } else {
            Some(self.create_parent_verification_id.trim().to_string())
        };

        let metadata = Metadata::new(tags, description, parent_verification_id);
        let proof = create_proof_from_bytes(
            &bytes,
            asset_type,
            self.create_ai_assisted,
            metadata,
            &kp,
        )
        .map_err(|e| e.to_string())?;

        let storage = Storage::new(self.storage_dir.clone());
        storage.store_proof(&proof).map_err(|e| e.to_string())?;

        let peers_arc = Arc::clone(&self.peers_arc);
        let peers = self
            .rt
            .block_on(async move { peers_arc.read().await.clone() });
        if !peers.is_empty() {
            self.rt
                .block_on(async { replicate_proof(&proof, &peers).await });
        }

        self.created_verification_id = proof.verification_id;
        Ok(())
    }

    fn verify(&mut self) -> std::result::Result<(), String> {
        let vid = self.verify_verification_id.trim().to_string();
        let storage = Storage::new(self.storage_dir.clone());
        let peers_arc = Arc::clone(&self.peers_arc);
        let peers = self
            .rt
            .block_on(async move { peers_arc.read().await.clone() });

        let content = if self.verify_file_path.trim().is_empty() {
            None
        } else {
            Some(std::fs::read(self.verify_file_path.trim()).map_err(|e| e.to_string())?)
        };

        if vid.is_empty() {
            let bytes = content.ok_or_else(|| "file is required when verification_id is empty".to_string())?;
            let asset_hash = blake3_hash_bytes(&bytes);

            let mut ids = storage
                .lookup_by_hash(&asset_hash)
                .map_err(|e| e.to_string())?;

            if ids.is_empty() && !peers.is_empty() {
                ids = self
                    .rt
                    .block_on(fetch_ids_by_hash_from_peers(&peers, &asset_hash))
                    .map_err(|e| e.to_string())?;
            }

            for id in ids {
                let proof = if storage.contains(&id) {
                    storage.retrieve_proof(&id).map_err(|e| e.to_string())?
                } else if !peers.is_empty() {
                    let maybe = self
                        .rt
                        .block_on(fetch_proof_from_peers(&peers, &id))
                        .map_err(|e| e.to_string())?;
                    let Some(p) = maybe else { continue };
                    storage.store_proof(&p).map_err(|e| e.to_string())?;
                    p
                } else {
                    continue;
                };

                if verify_proof(&proof, Some(&bytes)).is_ok() {
                    self.verify_status = format!("valid (verification_id={})", proof.verification_id);
                    return Ok(());
                }
            }

            self.verify_status = "not found".to_string();
            return Ok(());
        }

        let proof = if storage.contains(&vid) {
            storage.retrieve_proof(&vid).map_err(|e| e.to_string())?
        } else if !peers.is_empty() {
            let maybe = self
                .rt
                .block_on(fetch_proof_from_peers(&peers, &vid))
                .map_err(|e| e.to_string())?;
            let Some(p) = maybe else {
                self.verify_status = "not found".to_string();
                return Ok(());
            };
            storage.store_proof(&p).map_err(|e| e.to_string())?;
            p
        } else {
            self.verify_status = "not found".to_string();
            return Ok(());
        };

        verify_proof(&proof, content.as_deref()).map_err(|e| e.to_string())?;
        self.verify_status = "valid".to_string();
        Ok(())
    }
}

async fn sync_network_once(
    bind: SocketAddr,
    max_peers: usize,
    peers_arc: Arc<RwLock<Vec<SocketAddr>>>,
    peer_graph: Arc<RwLock<HashMap<SocketAddr, Vec<SocketAddr>>>>,
    cnt_server: SocketAddr,
    bootstrap_entries: Arc<Mutex<Vec<PeerEntry>>>,
    reachable_peers: Arc<Mutex<Vec<SocketAddr>>>,
    cnt_enabled: bool,
    cnt_report_only: bool,
) -> anyhow::Result<()> {
    let snapshot = peers_arc.read().await.clone();

    let connections_snapshot: Vec<PeerConnections> = {
        let g = peer_graph.read().await;
        g.iter()
            .map(|(addr, connected_peers)| PeerConnections {
                addr: *addr,
                connected_peers: connected_peers.clone(),
            })
            .collect()
    };

    let mut join_set = tokio::task::JoinSet::new();
    if !cnt_report_only {
        for peer in snapshot.iter().copied() {
            if peer == bind {
                continue;
            }
            let known = snapshot.clone();
            let conn = connections_snapshot.clone();
            join_set.spawn(async move { (peer, ping_peer(peer, bind, known, conn).await) });
        }
    }

    let mut reachable = Vec::new();
    let mut dead = Vec::new();
    let mut newly_discovered = Vec::new();
    let mut conn_updates: Vec<PeerConnections> = Vec::new();

    if !cnt_report_only {
        while let Some(join_res) = join_set.join_next().await {
            match join_res {
                Ok((peer, Ok((peer_list, conn_graph)))) => {
                    reachable.push(peer);
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
            let mut g = peer_graph.write().await;
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
            let mut set = peers_arc.write().await;
            set.retain(|p| !dead.contains(p));
            let mut g = peer_graph.write().await;
            for d in dead.iter().copied() {
                g.remove(&d);
            }
            for peers in g.values_mut() {
                peers.retain(|p| !dead.contains(p));
            }
        }

        if !newly_discovered.is_empty() {
            let mut set = peers_arc.write().await;
            for p in newly_discovered {
                if !set.contains(&p) {
                    set.push(p);
                }
            }
        }
    }

    {
        let mut g = peer_graph.write().await;
        g.insert(bind, reachable.clone());
    }

    let known_peers = peers_arc.read().await.clone();
    let report = PeerReport {
        addr: bind,
        known_peers,
        connected_peers: reachable,
    };

    if cnt_enabled {
        if let Ok(entries) = report_and_get_peers(cnt_server, report).await {
            if let Ok(mut guard) = bootstrap_entries.lock() {
                *guard = entries.clone();
            }

            let mut set = peers_arc.write().await;
            for e in entries {
                if e.addr == bind {
                    continue;
                }
                if !set.contains(&e.addr) {
                    set.push(e.addr);
                }
            }
        }
    }

    Ok(())
}

fn parse_tags(tags: &str) -> Option<Vec<String>> {
    let parts: Vec<String> = tags
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();

    if parts.is_empty() {
        None
    } else {
        Some(parts)
    }
}

fn parse_asset_type(s: &str) -> std::result::Result<AssetType, String> {
    match s.trim().to_ascii_lowercase().as_str() {
        "text" => Ok(AssetType::Text),
        "code" => Ok(AssetType::Code),
        "image" => Ok(AssetType::Image),
        "video" => Ok(AssetType::Video),
        "other" => Ok(AssetType::Other),
        _ => Err("unknown asset_type".to_string()),
    }
}

fn parse_peers(peers: &str) -> std::result::Result<Vec<SocketAddr>, String> {
    let mut out = Vec::new();
    for part in peers.split(',') {
        let p = part.trim();
        if p.is_empty() {
            continue;
        }
        out.push(p.parse::<SocketAddr>().map_err(|_| "invalid peer".to_string())?);
    }
    Ok(out)
}
