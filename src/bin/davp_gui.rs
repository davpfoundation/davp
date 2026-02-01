use anyhow::Result;
use base64::Engine as _;
use davp::modules::asset::create_proof_from_bytes;
use davp::modules::certification::PublishedProof;
use davp::modules::hash::blake3_hash_bytes;
use davp::modules::bootstrap::{report_and_get_peers, PeerEntry, PeerReport};
use davp::modules::issuer_certificate::{
    fetch_certificate_bundle, verify_issuer_certificate_detailed, IssuerCertificateBundle,
    IssuerCertificationDetailed, DEFAULT_CERTS_URL,
};
use davp::modules::metadata::{AssetType, Metadata};
use davp::modules::network::{
    fetch_ids_by_hash_from_peers, fetch_proof_from_peers, fetch_published_proof_from_peers,
    replicate_published_proof, replicate_proof,
    run_node_with_shutdown, NodeConfig, PeerConnections, ping_peer,
};
use davp::modules::storage::Storage;
use davp::modules::verification::verify_proof;
use davp::KeypairBytes;
use eframe::egui;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::time::SystemTime;
use tokio::sync::watch;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct CntTrackerEntry {
    name: String,
    addr: String,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct GuiSettingsFile {
    cnt_selected_addr: Option<String>,
    cnt_trackers: Vec<CntTrackerEntry>,
}

#[derive(Debug, Clone)]
struct VerifyResultView {
    verification_id: String,
    creator_public_key_base64: String,
    signature_base64: String,
    issuer_certificate_id: Option<String>,
    issuer_certified: bool,
    organization_name: Option<String>,
    issuer_unverified_reason: Option<String>,
}

fn issuer_unverified_reason(d: &IssuerCertificationDetailed) -> Option<String> {
    match d {
        IssuerCertificationDetailed::Certified { .. } => None,
        IssuerCertificationDetailed::NotFound => Some("certificate_id not found in certs.json".to_string()),
        IssuerCertificationDetailed::InvalidCaSignature => Some("certificate CA signature invalid".to_string()),
        IssuerCertificationDetailed::InvalidValidityWindow => Some("certificate not valid now (expired/not yet valid/invalid window)".to_string()),
        IssuerCertificationDetailed::InvalidIssuerPublicKey => Some("certificate issuer_public_key is invalid base64/length".to_string()),
        IssuerCertificationDetailed::IssuerKeyMismatch => Some(
            "issuer key mismatch: proof.creator_public_key != certificate.issuer_public_key (you signed the proof with the wrong keypair)"
                .to_string(),
        ),
    }
}

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
    cnt_enabled: bool,

    cnt_selected_addr: String,
    cnt_trackers: Vec<CntTrackerEntry>,
    cnt_new_name: String,
    cnt_new_addr: String,

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
    node_handle: Option<tokio::task::JoinHandle<()>>,
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
    create_issuer_certificate_id: String,
    created_verification_id: String,
    created_creator_public_key_base64: String,
    created_signature_base64: String,
    created_issuer_certificate_id_display: String,

    // verify
    verify_verification_id: String,
    verify_file_path: String,
    verify_status: String,
    verify_view: Option<VerifyResultView>,

    certs_url: String,
    certs_last_fetch_status: String,
    certs_bundle_cache: Option<IssuerCertificateBundle>,
    certs_bundle_cache_at: Option<Instant>,

    show_network_panel: bool,
    show_about_window: bool,

    last_error: String,

    manual_connect_open: bool,
    manual_connect_addr: String,
}

impl Default for DavpApp {
    fn default() -> Self {
        let peers_arc: Arc<RwLock<Vec<SocketAddr>>> = Arc::new(RwLock::new(Vec::new()));
        let peer_graph: Arc<RwLock<HashMap<SocketAddr, Vec<SocketAddr>>>> = Arc::new(RwLock::new(HashMap::new()));
        let mut s = Self {
            tab: Tab::default(),
            storage_dir: "davp_storage".to_string(),
            peers: "".to_string(),
            cnt_server: "127.0.0.1:9100".to_string(),
            cnt_enabled: false,

            cnt_selected_addr: "127.0.0.1:9100".to_string(),
            cnt_trackers: Vec::new(),
            cnt_new_name: String::new(),
            cnt_new_addr: String::new(),
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
            node_handle: None,
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
            create_issuer_certificate_id: String::new(),
            created_verification_id: String::new(),
            created_creator_public_key_base64: String::new(),
            created_signature_base64: String::new(),
            created_issuer_certificate_id_display: String::new(),

            verify_verification_id: String::new(),
            verify_file_path: String::new(),
            verify_status: String::new(),
            verify_view: None,

            certs_url: DEFAULT_CERTS_URL.to_string(),
            certs_last_fetch_status: String::new(),
            certs_bundle_cache: None,
            certs_bundle_cache_at: None,

            show_network_panel: true,
            show_about_window: false,

            last_error: String::new(),

            manual_connect_open: false,
            manual_connect_addr: String::new(),
        };
        s.load_gui_settings();
        s
    }
}

#[derive(Default, Clone, Copy, PartialEq, Eq)]
enum Tab {
    #[default]
    Create,
    Verify,
    Keygen,
    Settings,
}

impl eframe::App for DavpApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::TopBottomPanel::top("top")
            .resizable(false)
            .show(ctx, |ui| {
                egui::menu::bar(ui, |ui| {
                    ui.menu_button("File", |ui| {
                        if ui.button("Quit").clicked() {
                            ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                        }
                    });

                    ui.menu_button("View", |ui| {
                        ui.checkbox(&mut self.show_network_panel, "Network panel");
                    });

                    ui.menu_button("Network", |ui| {
                        if !self.networking_started {
                            if ui.button("Start networking").clicked() {
                                self.networking_started = true;
                                self.show_network_panel = true;
                            }
                        } else if ui.button("Disconnect network").clicked() {
                            self.stop_network();
                        }

                        ui.separator();
                        if ui.button("Connect manually...").clicked() {
                            self.manual_connect_open = true;
                        }

                        ui.separator();
                        ui.add_enabled_ui(self.networking_started, |ui| {
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
                        });

                        ui.separator();
                        if ui.button("Show network panel").clicked() {
                            self.show_network_panel = true;
                        }
                    });

                    ui.menu_button("Settings", |ui| {
                        if ui.button("Open settings").clicked() {
                            self.tab = Tab::Settings;
                        }
                    });

                    ui.menu_button("Help", |ui| {
                        if ui.button("About").clicked() {
                            self.show_about_window = true;
                        }
                    });
                });

                ui.add_space(6.0);

                ui.horizontal(|ui| {
                    ui.selectable_value(&mut self.tab, Tab::Create, "Create");
                    ui.selectable_value(&mut self.tab, Tab::Verify, "Verify");
                    ui.selectable_value(&mut self.tab, Tab::Keygen, "Keygen");
                    ui.selectable_value(&mut self.tab, Tab::Settings, "Settings");

                    ui.separator();
                    ui.label(format!(
                        "Network: {}",
                        if self.networking_started { "running" } else { "stopped" }
                    ));
                    ui.label(format!(
                        "CNT: {}",
                        if self.cnt_enabled { "enabled" } else { "disabled" }
                    ));
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

        if self.networking_started {
            self.ensure_background_tasks();
        }
        if self.show_about_window {
            self.ui_about_window(ctx);
        }

        if self.show_network_panel {
            egui::SidePanel::right("network_panel")
                .resizable(true)
                .default_width(340.0)
                .show(ctx, |ui| {
                    self.ui_network_panel(ui);
                });
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            if !self.last_error.is_empty() {
                egui::Frame::group(ui.style()).show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.colored_label(egui::Color32::RED, &self.last_error);
                        if ui.button("Clear").clicked() {
                            self.last_error.clear();
                        }
                    });
                });
                ui.add_space(10.0);
            }

            match self.tab {
                Tab::Create => self.ui_create(ui),
                Tab::Verify => self.ui_verify(ui),
                Tab::Keygen => self.ui_keygen(ui),
                Tab::Settings => self.ui_settings_tab(ui),
            }
        });
    }
}

impl DavpApp {
    fn all_cnt_trackers(&self) -> Vec<(String, String)> {
        let mut v = vec![("CNT World".to_string(), "127.0.0.1:9100".to_string())];
        for t in &self.cnt_trackers {
            v.push((t.name.clone(), t.addr.clone()));
        }
        v
    }

    fn all_certs_sources(&self) -> Vec<(String, String)> {
        vec![("DAVP World".to_string(), DEFAULT_CERTS_URL.to_string())]
    }

    fn settings_path(&self) -> PathBuf {
        PathBuf::from(self.storage_dir.trim()).join("gui_settings.json")
    }

    fn load_gui_settings(&mut self) {
        let path = self.settings_path();
        let Ok(bytes) = std::fs::read(&path) else {
            self.cnt_selected_addr = "127.0.0.1:9100".to_string();
            self.cnt_server = self.cnt_selected_addr.clone();
            self.certs_url = DEFAULT_CERTS_URL.to_string();
            return;
        };
        let Ok(s) = String::from_utf8(bytes) else {
            self.cnt_selected_addr = "127.0.0.1:9100".to_string();
            self.cnt_server = self.cnt_selected_addr.clone();
            return;
        };
        let Ok(settings) = serde_json::from_str::<GuiSettingsFile>(&s) else {
            self.cnt_selected_addr = "127.0.0.1:9100".to_string();
            self.cnt_server = self.cnt_selected_addr.clone();
            self.certs_url = DEFAULT_CERTS_URL.to_string();
            return;
        };
        self.cnt_trackers = settings.cnt_trackers;
        if let Some(addr) = settings.cnt_selected_addr {
            if self
                .all_cnt_trackers()
                .iter()
                .any(|(_, a)| a.trim() == addr.trim())
            {
                self.cnt_selected_addr = addr;
            } else {
                self.cnt_selected_addr = "127.0.0.1:9100".to_string();
            }
        } else {
            self.cnt_selected_addr = "127.0.0.1:9100".to_string();
        }
        self.cnt_server = self.cnt_selected_addr.clone();

        self.certs_url = DEFAULT_CERTS_URL.to_string();
    }

    fn save_gui_settings(&self) -> std::result::Result<(), String> {
        let base = PathBuf::from(self.storage_dir.trim());
        std::fs::create_dir_all(&base).map_err(|e| e.to_string())?;
        let path = self.settings_path();
        let settings = GuiSettingsFile {
            cnt_selected_addr: Some(self.cnt_selected_addr.clone()),
            cnt_trackers: self.cnt_trackers.clone(),
        };
        let json = serde_json::to_string_pretty(&settings).map_err(|e| e.to_string())?;
        std::fs::write(&path, json).map_err(|e| e.to_string())?;
        Ok(())
    }

    fn ui_settings_tab(&mut self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical().auto_shrink([false; 2]).show(ui, |ui| {
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.heading("Certificates");
                let sources = self.all_certs_sources();
                let mut selected = sources
                    .iter()
                    .position(|(_, url)| url.trim() == self.certs_url.trim())
                    .unwrap_or(0);
                egui::ComboBox::from_id_source("certs_source_select")
                    .selected_text(format!("{}", sources[selected].0))
                    .show_ui(ui, |ui| {
                        for (i, (name, _)) in sources.iter().enumerate() {
                            ui.selectable_value(&mut selected, i, name);
                        }
                    });
                self.certs_url = sources[selected].1.clone();
                ui.horizontal(|ui| {
                    if ui.button("Refresh certs").clicked() {
                        let _ = self.fetch_certs_bundle_for_verify(true);
                    }
                });
                if !self.certs_last_fetch_status.is_empty() {
                    ui.monospace(&self.certs_last_fetch_status);
                }
            });

            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.heading("CNT trackers");

                ui.add_enabled_ui(!self.networking_started, |ui| {
                    let trackers = self.all_cnt_trackers();
                    let mut selected = trackers
                        .iter()
                        .position(|(_, addr)| addr.trim() == self.cnt_selected_addr.trim())
                        .unwrap_or(0);

                    egui::ComboBox::from_id_source("cnt_tracker_select")
                        .selected_text(format!(
                            "{} ({})",
                            trackers[selected].0,
                            trackers[selected].1
                        ))
                        .show_ui(ui, |ui: &mut egui::Ui| {
                            for (i, (name, addr)) in trackers.iter().enumerate() {
                                ui.selectable_value(
                                    &mut selected,
                                    i,
                                    format!("{} ({})", name, addr),
                                );
                            }
                        });

                    let new_addr = trackers
                        .get(selected)
                        .map(|t| t.1.clone())
                        .unwrap_or_else(|| "127.0.0.1:9100".to_string());
                    if new_addr.trim() != self.cnt_selected_addr.trim() {
                        self.cnt_selected_addr = new_addr;
                        self.cnt_server = self.cnt_selected_addr.clone();
                        if let Err(e) = self.save_gui_settings() {
                            self.last_error = e;
                        }
                    }

                    ui.add_space(8.0);
                    ui.separator();
                    ui.label("Add custom CNT tracker");
                    ui.horizontal(|ui| {
                        ui.label("Name");
                        ui.text_edit_singleline(&mut self.cnt_new_name);
                    });
                    ui.horizontal(|ui| {
                        ui.label("Addr (host:port)");
                        ui.text_edit_singleline(&mut self.cnt_new_addr);
                    });
                    if ui.button("Add").clicked() {
                        let name = self.cnt_new_name.trim().to_string();
                        let addr = self.cnt_new_addr.trim().to_string();
                        if name.is_empty() {
                            self.last_error = "tracker name cannot be empty".to_string();
                        } else if addr.is_empty() {
                            self.last_error = "tracker addr cannot be empty".to_string();
                        } else if addr.parse::<SocketAddr>().is_err() {
                            self.last_error = "tracker addr must be host:port".to_string();
                        } else if self
                            .all_cnt_trackers()
                            .iter()
                            .any(|(_, a)| a.trim() == addr.trim())
                        {
                            self.last_error = "tracker addr already exists".to_string();
                        } else {
                            self.cnt_trackers.push(CntTrackerEntry {
                                name,
                                addr: addr.clone(),
                            });
                            self.cnt_selected_addr = addr;
                            self.cnt_server = self.cnt_selected_addr.clone();
                            self.cnt_new_name.clear();
                            self.cnt_new_addr.clear();
                            if let Err(e) = self.save_gui_settings() {
                                self.last_error = e;
                            }
                        }
                    }

                    if !self.cnt_trackers.is_empty() {
                        ui.add_space(8.0);
                        ui.separator();
                        ui.label("Custom CNT trackers");
                        let mut remove_addr: Option<String> = None;
                        for t in &self.cnt_trackers {
                            ui.horizontal(|ui| {
                                ui.monospace(format!("{} ({})", t.name, t.addr));
                                if ui.button("Remove").clicked() {
                                    remove_addr = Some(t.addr.clone());
                                }
                            });
                        }
                        if let Some(addr) = remove_addr {
                            self.cnt_trackers.retain(|t| t.addr.trim() != addr.trim());
                            if self.cnt_selected_addr.trim() == addr.trim() {
                                self.cnt_selected_addr = "127.0.0.1:9100".to_string();
                                self.cnt_server = self.cnt_selected_addr.clone();
                            }
                            if let Err(e) = self.save_gui_settings() {
                                self.last_error = e;
                            }
                        }
                    }
                });

                if self.networking_started {
                    ui.add_space(6.0);
                    ui.colored_label(
                        egui::Color32::YELLOW,
                        "Stop networking to change CNT tracker settings.",
                    );
                }
            });
        });
    }

    fn ui_about_window(&mut self, ctx: &egui::Context) {
        egui::Window::new("About")
            .open(&mut self.show_about_window)
            .collapsible(false)
            .resizable(false)
            .show(ctx, |ui| {
                ui.heading("davp");
                ui.add_space(6.0);
                ui.monospace(format!(
                    "build_time={}",
                    SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .map(|d| d.as_secs().to_string())
                        .unwrap_or_else(|_| "unknown".to_string())
                ));
                ui.add_space(6.0);
                ui.label("Certificate verification uses certs.json from Settings.");
            });
    }

    fn ui_network_panel(&mut self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical().auto_shrink([false; 2]).show(ui, |ui| {
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.heading("Network");
                ui.horizontal(|ui| {
                    if !self.networking_started {
                        if ui.button("Start").clicked() {
                            self.networking_started = true;
                        }
                    } else if ui.button("Disconnect").clicked() {
                        self.stop_network();
                    }

                    if ui.button("Connect...").clicked() {
                        self.manual_connect_open = true;
                    }
                });

                ui.add_enabled_ui(self.networking_started, |ui| {
                    ui.checkbox(&mut self.cnt_enabled, "CNT");
                    if let Some(tx) = &self.cnt_enabled_tx {
                        let _ = tx.send(self.cnt_enabled);
                    }
                });
            });

            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.heading("Config");
                ui.add_enabled_ui(!self.networking_started, |ui| {
                    ui.label("Node bind");
                    ui.text_edit_singleline(&mut self.node_bind);
                    ui.horizontal(|ui| {
                        ui.label("Max peers");
                        ui.add(egui::DragValue::new(&mut self.max_peers).clamp_range(1..=100));
                        ui.checkbox(&mut self.run_node_enabled, "Run node");
                    });

                    let cnt_name = self
                        .all_cnt_trackers()
                        .into_iter()
                        .find(|t| t.1 == self.cnt_selected_addr)
                        .map(|t| t.0)
                        .unwrap_or_else(|| "CNT World".to_string());
                    ui.label(format!("CNT tracker: {}", cnt_name));
                    ui.label(&self.cnt_selected_addr);

                    ui.label("Seed peers");
                    ui.text_edit_singleline(&mut self.peers);
                    ui.horizontal(|ui| {
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
                            let snapshot =
                                self.rt.block_on(async move { peers_arc.read().await.clone() });
                            self.peers = snapshot
                                .iter()
                                .map(|p| p.to_string())
                                .collect::<Vec<_>>()
                                .join(",");
                        }
                    });
                });
            });

            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.heading("Status");
                let known_peers_snapshot = {
                    let peers_arc = Arc::clone(&self.peers_arc);
                    self.rt
                        .block_on(async move { peers_arc.read().await.clone() })
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

                ui.label(format!("Known: {}", known_peers_snapshot.len()));
                ui.label(format!("Reachable: {}", reachable_snapshot.len()));
                ui.label(format!("CNT peers: {}", entries.len()));
            });
        });
    }
}

impl DavpApp {
    fn fetch_certs_bundle_for_verify(
        &mut self,
        force_refresh: bool,
    ) -> std::result::Result<IssuerCertificateBundle, String> {
        let ttl = Duration::from_secs(60);
        if !force_refresh {
            if let (Some(bundle), Some(at)) = (&self.certs_bundle_cache, self.certs_bundle_cache_at) {
                if at.elapsed() <= ttl {
                    self.certs_last_fetch_status = format!(
                        "using cached {} certificate(s)",
                        bundle.certificates.len()
                    );
                    return Ok(bundle.clone());
                }
            }
        }

        let url = if self.certs_url.trim().is_empty() {
            DEFAULT_CERTS_URL
        } else {
            self.certs_url.trim()
        };

        let res = self
            .rt
            .block_on(fetch_certificate_bundle(url))
            .map_err(|e| e.to_string());

        match &res {
            Ok(b) => {
                self.certs_last_fetch_status = format!(
                    "loaded {} certificate(s) from {}",
                    b.certificates.len(),
                    url
                );
                self.certs_bundle_cache = Some(b.clone());
                self.certs_bundle_cache_at = Some(Instant::now());
            }
            Err(e) => {
                self.certs_last_fetch_status = format!("failed to fetch {}: {}", url, e);
            }
        }

        res
    }

    fn issuer_certification(
        &mut self,
        issuer_certificate_id: &str,
        proof_creator_public_key: &[u8; 32],
    ) -> (IssuerCertificationDetailed, Option<String>) {
        let bundle = match self.fetch_certs_bundle_for_verify(false) {
            Ok(b) => b,
            Err(e) => {
                return (
                    IssuerCertificationDetailed::NotFound,
                    Some(format!("failed to fetch certs.json: {}", e)),
                );
            }
        };

        let ca_b64 = bundle
            .certificates
            .iter()
            .find(|c| c.certificate_id.trim() == issuer_certificate_id.trim())
            .and_then(|c| c.ca_public_key_base64.as_deref())
            .or(bundle.ca_public_key_base64.as_deref())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .or_else(|| std::env::var("DAVP_CA_PUBLIC_KEY_BASE64").ok());

        let Some(ca_b64) = ca_b64 else {
            return (IssuerCertificationDetailed::InvalidCaSignature, None);
        };

        let ca_pk_bytes = base64::engine::general_purpose::STANDARD
            .decode(ca_b64.trim())
            .ok();
        let ca_pk: Option<[u8; 32]> = ca_pk_bytes.and_then(|b| b.try_into().ok());
        let Some(ca_pk) = ca_pk else {
            return (IssuerCertificationDetailed::InvalidCaSignature, None);
        };

        let detailed = verify_issuer_certificate_detailed(
            &bundle.certificates,
            issuer_certificate_id,
            proof_creator_public_key,
            &ca_pk,
            chrono::Utc::now(),
        )
        .unwrap_or(IssuerCertificationDetailed::InvalidCaSignature);

        (detailed, None)
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
        if let Some(node_handle) = self.node_handle.take() {
            if let Some(tx) = self.node_shutdown_tx.take() {
                let _ = tx.send(true);
            }
            let _ = self.rt.block_on(async { node_handle.await });
        }
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

            let node_handle = self.rt.spawn(async move {
                let _ = run_node_with_shutdown(storage, config, node_shutdown_rx).await;
            });

            self.node_handle = Some(node_handle);
        }

        self.rt.spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_millis(100));
            let mut cnt_report_tick = tokio::time::interval(std::time::Duration::from_secs(2));

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
                            false, // cnt_report_only
                        )
                        .await;
                    }
                    _ = cnt_report_tick.tick() => {
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
                            true, // cnt_report_only
                        )
                        .await;
                    }
                }
            }
        });

        self.tasks_started = true;
    }

    fn ui_keygen(&mut self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical().auto_shrink([false; 2]).show(ui, |ui| {
            ui.heading("Keygen");

            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.horizontal(|ui| {
                    if ui.button("Generate new keypair").clicked() {
                        match self.keygen() {
                            Ok(()) => {}
                            Err(e) => self.last_error = e,
                        }
                    }
                    if ui.button("Copy public key").clicked() {
                        ui.output_mut(|o| o.copied_text = self.public_key_base64.clone());
                    }
                });
            });

            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.label("Keypair (base64)");
                ui.add(egui::TextEdit::multiline(&mut self.keypair_base64));
            });

            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.label("Public key (base64)");
                ui.add(egui::TextEdit::multiline(&mut self.public_key_base64));
            });
        });
    }

    fn ui_create(&mut self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical().auto_shrink([false; 2]).show(ui, |ui| {
            ui.heading("Create Proof");

            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.heading("Inputs");
                ui.horizontal(|ui| {
                    ui.label("File");
                    ui.text_edit_singleline(&mut self.create_file_path);
                    if ui.button("Browse").clicked() {
                        if let Some(path) = rfd::FileDialog::new().pick_file() {
                            self.create_file_path = path.to_string_lossy().to_string();
                        }
                    }
                });

                ui.horizontal(|ui| {
                    ui.label("Asset type");
                    if self.create_asset_type.is_empty() {
                        self.create_asset_type = "other".to_string();
                    }
                    egui::ComboBox::from_id_source("asset_type")
                        .selected_text(self.create_asset_type.clone())
                        .show_ui(ui, |ui| {
                            for t in ["other", "text", "image", "video", "audio", "code"] {
                                ui.selectable_value(&mut self.create_asset_type, t.to_string(), t);
                            }
                        });
                    ui.checkbox(&mut self.create_ai_assisted, "AI assisted");
                });
            });

            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.heading("Metadata");
                ui.label("Description");
                ui.text_edit_multiline(&mut self.create_description);
                ui.label("Tags (comma-separated)");
                ui.text_edit_singleline(&mut self.create_tags);
                ui.label("Parent verification_id*");
                ui.text_edit_singleline(&mut self.create_parent_verification_id);
                ui.label("Issuer certificate id*");
                ui.text_edit_singleline(&mut self.create_issuer_certificate_id);
            });

            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.heading("Signing");
                ui.label("Keypair (base64)");
                ui.text_edit_multiline(&mut self.keypair_base64);
                ui.horizontal(|ui| {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("Create proof").clicked() {
                            match self.create_proof() {
                                Ok(()) => {}
                                Err(e) => self.last_error = e,
                            }
                        }
                    });
                });
            });

            if !self.created_verification_id.is_empty() {
                egui::Frame::group(ui.style()).show(ui, |ui| {
                    ui.heading("Output");

                    ui.horizontal(|ui| {
                        ui.label("verification_id");
                        ui.monospace(&self.created_verification_id);
                        if ui.button("Copy").clicked() {
                            ui.output_mut(|o| o.copied_text = self.created_verification_id.clone());
                        }
                    });
                    ui.horizontal(|ui| {
                        ui.label("creator_public_key");
                        ui.monospace(&self.created_creator_public_key_base64);
                        if ui.button("Copy").clicked() {
                            ui.output_mut(|o| o.copied_text = self.created_creator_public_key_base64.clone());
                        }
                    });
                    ui.horizontal(|ui| {
                        ui.label("signature");
                        ui.monospace(&self.created_signature_base64);
                        if ui.button("Copy").clicked() {
                            ui.output_mut(|o| o.copied_text = self.created_signature_base64.clone());
                        }
                    });
                    if !self.created_issuer_certificate_id_display.is_empty() {
                        ui.horizontal(|ui| {
                            ui.label("issuer_certificate_id");
                            ui.monospace(&self.created_issuer_certificate_id_display);
                            if ui.button("Copy").clicked() {
                                ui.output_mut(|o| {
                                    o.copied_text = self.created_issuer_certificate_id_display.clone()
                                });
                            }
                        });
                    }
                });
            }
        });
    }

    fn ui_verify(&mut self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical().auto_shrink([false; 2]).show(ui, |ui| {
            ui.heading("Verify Proof");

            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.heading("Inputs");
                ui.label("verification_id");
                ui.text_edit_singleline(&mut self.verify_verification_id);

                ui.horizontal(|ui| {
                    ui.label("File*");
                    ui.text_edit_singleline(&mut self.verify_file_path);
                    if ui.button("Browse").clicked() {
                        if let Some(path) = rfd::FileDialog::new().pick_file() {
                            self.verify_file_path = path.to_string_lossy().to_string();
                        }
                    }
                });

                ui.horizontal(|ui| {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("Verify").clicked() {
                            match self.verify() {
                                Ok(()) => {}
                                Err(e) => self.last_error = e,
                            }
                        }
                    });
                });
            });

            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.heading("Certificates");
                ui.horizontal(|ui| {
                    ui.label("certs_url");
                    ui.monospace(self.certs_url.trim());
                    if ui.button("Refresh").clicked() {
                        let _ = self.fetch_certs_bundle_for_verify(true);
                    }
                    if ui.button("Settings").clicked() {
                        self.tab = Tab::Settings;
                    }
                });
                if !self.certs_last_fetch_status.is_empty() {
                    ui.monospace(&self.certs_last_fetch_status);
                }
            });

            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.heading("Result");

                if let Some(v) = &self.verify_view {
                    ui.horizontal(|ui| {
                        ui.label("status");
                        ui.colored_label(egui::Color32::GREEN, "valid");
                    });

                    ui.horizontal(|ui| {
                        ui.label("verification_id");
                        ui.monospace(&v.verification_id);
                        if ui.button("Copy").clicked() {
                            ui.output_mut(|o| o.copied_text = v.verification_id.clone());
                        }
                    });

                    ui.horizontal(|ui| {
                        ui.label("creator_public_key");
                        ui.monospace(&v.creator_public_key_base64);
                        if ui.button("Copy").clicked() {
                            ui.output_mut(|o| o.copied_text = v.creator_public_key_base64.clone());
                        }
                    });

                    ui.horizontal(|ui| {
                        ui.label("signature");
                        ui.monospace(&v.signature_base64);
                        if ui.button("Copy").clicked() {
                            ui.output_mut(|o| o.copied_text = v.signature_base64.clone());
                        }
                    });

                    if let Some(id) = &v.issuer_certificate_id {
                        ui.horizontal(|ui| {
                            ui.label("issuer_certificate_id");
                            ui.monospace(id);
                            if ui.button("Copy").clicked() {
                                ui.output_mut(|o| o.copied_text = id.clone());
                            }
                        });
                        if v.issuer_certified {
                            if let Some(org) = &v.organization_name {
                                ui.colored_label(
                                    egui::Color32::GREEN,
                                    format!("certified issuer: {}", org),
                                );
                            } else {
                                ui.colored_label(egui::Color32::GREEN, "certified issuer");
                            }
                        } else {
                            ui.colored_label(egui::Color32::YELLOW, "unverified issuer");
                            if let Some(r) = &v.issuer_unverified_reason {
                                ui.monospace(r);
                            }
                        }
                    } else {
                        ui.colored_label(egui::Color32::YELLOW, "unverified issuer");
                    }

                    egui::CollapsingHeader::new("Raw status")
                        .default_open(false)
                        .show(ui, |ui| {
                            if !self.verify_status.is_empty() {
                                ui.monospace(&self.verify_status);
                            }
                        });
                } else if !self.verify_status.is_empty() {
                    ui.label("Status");
                    ui.monospace(&self.verify_status);
                } else {
                    ui.label("No result yet.");
                }
            });
        });
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

        let issuer_certificate_id = if self.create_issuer_certificate_id.trim().is_empty() {
            None
        } else {
            Some(self.create_issuer_certificate_id.trim().to_string())
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
        let published = PublishedProof {
            proof: proof.clone(),
            issuer_certificate_id: issuer_certificate_id.clone(),
        };
        storage.store_published_proof(&published).map_err(|e| e.to_string())?;

        let peers_arc = Arc::clone(&self.peers_arc);
        let peers = self
            .rt
            .block_on(async move { peers_arc.read().await.clone() });
        if !peers.is_empty() {
            self.rt
                .block_on(async {
                    if published.issuer_certificate_id.is_some() {
                        replicate_published_proof(&published, &peers).await;
                    } else {
                        replicate_proof(&proof, &peers).await;
                    }
                });
        }

        self.created_verification_id = proof.verification_id;
        self.created_creator_public_key_base64 =
            base64::engine::general_purpose::STANDARD.encode(proof.creator_public_key);
        self.created_signature_base64 =
            base64::engine::general_purpose::STANDARD.encode(proof.signature.0);
        self.created_issuer_certificate_id_display = issuer_certificate_id.unwrap_or_default();
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
            self.verify_view = None;
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
                let published = if storage.contains(&id) {
                    storage.retrieve_published_proof(&id).map_err(|e| e.to_string())?
                } else if !peers.is_empty() {
                    let maybe_published = self
                        .rt
                        .block_on(fetch_published_proof_from_peers(&peers, &id))
                        .map_err(|e| e.to_string())?;
                    if let Some(published) = maybe_published {
                        storage
                            .store_published_proof(&published)
                            .map_err(|e| e.to_string())?;
                        published
                    } else {
                        let maybe = self
                            .rt
                            .block_on(fetch_proof_from_peers(&peers, &id))
                            .map_err(|e| e.to_string())?;
                        let Some(p) = maybe else { continue };
                        storage.store_proof(&p).map_err(|e| e.to_string())?;
                        PublishedProof {
                            proof: p,
                            issuer_certificate_id: None,
                        }
                    }
                } else {
                    continue;
                };

                if verify_proof(&published.proof, Some(&bytes)).is_ok() {
                    let mut status = String::new();
                    status.push_str("valid\n");
                    status.push_str(&format!("verification_id={}\n", published.proof.verification_id));
                    status.push_str(&format!(
                        "creator_public_key_base64={}\n",
                        base64::engine::general_purpose::STANDARD.encode(published.proof.creator_public_key)
                    ));
                    status.push_str(&format!(
                        "signature_base64={}\n",
                        base64::engine::general_purpose::STANDARD.encode(published.proof.signature.0)
                    ));
                    if let Some(id) = published.issuer_certificate_id.as_deref() {
                        status.push_str(&format!("issuer_certificate_id={}\n", id));

                        let (cert_detailed, fetch_err_reason) =
                            self.issuer_certification(id, &published.proof.creator_public_key);

                        match cert_detailed {
                            IssuerCertificationDetailed::Certified { organization_name } => {
                                status.push_str("certified issuer\n");
                                status.push_str(&format!("organization_name={}\n", organization_name));
                                self.verify_view = Some(VerifyResultView {
                                    verification_id: published.proof.verification_id.clone(),
                                    creator_public_key_base64: base64::engine::general_purpose::STANDARD
                                        .encode(published.proof.creator_public_key),
                                    signature_base64: base64::engine::general_purpose::STANDARD
                                        .encode(published.proof.signature.0),
                                    issuer_certificate_id: Some(id.to_string()),
                                    issuer_certified: true,
                                    organization_name: Some(organization_name),
                                    issuer_unverified_reason: None,
                                });
                            }
                            _ => {
                                status.push_str("unverified issuer\n");
                                self.verify_view = Some(VerifyResultView {
                                    verification_id: published.proof.verification_id.clone(),
                                    creator_public_key_base64: base64::engine::general_purpose::STANDARD
                                        .encode(published.proof.creator_public_key),
                                    signature_base64: base64::engine::general_purpose::STANDARD
                                        .encode(published.proof.signature.0),
                                    issuer_certificate_id: Some(id.to_string()),
                                    issuer_certified: false,
                                    organization_name: None,
                                    issuer_unverified_reason: fetch_err_reason
                                        .or_else(|| issuer_unverified_reason(&cert_detailed)),
                                });
                            }
                        }
                    } else {
                        status.push_str("unverified issuer\n");
                        self.verify_view = Some(VerifyResultView {
                            verification_id: published.proof.verification_id.clone(),
                            creator_public_key_base64: base64::engine::general_purpose::STANDARD
                                .encode(published.proof.creator_public_key),
                            signature_base64: base64::engine::general_purpose::STANDARD
                                .encode(published.proof.signature.0),
                            issuer_certificate_id: None,
                            issuer_certified: false,
                            organization_name: None,
                            issuer_unverified_reason: None,
                        });
                    }
                    self.verify_status = status;
                    return Ok(());
                }
            }

            self.verify_status = "not found".to_string();
            self.verify_view = None;
            return Ok(());
        }

        let published = if storage.contains(&vid) {
            storage.retrieve_published_proof(&vid).map_err(|e| e.to_string())?
        } else if !peers.is_empty() {
            let maybe_published = self
                .rt
                .block_on(fetch_published_proof_from_peers(&peers, &vid))
                .map_err(|e| e.to_string())?;
            if let Some(published) = maybe_published {
                storage
                    .store_published_proof(&published)
                    .map_err(|e| e.to_string())?;
                published
            } else {
                let maybe = self
                    .rt
                    .block_on(fetch_proof_from_peers(&peers, &vid))
                    .map_err(|e| e.to_string())?;
                let Some(p) = maybe else {
                    self.verify_status = "not found".to_string();
                    return Ok(());
                };
                storage.store_proof(&p).map_err(|e| e.to_string())?;
                PublishedProof {
                    proof: p,
                    issuer_certificate_id: None,
                }
            }
        } else {
            self.verify_status = "not found".to_string();
            return Ok(());
        };

        verify_proof(&published.proof, content.as_deref()).map_err(|e| e.to_string())?;
        let mut status = String::new();
        status.push_str("valid\n");
        status.push_str(&format!("verification_id={}\n", published.proof.verification_id));
        status.push_str(&format!(
            "creator_public_key_base64={}\n",
            base64::engine::general_purpose::STANDARD.encode(published.proof.creator_public_key)
        ));
        status.push_str(&format!(
            "signature_base64={}\n",
            base64::engine::general_purpose::STANDARD.encode(published.proof.signature.0)
        ));
        if let Some(id) = published.issuer_certificate_id.as_deref() {
            status.push_str(&format!("issuer_certificate_id={}\n", id));

            let (cert_detailed, fetch_err_reason) =
                self.issuer_certification(id, &published.proof.creator_public_key);

            match cert_detailed {
                IssuerCertificationDetailed::Certified { organization_name } => {
                    status.push_str("certified issuer\n");
                    status.push_str(&format!("organization_name={}\n", organization_name));
                    self.verify_view = Some(VerifyResultView {
                        verification_id: published.proof.verification_id.clone(),
                        creator_public_key_base64: base64::engine::general_purpose::STANDARD
                            .encode(published.proof.creator_public_key),
                        signature_base64: base64::engine::general_purpose::STANDARD
                            .encode(published.proof.signature.0),
                        issuer_certificate_id: Some(id.to_string()),
                        issuer_certified: true,
                        organization_name: Some(organization_name),
                        issuer_unverified_reason: None,
                    });
                }
                _ => {
                    status.push_str("unverified issuer\n");
                    self.verify_view = Some(VerifyResultView {
                        verification_id: published.proof.verification_id.clone(),
                        creator_public_key_base64: base64::engine::general_purpose::STANDARD
                            .encode(published.proof.creator_public_key),
                        signature_base64: base64::engine::general_purpose::STANDARD
                            .encode(published.proof.signature.0),
                        issuer_certificate_id: Some(id.to_string()),
                        issuer_certified: false,
                        organization_name: None,
                        issuer_unverified_reason: fetch_err_reason
                            .or_else(|| issuer_unverified_reason(&cert_detailed)),
                    });
                }
            }
        } else {
            status.push_str("unverified issuer\n");
            self.verify_view = Some(VerifyResultView {
                verification_id: published.proof.verification_id.clone(),
                creator_public_key_base64: base64::engine::general_purpose::STANDARD
                    .encode(published.proof.creator_public_key),
                signature_base64: base64::engine::general_purpose::STANDARD
                    .encode(published.proof.signature.0),
                issuer_certificate_id: None,
                issuer_certified: false,
                organization_name: None,
                issuer_unverified_reason: None,
            });
        }
        self.verify_status = status;
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
