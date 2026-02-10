use anyhow::Result;
use base64::Engine as _;
use crate::modules::asset::create_proof_from_bytes;
use crate::modules::asset::Proof;
use crate::modules::bootstrap::{report_and_get_peers, PeerEntry, PeerReport};
use crate::modules::certification::PublishedProof;
use crate::modules::hash::blake3_hash_bytes;
use crate::modules::issuer_certificate::{
    fetch_certificate_bundle, verify_issuer_certificate_detailed, IssuerCertificateBundle,
    IssuerCertificationDetailed,
};
use crate::modules::metadata::{AssetType, Metadata};
use crate::modules::net_utils::{
    is_invalid_observed_ip, is_invalid_peer_addr, is_unroutable_ip,
};
use crate::modules::network::{
    connected_session_peers, fetch_proof_from_peers, fetch_published_proof_from_peers,
    ping_peer_detailed, replicate_proof, replicate_published_proof, run_node_with_shutdown,
    NodeConfig, PeerConnections,
};
use crate::modules::settings::{AppConfig, CntTrackerEntry};
use crate::modules::storage::Storage;
use crate::modules::verification::verify_proof;
use crate::p2p::{run_p2p, OutboundMsg};
use crate::config::{
    DEFAULT_CERTS_URL, DEFAULT_CNT_TRACKER_ADDR, DEFAULT_CREATE_ASSET_TYPE, DEFAULT_DATA_DIR,
    DEFAULT_NODE_BIND,
};
use crate::KeypairBytes;
use eframe::egui;
use igd_next::aio::tokio as igd_tokio;
use igd_next::{PortMappingProtocol, SearchOptions};
use std::collections::{HashMap, HashSet};
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::UdpSocket;
use std::path::PathBuf;
use std::process::Command;
use tokio::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::watch;
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
enum GuiTaskMsg {
    CreateDone {
        verification_id: String,
        creator_public_key_base64: String,
        signature_base64: String,
        issuer_certificate_id_display: String,
    },
    VerifyDone {
        status: String,
        view: Option<VerifyResultView>,
    },
    TaskError {
        message: String,
    },
}

#[derive(Debug, Clone)]
struct VerifyResultView {
    verification_id: String,
    timestamp_rfc3339: String,
    creator_public_key_base64: String,
    signature_base64: String,
    issuer_certificate_id: Option<String>,
    issuer_certified: bool,
    organization_name: Option<String>,
    issuer_unverified_reason: Option<String>,
}

#[derive(Debug, Clone, Default)]
struct PeerDialStatus {
    last_attempt: Option<Instant>,
    last_result: Option<Instant>,
    last_duration_ms: Option<u128>,
    last_ok: Option<Instant>,
    last_stage: Option<String>,
    last_stage_msg: Option<String>,
    last_error: Option<String>,
    ok_count: u64,
    err_count: u64,
    consecutive_failures: u32,
    failure_score: u64,
    last_score_decay: Option<Instant>,
}

#[derive(Debug, Default, Clone)]
struct CntUiStatus {
    last_ok: Option<Instant>,
    last_error: Option<String>,
    last_entry_count: usize,
    requester_stable: bool,
}

fn issuer_unverified_reason(d: &IssuerCertificationDetailed) -> Option<String> {
    match d {
        IssuerCertificationDetailed::Certified { .. } => None,
        IssuerCertificationDetailed::NotFound => {
            Some("Certificate_id not found in certs.json".to_string())
        }
        IssuerCertificationDetailed::InvalidCaSignature => {
            Some("Certificate CA signature invalid".to_string())
        }
        IssuerCertificationDetailed::InvalidValidityWindow => {
            Some("Certificate not valid now (expired/not yet valid/invalid window)".to_string())
        }
        IssuerCertificationDetailed::InvalidIssuerPublicKey => {
            Some("Certificate issuer_public_key is invalid base64/length".to_string())
        }
        IssuerCertificationDetailed::IssuerKeyMismatch => Some(
            "Issuer key mismatch" // proof.creator_public_key != certificate.issuer_public_key (you signed the proof with the wrong keypair)
                .to_string(),
        ),
    }
}

fn drop_default_port_dupes(peers: &mut Vec<SocketAddr>) {
    let mut has_non_default: HashSet<IpAddr> = HashSet::new();
    for p in peers.iter() {
        if p.port() != 9001 {
            has_non_default.insert(p.ip());
        }
    }
    if has_non_default.is_empty() {
        return;
    }
    peers.retain(|p| !(p.port() == 9001 && has_non_default.contains(&p.ip())));
}

pub fn run_gui() -> Result<()> {
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size(egui::vec2(700.0, 700.0)),
        ..Default::default()
    };
    eframe::run_native(
        "DAVP - Decentralized Asset Verification Protocol - GUI Mode",
        native_options,
        Box::new(|_cc| Box::new(DavpApp::default())),
    )
    .map_err(|e| anyhow::anyhow!(e.to_string()))?;

    Ok(())
}

struct DavpApp {
    tab: Tab,

    storage_dir: String,

    config_import_path: String,
    config_export_path: String,

    peers: String,
    seed_peers_bulk_edit: bool,
    seed_peers_last_applied: String,
    seed_peers_last_error: String,

    cnt_server: String,
    cnt_enabled: bool,

    cnt_selected_addr: String,
    cnt_trackers: Vec<CntTrackerEntry>,
    cnt_new_name: String,
    cnt_new_addr: String,

    node_port: u16,
    node_port_text: String,
    detected_ip: IpAddr,
    observed_public_ip: Arc<Mutex<Option<IpAddr>>>,

    node_bind: String,
    advertise_addr: String,
    upnp_enabled: bool,
    upnp_status_line: Arc<Mutex<String>>,
    upnp_external_ip: Arc<Mutex<Option<IpAddr>>>,
    upnp_mapped_addr: Arc<Mutex<Option<SocketAddr>>>,
    upnp_handle: Option<tokio::task::JoinHandle<()>>,
    max_peers: usize,

    networking_started: bool,
    networking_started_at: Option<Instant>,

    peers_arc: Arc<RwLock<Vec<SocketAddr>>>,
    peer_graph: Arc<RwLock<HashMap<SocketAddr, Vec<SocketAddr>>>>,

    bootstrap_entries: Arc<Mutex<Vec<PeerEntry>>>,
    reachable_peers: Arc<Mutex<Vec<SocketAddr>>>,
    recent_peer_hits: Arc<Mutex<HashMap<SocketAddr, Instant>>>,
    dial_diagnostics: Arc<Mutex<HashMap<SocketAddr, PeerDialStatus>>>,
    cnt_ui_status: Arc<Mutex<CntUiStatus>>,
    last_inbound: Arc<Mutex<Option<Instant>>>,
    tasks_started: bool,

    node_shutdown_tx: Option<watch::Sender<bool>>,
    node_handle: Option<tokio::task::JoinHandle<()>>,
    sync_handle: Option<tokio::task::JoinHandle<()>>,
    cnt_handle: Option<tokio::task::JoinHandle<()>>,
    sync_shutdown_tx: Option<watch::Sender<bool>>,
    cnt_enabled_tx: Option<watch::Sender<bool>>,

    p2p_shutdown_tx: Option<watch::Sender<bool>>,
    p2p_handle: Option<tokio::task::JoinHandle<()>>,
    p2p_outbound_tx: Option<mpsc::UnboundedSender<OutboundMsg>>,

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
    create_modal_open: bool,
    create_in_progress: bool,

    verify_modal_open: bool,
    verify_in_progress: bool,

    // verify
    verify_verification_id: String,
    verify_file_path: String,
    verify_status: String,
    verify_view: Option<VerifyResultView>,

    certs_url: String,
    certs_last_fetch_status: String,
    certs_bundle_cache: Option<IssuerCertificateBundle>,
    certs_bundle_cache_at: Option<Instant>,

    last_error: String,

    last_saved_config: Option<AppConfig>,

    gui_task_tx: mpsc::UnboundedSender<GuiTaskMsg>,
    gui_task_rx: mpsc::UnboundedReceiver<GuiTaskMsg>,
}

impl Default for DavpApp {
    fn default() -> Self {
        let peers_arc: Arc<RwLock<Vec<SocketAddr>>> = Arc::new(RwLock::new(Vec::new()));
        let peer_graph: Arc<RwLock<HashMap<SocketAddr, Vec<SocketAddr>>>> = Arc::new(RwLock::new(HashMap::new()));
        let recent_peer_hits: Arc<Mutex<HashMap<SocketAddr, Instant>>> = Arc::new(Mutex::new(HashMap::new()));
        let dial_diagnostics: Arc<Mutex<HashMap<SocketAddr, PeerDialStatus>>> = Arc::new(Mutex::new(HashMap::new()));
        let cnt_ui_status: Arc<Mutex<CntUiStatus>> = Arc::new(Mutex::new(CntUiStatus::default()));
        let observed_public_ip: Arc<Mutex<Option<IpAddr>>> = Arc::new(Mutex::new(None));
        let upnp_status_line: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
        let upnp_external_ip: Arc<Mutex<Option<IpAddr>>> = Arc::new(Mutex::new(None));
        let upnp_mapped_addr: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
        let last_inbound: Arc<Mutex<Option<Instant>>> = Arc::new(Mutex::new(None));
        let (gui_task_tx, gui_task_rx) = mpsc::unbounded_channel::<GuiTaskMsg>();

        Self {
            tab: Tab::Workspace,
            storage_dir: DEFAULT_DATA_DIR.to_string(),
            config_import_path: String::new(),
            config_export_path: String::new(),
            peers: "".to_string(),
            seed_peers_bulk_edit: false,
            seed_peers_last_applied: String::new(),
            seed_peers_last_error: String::new(),
            cnt_server: DEFAULT_CNT_TRACKER_ADDR.to_string(),
            cnt_enabled: false,

            cnt_selected_addr: DEFAULT_CNT_TRACKER_ADDR.to_string(),
            cnt_trackers: Vec::new(),
            cnt_new_name: String::new(),
            cnt_new_addr: String::new(),

            node_port: 9001,
            node_port_text: "9001".to_string(),
            detected_ip: detect_local_ip().unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            observed_public_ip: Arc::clone(&observed_public_ip),

            node_bind: DEFAULT_NODE_BIND.to_string(),
            advertise_addr: String::new(),
            upnp_enabled: false,
            upnp_status_line: Arc::clone(&upnp_status_line),
            upnp_external_ip: Arc::clone(&upnp_external_ip),
            upnp_mapped_addr: Arc::clone(&upnp_mapped_addr),
            upnp_handle: None,
            max_peers: 50,
            networking_started: false,
            networking_started_at: None,
            peers_arc: Arc::clone(&peers_arc),
            peer_graph: Arc::clone(&peer_graph),

            bootstrap_entries: Arc::new(Mutex::new(Vec::new())),
            reachable_peers: Arc::new(Mutex::new(Vec::new())),
            recent_peer_hits: Arc::clone(&recent_peer_hits),
            dial_diagnostics: Arc::clone(&dial_diagnostics),
            cnt_ui_status: Arc::clone(&cnt_ui_status),
            last_inbound: Arc::clone(&last_inbound),
            tasks_started: false,
            node_shutdown_tx: None,
            node_handle: None,
            sync_handle: None,
            cnt_handle: None,
            sync_shutdown_tx: None,
            cnt_enabled_tx: None,
            p2p_shutdown_tx: None,
            p2p_handle: None,
            p2p_outbound_tx: None,
            rt: tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("tokio runtime"),

            keypair_base64: String::new(),
            public_key_base64: String::new(),

            create_file_path: String::new(),
            create_asset_type: DEFAULT_CREATE_ASSET_TYPE.to_string(),
            create_ai_assisted: false,
            create_description: String::new(),
            create_tags: String::new(),
            create_parent_verification_id: String::new(),
            create_issuer_certificate_id: String::new(),
            created_verification_id: String::new(),
            created_creator_public_key_base64: String::new(),
            created_signature_base64: String::new(),
            created_issuer_certificate_id_display: String::new(),
            create_modal_open: false,
            create_in_progress: false,

            verify_modal_open: false,
            verify_in_progress: false,

            verify_verification_id: String::new(),
            verify_file_path: String::new(),
            verify_status: String::new(),
            verify_view: None,

            certs_url: DEFAULT_CERTS_URL.to_string(),
            certs_last_fetch_status: String::new(),
            certs_bundle_cache: None,
            certs_bundle_cache_at: None,

            last_error: String::new(),

            last_saved_config: None,

            gui_task_tx,
            gui_task_rx,
        }
    }
}

#[derive(Default, Clone, Copy, PartialEq, Eq)]
enum Tab {
    #[default]
    Workspace,
    Keygen,
}

impl eframe::App for DavpApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let _ = (&self.config_export_path, &self.cnt_new_name, &self.cnt_new_addr);

        ctx.request_repaint_after(Duration::from_millis(100));

        while let Ok(msg) = self.gui_task_rx.try_recv() {
            match msg {
                GuiTaskMsg::CreateDone {
                    verification_id,
                    creator_public_key_base64,
                    signature_base64,
                    issuer_certificate_id_display,
                } => {
                    self.create_in_progress = false;
                    self.create_modal_open = false;
                    self.created_verification_id = verification_id;
                    self.created_creator_public_key_base64 = creator_public_key_base64;
                    self.created_signature_base64 = signature_base64;
                    self.created_issuer_certificate_id_display = issuer_certificate_id_display;
                }
                GuiTaskMsg::VerifyDone { status, view } => {
                    self.verify_in_progress = false;
                    self.verify_modal_open = false;
                    self.verify_status = status;
                    self.verify_view = view;
                }
                GuiTaskMsg::TaskError { message } => {
                    self.create_in_progress = false;
                    self.verify_in_progress = false;
                    self.last_error = message;
                }
            }
        }

        egui::TopBottomPanel::top("top")
            .resizable(false)
            .show(ctx, |ui| {
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.selectable_value(&mut self.tab, Tab::Workspace, "Workspace");
                    ui.selectable_value(&mut self.tab, Tab::Keygen, "Keygen");

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(format!(
                            "CNT: {}",
                            if self.cnt_enabled { "enabled" } else { "disabled" }
                        ));
                        ui.label(format!(
                            "Network: {}",
                            if self.networking_started { "up" } else { "down" }
                        ));
                    });
                });

                ui.add_space(6.0);
                self.ui_network_bar(ui);
                ui.add_space(6.0);
            });

        if self.networking_started {
            self.ensure_background_tasks();
        }

        egui::TopBottomPanel::bottom("bottom_error_bar")
            .resizable(false)
            .show(ctx, |ui| {
                let bar_h = 24.0;
                ui.set_min_height(bar_h);
                ui.allocate_ui_with_layout(
                    egui::vec2(ui.available_width(), bar_h),
                    egui::Layout::left_to_right(egui::Align::Center),
                    |ui| {
                        if self.networking_started {
                            ui.label(egui::RichText::new("Running").color(egui::Color32::WHITE));
                        } else {
                            ui.label("Ready");
                        }

                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if !self.last_error.is_empty() {
                                let resp = ui.add(
                                    egui::Label::new(
                                        egui::RichText::new(&self.last_error)
                                            .color(egui::Color32::RED),
                                    )
                                    .sense(egui::Sense::click()),
                                );
                                if resp.clicked() {
                                    self.last_error.clear();
                                }
                            }
                        });
                    },
                );
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            match self.tab {
                Tab::Workspace => self.ui_workspace(ui),
                Tab::Keygen => self.ui_keygen(ui),
            }
        });

        self.autosave_app_config();
    }
}

impl DavpApp {
    const INPUT_WIDTH: f32 = 560.0;

    fn recompute_network_addrs(&mut self) {
        self.node_bind = format!("0.0.0.0:{}", self.node_port);
        self.advertise_addr = format!("{}:{}", self.detected_ip, self.node_port);
    }

    fn all_cnt_trackers(&self) -> Vec<(String, String)> {
        let mut v = vec![
            ("CNT World".to_string(), DEFAULT_CNT_TRACKER_ADDR.to_string()),
            ("Local".to_string(), "127.0.0.1:5157".to_string()),
        ];
        for t in &self.cnt_trackers {
            v.push((t.name.clone(), t.addr.clone()));
        }
        v
    }

    fn all_certs_sources(&self) -> Vec<(String, String)> {
        vec![("DAVP World".to_string(), DEFAULT_CERTS_URL.to_string())]
    }

    fn apply_seed_peers(&mut self) {
        let s = self.peers.trim();
        if s == self.seed_peers_last_applied.trim() {
            return;
        }

        if s.is_empty() {
            self.seed_peers_last_applied.clear();
            self.seed_peers_last_error.clear();
            if !self.networking_started {
                let peers_arc = Arc::clone(&self.peers_arc);
                self.rt.block_on(async move {
                    peers_arc.write().await.clear();
                });
            }
            return;
        }

        let list = match parse_peers(s) {
            Ok(v) => v,
            Err(e) => {
                self.seed_peers_last_error = e;
                return;
            }
        };

        self.seed_peers_last_error.clear();
        self.seed_peers_last_applied = s.to_string();

        let peers_arc = Arc::clone(&self.peers_arc);
        let networking_started = self.networking_started;
        self.rt.block_on(async move {
            let mut peers = peers_arc.write().await;
            if !networking_started {
                *peers = list;
                return;
            }
            for p in list {
                if !peers.contains(&p) {
                    peers.push(p);
                }
            }
        });
    }

    fn current_app_config_snapshot(&self) -> AppConfig {
        AppConfig {
            data_storage_location: self.storage_dir.trim().to_string(),
            auto_save: true,

            peers: self.peers.clone(),
            node_bind: self.node_bind.clone(),
            advertise_addr: self.advertise_addr.clone(),
            upnp_enabled: self.upnp_enabled,
            max_peers: self.max_peers,

            cnt_enabled: self.cnt_enabled,
            cnt_selected_addr: self.cnt_selected_addr.clone(),
            cnt_trackers: self.cnt_trackers.clone(),

            certs_url: self.certs_url.clone(),

            keypair_base64: self.keypair_base64.clone(),
            create_file_path: self.create_file_path.clone(),
            create_asset_type: self.create_asset_type.clone(),
            create_ai_assisted: self.create_ai_assisted,
            create_description: self.create_description.clone(),
            create_tags: self.create_tags.clone(),
            create_parent_verification_id: self.create_parent_verification_id.clone(),
            create_issuer_certificate_id: self.create_issuer_certificate_id.clone(),

            verify_verification_id: self.verify_verification_id.clone(),
            verify_file_path: self.verify_file_path.clone(),
        }
    }

    fn apply_app_config(&mut self, cfg: &AppConfig) {
        if !cfg.data_storage_location.trim().is_empty() {
            self.storage_dir = cfg.data_storage_location.clone();
        }

        self.peers = cfg.peers.clone();
        if let Ok(a) = cfg.node_bind.parse::<SocketAddr>() {
            self.node_port = a.port();
        }
        self.node_port_text = self.node_port.to_string();
        self.recompute_network_addrs();
        self.upnp_enabled = cfg.upnp_enabled;
        self.max_peers = cfg.max_peers;
        self.cnt_enabled = cfg.cnt_enabled;

        self.cnt_trackers = cfg.cnt_trackers.clone();

        let candidate = cfg.cnt_selected_addr.trim();
        if !candidate.is_empty()
            && self
                .all_cnt_trackers()
                .iter()
                .any(|(_, a)| a.trim() == candidate)
        {
            self.cnt_selected_addr = candidate.to_string();
        } else {
            self.cnt_selected_addr = DEFAULT_CNT_TRACKER_ADDR.to_string();
        }
        self.cnt_server = self.cnt_selected_addr.clone();

        if !cfg.certs_url.trim().is_empty() {
            self.certs_url = cfg.certs_url.clone();
        }

        self.keypair_base64 = cfg.keypair_base64.clone();
        self.create_file_path = cfg.create_file_path.clone();
        self.create_asset_type = cfg.create_asset_type.clone();
        self.create_ai_assisted = cfg.create_ai_assisted;
        self.create_description = cfg.create_description.clone();
        self.create_tags = cfg.create_tags.clone();
        self.create_parent_verification_id = cfg.create_parent_verification_id.clone();
        self.create_issuer_certificate_id = cfg.create_issuer_certificate_id.clone();

        self.verify_verification_id = cfg.verify_verification_id.clone();
        self.verify_file_path = cfg.verify_file_path.clone();
    }

    fn autosave_app_config(&mut self) {
        let snapshot = self.current_app_config_snapshot();

        if self
            .last_saved_config
            .as_ref()
            .is_some_and(|prev| *prev == snapshot)
        {
            return;
        }

        let path = AppConfig::path_in_repo_root();
        if snapshot.save(&path).is_ok() {
            self.last_saved_config = Some(snapshot);
        }
    }

    #[allow(dead_code)]
    fn export_app_config_to_path(&mut self, selected: &std::path::Path) -> std::result::Result<(), String> {
        let root_path = AppConfig::path_in_repo_root();
        let cfg = AppConfig::load_or_create(&root_path).map_err(|e| e.to_string())?;
        cfg.save(selected).map_err(|e| e.to_string())?;
        Ok(())
    }

    fn open_path_in_explorer(&self, p: &std::path::Path) -> std::result::Result<(), String> {
        #[cfg(target_os = "windows")]
        {
            let target = if p.is_dir() {
                p.to_path_buf()
            } else {
                p.parent().unwrap_or(p).to_path_buf()
            };
            Command::new("explorer")
                .arg(target)
                .spawn()
                .map_err(|e| e.to_string())?;
            Ok(())
        }

        #[cfg(not(target_os = "windows"))]
        {
            let _ = p;
            Err("Open folder not supported on this OS in GUI yet".to_string())
        }
    }

    fn ui_settings_section(&mut self, ui: &mut egui::Ui) {
        if self.networking_started {
            ui.add_space(6.0);
            ui.colored_label(egui::Color32::YELLOW, "Stop networking to change settings.");
            ui.add_space(6.0);
        }

        ui.add_enabled_ui(!self.networking_started, |ui| {
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.heading("Storage");

                ui.horizontal_wrapped(|ui| {
                    ui.label("Import config.json");
                    let w = ui.available_width().clamp(160.0, 520.0);
                    ui.add(egui::TextEdit::singleline(&mut self.config_import_path).desired_width(w));
                });

                ui.horizontal_wrapped(|ui| {
                    if ui.button("Browse").clicked() {
                        if let Some(file) = rfd::FileDialog::new()
                            .add_filter("config", &["json"])
                            .pick_file()
                        {
                            self.config_import_path = file.display().to_string();
                        }
                    }

                    if ui.button("Import").clicked() {
                        let p = PathBuf::from(self.config_import_path.trim());
                        if !self.config_import_path.trim().is_empty() {
                            if let Err(e) = self.import_app_config_from_path(&p) {
                                self.last_error = e;
                            }
                        }
                    }
                });

                let config_path = AppConfig::path_in_repo_root();
                ui.label(format!("config: {}", config_path.display()));

                ui.horizontal(|ui| {
                    if ui.button("Open config folder").clicked() {
                        if let Err(e) = self.open_path_in_explorer(&config_path) {
                            self.last_error = e;
                        }
                    }

                    if ui.button("Open data folder").clicked() {
                        let p = PathBuf::from(self.storage_dir.trim());
                        if let Err(e) = self.open_path_in_explorer(&p) {
                            self.last_error = e;
                        }
                    }
                });

                let old_storage_dir = self.storage_dir.clone();

                ui.horizontal_wrapped(|ui| {
                    ui.label("Data storage directory");

                    let w = (ui.available_width() * 0.55).clamp(160.0, 520.0);
                    ui.add(egui::TextEdit::singleline(&mut self.storage_dir).desired_width(w));

                    if ui.button("Browse").clicked() {
                        if let Some(folder) = rfd::FileDialog::new().pick_folder() {
                            self.storage_dir = folder.display().to_string();
                        }
                    }
                });

                if self.storage_dir.trim() != old_storage_dir.trim() {
                    self.autosave_app_config();
                }

                ui.add_space(2.0);
                ui.heading("Certificates / CNT Tracker");

                ui.horizontal_wrapped(|ui| {
                    let cert_sources = self.all_certs_sources();
                    let mut cert_idx = cert_sources
                        .iter()
                        .position(|(_, url)| url.trim() == self.certs_url.trim())
                        .unwrap_or(0);
                    egui::ComboBox::from_id_source("certs_source_select")
                        .selected_text(cert_sources[cert_idx].0.clone())
                        .show_ui(ui, |ui| {
                            for (i, (name, _)) in cert_sources.iter().enumerate() {
                                ui.selectable_value(&mut cert_idx, i, name);
                            }
                        });
                    self.certs_url = cert_sources[cert_idx].1.clone();

                    ui.separator();

                    let trackers = self.all_cnt_trackers();
                    let mut tracker_idx = trackers
                        .iter()
                        .position(|(_, addr)| addr.trim() == self.cnt_selected_addr.trim())
                        .unwrap_or(0);
                    egui::ComboBox::from_id_source("cnt_tracker_select")
                        .selected_text(format!("{} ({})", trackers[tracker_idx].0, trackers[tracker_idx].1))
                        .show_ui(ui, |ui| {
                            for (i, (name, addr)) in trackers.iter().enumerate() {
                                ui.selectable_value(
                                    &mut tracker_idx,
                                    i,
                                    format!("{} ({})", name, addr),
                                );
                            }
                        });
                    let new_addr = trackers[tracker_idx].1.clone();
                    if new_addr.trim() != self.cnt_selected_addr.trim() {
                        self.cnt_selected_addr = new_addr;
                        self.cnt_server = self.cnt_selected_addr.clone();
                        self.autosave_app_config();
                    }
                });

                ui.horizontal_wrapped(|ui| {
                    if ui.button("Refresh certs").clicked() {
                        let _ = self.fetch_certs_bundle_for_verify(true);
                    }
                });

                if !self.certs_last_fetch_status.is_empty() {
                    ui.monospace(&self.certs_last_fetch_status);
                }
            });
        });
    }

    fn ui_keygen(&mut self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical().auto_shrink([false; 2]).show(ui, |ui| {

            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.heading("Keygen");
                ui.label("Generate a signing keypair. Store the keypair securely; it can create proofs.");

                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if ui.button("Generate new keypair").clicked() {
                        if let Err(e) = self.create() {
                            self.last_error = e;
                        } else {
                            self.autosave_app_config();
                        }
                    }

                    if ui.button("Clear").clicked() {
                        self.keypair_base64.clear();
                        self.public_key_base64.clear();
                        self.autosave_app_config();
                    }
                });

                if !self.keypair_base64.trim().is_empty() {
                    let kp_copy = ui.button("Copy keypair");
                    if kp_copy.clicked() {
                        ui.output_mut(|o| o.copied_text = self.keypair_base64.clone());
                    }
                }

                ui.add_space(4.0);
                ui.label("Keypair (base64)");
                ui.add(
                    egui::TextEdit::multiline(&mut self.keypair_base64)
                        .desired_rows(5)
                        .desired_width(Self::INPUT_WIDTH),
                );

                if !self.public_key_base64.trim().is_empty() {
                    let pk_copy = ui.button("Copy public key");
                    if pk_copy.clicked() {
                        ui.output_mut(|o| o.copied_text = self.public_key_base64.clone());
                    }
                }

                ui.add_space(4.0);
                ui.label("Public key (base64)");
                ui.add(
                    egui::TextEdit::multiline(&mut self.public_key_base64)
                        .desired_rows(2)
                        .desired_width(Self::INPUT_WIDTH)
                        .interactive(false),
                );
            });
        });
    }

}

impl DavpApp {
    #[allow(dead_code)]
    fn load_app_config(&mut self) {
        let path = AppConfig::path_in_repo_root();
        if let Ok(cfg) = AppConfig::load_or_create(&path) {
            self.apply_app_config(&cfg);
            self.last_saved_config = Some(cfg);
        }
    }

    fn import_app_config_from_path(&mut self, selected: &std::path::Path) -> std::result::Result<(), String> {
        let bytes = std::fs::read(selected).map_err(|e| e.to_string())?;
        let s = String::from_utf8(bytes).map_err(|e| e.to_string())?;
        let cfg = serde_json::from_str::<AppConfig>(&s).map_err(|e| e.to_string())?;

        let root_path = AppConfig::path_in_repo_root();
        cfg.save(&root_path).map_err(|e| e.to_string())?;

        self.apply_app_config(&cfg);
        self.last_saved_config = Some(cfg);
        Ok(())
    }

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

    #[allow(dead_code)]
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
    fn stop_network(&mut self) {
        if let Some(tx) = self.sync_shutdown_tx.take() {
            let _ = tx.send(true);
        }

        if let Some(sync_handle) = self.sync_handle.take() {
            let _ = self.rt.block_on(sync_handle);
        }

        if let Some(tx) = self.p2p_shutdown_tx.take() {
            let _ = tx.send(true);
        }

        if let Some(p2p_handle) = self.p2p_handle.take() {
            let _ = self.rt.block_on(p2p_handle);
        }

        self.p2p_outbound_tx = None;

        if let Some(cnt_handle) = self.cnt_handle.take() {
            let _ = self.rt.block_on(cnt_handle);
        }

        if let Some(node_handle) = self.node_handle.take() {
            if let Some(tx) = self.node_shutdown_tx.take() {
                let _ = tx.send(true);
            }
            let _ = self.rt.block_on(node_handle);
        }

        if let Some(h) = self.upnp_handle.take() {
            h.abort();
            let _ = self.rt.block_on(h);
        }
        self.networking_started = false;
        self.networking_started_at = None;
        self.tasks_started = false;
        self.cnt_enabled_tx = None;

        if let Ok(mut g) = self.bootstrap_entries.lock() {
            g.clear();
        }
        if let Ok(mut g) = self.reachable_peers.lock() {
            g.clear();
        }
        if let Ok(mut g) = self.recent_peer_hits.lock() {
            g.clear();
        }
        if let Ok(mut g) = self.dial_diagnostics.lock() {
            g.clear();
        }
        if let Ok(mut s) = self.cnt_ui_status.lock() {
            *s = CntUiStatus::default();
        }

        if let Ok(mut g) = self.upnp_status_line.lock() {
            g.clear();
        }
        if let Ok(mut g) = self.upnp_external_ip.lock() {
            *g = None;
        }
        if let Ok(mut g) = self.upnp_mapped_addr.lock() {
            *g = None;
        }
    }

    fn ui_network_bar(&mut self, ui: &mut egui::Ui) {
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.vertical(|ui| {
                ui.horizontal(|ui| {
                    if !self.networking_started {
                        if ui.button("Start").clicked() {
                            self.apply_seed_peers();
                            self.networking_started = true;
                            self.networking_started_at = Some(Instant::now());
                        }
                    } else if ui.button("Stop").clicked() {
                        self.stop_network();
                    }

                    ui.separator();

                    let connected = {
                        self.rt
                            .block_on(async move { connected_session_peers().await.len() })
                    };
                    let known = {
                        let peers_arc = Arc::clone(&self.peers_arc);
                        self.rt.block_on(async move { peers_arc.read().await.len() })
                    };
                    ui.label(format!("Peers: {} out of {}", connected, known));
                });

                {
                    let status = self
                        .cnt_ui_status
                        .lock()
                        .map(|s| s.clone())
                        .unwrap_or_default();

                    let ok_part = status
                        .last_ok
                        .map(|t| format!(
                            "ok {}ms ago",
                            Instant::now().duration_since(t).as_millis()
                        ))
                        .unwrap_or_else(|| "ok never".to_string());

                    ui.add(
                        egui::Label::new(format!(
                            "CNT: {} entries | {} | {}",
                            status.last_entry_count,
                            if status.requester_stable {
                                "Stable"
                            } else {
                                "Non-stable"
                            },
                            ok_part
                        ))
                        .wrap(true),
                    );

                    if let Some(e) = status.last_error {
                        if !e.trim().is_empty() {
                            ui.add(egui::Label::new(format!("CNT error: {}", e)).wrap(true));
                        }
                    }
                }

                if self.networking_started {
                    let uptime = self
                        .networking_started_at
                        .map(|t| Instant::now().duration_since(t).as_secs())
                        .unwrap_or_default();

                    let upnp_line = self
                        .upnp_status_line
                        .lock()
                        .ok()
                        .map(|g| g.clone())
                        .filter(|s| !s.trim().is_empty())
                        .unwrap_or_else(|| "-".to_string());

                    let observed_ip = self.observed_public_ip.lock().ok().and_then(|g| *g);

                    ui.horizontal_wrapped(|ui| {
                        ui.label(": : ");
                        ui.label("Uptime");
                        ui.label(format!("{}s", uptime));
                        ui.separator();
                        ui.label("Listen");
                        ui.add(egui::Label::new(self.node_bind.trim()).wrap(true));
                    });

                    
                    let upstream_ip = observed_ip.or_else(|| self.upnp_external_ip.lock().ok().and_then(|g| *g));
                    if let Some(ip) = upstream_ip {
                        if is_unroutable_ip(ip) {
                            ui.colored_label(
                                egui::Color32::YELLOW,
                                "CGNAT/private upstream IP: inbound reachability unlikely (ok for client-only nodes).",
                            );
                        }
                    }
                }   
                
                egui::Grid::new("network_bar_grid")
                    .num_columns(2)
                    .spacing(egui::vec2(12.0, 6.0))
                    .show(ui, |ui| {
                    
                        ui.label("UPnP");
                        ui.add_enabled_ui(!self.networking_started, |ui| {
                            let before = self.upnp_enabled;
                            ui.checkbox(&mut self.upnp_enabled, "Enabled");
                            if before != self.upnp_enabled {
                                self.autosave_app_config();
                            }
                        });
                        ui.end_row();

                        ui.label("Node IP (auto)");
                        ui.add_enabled_ui(!self.networking_started, |ui| {
                            let ip = self
                                .observed_public_ip
                                .lock()
                                .ok()
                                .and_then(|g| *g)
                                .unwrap_or(self.detected_ip);
                            ui.label(ip.to_string());
                        });
                        ui.end_row();
                        

                        ui.label("Node port");
                        ui.add_enabled_ui(!self.networking_started, |ui| {
                            let mut v = self.node_port as u32;
                            let resp = ui.add(
                                egui::DragValue::new(&mut v)
                                    .clamp_range(1..=99999u32)
                                    .speed(1),
                            );
                            if ui.is_enabled() && resp.changed() {
                                let v = v.min(u16::MAX as u32);
                                self.node_port = v as u16;
                                self.node_port_text = self.node_port.to_string();
                                self.recompute_network_addrs();
                                self.autosave_app_config();
                            }
                        });

                        
                        ui.end_row();

                        ui.label("Max peers");
                        ui.add_enabled_ui(!self.networking_started, |ui| {
                            ui.horizontal(|ui| {
                                let mut v = self.max_peers;
                                let resp = ui.add(
                                    egui::DragValue::new(&mut v).clamp_range(50..=usize::MAX),
                                );
                                if ui.is_enabled() && resp.changed() {
                                    self.max_peers = v;
                                    self.autosave_app_config();
                                }
                            });
                        });
                        ui.end_row();


                        ui.with_layout(egui::Layout::top_down(egui::Align::Min), |ui| {
                            ui.label("Seed peers");
                        });
                        ui.add_enabled_ui(!self.networking_started, |ui| {
                            ui.vertical(|ui| {
                                ui.horizontal(|ui| {
                                    let mut changed = false;
                                    if self.seed_peers_bulk_edit {
                                        let resp = ui.add(
                                            egui::TextEdit::multiline(&mut self.peers)
                                                .desired_rows(5)
                                                .desired_width(420.0),
                                        );
                                        if resp.changed() {
                                            changed = true;
                                        }
                                        ui.vertical(|ui| {
                                            if ui.button("Bulk edit").clicked() {
                                                self.seed_peers_bulk_edit = false;
                                            }
                                        });
                                    } else {
                                        let resp = ui.add(
                                            egui::TextEdit::singleline(&mut self.peers)
                                                .desired_width(420.0),
                                        );
                                        if resp.changed() {
                                            changed = true;
                                        }
                                        if ui.button("Bulk edit").clicked() {
                                            self.seed_peers_bulk_edit = true;
                                        }
                                    }

                                    if changed {
                                        self.apply_seed_peers();
                                    }
                                });
                            });
                        });
                        ui.end_row();

                        ui.label("");
                        ui.colored_label(
                            egui::Color32::from_gray(140),
                            "Example: 127.0.0.1:9001, cnt.example.com",
                        );
                        ui.end_row();

                        ui.label("CNT Server");
                        ui.horizontal(|ui| {
                            ui.add_enabled_ui(!self.networking_started, |ui| {
                                let before = self.cnt_enabled;
                                ui.checkbox(&mut self.cnt_enabled, "Enabled");
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

                            ui.add_enabled_ui(!self.networking_started, |ui| {
                                let trackers = self.all_cnt_trackers();
                                let mut selected = trackers
                                    .iter()
                                    .position(|(_, addr)| addr.trim() == self.cnt_selected_addr.trim())
                                    .unwrap_or(0);

                                egui::ComboBox::from_id_source("cnt_tracker_select_top")
                                    .selected_text(trackers[selected].0.clone())
                                    .show_ui(ui, |ui| {
                                        for (i, (name, _)) in trackers.iter().enumerate() {
                                            ui.selectable_value(&mut selected, i, name);
                                        }

                                    });

                                let new_addr = trackers
                                    .get(selected)
                                    .map(|(_, addr)| addr.clone())
                                    .unwrap_or_else(|| DEFAULT_CNT_TRACKER_ADDR.to_string());
                                if new_addr.trim() != self.cnt_selected_addr.trim() {
                                    self.cnt_selected_addr = new_addr;
                                    self.cnt_server = self.cnt_selected_addr.clone();
                                    self.autosave_app_config();
                                }
                            });
                        });
                        ui.end_row();

                    });

                ui.add_space(6.0);

                egui::CollapsingHeader::new("Active sessions")
                    .default_open(false)
                    .show(ui, |ui| {
                        let mut peers = self.rt.block_on(async move { connected_session_peers().await });
                        peers.sort();
                        if peers.is_empty() {
                            ui.label("none");
                        } else {
                            for p in peers {
                                ui.monospace(p.to_string());
                            }
                        }
                    });

                egui::CollapsingHeader::new("Connected peers in last second")
                    .default_open(false)
                    .show(ui, |ui| {
                        let now = Instant::now();
                        let mut peers: Vec<SocketAddr> = Vec::new();
                        if let Ok(m) = self.recent_peer_hits.lock() {
                            for (addr, t) in m.iter() {
                                if now.duration_since(*t) <= Duration::from_secs(1) {
                                    peers.push(*addr);
                                }
                            }
                        }
                        peers.sort();

                        if peers.is_empty() {
                            ui.label("none");
                        } else {
                            for p in peers {
                                ui.monospace(p.to_string());
                            }
                        }
                    });

                egui::CollapsingHeader::new("Dial diagnostics")
                    .default_open(false)
                    .show(ui, |ui| {
                        let snapshot: HashMap<SocketAddr, PeerDialStatus> = self
                            .dial_diagnostics
                            .lock()
                            .map(|g| g.clone())
                            .unwrap_or_default();

                        if snapshot.is_empty() {
                            ui.label("none");
                            return;
                        }

                        let mut items: Vec<(SocketAddr, PeerDialStatus)> = snapshot.into_iter().collect();
                        items.sort_by_key(|(_, s)| s.last_attempt);
                        items.reverse();

                        let now = Instant::now();
                        for (peer, s) in items.into_iter().take(50) {
                            let age_ms = s
                                .last_attempt
                                .map(|t| now.duration_since(t).as_millis())
                                .unwrap_or_default();
                            let dur_ms = s.last_duration_ms.unwrap_or_default();
                            let stage = s
                                .last_stage
                                .as_deref()
                                .unwrap_or("-");
                            if let Some(err) = &s.last_error {
                                ui.monospace(format!(
                                    "{} | stage={} | unreachable (normal) | fail={} (consecutive={}) score={} | last={}ms_ago | dur={}ms | {}",
                                    peer,
                                    stage,
                                    s.err_count,
                                    s.consecutive_failures,
                                    s.failure_score,
                                    age_ms,
                                    dur_ms,
                                    err
                                ));
                            } else if s.last_ok.is_some() {
                                ui.monospace(format!(
                                    "{} | stage={} | ok={} score={} | last={}ms_ago | dur={}ms",
                                    peer,
                                    stage,
                                    s.ok_count,
                                    s.failure_score,
                                    age_ms,
                                    dur_ms
                                ));
                            } else {
                                ui.monospace(format!("{} | no attempts", peer));
                            }
                        }
                    });

                egui::CollapsingHeader::new("CNT gossip")
                    .default_open(false)
                    .show(ui, |ui| {
                        let entries = self
                            .bootstrap_entries
                            .lock()
                            .map(|g| g.clone())
                            .unwrap_or_default();

                        if entries.is_empty() {
                            ui.label("no entries");
                            return;
                        }

                        for e in entries {
                            let title = if e.stable {
                                format!("{} (stable)", e.addr)
                            } else {
                                e.addr.to_string()
                            };

                            egui::CollapsingHeader::new(title)
                                .id_source(format!("cnt_gossip_{}", e.addr))
                                .default_open(false)
                                .show(ui, |ui| {
                                    ui.label(format!(
                                        "uptime={}s known={} connected={}",
                                        e.uptime_seconds,
                                        e.known_peers.len(),
                                        e.connected_peers.len()
                                    ));

                                    ui.add_space(4.0);
                                    ui.label("Known peers");
                                    egui::ScrollArea::vertical()
                                        .id_source(format!("cnt_gossip_known_{}", e.addr))
                                        .max_height(120.0)
                                        .show(ui, |ui| {
                                        if e.known_peers.is_empty() {
                                            ui.label("(empty)");
                                        } else {
                                            for p in e.known_peers.iter() {
                                                ui.monospace(p.to_string());
                                            }
                                        }
                                    });

                                    ui.add_space(4.0);
                                    ui.label("Connected peers");
                                    egui::ScrollArea::vertical()
                                        .id_source(format!("cnt_gossip_connected_{}", e.addr))
                                        .max_height(120.0)
                                        .show(ui, |ui| {
                                        if e.connected_peers.is_empty() {
                                            ui.label("(empty)");
                                        } else {
                                            for p in e.connected_peers.iter() {
                                                ui.monospace(p.to_string());
                                            }
                                        }
                                    });
                                });
                        }
                    });
            });
        });
    }

    fn ensure_background_tasks(&mut self) {
        if self.tasks_started {
            return;
        }

        if !self.networking_started {
            return;
        }

        // Public address is discovered via peers (observed address in Ping/Pong).

        let bind: SocketAddr = match self.node_bind.parse() {
            Ok(v) => v,
            Err(_) => return,
        };

        let local_ip = self.detected_ip;
        let upnp_enabled = self.upnp_enabled;
        let upnp_status_line = Arc::clone(&self.upnp_status_line);
        let upnp_external_ip = Arc::clone(&self.upnp_external_ip);
        let upnp_mapped_addr = Arc::clone(&self.upnp_mapped_addr);

        let peers_arc = Arc::clone(&self.peers_arc);
        let peer_graph = Arc::clone(&self.peer_graph);
        let bootstrap_entries = Arc::clone(&self.bootstrap_entries);
        let reachable_peers = Arc::clone(&self.reachable_peers);
        let recent_peer_hits = Arc::clone(&self.recent_peer_hits);
        let dial_diagnostics = Arc::clone(&self.dial_diagnostics);
        let cnt_ui_status = Arc::clone(&self.cnt_ui_status);
        let observed_public_ip = Arc::clone(&self.observed_public_ip);

        let cnt_server: SocketAddr = match resolve_socket_addr(self.cnt_server.trim()) {
            Some(v) => v,
            None => return,
        };
        let max_peers = self.max_peers;
        let (sync_shutdown_tx, sync_shutdown_rx) = watch::channel(false);
        self.sync_shutdown_tx = Some(sync_shutdown_tx);

        let (node_shutdown_tx, node_shutdown_rx) = watch::channel(false);
        self.node_shutdown_tx = Some(node_shutdown_tx);

        let (p2p_shutdown_tx, p2p_shutdown_rx) = watch::channel(false);
        self.p2p_shutdown_tx = Some(p2p_shutdown_tx);

        let (cnt_enabled_tx, cnt_enabled_rx) = watch::channel(self.cnt_enabled);
        self.cnt_enabled_tx = Some(cnt_enabled_tx);

        let storage = Storage::new(self.storage_dir.clone());
        let advertise_addr_value: SocketAddr = self.advertise_addr.parse().unwrap_or(bind);
        let advertise_addr: Arc<Mutex<SocketAddr>> = Arc::new(Mutex::new(advertise_addr_value));
        let config = NodeConfig {
            bind_addr: bind,
            advertise_addr: Arc::clone(&advertise_addr),
            peers: Arc::clone(&peers_arc),
            peer_graph: Arc::clone(&peer_graph),
            last_inbound: Arc::clone(&self.last_inbound),
        };

        if upnp_enabled {
            let advertise_addr = Arc::clone(&advertise_addr);
            let upnp_mapped_addr_upnp = Arc::clone(&upnp_mapped_addr);
            let upnp_status_line_upnp = Arc::clone(&upnp_status_line);
            let upnp_handle = self.rt.spawn(async move {
                if let Ok(mut g) = upnp_status_line_upnp.lock() {
                    *g = "UPnP: searching gateway...".to_string();
                }

                let opts = SearchOptions {
                    timeout: Some(Duration::from_secs(3)),
                    ..Default::default()
                };
                let gw = match igd_tokio::search_gateway(opts).await {
                    Ok(v) => v,
                    Err(e) => {
                        if let Ok(mut g) = upnp_status_line_upnp.lock() {
                            *g = format!("UPnP: unavailable ({})", e);
                        }
                        return;
                    }
                };

                let ext_ip: Option<IpAddr> = match gw.get_external_ip().await {
                    Ok(v) => {
                        if let Ok(mut g) = upnp_external_ip.lock() {
                            *g = Some(v);
                        }
                        Some(v)
                    }
                    Err(e) => {
                        if let Ok(mut g) = upnp_status_line_upnp.lock() {
                            *g = format!(
                                "UPnP: gateway found, external IP unavailable ({})",
                                e
                            );
                        }
                        None
                    }
                };

                let local_addr = SocketAddr::new(local_ip, bind.port());
                let port = bind.port();

                let mut mapped: Option<SocketAddr> = None;
                let mut mapped_port: Option<u16> = None;
                if gw
                    .add_port(
                        PortMappingProtocol::TCP,
                        port,
                        local_addr,
                        3600,
                        "DAVP",
                    )
                    .await
                    .is_ok()
                {
                    mapped_port = Some(port);
                    if let Some(ext_ip) = ext_ip {
                        mapped = Some(SocketAddr::new(ext_ip, port));
                    }
                } else if let Ok(p) = gw
                    .add_any_port(PortMappingProtocol::TCP, local_addr, 3600, "DAVP")
                    .await
                {
                    mapped_port = Some(p);
                    if let Some(ext_ip) = ext_ip {
                        mapped = Some(SocketAddr::new(ext_ip, p));
                    }
                }

                if let Some(mapped) = mapped {
                    if let Ok(mut g) = upnp_mapped_addr_upnp.lock() {
                        *g = Some(mapped);
                    }
                    if !is_unroutable_ip(mapped.ip()) {
                        if let Ok(mut g) = advertise_addr.lock() {
                            *g = mapped;
                        }
                    }
                    if let Ok(mut g) = upnp_status_line_upnp.lock() {
                        *g = format!("UPnP: mapped {} -> {}", mapped, local_addr);
                    }
                    return;
                }

                if let Some(p) = mapped_port {
                    if let Ok(mut g) = upnp_status_line_upnp.lock() {
                        *g = format!(
                            "UPnP: mapped external port {} -> {} (external IP unknown)",
                            p, local_addr
                        );
                    }
                    return;
                }

                if let Ok(mut g) = upnp_status_line_upnp.lock() {
                    *g = match ext_ip {
                        Some(ip) => format!("UPnP: gateway external IP {} (no mapping)", ip),
                        None => "UPnP: gateway found (no mapping)".to_string(),
                    };
                }
            });

            self.upnp_handle = Some(upnp_handle);
        }

        // Start libp2p overlay network (gossipsub hub). This enables proof propagation even
        // when direct TCP dialing fails due to NAT.
        let (p2p_outbound_tx, p2p_outbound_rx) = mpsc::unbounded_channel::<OutboundMsg>();
        self.p2p_outbound_tx = Some(p2p_outbound_tx);
        let p2p_storage = storage.clone();
        let mut bootstrap = Vec::new();
        // Default hub. You can override with DAVP_P2P_HUB, e.g.
        // /ip4/cnt.unitedorigins.com/tcp/4002
        if let Ok(s) = std::env::var("DAVP_P2P_HUB") {
            if let Ok(ma) = s.parse::<libp2p::Multiaddr>() {
                bootstrap.push(ma);
            }
        }
        if bootstrap.is_empty() {
            if let Ok(ma) = "/ip4/cnt.unitedorigins.com/tcp/4002".parse::<libp2p::Multiaddr>() {
                bootstrap.push(ma);
            }
        }
        let listen_ma = "/ip4/0.0.0.0/tcp/0".parse::<libp2p::Multiaddr>().unwrap();
        let p2p_handle = self.rt.spawn(async move {
            let _ = run_p2p(p2p_storage, listen_ma, bootstrap, p2p_shutdown_rx, p2p_outbound_rx).await;
        });
        self.p2p_handle = Some(p2p_handle);

        let node_handle = self.rt.spawn(async move {
            let _ = run_node_with_shutdown(storage, config, node_shutdown_rx).await;
        });

        self.node_handle = Some(node_handle);

        let mut sync_shutdown_rx_ping = sync_shutdown_rx.clone();
        let cnt_enabled_rx_ping = cnt_enabled_rx.clone();

        let peers_arc_ping = Arc::clone(&peers_arc);
        let peer_graph_ping = Arc::clone(&peer_graph);
        let bootstrap_entries_ping = Arc::clone(&bootstrap_entries);
        let reachable_peers_ping = Arc::clone(&reachable_peers);
        let recent_peer_hits_ping = Arc::clone(&recent_peer_hits);
        let dial_diagnostics_ping = Arc::clone(&dial_diagnostics);
        let cnt_ui_status_ping = Arc::clone(&cnt_ui_status);
        let observed_public_ip_ping = Arc::clone(&observed_public_ip);
        let advertise_addr_ping = Arc::clone(&advertise_addr);

        let (cnt_force_tx, mut cnt_force_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
let dial_cursor = Arc::new(AtomicUsize::new(0));
        let sync_handle = self.rt.spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_millis(100));

            loop {
                if *sync_shutdown_rx_ping.borrow() {
                    break;
                }

                tokio::select! {
                    _ = sync_shutdown_rx_ping.changed() => {
                        continue;
                    }
                    _ = tick.tick() => {
                        let cnt_enabled = *cnt_enabled_rx_ping.borrow();
                        let ctx = SyncNetworkCtx {
                            bind,
                            advertise_addr: Arc::clone(&advertise_addr_ping),
                            max_peers,
                            peers_arc: Arc::clone(&peers_arc_ping),
                            peer_graph: Arc::clone(&peer_graph_ping),
                            cnt_server,
                            bootstrap_entries: Arc::clone(&bootstrap_entries_ping),
                            reachable_peers: Arc::clone(&reachable_peers_ping),
                            recent_peer_hits: Arc::clone(&recent_peer_hits_ping),
                            dial_diagnostics: Arc::clone(&dial_diagnostics_ping),
                            cnt_ui_status: Arc::clone(&cnt_ui_status_ping),
                            observed_public_ip: Arc::clone(&observed_public_ip_ping),
                            cnt_enabled,
                            cnt_report_only: false,
                            cnt_force_tx: cnt_force_tx.clone(),
                            dial_cursor: Arc::clone(&dial_cursor),
                        };
                        let _ = sync_network_once(ctx).await;
                    }
                }
            }
        });

        self.sync_handle = Some(sync_handle);

        let mut sync_shutdown_rx_cnt = sync_shutdown_rx.clone();
        let cnt_enabled_rx_cnt = cnt_enabled_rx.clone();

        let peers_arc_cnt = Arc::clone(&peers_arc);
        let peer_graph_cnt = Arc::clone(&peer_graph);
        let bootstrap_entries_cnt = Arc::clone(&bootstrap_entries);
        let cnt_ui_status_cnt = Arc::clone(&cnt_ui_status);
        let observed_public_ip_cnt = Arc::clone(&observed_public_ip);
        let advertise_addr_cnt = Arc::clone(&advertise_addr);
        let cnt_handle = self.rt.spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(1));
            let mut upload_gossip = false;
            let mut last_forced_report: Option<Instant> = None;

            loop {
                if *sync_shutdown_rx_cnt.borrow() {
                    break;
                }

                tokio::select! {
                    _ = sync_shutdown_rx_cnt.changed() => {
                        continue;
                    }
                    Some(_) = cnt_force_rx.recv() => {
                        let now = Instant::now();
                        let can_send = last_forced_report
                            .map(|t| now.duration_since(t) >= Duration::from_millis(250))
                            .unwrap_or(true);

                        if can_send {
                            last_forced_report = Some(now);
                            let cnt_enabled = *cnt_enabled_rx_cnt.borrow();
                            let ctx = CntReportCtx {
                                bind,
                                advertise_addr: Arc::clone(&advertise_addr_cnt),
                                peers_arc: Arc::clone(&peers_arc_cnt),
                                peer_graph: Arc::clone(&peer_graph_cnt),
                                upnp_enabled,
                                upnp_mapped_addr: Arc::clone(&upnp_mapped_addr),
                                upnp_status_line: Arc::clone(&upnp_status_line),
                                cnt_server,
                                bootstrap_entries: Arc::clone(&bootstrap_entries_cnt),
                                cnt_ui_status: Arc::clone(&cnt_ui_status_cnt),
                                observed_public_ip: Arc::clone(&observed_public_ip_cnt),
                                cnt_enabled,
                                upload_gossip: true,
                            };
                            let _ = cnt_report_once(ctx).await;
                        }
                    }
                    _ = tick.tick() => {
                        let cnt_enabled = *cnt_enabled_rx_cnt.borrow();
                        let ctx = CntReportCtx {
                            bind,
                            advertise_addr: Arc::clone(&advertise_addr_cnt),
                            peers_arc: Arc::clone(&peers_arc_cnt),
                            peer_graph: Arc::clone(&peer_graph_cnt),
                            upnp_enabled,
                            upnp_mapped_addr: Arc::clone(&upnp_mapped_addr),
                            upnp_status_line: Arc::clone(&upnp_status_line),
                            cnt_server,
                            bootstrap_entries: Arc::clone(&bootstrap_entries_cnt),
                            cnt_ui_status: Arc::clone(&cnt_ui_status_cnt),
                            observed_public_ip: Arc::clone(&observed_public_ip_cnt),
                            cnt_enabled,
                            upload_gossip,
                        };
                        let _ = cnt_report_once(ctx).await;
                        upload_gossip = !upload_gossip;
                    }
                }
            }
        });

        self.cnt_handle = Some(cnt_handle);

        self.tasks_started = true;
    }

    fn ui_workspace(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();

        egui::ScrollArea::vertical().auto_shrink([false; 2]).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.group(|ui| {
                    ui.heading("Create");
                    ui.separator();
                    if ui.button("Create Proof").clicked() {
                        self.create_modal_open = true;
                    }
                });

                ui.group(|ui| {
                    ui.heading("Verify");
                    ui.separator();
                    if ui.button("Verify Proof").clicked() {
                        self.verify_modal_open = true;
                    }
                });
            });

            ui.add_space(8.0);
            self.ui_settings_section(ui);

            if !self.created_verification_id.is_empty() {
                ui.add_space(8.0);
                egui::Frame::group(ui.style()).show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.heading("Output");
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.button("Dismiss").clicked() {
                                self.created_verification_id.clear();
                                self.created_creator_public_key_base64.clear();
                                self.created_signature_base64.clear();
                                self.created_issuer_certificate_id_display.clear();
                            }
                        });
                    });

                    egui::Grid::new("create_output_grid")
                        .num_columns(2)
                        .show(ui, |ui| {
                            ui.label("Verification ID");
                            ui.horizontal(|ui| {
                                let copy_w = 70.0;
                                let spacing = ui.spacing().item_spacing.x;
                                let w = (ui.available_width() - copy_w - spacing).max(120.0);
                                ui.add_sized(
                                    [w, 44.0],
                                    egui::TextEdit::multiline(&mut self.created_verification_id)
                                        .desired_rows(2)
                                        .interactive(false),
                                );
                                if ui.add_sized([copy_w, 28.0], egui::Button::new("Copy")).clicked() {
                                    ui.output_mut(|o| o.copied_text = self.created_verification_id.clone());
                                }
                            });
                            ui.end_row();

                            ui.label("Creator public key");
                            ui.horizontal(|ui| {
                                let copy_w = 70.0;
                                let spacing = ui.spacing().item_spacing.x;
                                let w = (ui.available_width() - copy_w - spacing).max(120.0);
                                ui.add_sized(
                                    [w, 44.0],
                                    egui::TextEdit::multiline(&mut self.created_creator_public_key_base64)
                                        .desired_rows(2)
                                        .interactive(false),
                                );
                                if ui.add_sized([copy_w, 28.0], egui::Button::new("Copy")).clicked() {
                                    ui.output_mut(|o| {
                                        o.copied_text = self.created_creator_public_key_base64.clone();
                                    });
                                }
                            });
                            ui.end_row();

                            ui.label("Signature");
                            ui.horizontal(|ui| {
                                let copy_w = 70.0;
                                let spacing = ui.spacing().item_spacing.x;
                                let w = (ui.available_width() - copy_w - spacing).max(120.0);
                                ui.add_sized(
                                    [w, 44.0],
                                    egui::TextEdit::multiline(&mut self.created_signature_base64)
                                        .desired_rows(2)
                                        .interactive(false),
                                );
                                if ui.add_sized([copy_w, 28.0], egui::Button::new("Copy")).clicked() {
                                    ui.output_mut(|o| o.copied_text = self.created_signature_base64.clone());
                                }
                            });
                            ui.end_row();

                            if !self.created_issuer_certificate_id_display.is_empty() {
                                ui.label("issuer_certificate_id");
                                ui.horizontal(|ui| {
                                    let copy_w = 70.0;
                                    let spacing = ui.spacing().item_spacing.x;
                                    let w = (ui.available_width() - copy_w - spacing).max(120.0);
                                    ui.add_sized(
                                        [w, 44.0],
                                        egui::TextEdit::multiline(&mut self.created_issuer_certificate_id_display)
                                            .desired_rows(2)
                                            .interactive(false),
                                    );
                                    if ui.add_sized([copy_w, 28.0], egui::Button::new("Copy")).clicked() {
                                        ui.output_mut(|o| {
                                            o.copied_text = self.created_issuer_certificate_id_display.clone()
                                        });
                                    }
                                });
                                ui.end_row();
                            }
                        });
                });
            }

            if self.verify_view.is_some() || !self.verify_status.is_empty() {
                ui.add_space(8.0);
                egui::Frame::group(ui.style()).show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.heading("Verification result");
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.button("Dismiss").clicked() {
                                self.verify_view = None;
                                self.verify_status.clear();
                            }
                        });
                    });

                    if let Some(v) = &self.verify_view {
                        ui.horizontal(|ui| {
                            ui.label("Status");
                            ui.colored_label(egui::Color32::GREEN, "valid");
                        });

                        egui::Grid::new("verify_output_grid")
                            .num_columns(2)
                            .show(ui, |ui| {
                                ui.label("Timestamp");
                                ui.horizontal(|ui| {
                                    let copy_w = 70.0;
                                    let spacing = ui.spacing().item_spacing.x;
                                    let w = (ui.available_width() - copy_w - spacing).max(120.0);
                                    ui.add_sized(
                                        [w, 44.0],
                                        egui::TextEdit::multiline(&mut v.timestamp_rfc3339.clone())
                                            .desired_rows(2)
                                            .interactive(false),
                                    );
                                    if ui.add_sized([copy_w, 28.0], egui::Button::new("Copy")).clicked() {
                                        ui.output_mut(|o| o.copied_text = v.timestamp_rfc3339.clone());
                                    }
                                });
                                ui.end_row();

                                ui.label("Verification ID");
                                ui.horizontal(|ui| {
                                    let copy_w = 70.0;
                                    let spacing = ui.spacing().item_spacing.x;
                                    let w = (ui.available_width() - copy_w - spacing).max(120.0);
                                    ui.add_sized(
                                        [w, 44.0],
                                        egui::TextEdit::multiline(&mut v.verification_id.clone())
                                            .desired_rows(2)
                                            .interactive(false),
                                    );
                                    if ui.add_sized([copy_w, 28.0], egui::Button::new("Copy")).clicked() {
                                        ui.output_mut(|o| o.copied_text = v.verification_id.clone());
                                    }
                                });
                                ui.end_row();

                                ui.label("Creator public key");
                                ui.horizontal(|ui| {
                                    let copy_w = 70.0;
                                    let spacing = ui.spacing().item_spacing.x;
                                    let w = (ui.available_width() - copy_w - spacing).max(120.0);
                                    ui.add_sized(
                                        [w, 44.0],
                                        egui::TextEdit::multiline(&mut v.creator_public_key_base64.clone())
                                            .desired_rows(2)
                                            .interactive(false),
                                    );
                                    if ui.add_sized([copy_w, 28.0], egui::Button::new("Copy")).clicked() {
                                        ui.output_mut(|o| o.copied_text = v.creator_public_key_base64.clone());
                                    }
                                });
                                ui.end_row();

                                ui.label("Signature");
                                ui.horizontal(|ui| {
                                    let copy_w = 70.0;
                                    let spacing = ui.spacing().item_spacing.x;
                                    let w = (ui.available_width() - copy_w - spacing).max(120.0);
                                    ui.add_sized(
                                        [w, 44.0],
                                        egui::TextEdit::multiline(&mut v.signature_base64.clone())
                                            .desired_rows(2)
                                            .interactive(false),
                                    );
                                    if ui.add_sized([copy_w, 28.0], egui::Button::new("Copy")).clicked() {
                                        ui.output_mut(|o| o.copied_text = v.signature_base64.clone());
                                    }
                                });
                                ui.end_row();

                                if let Some(id) = &v.issuer_certificate_id {
                                    ui.label("issuer_certificate_id");
                                    ui.horizontal(|ui| {
                                        let copy_w = 70.0;
                                        let spacing = ui.spacing().item_spacing.x;
                                        let w = (ui.available_width() - copy_w - spacing).max(120.0);
                                        ui.add_sized(
                                            [w, 44.0],
                                            egui::TextEdit::multiline(&mut id.clone())
                                                .desired_rows(2)
                                                .interactive(false),
                                        );
                                        if ui.add_sized([copy_w, 28.0], egui::Button::new("Copy")).clicked() {
                                            ui.output_mut(|o| o.copied_text = id.clone());
                                        }
                                    });
                                    ui.end_row();
                                }
                            });

                        if let Some(id) = &v.issuer_certificate_id {
                            let _ = id;
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
                    } else {
                        ui.label("Status");
                        ui.monospace(&self.verify_status);
                    }
                });
            }
        });

        let mut open = self.create_modal_open;
        let mut close_modal = false;
        if open {
            egui::Window::new("Create Proof")
                .collapsible(false)
                .resizable(true)
                .open(&mut open)
                .show(&ctx, |ui| {
                    let body_h = (ui.available_height() - 44.0).max(120.0);
                    egui::ScrollArea::vertical().auto_shrink([false; 2]).max_height(body_h).show(ui, |ui| {
                        egui::Frame::group(ui.style()).show(ui, |ui| {
                            ui.heading("Inputs");
                            egui::Grid::new("create_inputs_grid")
                                .num_columns(3)
                                .spacing(egui::vec2(12.0, 8.0))
                                .show(ui, |ui| {
                                    ui.label("File");
                                    ui.add(
                                        egui::TextEdit::singleline(&mut self.create_file_path)
                                            .desired_width(Self::INPUT_WIDTH),
                                    );
                                    if ui.button("Browse").clicked() {
                                        if let Some(path) = rfd::FileDialog::new().pick_file() {
                                            self.create_file_path = path.to_string_lossy().to_string();
                                        }
                                    }
                                    ui.end_row();

                                    ui.label("Asset type:");
                                    if self.create_asset_type.is_empty() {
                                        self.create_asset_type = DEFAULT_CREATE_ASSET_TYPE.to_string();
                                    }
                                    ui.horizontal(|ui| {
                                        egui::ComboBox::from_id_source("asset_type")
                                            .selected_text(self.create_asset_type.clone())
                                            .show_ui(ui, |ui| {
                                                for t in ["other", "text", "image", "video", "audio", "code"] {
                                                    ui.selectable_value(&mut self.create_asset_type, t.to_string(), t);
                                                }
                                            });
                                        ui.add_space(8.0);
                                        ui.checkbox(&mut self.create_ai_assisted, "AI assisted");
                                    });
                                    ui.end_row();
                                });
                            ui.separator();
                            ui.heading("Metadata");
                            ui.label("Description*:");
                            ui.add(
                                egui::TextEdit::multiline(&mut self.create_description)
                                    .desired_rows(4)
                                    .desired_width(Self::INPUT_WIDTH),
                            );

                            ui.add_space(8.0);

                            egui::Grid::new("create_metadata_grid")
                                .num_columns(2)
                                .spacing(egui::vec2(12.0, 8.0))
                                .show(ui, |ui| {
                                    ui.label("Tags (comma-separated)*:");
                                    ui.add(
                                        egui::TextEdit::singleline(&mut self.create_tags)
                                            .desired_width(Self::INPUT_WIDTH),
                                    );
                                    ui.end_row();

                                    ui.label("Parent verification ID*:");
                                    ui.add(
                                        egui::TextEdit::singleline(&mut self.create_parent_verification_id)
                                            .desired_width(Self::INPUT_WIDTH),
                                    );
                                    ui.end_row();

                                    ui.label("Issuer certificate ID*:");
                                    ui.add(
                                        egui::TextEdit::singleline(&mut self.create_issuer_certificate_id)
                                            .desired_width(Self::INPUT_WIDTH),
                                    );
                                    ui.end_row();
                                });
                            ui.separator();
                            ui.heading("Signing");
                            ui.label("Keypair (base64):");
                            ui.add(
                                egui::TextEdit::multiline(&mut self.keypair_base64)
                                    .desired_rows(5)
                                    .desired_width(Self::INPUT_WIDTH),
                            );
                        });
                    });

                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        let mut do_create = false;
                        if ui
                            .add_enabled(!self.create_in_progress, egui::Button::new("Create proof"))
                            .clicked()
                        {
                            do_create = true;
                        }
                        if ui.button("Cancel").clicked() {
                            close_modal = true;
                        }
                        if do_create {
                            self.start_create_proof();
                        }
                        if self.create_in_progress {
                            ui.add_space(8.0);
                            ui.monospace("working...");
                        }
                    });
                });
        }
        if close_modal {
            open = false;
        }
        self.create_modal_open = open;

        let mut verify_open = self.verify_modal_open;
        let mut close_verify_modal = false;
        if verify_open {
            egui::Window::new("Verify Proof")
                .collapsible(false)
                .resizable(true)
                .default_size(egui::vec2(300.0, 180.0))
                .max_height(360.0)
                .open(&mut verify_open)
                .show(&ctx, |ui| {
                    let body_h = (ui.available_height() - 44.0).max(120.0);
                    egui::ScrollArea::vertical().auto_shrink([false; 2]).max_height(body_h).show(ui, |ui| {
                        egui::Frame::group(ui.style()).show(ui, |ui| {
                            ui.heading("Inputs");

                            ui.label("Verification ID");
                            ui.add_sized(
                                [ui.available_width(), 28.0],
                                egui::TextEdit::singleline(&mut self.verify_verification_id),
                            );

                            ui.label("File*");
                            ui.horizontal(|ui| {
                                let browse_w = 90.0;
                                let spacing = ui.spacing().item_spacing.x;
                                let file_w = (ui.available_width() - browse_w - spacing).max(120.0);
                                ui.add_sized(
                                    [file_w, 28.0],
                                    egui::TextEdit::singleline(&mut self.verify_file_path),
                                );
                                if ui.add_sized([browse_w, 28.0], egui::Button::new("Browse")).clicked() {
                                    if let Some(path) = rfd::FileDialog::new().pick_file() {
                                        self.verify_file_path = path.to_string_lossy().to_string();
                                    }
                                }
                            });
                        });
                    });

                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        let mut do_verify = false;
                        if ui
                            .add_enabled(!self.verify_in_progress, egui::Button::new("Verify"))
                            .clicked()
                        {
                            do_verify = true;
                        }
                        if ui.button("Close").clicked() {
                            close_verify_modal = true;
                        }
                        if do_verify {
                            self.start_verify();
                        }
                        if self.verify_in_progress {
                            ui.add_space(8.0);
                            ui.monospace("working...");
                        }
                    });
                });
        }
        if close_verify_modal {
            verify_open = false;
        }
        self.verify_modal_open = verify_open;

    }

    fn create(&mut self) -> std::result::Result<(), String> {
        let keypair = KeypairBytes::generate();
        let pubkey = keypair.public_key_bytes().map_err(|e| e.to_string())?;

        self.keypair_base64 = keypair.to_base64();
        self.public_key_base64 = base64::engine::general_purpose::STANDARD.encode(pubkey);
        Ok(())
    }

    fn start_create_proof(&mut self) {
        if self.create_in_progress {
            return;
        }
        self.create_in_progress = true;

        let create_file_path = self.create_file_path.trim().to_string();
        let keypair_base64 = self.keypair_base64.trim().to_string();
        let create_asset_type = self.create_asset_type.clone();
        let create_ai_assisted = self.create_ai_assisted;
        let create_tags = self.create_tags.clone();
        let create_description = self.create_description.clone();
        let create_parent_verification_id = self.create_parent_verification_id.clone();
        let create_issuer_certificate_id = self.create_issuer_certificate_id.clone();
        let storage_dir = self.storage_dir.clone();

        let peers_arc = Arc::clone(&self.peers_arc);
        let bootstrap_entries = Arc::clone(&self.bootstrap_entries);
        let bind: SocketAddr = self
            .node_bind
            .trim()
            .parse()
            .unwrap_or(SocketAddr::from(([127, 0, 0, 1], 0)));
        let gui_task_tx = self.gui_task_tx.clone();
        let p2p_tx = self.p2p_outbound_tx.clone();

        self.rt.spawn(async move {
            let blocking_res = tokio::task::spawn_blocking(move || -> std::result::Result<(Proof, PublishedProof, String), String> {
                let file_path = PathBuf::from(create_file_path.trim());
                let bytes = std::fs::read(file_path).map_err(|e| e.to_string())?;

                let kp = KeypairBytes::from_base64(keypair_base64.trim()).map_err(|e| e.to_string())?;
                let asset_type = parse_asset_type(&create_asset_type)?;

                let tags = parse_tags(&create_tags);
                let description = if create_description.trim().is_empty() {
                    None
                } else {
                    Some(create_description.trim().to_string())
                };
                let parent_verification_id = if create_parent_verification_id.trim().is_empty() {
                    None
                } else {
                    Some(create_parent_verification_id.trim().to_string())
                };
                let issuer_certificate_id = if create_issuer_certificate_id.trim().is_empty() {
                    None
                } else {
                    Some(create_issuer_certificate_id.trim().to_string())
                };

                let metadata = Metadata::new(tags, description, parent_verification_id);
                let proof = create_proof_from_bytes(
                    &bytes,
                    asset_type,
                    create_ai_assisted,
                    metadata,
                    &kp,
                )
                .map_err(|e| e.to_string())?;

                let storage = Storage::new(storage_dir);
                let published = PublishedProof {
                    proof: proof.clone(),
                    issuer_certificate_id: issuer_certificate_id.clone(),
                };
                storage.store_published_proof(&published).map_err(|e| e.to_string())?;

                Ok((proof, published, issuer_certificate_id.unwrap_or_default()))
            })
            .await;

            let (proof, published, issuer_certificate_id_display) = match blocking_res {
                Ok(Ok(v)) => v,
                Ok(Err(e)) => {
                    let _ = gui_task_tx.send(GuiTaskMsg::TaskError { message: e });
                    return;
                }
                Err(e) => {
                    let _ = gui_task_tx.send(GuiTaskMsg::TaskError { message: format!("{}", e) });
                    return;
                }
            };

            let mut peers = connected_session_peers().await;
            if peers.is_empty() {
                peers = peers_arc.read().await.clone();
                if let Ok(g) = bootstrap_entries.lock() {
                    for e in g.iter() {
                        peers.push(e.addr);
                    }
                }
            }
            peers.retain(|p| *p != bind);
            peers.sort();
            peers.dedup();
            peers.truncate(8);

            if !peers.is_empty() {
                if published.issuer_certificate_id.is_some() {
                    replicate_published_proof(&published, &peers).await;
                } else {
                    replicate_proof(&proof, &peers).await;
                }
            }
            if let Some(tx) = p2p_tx {
                let _ = tx.send(OutboundMsg::PublishedProof(published.clone()));
            }

            let _ = gui_task_tx.send(GuiTaskMsg::CreateDone {
                verification_id: proof.verification_id,
                creator_public_key_base64: base64::engine::general_purpose::STANDARD
                    .encode(proof.creator_public_key),
                signature_base64: base64::engine::general_purpose::STANDARD.encode(proof.signature.0),
                issuer_certificate_id_display,
            });
        });
    }

    fn start_verify(&mut self) {
        if self.verify_in_progress {
            return;
        }
        self.verify_in_progress = true;

        let vid = self.verify_verification_id.trim().to_string();
        let verify_file_path = self.verify_file_path.trim().to_string();
        let storage_dir = self.storage_dir.clone();
        let certs_url = self.certs_url.clone();

        let peers_arc = Arc::clone(&self.peers_arc);
        let bootstrap_entries = Arc::clone(&self.bootstrap_entries);
        let bind: SocketAddr = self
            .node_bind
            .trim()
            .parse()
            .unwrap_or(SocketAddr::from(([127, 0, 0, 1], 0)));
        let gui_task_tx = self.gui_task_tx.clone();

        self.rt.spawn(async move {
            let mut peers = connected_session_peers().await;
            if peers.is_empty() {
                peers = peers_arc.read().await.clone();
                if let Ok(g) = bootstrap_entries.lock() {
                    for e in g.iter() {
                        peers.push(e.addr);
                    }
                }
            }
            peers.retain(|p| *p != bind);
            peers.sort();
            peers.dedup();
            peers.truncate(8);

            let content = if verify_file_path.trim().is_empty() {
                None
            } else {
                match tokio::task::spawn_blocking(move || std::fs::read(verify_file_path)).await {
                    Ok(Ok(v)) => Some(v),
                    Ok(Err(e)) => {
                        let _ = gui_task_tx.send(GuiTaskMsg::TaskError { message: format!("{}", e) });
                        return;
                    }
                    Err(e) => {
                        let _ = gui_task_tx.send(GuiTaskMsg::TaskError { message: format!("{}", e) });
                        return;
                    }
                }
            };

            let vid_for_blocking = vid.clone();
            let storage_dir_for_blocking = storage_dir.clone();
            let content_for_blocking = content.clone();
            let res = tokio::task::spawn_blocking(move || -> std::result::Result<(String, Option<VerifyResultView>), String> {
                let storage = Storage::new(storage_dir_for_blocking);

                if vid_for_blocking.is_empty() {
                    let bytes = content_for_blocking.ok_or_else(|| "file is required when verification_id is empty".to_string())?;
                    let asset_hash = blake3_hash_bytes(&bytes);

                    let ids = storage.lookup_by_hash(&asset_hash).map_err(|e| e.to_string())?;
                    return Ok((
                        if ids.is_empty() { "not found".to_string() } else { ids.join("\n") },
                        None,
                    ));
                }

                let published = if storage.contains(&vid_for_blocking) {
                    storage
                        .retrieve_published_proof(&vid_for_blocking)
                        .map_err(|e| e.to_string())?
                } else {
                    return Ok(("not found".to_string(), None));
                };

                verify_proof(&published.proof, content_for_blocking.as_deref()).map_err(|e| e.to_string())?;

                let mut status = String::new();
                status.push_str("valid\n");
                status.push_str(&format!("verification_id={}\n", published.proof.verification_id));
                status.push_str(&format!("timestamp={}\n", published.proof.timestamp.to_rfc3339()));
                status.push_str(&format!(
                    "creator_public_key_base64={}\n",
                    base64::engine::general_purpose::STANDARD.encode(published.proof.creator_public_key)
                ));
                status.push_str(&format!(
                    "signature_base64={}\n",
                    base64::engine::general_purpose::STANDARD.encode(published.proof.signature.0)
                ));

                let view = Some(VerifyResultView {
                    verification_id: published.proof.verification_id.clone(),
                    timestamp_rfc3339: published.proof.timestamp.to_rfc3339(),
                    creator_public_key_base64: base64::engine::general_purpose::STANDARD
                        .encode(published.proof.creator_public_key),
                    signature_base64: base64::engine::general_purpose::STANDARD
                        .encode(published.proof.signature.0),
                    issuer_certificate_id: published.issuer_certificate_id.clone(),
                    issuer_certified: false,
                    organization_name: None,
                    issuer_unverified_reason: None,
                });

                Ok((status, view))
            })
            .await;

            let (mut status, mut view) = match res {
                Ok(Ok(v)) => v,
                Ok(Err(e)) => {
                    let _ = gui_task_tx.send(GuiTaskMsg::TaskError { message: e });
                    return;
                }
                Err(e) => {
                    let _ = gui_task_tx.send(GuiTaskMsg::TaskError { message: format!("{}", e) });
                    return;
                }
            };

            if status.trim() == "not found" && !peers.is_empty() && !vid.is_empty() {
                let maybe_published = match fetch_published_proof_from_peers(&peers, &vid).await {
                    Ok(v) => v,
                    Err(e) => {
                        let _ = gui_task_tx.send(GuiTaskMsg::TaskError { message: format!("{}", e) });
                        return;
                    }
                };

                if let Some(published) = maybe_published {
                    let _ = tokio::task::spawn_blocking({
                        let storage_dir2 = storage_dir.clone();
                        let published2 = published.clone();
                        move || {
                            let storage = Storage::new(storage_dir2);
                            let _ = storage.store_published_proof(&published2);
                        }
                    })
                    .await;

                    status = "valid\n".to_string();
                    view = Some(VerifyResultView {
                        verification_id: published.proof.verification_id.clone(),
                        timestamp_rfc3339: published.proof.timestamp.to_rfc3339(),
                        creator_public_key_base64: base64::engine::general_purpose::STANDARD
                            .encode(published.proof.creator_public_key),
                        signature_base64: base64::engine::general_purpose::STANDARD
                            .encode(published.proof.signature.0),
                        issuer_certificate_id: published.issuer_certificate_id.clone(),
                        issuer_certified: false,
                        organization_name: None,
                        issuer_unverified_reason: None,
                    });
                } else {
                    let maybe = match fetch_proof_from_peers(&peers, &vid).await {
                        Ok(v) => v,
                        Err(e) => {
                            let _ = gui_task_tx.send(GuiTaskMsg::TaskError { message: format!("{}", e) });
                            return;
                        }
                    };
                    if let Some(p) = maybe {
                        let _ = tokio::task::spawn_blocking({
                            let storage_dir2 = storage_dir.clone();
                            let p2 = p.clone();
                            move || {
                                let storage = Storage::new(storage_dir2);
                                let _ = storage.store_proof(&p2);
                            }
                        })
                        .await;
                        status = "valid\n".to_string();
                        view = Some(VerifyResultView {
                            verification_id: p.verification_id.clone(),
                            timestamp_rfc3339: p.timestamp.to_rfc3339(),
                            creator_public_key_base64: base64::engine::general_purpose::STANDARD
                                .encode(p.creator_public_key),
                            signature_base64: base64::engine::general_purpose::STANDARD.encode(p.signature.0),
                            issuer_certificate_id: None,
                            issuer_certified: false,
                            organization_name: None,
                            issuer_unverified_reason: None,
                        });
                    }
                }
            }

            if let Some(v) = view.as_mut() {
                if let Some(id) = v.issuer_certificate_id.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                    let url = if certs_url.trim().is_empty() {
                        DEFAULT_CERTS_URL.to_string()
                    } else {
                        certs_url.trim().to_string()
                    };

                    let creator_pk_bytes = match base64::engine::general_purpose::STANDARD
                        .decode(v.creator_public_key_base64.trim())
                        .ok()
                        .and_then(|b| b.as_slice().try_into().ok())
                    {
                        Some(v) => v,
                        None => {
                            v.issuer_certified = false;
                            v.organization_name = None;
                            v.issuer_unverified_reason = Some(
                                "invalid creator_public_key_base64 (expected 32-byte ed25519 key)".to_string(),
                            );
                            let _ = gui_task_tx.send(GuiTaskMsg::VerifyDone { status, view });
                            return;
                        }
                    };

                    match fetch_certificate_bundle(&url).await {
                        Ok(bundle) => {
                            let ca_b64 = bundle
                                .certificates
                                .iter()
                                .find(|c| c.certificate_id.trim() == id)
                                .and_then(|c| c.ca_public_key_base64.as_deref())
                                .or(bundle.ca_public_key_base64.as_deref())
                                .map(str::trim)
                                .filter(|s| !s.is_empty())
                                .map(|s| s.to_string())
                                .or_else(|| std::env::var("DAVP_CA_PUBLIC_KEY_BASE64").ok());

                            let Some(ca_b64) = ca_b64 else {
                                v.issuer_certified = false;
                                v.organization_name = None;
                                v.issuer_unverified_reason = Some("missing ca_public_key_base64".to_string());
                                let _ = gui_task_tx.send(GuiTaskMsg::VerifyDone { status, view });
                                return;
                            };

                            let ca_pk_bytes = base64::engine::general_purpose::STANDARD
                                .decode(ca_b64.trim())
                                .ok();
                            let ca_pk: Option<[u8; 32]> = ca_pk_bytes.and_then(|b| b.try_into().ok());
                            let Some(ca_pk) = ca_pk else {
                                v.issuer_certified = false;
                                v.organization_name = None;
                                v.issuer_unverified_reason = Some("invalid ca_public_key_base64".to_string());
                                let _ = gui_task_tx.send(GuiTaskMsg::VerifyDone { status, view });
                                return;
                            };

                            let detailed = verify_issuer_certificate_detailed(
                                &bundle.certificates,
                                id,
                                &creator_pk_bytes,
                                &ca_pk,
                                chrono::Utc::now(),
                            )
                            .unwrap_or(IssuerCertificationDetailed::InvalidCaSignature);

                            match detailed {
                                IssuerCertificationDetailed::Certified { organization_name } => {
                                    v.issuer_certified = true;
                                    v.organization_name = Some(organization_name);
                                    v.issuer_unverified_reason = None;
                                }
                                _ => {
                                    v.issuer_certified = false;
                                    v.organization_name = None;
                                    v.issuer_unverified_reason = issuer_unverified_reason(&detailed);
                                }
                            }
                        }
                        Err(e) => {
                            v.issuer_certified = false;
                            v.organization_name = None;
                            v.issuer_unverified_reason = Some(format!("failed to fetch certs.json: {}", e));
                        }
                    }
                }
            }

            let _ = gui_task_tx.send(GuiTaskMsg::VerifyDone { status, view });
        });
    }
}

struct SyncNetworkCtx {
    bind: SocketAddr,
    advertise_addr: Arc<Mutex<SocketAddr>>,
    max_peers: usize,
    peers_arc: Arc<RwLock<Vec<SocketAddr>>>,
    peer_graph: Arc<RwLock<HashMap<SocketAddr, Vec<SocketAddr>>>>,
    cnt_server: SocketAddr,
    bootstrap_entries: Arc<Mutex<Vec<PeerEntry>>>,
    reachable_peers: Arc<Mutex<Vec<SocketAddr>>>,
    recent_peer_hits: Arc<Mutex<HashMap<SocketAddr, Instant>>>,
    dial_diagnostics: Arc<Mutex<HashMap<SocketAddr, PeerDialStatus>>>,
    cnt_ui_status: Arc<Mutex<CntUiStatus>>,
    observed_public_ip: Arc<Mutex<Option<IpAddr>>>,
    cnt_enabled: bool,
    cnt_report_only: bool,
    cnt_force_tx: tokio::sync::mpsc::UnboundedSender<()>,
    dial_cursor: Arc<AtomicUsize>,
}

struct CntReportCtx {
    bind: SocketAddr,
    advertise_addr: Arc<Mutex<SocketAddr>>,
    peers_arc: Arc<RwLock<Vec<SocketAddr>>>,
    peer_graph: Arc<RwLock<HashMap<SocketAddr, Vec<SocketAddr>>>>,
    upnp_enabled: bool,
    upnp_mapped_addr: Arc<Mutex<Option<SocketAddr>>>,
    upnp_status_line: Arc<Mutex<String>>,
    cnt_server: SocketAddr,
    bootstrap_entries: Arc<Mutex<Vec<PeerEntry>>>,
    cnt_ui_status: Arc<Mutex<CntUiStatus>>,
    observed_public_ip: Arc<Mutex<Option<IpAddr>>>,
    cnt_enabled: bool,
    upload_gossip: bool,
}

async fn sync_network_once(ctx: SyncNetworkCtx) -> anyhow::Result<()> {
    let bind = ctx.bind;
    let self_advertised = ctx
        .advertise_addr
        .lock()
        .ok()
        .map(|g| *g)
        .unwrap_or(bind);

    let observed_ip = ctx.observed_public_ip.lock().ok().and_then(|g| *g);
    let self_public_bind = observed_ip.map(|ip| SocketAddr::new(ip, bind.port()));
    let self_public_adv = observed_ip.map(|ip| SocketAddr::new(ip, self_advertised.port()));

    // Decay peer failure scores over time.
    {
        let now = Instant::now();
        if let Ok(mut m) = ctx.dial_diagnostics.lock() {
            for s in m.values_mut() {
                let last = s.last_score_decay.unwrap_or(now);
                let elapsed = now.duration_since(last);
                // every 30s, decay score by 10%
                let steps = (elapsed.as_secs() / 30) as u32;
                if steps > 0 {
                    for _ in 0..steps {
                        s.failure_score = (s.failure_score.saturating_mul(9)) / 10;
                    }
                    s.last_score_decay = Some(now);
                }
            }
        }
    }

    let snapshot = ctx.peers_arc.read().await.clone();

    let known_good_snapshot: Vec<SocketAddr> = {
        let now = Instant::now();
        let mut out = Vec::new();
        if let Ok(m) = ctx.recent_peer_hits.lock() {
            for (addr, t) in m.iter() {
                if *addr == bind {
                    continue;
                }
                if now.duration_since(*t) <= Duration::from_secs(2) {
                    out.push(*addr);
                }
            }
        }
        out.sort();
        out
    };

    let connections_snapshot: Vec<PeerConnections> = {
        let g = ctx.peer_graph.read().await;
        g.iter()
            .map(|(addr, connected_peers)| PeerConnections {
                addr: *addr,
                connected_peers: connected_peers.clone(),
            })
            .collect()
    };

    let mut join_set = tokio::task::JoinSet::new();
    if !ctx.cnt_report_only {
        // Prefer peers that have previously succeeded a handshake.
        let peers_to_ping: Vec<SocketAddr> = {
            let mut peers = snapshot;
            peers.retain(|p| *p != bind && *p != self_advertised && !is_invalid_peer_addr(*p));
            if let Some(a) = self_public_bind {
                peers.retain(|p| *p != a);
            }
            if let Some(a) = self_public_adv {
                peers.retain(|p| *p != a);
            }

            let diag_snapshot: HashMap<SocketAddr, PeerDialStatus> = ctx
                .dial_diagnostics
                .lock()
                .map(|g| g.clone())
                .unwrap_or_default();

            peers.sort_by(|a, b| {
                let sa = diag_snapshot.get(a);
                let sb = diag_snapshot.get(b);

                let a_ok = sa.and_then(|s| s.last_ok).is_some();
                let b_ok = sb.and_then(|s| s.last_ok).is_some();
                if a_ok != b_ok {
                    return b_ok.cmp(&a_ok);
                }

                let a_score = sa.map(|s| s.failure_score).unwrap_or_default();
                let b_score = sb.map(|s| s.failure_score).unwrap_or_default();
                if a_score != b_score {
                    return a_score.cmp(&b_score);
                }

                let a_last = sa.and_then(|s| s.last_attempt).unwrap_or(Instant::now());
                let b_last = sb.and_then(|s| s.last_attempt).unwrap_or(Instant::now());
                a_last.cmp(&b_last)
            });

            let peers: Vec<SocketAddr> = peers.into_iter().take(ctx.max_peers).collect();
            let mut peers = peers;
            drop_default_port_dupes(&mut peers);
            let n = peers.len();
            if n == 0 {
                Vec::new()
            } else {
                let per_tick: usize = 5.min(n);
                let start = ctx.dial_cursor.fetch_add(per_tick, Ordering::Relaxed);
                let mut out = Vec::with_capacity(per_tick);
                for i in 0..per_tick {
                    out.push(peers[(start + i) % n]);
                }
                out
            }
        };

        for peer in peers_to_ping.into_iter() {
            if peer == bind {
                continue;
            }
            if peer == self_advertised {
                continue;
            }
            if self_public_bind.is_some_and(|a| peer == a) {
                continue;
            }
            if self_public_adv.is_some_and(|a| peer == a) {
                continue;
            }

            if let Ok(mut m) = ctx.dial_diagnostics.lock() {
                let s = m.entry(peer).or_default();
                s.last_attempt = Some(Instant::now());
            }

            let known = known_good_snapshot.clone();
            let conn = connections_snapshot.clone();
            join_set.spawn(async move {
                let res = ping_peer_detailed(peer, bind, known, conn).await;
                (peer, res)
            });
        }
    }

    let mut reachable = Vec::new();
    let mut newly_discovered: HashSet<SocketAddr> = HashSet::new();
    let mut conn_updates: Vec<PeerConnections> = Vec::new();

    if !ctx.cnt_report_only {
        while let Some(join_res) = join_set.join_next().await {
            match join_res {
                Ok((peer, Ok((peer_list, conn_graph, observed_addr)))) => {
                    reachable.push(peer);
                    if let Ok(mut m) = ctx.recent_peer_hits.lock() {
                        m.insert(peer, Instant::now());
                    }

                    if let Ok(mut m) = ctx.dial_diagnostics.lock() {
                        let now = Instant::now();
                        let s = m.entry(peer).or_default();
                        s.last_result = Some(now);
                        s.last_duration_ms = s
                            .last_attempt
                            .map(|t| now.duration_since(t).as_millis())
                            .or(Some(0))
                            .map(|v| v as u128);
                        s.last_ok = Some(Instant::now());
                        s.last_error = None;
                        s.last_stage = Some("pong".to_string());
                        s.last_stage_msg = None;
                        s.ok_count = s.ok_count.saturating_add(1);
                        s.consecutive_failures = 0;
                        s.failure_score = s.failure_score / 2;
                        s.last_score_decay = Some(now);
                    }

                    let observed_ip = observed_addr.ip();
                    if !is_invalid_observed_ip(observed_ip) {
                        if let Ok(mut g) = ctx.observed_public_ip.lock() {
                            if g.map(|v| v != observed_ip).unwrap_or(true) {
                                *g = Some(observed_ip);
                            }
                        }
                    }
                    for p in peer_list {
                        if p == bind || is_invalid_peer_addr(p) {
                            continue;
                        }
                        newly_discovered.insert(p);
                    }

                    for pc in conn_graph.iter() {
                        if pc.addr != bind && !is_invalid_peer_addr(pc.addr) {
                            newly_discovered.insert(pc.addr);
                        }
                        for p in pc.connected_peers.iter().copied() {
                            if p == bind || is_invalid_peer_addr(p) {
                                continue;
                            }
                            newly_discovered.insert(p);
                        }
                    }

                    if !conn_graph.is_empty() {
                        conn_updates.extend(conn_graph);
                    }
                }
                Ok((peer, Err(e))) => {
                    let now = Instant::now();
                    if let Ok(mut m) = ctx.dial_diagnostics.lock() {
                        let s = m.entry(peer).or_default();
                        s.last_result = Some(now);
                        s.last_duration_ms = s
                            .last_attempt
                            .map(|t| now.duration_since(t).as_millis())
                            .or(Some(0))
                            .map(|v| v as u128);

                        s.last_ok = None;
                        s.last_stage = Some(format!("{:?}", e.stage));
                        s.last_stage_msg = Some(e.message.clone());
                        s.last_error = Some(format!("{}", e.message));

                        s.err_count = s.err_count.saturating_add(1);
                        s.consecutive_failures = s.consecutive_failures.saturating_add(1);
                        s.failure_score = s.failure_score.saturating_add(10);
                        s.last_score_decay = Some(now);
                    }
                }
                Err(_join_err) => {
                    // Treat task join errors as dial failures (rare).
                }
            }
        }

        if !conn_updates.is_empty() {
            let mut g = ctx.peer_graph.write().await;
            for pc in conn_updates {
                let entry = g.entry(pc.addr).or_default();
                for p in pc.connected_peers {
                    if !entry.contains(&p) {
                        entry.push(p);
                    }
                }
            }
        }

        // We do not prune peers purely due to dial failures.

        if !newly_discovered.is_empty() {
            let mut set = ctx.peers_arc.write().await;
            for p in newly_discovered.into_iter() {
                if !set.contains(&p) {
                    set.push(p);
                }
            }
            drop_default_port_dupes(&mut set);
        }

        if let Ok(mut g) = ctx.reachable_peers.lock() {
            *g = reachable.clone();
        }
    }

    if !ctx.cnt_report_only {
        let now = Instant::now();
        let prev_connected: std::collections::HashSet<SocketAddr> = {
            let g = ctx.peer_graph.read().await;
            g.get(&bind)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .collect()
        };
        let mut connected_recent: Vec<SocketAddr> = Vec::new();
        if let Ok(m) = ctx.recent_peer_hits.lock() {
            for (addr, t) in m.iter() {
                if *addr == bind {
                    continue;
                }
                if now.duration_since(*t) <= Duration::from_secs(2) {
                    connected_recent.push(*addr);
                }
            }
        }
        connected_recent.sort();

        let has_new_connection = connected_recent
            .iter()
            .any(|p| !prev_connected.contains(p));

        let mut g = ctx.peer_graph.write().await;
        g.insert(bind, connected_recent);

        if has_new_connection {
            let _ = ctx.cnt_force_tx.send(());
        }
    }

    let _ = (
        ctx.cnt_enabled,
        ctx.cnt_server,
        ctx.bootstrap_entries,
        ctx.cnt_ui_status,
        ctx.cnt_force_tx,
        ctx.reachable_peers,
    );

    Ok(())
}

async fn cnt_report_once(ctx: CntReportCtx) -> anyhow::Result<()> {
    if !ctx.cnt_enabled {
        return Ok(());
    }

    let is_local_cnt = ctx.cnt_server.ip().is_loopback();
    let reported_addr = if is_local_cnt {
        ctx.bind
    } else {
        // Prefer the node's advertised address (UPnP updates this to the external mapped addr).
        let advertised = ctx
            .advertise_addr
            .lock()
            .ok()
            .map(|g| *g)
            .unwrap_or(ctx.bind);
        let port = if advertised.port() != 0 {
            advertised.port()
        } else {
            ctx.bind.port()
        };

        let candidate = if !is_unroutable_ip(advertised.ip()) {
            advertised
        } else if let Ok(ip_opt) = ctx.observed_public_ip.lock().map(|g| *g) {
            if let Some(ip) = ip_opt {
                if !is_unroutable_ip(ip) {
                    SocketAddr::new(ip, port)
                } else {
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port)
                }
            } else {
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port)
            }
        } else {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port)
        };

        if candidate.ip().is_unspecified() {
            if let Some(local_ip) = detect_local_ip_to(ctx.cnt_server) {
                SocketAddr::new(local_ip, port)
            } else {
                candidate
            }
        } else {
            candidate
        }
    };

    let stable_hint = ctx
        .cnt_ui_status
        .lock()
        .map(|s| s.requester_stable)
        .unwrap_or(false);
    let send_gossip = ctx.upload_gossip && stable_hint;

    let connected_peers = if send_gossip {
        {
            let g = ctx.peer_graph.read().await;
            g.get(&ctx.bind).cloned().unwrap_or_default()
        }
    } else {
        Vec::new()
    };

    let upnp_enabled = if !ctx.upnp_enabled {
        false
    } else {
        let has_mapping = ctx
            .upnp_mapped_addr
            .lock()
            .ok()
            .and_then(|g| *g)
            .is_some();
        let status_mapped = ctx
            .upnp_status_line
            .lock()
            .ok()
            .map(|g| g.to_ascii_lowercase().contains("mapped"))
            .unwrap_or(false);
        has_mapping || status_mapped
    };

    let report = if send_gossip {
        PeerReport {
            addr: if is_local_cnt { ctx.bind } else { reported_addr },
            upnp_enabled,
            known_peers: connected_peers.clone(),
            connected_peers: connected_peers.clone(),
        }
    } else {
        PeerReport {
            addr: if is_local_cnt { ctx.bind } else { reported_addr },
            upnp_enabled,
            known_peers: Vec::new(),
            connected_peers: Vec::new(),
        }
    };

    match report_and_get_peers(ctx.cnt_server, report).await {
        Ok((entries, requester_stable, requester_effective_addr)) => {
            if let Ok(mut s) = ctx.cnt_ui_status.lock() {
                s.last_ok = Some(Instant::now());
                s.last_error = None;
                s.last_entry_count = entries.len();
                s.requester_stable = requester_stable;
            }
            if let Ok(mut g) = ctx.bootstrap_entries.lock() {
                *g = entries.clone();
            }

            let mut stable_addrs: Vec<SocketAddr> = Vec::new();
            let mut unstable_addrs: Vec<SocketAddr> = Vec::new();

            let self_advertised = ctx
                .advertise_addr
                .lock()
                .ok()
                .map(|g| *g)
                .unwrap_or(ctx.bind);
            let observed_ip = ctx.observed_public_ip.lock().ok().and_then(|g| *g);
            let self_public_bind = observed_ip.map(|ip| SocketAddr::new(ip, ctx.bind.port()));
            let self_public_adv = observed_ip.map(|ip| SocketAddr::new(ip, self_advertised.port()));
            let self_reported_addr = if is_local_cnt {
                ctx.bind
            } else {
                requester_effective_addr
            };

            for e in entries {
                if e.addr == ctx.bind {
                    continue;
                }
                if e.addr == self_advertised {
                    continue;
                }
                if e.addr == self_reported_addr {
                    continue;
                }
                if self_public_bind.is_some_and(|a| e.addr == a) {
                    continue;
                }
                if self_public_adv.is_some_and(|a| e.addr == a) {
                    continue;
                }
                if e.stable {
                    stable_addrs.push(e.addr);
                } else {
                    unstable_addrs.push(e.addr);
                }
            }

            let mut set = ctx.peers_arc.write().await;

            for a in stable_addrs.into_iter() {
                if !set.contains(&a) {
                    set.push(a);
                }
            }

            // If CNT has not yet classified any peer as stable, we still need a few dial targets
            // to bootstrap sessions. Keep this small to avoid spam.
            if is_local_cnt || set.is_empty() {
                for a in unstable_addrs.into_iter().take(2) {
                    if !set.contains(&a) {
                        set.push(a);
                    }
                }
            }

            drop_default_port_dupes(&mut set);
        }
        Err(e) => {
            if let Ok(mut s) = ctx.cnt_ui_status.lock() {
                s.last_error = Some(format!("{}", e));
                s.last_entry_count = 0;
                s.requester_stable = false;
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

fn resolve_socket_addr(s: &str) -> Option<SocketAddr> {
    if let Ok(v) = s.parse::<SocketAddr>() {
        return Some(v);
    }
    s.to_socket_addrs().ok()?.next()
}

fn detect_local_ip() -> Option<IpAddr> {
    // No packets are sent for UDP "connect"; it just picks a default route.
    // This yields the local interface IP used for outbound traffic.
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("8.8.8.8:80").ok()?;
    Some(sock.local_addr().ok()?.ip())
}

fn detect_local_ip_to(remote: SocketAddr) -> Option<IpAddr> {
    // No packets are sent for UDP "connect"; it just picks a default route.
    // Use the CNT server as the route target so we get the right interface IP.
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect(remote).ok()?;
    Some(sock.local_addr().ok()?.ip())
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
    for part in peers
        .split(|c: char| c == ',' || c.is_whitespace())
    {
        let p = part.trim();
        if p.is_empty() {
            continue;
        }
        if let Ok(addr) = p.parse::<SocketAddr>() {
            if is_invalid_peer_addr(addr) {
                continue;
            }
            out.push(addr);
        } else if p.parse::<IpAddr>().is_ok() {
            return Err("peer missing port (use ip:port)".to_string());
        } else {
            return Err("invalid peer".to_string());
        }
    }
    Ok(out)
}
