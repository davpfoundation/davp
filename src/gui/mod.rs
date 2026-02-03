use anyhow::Result;
use base64::Engine as _;
use crate::modules::asset::create_proof_from_bytes;
use crate::modules::bootstrap::{report_and_get_peers, PeerEntry, PeerReport};
use crate::modules::certification::PublishedProof;
use crate::modules::hash::blake3_hash_bytes;
use crate::modules::issuer_certificate::{
    fetch_certificate_bundle, verify_issuer_certificate_detailed, IssuerCertificateBundle,
    IssuerCertificationDetailed, DEFAULT_CERTS_URL,
};
use crate::modules::metadata::{AssetType, Metadata};
use crate::modules::network::{
    fetch_ids_by_hash_from_peers, fetch_proof_from_peers, fetch_published_proof_from_peers,
    replicate_published_proof, replicate_proof,
    run_node_with_shutdown, NodeConfig, PeerConnections, ping_peer,
};
use crate::modules::settings::{AppConfig, CntTrackerEntry};
use crate::modules::storage::Storage;
use crate::modules::verification::verify_proof;
use crate::KeypairBytes;
use eframe::egui;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::watch;
use tokio::sync::RwLock;

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
    seed_peers_last_applied: String,
    seed_peers_last_error: String,

    cnt_server: String,
    cnt_enabled: bool,

    cnt_selected_addr: String,
    cnt_trackers: Vec<CntTrackerEntry>,
    cnt_new_name: String,
    cnt_new_addr: String,

    node_bind: String,
    max_peers: usize,

    networking_started: bool,
    networking_started_at: Option<Instant>,

    peers_arc: Arc<RwLock<Vec<SocketAddr>>>,
    peer_graph: Arc<RwLock<HashMap<SocketAddr, Vec<SocketAddr>>>>,

    bootstrap_entries: Arc<Mutex<Vec<PeerEntry>>>,
    reachable_peers: Arc<Mutex<Vec<SocketAddr>>>,
    recent_peer_hits: Arc<Mutex<HashMap<SocketAddr, Instant>>>,
    cnt_ui_status: Arc<Mutex<CntUiStatus>>,
    tasks_started: bool,

    node_shutdown_tx: Option<watch::Sender<bool>>,
    node_handle: Option<tokio::task::JoinHandle<()>>,
    sync_handle: Option<tokio::task::JoinHandle<()>>,
    cnt_handle: Option<tokio::task::JoinHandle<()>>,
    sync_shutdown_tx: Option<watch::Sender<bool>>,
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
    create_modal_open: bool,

    verify_modal_open: bool,

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
}

impl Default for DavpApp {
    fn default() -> Self {
        let peers_arc: Arc<RwLock<Vec<SocketAddr>>> = Arc::new(RwLock::new(Vec::new()));
        let peer_graph: Arc<RwLock<HashMap<SocketAddr, Vec<SocketAddr>>>> = Arc::new(RwLock::new(HashMap::new()));
        let recent_peer_hits: Arc<Mutex<HashMap<SocketAddr, Instant>>> = Arc::new(Mutex::new(HashMap::new()));
        let cnt_ui_status: Arc<Mutex<CntUiStatus>> = Arc::new(Mutex::new(CntUiStatus::default()));
        let mut s = Self {
            tab: Tab::default(),
            storage_dir: "davp_storage".to_string(),
            config_import_path: String::new(),
            config_export_path: String::new(),
            peers: "".to_string(),
            seed_peers_last_applied: String::new(),
            seed_peers_last_error: String::new(),
            cnt_server: "127.0.0.1:9100".to_string(),
            cnt_enabled: false,

            cnt_selected_addr: "127.0.0.1:9100".to_string(),
            cnt_trackers: Vec::new(),
            cnt_new_name: String::new(),
            cnt_new_addr: String::new(),
            node_bind: "127.0.0.1:9002".to_string(),
            max_peers: 50,
            networking_started: false,
            networking_started_at: None,
            peers_arc: Arc::clone(&peers_arc),
            peer_graph: Arc::clone(&peer_graph),

            bootstrap_entries: Arc::new(Mutex::new(Vec::new())),
            reachable_peers: Arc::new(Mutex::new(Vec::new())),
            recent_peer_hits: Arc::clone(&recent_peer_hits),
            cnt_ui_status: Arc::clone(&cnt_ui_status),
            tasks_started: false,
            node_shutdown_tx: None,
            node_handle: None,
            sync_handle: None,
            cnt_handle: None,
            sync_shutdown_tx: None,
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
            create_modal_open: false,

            verify_modal_open: false,

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
        };
        s.load_app_config();
        s
    }
}

#[derive(Default, Clone, Copy, PartialEq, Eq)]
enum Tab {
    #[default]
    Workspace,
    Misc,
}

impl eframe::App for DavpApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        ctx.request_repaint_after(Duration::from_millis(100));

        egui::TopBottomPanel::top("top")
            .resizable(false)
            .show(ctx, |ui| {
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.selectable_value(&mut self.tab, Tab::Workspace, "Workspace");
                    ui.selectable_value(&mut self.tab, Tab::Misc, "Misc");

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(format!(
                            "CNT: {}",
                            if self.cnt_enabled { "enabled" } else { "disabled" }
                        ));
                        ui.label(format!(
                            "Network: {}",
                            if self.networking_started { "running" } else { "stopped" }
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
                Tab::Misc => self.ui_misc(ui),
            }
        });

        self.autosave_app_config();
    }
}

impl DavpApp {
    const INPUT_WIDTH: f32 = 560.0;

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
        self.node_bind = cfg.node_bind.clone();
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
            self.cnt_selected_addr = "127.0.0.1:9100".to_string();
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
                ui.heading("Storage");

                ui.horizontal(|ui| {
                    ui.label("Import config.json");

                    ui.add(
                        egui::TextEdit::singleline(&mut self.config_import_path)
                            .desired_width(420.0),
                    );

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

                ui.horizontal(|ui| {
                    ui.label("Data storage directory");
                    ui.text_edit_singleline(&mut self.storage_dir);

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

                ui.horizontal(|ui| {
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

    fn ui_misc(&mut self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical().auto_shrink([false; 2]).show(ui, |ui| {
            ui.heading("Misc");
        });
    }

}

impl DavpApp {
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

        if let Some(h) = self.sync_handle.take() {
            h.abort();
        }
        if let Some(h) = self.cnt_handle.take() {
            h.abort();
        }

        if let Some(node_handle) = self.node_handle.take() {
            if let Some(tx) = self.node_shutdown_tx.take() {
                let _ = tx.send(true);
            }
            let _ = self.rt.block_on(node_handle);
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
        if let Ok(mut s) = self.cnt_ui_status.lock() {
            *s = CntUiStatus::default();
        }
    }

    fn ui_network_bar(&mut self, ui: &mut egui::Ui) {
        egui::Frame::group(ui.style()).show(ui, |ui| {
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

                    let connected = self
                        .reachable_peers
                        .lock()
                        .map(|g| g.len())
                        .unwrap_or_default();
                    let known = {
                        let peers_arc = Arc::clone(&self.peers_arc);
                        self.rt.block_on(async move { peers_arc.read().await.len() })
                    };
                    ui.label(format!("Peers: {} connected / {} known", connected, known));

                    if self.networking_started {
                        ui.separator();

                        let uptime = self
                            .networking_started_at
                            .map(|t| Instant::now().duration_since(t).as_secs())
                            .unwrap_or_default();
                        ui.label(format!("Local uptime: {}s", uptime));

                        let bind: Option<SocketAddr> = self.node_bind.parse().ok();
                        let cnt_uptime_seconds: Option<i64> = bind.and_then(|b| {
                            self.bootstrap_entries
                                .lock()
                                .ok()
                                .and_then(|g| g.iter().find(|e| e.addr == b).map(|e| e.uptime_seconds))
                        });

                        if let Some(cnt_uptime_seconds) = cnt_uptime_seconds {
                            ui.label(format!("CNT uptime: {}s", cnt_uptime_seconds));
                        } else {
                            ui.label("CNT uptime: -");
                        }
                    }
                });

                {
                    let status = self
                        .cnt_ui_status
                        .lock()
                        .map(|s| s.clone())
                        .unwrap_or_default();
                    let mut line = format!(
                        "CNT: entries={} stable={} ",
                        status.last_entry_count,
                        if status.requester_stable { "yes" } else { "no" }
                    );
                    if let Some(t) = status.last_ok {
                        let ago_ms = Instant::now().duration_since(t).as_millis();
                        line.push_str(&format!("last_ok={}ms_ago", ago_ms));
                    } else {
                        line.push_str("last_ok=never");
                    }
                    if let Some(e) = status.last_error {
                        line.push_str(" error=");
                        line.push_str(&e);
                    }
                    ui.label(line);
                }

                ui.add_space(6.0);

                egui::Grid::new("network_bar_grid")
                    .num_columns(2)
                    .spacing(egui::vec2(12.0, 6.0))
                    .show(ui, |ui| {
                        ui.label("Max peers");
                        ui.add_enabled_ui(!self.networking_started, |ui| {
                            ui.horizontal(|ui| {
                                ui.add(egui::DragValue::new(&mut self.max_peers).clamp_range(50..=usize::MAX));
                            });
                        });
                        ui.end_row();

                        ui.label("Node bind");
                        ui.add_enabled_ui(!self.networking_started, |ui| {
                            ui.text_edit_singleline(&mut self.node_bind);
                        });
                        ui.end_row();

                        ui.label("Seed peers");
                        ui.add_enabled_ui(!self.networking_started, |ui| {
                            ui.horizontal(|ui| {
                                let resp = ui.add(egui::TextEdit::singleline(&mut self.peers).desired_width(420.0));
                                if resp.changed() {
                                    self.apply_seed_peers();
                                }
                            });
                        });
                        ui.end_row();

                        ui.label("CNT");
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
                                    .unwrap_or_else(|| "127.0.0.1:9100".to_string());
                                if new_addr.trim() != self.cnt_selected_addr.trim() {
                                    self.cnt_selected_addr = new_addr;
                                    self.cnt_server = self.cnt_selected_addr.clone();
                                    self.autosave_app_config();
                                }
                            });
                        });
                        ui.end_row();
                    });
                });

                ui.add_space(6.0);

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
        let recent_peer_hits = Arc::clone(&self.recent_peer_hits);
        let cnt_ui_status = Arc::clone(&self.cnt_ui_status);

        let cnt_server: SocketAddr = match self.cnt_server.parse() {
            Ok(v) => v,
            Err(_) => return,
        };
        let max_peers = self.max_peers;

        let (sync_shutdown_tx, sync_shutdown_rx) = watch::channel(false);
        self.sync_shutdown_tx = Some(sync_shutdown_tx);

        let (node_shutdown_tx, node_shutdown_rx) = watch::channel(false);
        self.node_shutdown_tx = Some(node_shutdown_tx);

        let (cnt_enabled_tx, cnt_enabled_rx) = watch::channel(self.cnt_enabled);
        self.cnt_enabled_tx = Some(cnt_enabled_tx);

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

        let mut sync_shutdown_rx_ping = sync_shutdown_rx.clone();
        let cnt_enabled_rx_ping = cnt_enabled_rx.clone();

        let peers_arc_ping = Arc::clone(&peers_arc);
        let peer_graph_ping = Arc::clone(&peer_graph);
        let bootstrap_entries_ping = Arc::clone(&bootstrap_entries);
        let reachable_peers_ping = Arc::clone(&reachable_peers);
        let recent_peer_hits_ping = Arc::clone(&recent_peer_hits);
        let cnt_ui_status_ping = Arc::clone(&cnt_ui_status);

        let (cnt_force_tx, mut cnt_force_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
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
                            max_peers,
                            peers_arc: Arc::clone(&peers_arc_ping),
                            peer_graph: Arc::clone(&peer_graph_ping),
                            cnt_server,
                            bootstrap_entries: Arc::clone(&bootstrap_entries_ping),
                            reachable_peers: Arc::clone(&reachable_peers_ping),
                            recent_peer_hits: Arc::clone(&recent_peer_hits_ping),
                            cnt_ui_status: Arc::clone(&cnt_ui_status_ping),
                            cnt_enabled,
                            cnt_report_only: false,
                            cnt_force_tx: cnt_force_tx.clone(),
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
                                peers_arc: Arc::clone(&peers_arc_cnt),
                                peer_graph: Arc::clone(&peer_graph_cnt),
                                cnt_server,
                                bootstrap_entries: Arc::clone(&bootstrap_entries_cnt),
                                cnt_ui_status: Arc::clone(&cnt_ui_status_cnt),
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
                            peers_arc: Arc::clone(&peers_arc_cnt),
                            peer_graph: Arc::clone(&peer_graph_cnt),
                            cnt_server,
                            bootstrap_entries: Arc::clone(&bootstrap_entries_cnt),
                            cnt_ui_status: Arc::clone(&cnt_ui_status_cnt),
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
                                        self.create_asset_type = "other".to_string();
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
                        if ui.button("Create proof").clicked() {
                            do_create = true;
                        }
                        if ui.button("Cancel").clicked() {
                            close_modal = true;
                        }
                        if do_create {
                            match self.create_proof() {
                                Ok(()) => {
                                    close_modal = true;
                                }
                                Err(e) => self.last_error = e,
                            }
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
                        if ui.button("Verify").clicked() {
                            do_verify = true;
                        }
                        if ui.button("Close").clicked() {
                            close_verify_modal = true;
                        }
                        if do_verify {
                            match self.verify() {
                                Ok(()) => {
                                    close_verify_modal = true;
                                }
                                Err(e) => self.last_error = e,
                            }
                        }
                    });
                });
        }
        if close_verify_modal {
            verify_open = false;
        }
        self.verify_modal_open = verify_open;
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
                        if let Err(e) = storage.store_published_proof(&published) {
                            if self.last_error.trim().is_empty() {
                                self.last_error = format!("storage: {}", e);
                            }
                        }
                        published
                    } else {
                        let maybe = self
                            .rt
                            .block_on(fetch_proof_from_peers(&peers, &id))
                            .map_err(|e| e.to_string())?;
                        let Some(p) = maybe else { continue };
                        if let Err(e) = storage.store_proof(&p) {
                            if self.last_error.trim().is_empty() {
                                self.last_error = format!("storage: {}", e);
                            }
                        }
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
                    status.push_str(&format!("timestamp={}\n", published.proof.timestamp.to_rfc3339()));
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
                                    timestamp_rfc3339: published.proof.timestamp.to_rfc3339(),
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
                                    timestamp_rfc3339: published.proof.timestamp.to_rfc3339(),
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
                            timestamp_rfc3339: published.proof.timestamp.to_rfc3339(),
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
                if let Err(e) = storage.store_published_proof(&published) {
                    if self.last_error.trim().is_empty() {
                        self.last_error = format!("storage: {}", e);
                    }
                }
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
                if let Err(e) = storage.store_proof(&p) {
                    if self.last_error.trim().is_empty() {
                        self.last_error = format!("storage: {}", e);
                    }
                }
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
        status.push_str(&format!("timestamp={}\n", published.proof.timestamp.to_rfc3339()));
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
                        timestamp_rfc3339: published.proof.timestamp.to_rfc3339(),
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
                        timestamp_rfc3339: published.proof.timestamp.to_rfc3339(),
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
                timestamp_rfc3339: published.proof.timestamp.to_rfc3339(),
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

struct SyncNetworkCtx {
    bind: SocketAddr,
    max_peers: usize,
    peers_arc: Arc<RwLock<Vec<SocketAddr>>>,
    peer_graph: Arc<RwLock<HashMap<SocketAddr, Vec<SocketAddr>>>>,
    cnt_server: SocketAddr,
    bootstrap_entries: Arc<Mutex<Vec<PeerEntry>>>,
    reachable_peers: Arc<Mutex<Vec<SocketAddr>>>,
    recent_peer_hits: Arc<Mutex<HashMap<SocketAddr, Instant>>>,
    cnt_ui_status: Arc<Mutex<CntUiStatus>>,
    cnt_enabled: bool,
    cnt_report_only: bool,
    cnt_force_tx: tokio::sync::mpsc::UnboundedSender<()>,
}

struct CntReportCtx {
    bind: SocketAddr,
    peers_arc: Arc<RwLock<Vec<SocketAddr>>>,
    peer_graph: Arc<RwLock<HashMap<SocketAddr, Vec<SocketAddr>>>>,
    cnt_server: SocketAddr,
    bootstrap_entries: Arc<Mutex<Vec<PeerEntry>>>,
    cnt_ui_status: Arc<Mutex<CntUiStatus>>,
    cnt_enabled: bool,
    upload_gossip: bool,
}

async fn sync_network_once(ctx: SyncNetworkCtx) -> anyhow::Result<()> {
    let bind = ctx.bind;
    let snapshot = ctx.peers_arc.read().await.clone();

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
        let peers_to_ping: Vec<SocketAddr> = if snapshot.len() <= ctx.max_peers {
            snapshot
                .iter()
                .copied()
                .filter(|p| *p != bind)
                .collect()
        } else {
            let last_hits = ctx
                .recent_peer_hits
                .lock()
                .ok()
                .map(|m| m.clone())
                .unwrap_or_default();
            let now = Instant::now();
            let very_old = now
                .checked_sub(Duration::from_secs(3600))
                .unwrap_or(now);
            let mut candidates: Vec<(SocketAddr, Instant)> = snapshot
                .iter()
                .copied()
                .filter(|p| *p != bind)
                .map(|p| (p, last_hits.get(&p).copied().unwrap_or(very_old)))
                .collect();
            candidates.sort_by_key(|(_, t)| *t);
            candidates
                .into_iter()
                .take(ctx.max_peers)
                .map(|(p, _)| p)
                .collect()
        };

        for peer in peers_to_ping.into_iter() {
            if peer == bind {
                continue;
            }
            let known = snapshot.clone();
            let conn = connections_snapshot.clone();
            join_set.spawn(async move { (peer, ping_peer(peer, bind, known, conn).await) });
        }
    }

    let mut reachable = Vec::new();
    let mut dead: HashSet<SocketAddr> = HashSet::new();
    let mut newly_discovered: HashSet<SocketAddr> = HashSet::new();
    let mut conn_updates: Vec<PeerConnections> = Vec::new();

    if !ctx.cnt_report_only {
        while let Some(join_res) = join_set.join_next().await {
            match join_res {
                Ok((peer, Ok((peer_list, conn_graph)))) => {
                    reachable.push(peer);
                    if let Ok(mut m) = ctx.recent_peer_hits.lock() {
                        m.insert(peer, Instant::now());
                    }
                    for p in peer_list {
                        if p == bind {
                            continue;
                        }
                        newly_discovered.insert(p);
                    }

                    for pc in conn_graph.iter() {
                        if pc.addr != bind {
                            newly_discovered.insert(pc.addr);
                        }
                        for p in pc.connected_peers.iter().copied() {
                            if p == bind {
                                continue;
                            }
                            newly_discovered.insert(p);
                        }
                    }

                    if !conn_graph.is_empty() {
                        conn_updates.extend(conn_graph);
                    }
                }
                Ok((peer, Err(_))) => {
                    dead.insert(peer);
                }
                Err(_) => {}
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

        if !dead.is_empty() {
            let mut set = ctx.peers_arc.write().await;
            set.retain(|p| !dead.contains(p));
            let mut g = ctx.peer_graph.write().await;
            for d in dead.iter() {
                g.remove(d);
            }
            for peers in g.values_mut() {
                peers.retain(|p| !dead.contains(p));
            }

            if let Ok(mut m) = ctx.recent_peer_hits.lock() {
                for d in dead.iter() {
                    m.remove(d);
                }
            }
        }

        if !newly_discovered.is_empty() {
            let mut set = ctx.peers_arc.write().await;
            for p in newly_discovered.into_iter() {
                if !set.contains(&p) {
                    set.push(p);
                }
            }
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

    let stable_hint = ctx
        .cnt_ui_status
        .lock()
        .map(|s| s.requester_stable)
        .unwrap_or(false);
    let send_gossip = ctx.upload_gossip && stable_hint;

    let (known_peers, connected_peers, cached_entries) = if send_gossip {
        let known_peers = ctx.peers_arc.read().await.clone();
        let connected_peers = {
            let g = ctx.peer_graph.read().await;
            g.get(&ctx.bind).cloned().unwrap_or_default()
        };
        let cached_entries: Vec<PeerEntry> = ctx
            .bootstrap_entries
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default();
        (known_peers, connected_peers, cached_entries)
    } else {
        (Vec::new(), Vec::new(), Vec::new())
    };

    let report = if send_gossip {
        let mut agg: std::collections::HashSet<SocketAddr> = std::collections::HashSet::new();
        for p in known_peers.iter().copied() {
            agg.insert(p);
        }
        for p in connected_peers.iter().copied() {
            agg.insert(p);
        }
        for e in cached_entries.iter() {
            agg.insert(e.addr);
            for p in e.known_peers.iter().copied() {
                agg.insert(p);
            }
            for p in e.connected_peers.iter().copied() {
                agg.insert(p);
            }
        }

        agg.remove(&ctx.bind);
        let mut combined: Vec<SocketAddr> = agg.into_iter().collect();
        combined.sort();

        PeerReport {
            addr: ctx.bind,
            known_peers: combined,
            connected_peers: connected_peers.clone(),
        }
    } else {
        PeerReport {
            addr: ctx.bind,
            known_peers: Vec::new(),
            connected_peers: Vec::new(),
        }
    };

    match report_and_get_peers(ctx.cnt_server, report).await {
        Ok((entries, requester_stable)) => {
            if let Ok(mut s) = ctx.cnt_ui_status.lock() {
                s.last_ok = Some(Instant::now());
                s.last_error = None;
                s.last_entry_count = entries.len();
                s.requester_stable = requester_stable;
            }
            if let Ok(mut guard) = ctx.bootstrap_entries.lock() {
                *guard = entries.clone();
            }

            let mut set = ctx.peers_arc.write().await;
            for e in entries {
                if e.addr == ctx.bind {
                    continue;
                }

                let mut discovered: std::collections::HashSet<SocketAddr> =
                    std::collections::HashSet::new();
                discovered.insert(e.addr);
                for p in e.known_peers.iter().copied() {
                    discovered.insert(p);
                }
                for p in e.connected_peers.iter().copied() {
                    discovered.insert(p);
                }

                for p in discovered.into_iter() {
                    if p == ctx.bind {
                        continue;
                    }
                    if !set.contains(&p) {
                        set.push(p);
                    }
                }
            }
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
