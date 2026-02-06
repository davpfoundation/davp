
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const DEFAULT_DATA_DIR: &str = "davp_storage";

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct CntTrackerEntry {
    pub name: String,
    pub addr: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct AppConfig {
    pub data_storage_location: String,
    pub auto_save: bool,

    // GUI / runtime options (persisted so the app can restore state on startup)
    #[serde(default, skip_serializing)]
    pub peers: String,

    #[serde(default, skip_serializing)]
    pub node_bind: String,

    #[serde(default, skip_serializing)]
    pub advertise_addr: String,

    #[serde(default, skip_serializing)]
    pub upnp_enabled: bool,

    #[serde(default = "default_max_peers", skip_serializing)]
    pub max_peers: usize,

    #[serde(default, skip_serializing)]
    pub cnt_enabled: bool,

    #[serde(default = "default_cnt_selected_addr", skip_serializing)]
    pub cnt_selected_addr: String,

    #[serde(default, skip_serializing)]
    pub cnt_trackers: Vec<CntTrackerEntry>,

    #[serde(default = "default_certs_url", skip_serializing)]
    pub certs_url: String,

    // Create / verify form state
    #[serde(default, skip_serializing)]
    pub keypair_base64: String,
    #[serde(default, skip_serializing)]
    pub create_file_path: String,
    #[serde(default = "default_create_asset_type", skip_serializing)]
    pub create_asset_type: String,
    #[serde(default, skip_serializing)]
    pub create_ai_assisted: bool,
    #[serde(default, skip_serializing)]
    pub create_description: String,
    #[serde(default, skip_serializing)]
    pub create_tags: String,
    #[serde(default, skip_serializing)]
    pub create_parent_verification_id: String,
    #[serde(default, skip_serializing)]
    pub create_issuer_certificate_id: String,

    #[serde(default, skip_serializing)]
    pub verify_verification_id: String,
    #[serde(default, skip_serializing)]
    pub verify_file_path: String,
}

fn default_max_peers() -> usize {
    50
}

fn default_cnt_selected_addr() -> String {
    "cnt.unitedorigins.com:5157".to_string()
}

fn default_certs_url() -> String {
    "https://davpfoundation.github.io/certs.json".to_string()
}

fn default_create_asset_type() -> String {
    "other".to_string()
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            data_storage_location: DEFAULT_DATA_DIR.to_string(),
            auto_save: true,

            peers: String::new(),
            node_bind: "0.0.0.0:9001".to_string(),
            advertise_addr: String::new(),
            upnp_enabled: false,
            max_peers: default_max_peers(),
            cnt_enabled: false,
            cnt_selected_addr: default_cnt_selected_addr(),
            cnt_trackers: Vec::new(),
            certs_url: default_certs_url(),

            keypair_base64: String::new(),
            create_file_path: String::new(),
            create_asset_type: default_create_asset_type(),
            create_ai_assisted: false,
            create_description: String::new(),
            create_tags: String::new(),
            create_parent_verification_id: String::new(),
            create_issuer_certificate_id: String::new(),

            verify_verification_id: String::new(),
            verify_file_path: String::new(),
        }
    }
}

impl AppConfig {
    pub fn path_in_repo_root() -> PathBuf {
        // Keep the function name for compatibility with existing call sites,
        // but store config.json next to the running executable.
        if let Ok(exe) = env::current_exe() {
            if let Some(dir) = exe.parent() {
                return dir.join("config.json");
            }
        }
        PathBuf::from("config.json")
    }

    pub fn load_or_create(path: &Path) -> io::Result<Self> {
        if path.exists() {
            let bytes = fs::read(path)?;
            let s = String::from_utf8(bytes)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            let cfg = serde_json::from_str::<Self>(&s)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            Ok(cfg)
        } else {
            let cfg = Self::default();
            cfg.save(path)?;
            Ok(cfg)
        }
    }

    pub fn save(&self, path: &Path) -> io::Result<()> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        fs::write(path, json)?;
        Ok(())
    }

    pub fn set_data_storage_location(&mut self, path: &Path, new_value: String) -> io::Result<()> {
        self.data_storage_location = new_value;
        if self.auto_save {
            self.save(path)?;
        }
        Ok(())
    }
}
