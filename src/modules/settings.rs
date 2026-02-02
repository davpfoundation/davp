
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const DEFAULT_DATA_DIR: &str = "davp_storage";

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AppConfig {
    pub data_storage_location: String,
    pub auto_save: bool,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            data_storage_location: DEFAULT_DATA_DIR.to_string(),
            auto_save: true,
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
