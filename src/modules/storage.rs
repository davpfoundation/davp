use crate::modules::asset::Proof;
use crate::modules::hash::AssetHash;
use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct Storage {
    base_dir: PathBuf,
}

impl Storage {
    pub fn new(base_dir: impl Into<PathBuf>) -> Self {
        Self {
            base_dir: base_dir.into(),
        }
    }

    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }

    pub fn store_proof(&self, proof: &Proof) -> Result<()> {
        fs::create_dir_all(&self.base_dir)?;
        let path = self.proof_path(&proof.verification_id);
        let bytes = bincode::serialize(proof)?;
        fs::write(path, bytes)?;

        let mut index = self.load_hash_index().unwrap_or_default();
        index
            .entries
            .entry(proof.asset_hash)
            .or_default()
            .push(proof.verification_id.clone());
        index
            .entries
            .entry(proof.asset_hash)
            .or_default()
            .sort();
        index
            .entries
            .entry(proof.asset_hash)
            .or_default()
            .dedup();
        self.save_hash_index(&index)?;

        Ok(())
    }

    pub fn retrieve_proof(&self, verification_id: &str) -> Result<Proof> {
        let path = self.proof_path(verification_id);
        let bytes = fs::read(path)?;
        let proof = bincode::deserialize::<Proof>(&bytes)?;
        if proof.verification_id != verification_id {
            return Err(anyhow!("stored proof verification_id mismatch"));
        }
        Ok(proof)
    }

    pub fn contains(&self, verification_id: &str) -> bool {
        self.proof_path(verification_id).exists()
    }

    pub fn lookup_by_hash(&self, asset_hash: &AssetHash) -> Result<Vec<String>> {
        let index = self.load_hash_index().unwrap_or_default();
        Ok(index
            .entries
            .get(asset_hash)
            .cloned()
            .unwrap_or_default())
    }

    fn proof_path(&self, verification_id: &str) -> PathBuf {
        self.base_dir.join(format!("{}.bin", verification_id))
    }

    fn hash_index_path(&self) -> PathBuf {
        self.base_dir.join("hash_index.bin")
    }

    fn load_hash_index(&self) -> Result<HashIndex> {
        let path = self.hash_index_path();
        if !path.exists() {
            return Ok(HashIndex::default());
        }
        let bytes = fs::read(path)?;
        Ok(bincode::deserialize::<HashIndex>(&bytes)?)
    }

    fn save_hash_index(&self, index: &HashIndex) -> Result<()> {
        fs::create_dir_all(&self.base_dir)?;
        let bytes = bincode::serialize(index)?;
        fs::write(self.hash_index_path(), bytes)?;
        Ok(())
    }
}

#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
struct HashIndex {
    entries: HashMap<AssetHash, Vec<String>>,
}
