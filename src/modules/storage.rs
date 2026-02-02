use crate::modules::asset::Proof;
use crate::modules::certification::{IssuerCertificateId, PublishedProof};
use crate::modules::hash::AssetHash;
use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct Storage {
    base_dir: PathBuf,
}

#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
struct ProofMetadata {
    issuer_certificate_id: Option<IssuerCertificateId>,
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
        self.write_once_bytes(&path, &bytes)?;

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

    pub fn store_published_proof(&self, published: &PublishedProof) -> Result<()> {
        self.store_proof(&published.proof)?;
        fs::create_dir_all(&self.base_dir)?;
        // Only persist metadata if an issuer_certificate_id is present.
        // If it is None, absence of the metadata file represents the default state.
        if published.issuer_certificate_id.is_some() {
            let meta = ProofMetadata {
                issuer_certificate_id: published.issuer_certificate_id.clone(),
            };
            let bytes = bincode::serialize(&meta)?;
            let meta_path = self.proof_metadata_path(&published.proof.verification_id);
            self.write_once_bytes(&meta_path, &bytes)?;
        }
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

    pub fn retrieve_published_proof(&self, verification_id: &str) -> Result<PublishedProof> {
        let proof = self.retrieve_proof(verification_id)?;
        let issuer_certificate_id = self
            .load_proof_metadata(verification_id)
            .unwrap_or_default()
            .issuer_certificate_id;
        Ok(PublishedProof {
            proof,
            issuer_certificate_id,
        })
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

    fn proof_metadata_path(&self, verification_id: &str) -> PathBuf {
        self.base_dir.join(format!("{}.meta.bin", verification_id))
    }

    fn load_proof_metadata(&self, verification_id: &str) -> Result<ProofMetadata> {
        let path = self.proof_metadata_path(verification_id);
        if !path.exists() {
            return Ok(ProofMetadata::default());
        }
        let bytes = fs::read(path)?;
        Ok(bincode::deserialize::<ProofMetadata>(&bytes)?)
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

    fn write_once_bytes(&self, path: &Path, bytes: &[u8]) -> Result<()> {
        if path.exists() {
            let existing = fs::read(path)?;
            if existing == bytes {
                return Ok(());
            }
            return Err(anyhow!(
                "refusing to overwrite existing file with different content: {}",
                path.display()
            ));
        }

        let mut f = match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
        {
            Ok(f) => f,
            Err(e) => {
                // If creation failed due to a race, re-check and compare.
                if path.exists() {
                    let existing = fs::read(path)?;
                    if existing == bytes {
                        return Ok(());
                    }
                    return Err(anyhow!(
                        "refusing to overwrite existing file with different content: {}",
                        path.display()
                    ));
                }
                return Err(e.into());
            }
        };

        f.write_all(bytes)?;
        Ok(())
    }
}

#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
struct HashIndex {
    entries: HashMap<AssetHash, Vec<String>>,
}
