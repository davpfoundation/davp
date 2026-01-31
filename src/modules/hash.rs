use anyhow::Result;
use std::fs;
use std::path::Path;

pub type AssetHash = [u8; 32];

pub fn blake3_hash_bytes(content: &[u8]) -> AssetHash {
    blake3::hash(content).into()
}

pub fn blake3_hash_file(path: impl AsRef<Path>) -> Result<AssetHash> {
    let bytes = fs::read(path)?;
    Ok(blake3_hash_bytes(&bytes))
}
