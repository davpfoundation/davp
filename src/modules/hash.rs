use anyhow::Result;
use std::fs;
use std::io::Read;
use std::path::Path;

pub type AssetHash = [u8; 32];

pub fn blake3_hash_bytes(content: &[u8]) -> AssetHash {
    blake3::hash(content).into()
}

/// Hash a file without loading it fully into memory, so multi-GB assets can be
/// hashed with a bounded memory footprint.
pub fn blake3_hash_file(path: impl AsRef<Path>) -> Result<AssetHash> {
    let mut file = fs::File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().into())
}
