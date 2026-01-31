use crate::modules::asset::{signing_bytes_for_proof, Proof};
use crate::modules::hash::blake3_hash_bytes;
use crate::modules::signature::verify;
use anyhow::{anyhow, Result};

pub fn verify_proof(proof: &Proof, maybe_asset_content: Option<&[u8]>) -> Result<()> {
    if proof.verification_id.len() != 64 {
        return Err(anyhow!("invalid verification_id length"));
    }

    if let Some(content) = maybe_asset_content {
        let expected_hash = blake3_hash_bytes(content);
        if expected_hash != proof.asset_hash {
            return Err(anyhow!("asset hash mismatch"));
        }
    }

    let payload = signing_bytes_for_proof(proof)?;
    verify(&payload, &proof.signature, &proof.creator_public_key)?;

    Ok(())
}
