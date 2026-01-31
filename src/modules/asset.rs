use crate::modules::hash::{blake3_hash_bytes, AssetHash};
use crate::modules::metadata::{AssetType, Metadata};
use crate::modules::signature::{sign, KeypairBytes, PublicKeyBytes, SignatureBytes};
use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Proof {
    pub asset_hash: AssetHash,
    pub creator_public_key: PublicKeyBytes,
    pub timestamp: DateTime<Utc>,
    pub asset_type: AssetType,
    pub ai_assisted: bool,
    pub metadata: Metadata,
    pub signature: SignatureBytes,
    pub verification_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct SigningPayload {
    asset_hash: AssetHash,
    timestamp: DateTime<Utc>,
    asset_type: AssetType,
    ai_assisted: bool,
    metadata: Metadata,
}

pub fn generate_verification_id() -> String {
    let mut rng = OsRng {};

    loop {
        let mut bytes = [0u8; 48];
        rng.fill_bytes(&mut bytes);
        let id = bs58::encode(bytes).into_string();
        if id.len() >= 64 {
            return id[..64].to_string();
        }
    }
}

pub fn create_proof_from_bytes(
    content: &[u8],
    asset_type: AssetType,
    ai_assisted: bool,
    metadata: Metadata,
    creator_keypair: &KeypairBytes,
) -> Result<Proof> {
    let asset_hash = blake3_hash_bytes(content);
    let timestamp = Utc::now();

    let payload = SigningPayload {
        asset_hash,
        timestamp,
        asset_type,
        ai_assisted,
        metadata: metadata.clone(),
    };

    let payload_bytes = bincode::serialize(&payload)?;
    let signature = sign(&payload_bytes, creator_keypair)?;
    let creator_public_key = creator_keypair.public_key_bytes()?;

    let verification_id = generate_verification_id();

    if verification_id.len() != 64 {
        return Err(anyhow!("verification_id must be 64 chars"));
    }

    Ok(Proof {
        asset_hash,
        creator_public_key,
        timestamp,
        asset_type,
        ai_assisted,
        metadata,
        signature,
        verification_id,
    })
}

pub fn signing_bytes_for_proof(proof: &Proof) -> Result<Vec<u8>> {
    let payload = SigningPayload {
        asset_hash: proof.asset_hash,
        timestamp: proof.timestamp,
        asset_type: proof.asset_type,
        ai_assisted: proof.ai_assisted,
        metadata: proof.metadata.clone(),
    };

    Ok(bincode::serialize(&payload)?)
}
