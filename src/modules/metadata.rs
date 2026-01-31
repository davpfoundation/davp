use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u8 = 1;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum AssetType {
    Text,
    Code,
    Image,
    Video,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Metadata {
    pub tags: Option<Vec<String>>,
    pub description: Option<String>,
    pub protocol_version: u8,
    pub parent_verification_id: Option<String>,
}

impl Metadata {
    pub fn new(
        tags: Option<Vec<String>>,
        description: Option<String>,
        parent_verification_id: Option<String>,
    ) -> Self {
        Self {
            tags,
            description,
            protocol_version: PROTOCOL_VERSION,
            parent_verification_id,
        }
    }
}
