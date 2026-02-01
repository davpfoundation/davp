use crate::modules::asset::Proof;
use serde::{Deserialize, Serialize};

pub type IssuerCertificateId = String;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublishedProof {
    pub proof: Proof,
    pub issuer_certificate_id: Option<IssuerCertificateId>,
}
