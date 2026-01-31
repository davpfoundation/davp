use crate::modules::signature::{sign, verify, KeypairBytes, PublicKeyBytes, SignatureBytes};
use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub type IssuerCertificateId = String;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublishedProof {
    pub proof: crate::modules::asset::Proof,
    pub issuer_certificate_id: Option<IssuerCertificateId>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IssuerCertificate {
    pub issuer_public_key: PublicKeyBytes,
    pub organization_name: String,
    pub organization_metadata: Option<serde_json::Value>,
    pub certificate_id: IssuerCertificateId,
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub ca_signature: SignatureBytes,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct CertificateSigningPayload {
    issuer_public_key: PublicKeyBytes,
    organization_name: String,
    organization_metadata: Option<serde_json::Value>,
    certificate_id: IssuerCertificateId,
    valid_from: DateTime<Utc>,
    valid_until: DateTime<Utc>,
}

pub fn signing_bytes_for_certificate(cert: &IssuerCertificate) -> Result<Vec<u8>> {
    let payload = CertificateSigningPayload {
        issuer_public_key: cert.issuer_public_key,
        organization_name: cert.organization_name.clone(),
        organization_metadata: cert.organization_metadata.clone(),
        certificate_id: cert.certificate_id.clone(),
        valid_from: cert.valid_from,
        valid_until: cert.valid_until,
    };

    Ok(bincode::serialize(&payload)?)
}

pub fn sign_certificate(
    issuer_public_key: PublicKeyBytes,
    organization_name: String,
    organization_metadata: Option<serde_json::Value>,
    certificate_id: IssuerCertificateId,
    valid_from: DateTime<Utc>,
    valid_until: DateTime<Utc>,
    ca_keypair: &KeypairBytes,
) -> Result<IssuerCertificate> {
    if valid_until <= valid_from {
        return Err(anyhow!("certificate validity period invalid"));
    }

    let unsigned = IssuerCertificate {
        issuer_public_key,
        organization_name,
        organization_metadata,
        certificate_id,
        valid_from,
        valid_until,
        ca_signature: SignatureBytes([0u8; 64]),
    };

    let payload = signing_bytes_for_certificate(&unsigned)?;
    let sig = sign(&payload, ca_keypair)?;

    Ok(IssuerCertificate {
        ca_signature: sig,
        ..unsigned
    })
}

pub fn verify_certificate_signature(cert: &IssuerCertificate, ca_public_key: &PublicKeyBytes) -> Result<()> {
    let payload = signing_bytes_for_certificate(cert)?;
    verify(&payload, &cert.ca_signature, ca_public_key)
}

pub fn is_certificate_valid_now(cert: &IssuerCertificate, now: DateTime<Utc>) -> bool {
    now >= cert.valid_from && now <= cert.valid_until
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofIssuerTag {
    UncertifiedIssuer,
    CertifiedIssuer,
}

pub fn tag_proof_issuer(
    proof_creator_public_key: &PublicKeyBytes,
    issuer_certificate_id: Option<&str>,
    certificate: Option<&IssuerCertificate>,
    ca_public_key: Option<&PublicKeyBytes>,
    now: DateTime<Utc>,
) -> ProofIssuerTag {
    let Some(_id) = issuer_certificate_id else {
        return ProofIssuerTag::UncertifiedIssuer;
    };

    let Some(cert) = certificate else {
        return ProofIssuerTag::UncertifiedIssuer;
    };

    if proof_creator_public_key != &cert.issuer_public_key {
        return ProofIssuerTag::UncertifiedIssuer;
    }

    if !is_certificate_valid_now(cert, now) {
        return ProofIssuerTag::UncertifiedIssuer;
    }

    let Some(ca_pk) = ca_public_key else {
        return ProofIssuerTag::UncertifiedIssuer;
    };

    if verify_certificate_signature(cert, ca_pk).is_err() {
        return ProofIssuerTag::UncertifiedIssuer;
    }

    ProofIssuerTag::CertifiedIssuer
}
