use crate::modules::signature::{verify, PublicKeyBytes, SignatureBytes};
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub use crate::config::DEFAULT_CERTS_URL;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IssuerCertificateBundle {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_public_key_base64: Option<String>,
    pub certificates: Vec<IssuerCertificate>,
}

pub async fn verify_issuer_certificate_via_bundle_url(
    url: &str,
    issuer_certificate_id: &str,
    proof_creator_public_key: &PublicKeyBytes,
    now: DateTime<Utc>,
) -> Result<IssuerCertificationStatus> {
    let bundle = fetch_certificate_bundle(url).await?;
    let cert = bundle
        .certificates
        .iter()
        .find(|c| c.certificate_id.trim() == issuer_certificate_id.trim());
    let ca_pk_b64 = cert
        .and_then(|c| c.ca_public_key_base64.as_deref())
        .or(bundle.ca_public_key_base64.as_deref());
    let ca_pk = decode_ed25519_public_key_base64_opt(ca_pk_b64)?
        .ok_or_else(|| anyhow!("missing ca_public_key_base64"))?;
    verify_issuer_certificate(
        &bundle.certificates,
        issuer_certificate_id,
        proof_creator_public_key,
        &ca_pk,
        now,
    )
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct IssuerCertificatePayload {
    certificate_id: String,
    issuer_public_key: String,
    organization_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    metadata: Option<serde_json::Value>,
    valid_from: String,
    valid_to: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct IssuerCertificatePayloadLegacy {
    certificate_id: String,
    issuer_public_key: String,
    organization_name: String,
    valid_from: String,
    valid_to: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IssuerCertificate {
    pub certificate_id: String,
    pub issuer_public_key: String,
    pub organization_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    pub valid_from: String,
    pub valid_to: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_public_key_base64: Option<String>,
    pub ca_signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IssuerCertificationStatus {
    Certified { organization_name: String },
    Unverified,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IssuerCertificationDetailed {
    Certified { organization_name: String },
    NotFound,
    InvalidCaSignature,
    InvalidValidityWindow,
    InvalidIssuerPublicKey,
    IssuerKeyMismatch,
}

fn decode_ed25519_public_key_base64_opt(s: Option<&str>) -> Result<Option<PublicKeyBytes>> {
    let Some(s) = s else { return Ok(None) };
    let s = s.trim();
    if s.is_empty() {
        return Ok(None);
    }
    Ok(Some(decode_ed25519_public_key_base64(s)?))
}

fn parse_rfc3339_utc(s: &str) -> Result<DateTime<Utc>> {
    let dt = DateTime::parse_from_rfc3339(s.trim())?;
    Ok(dt.with_timezone(&Utc))
}

fn decode_ed25519_public_key_base64(s: &str) -> Result<PublicKeyBytes> {
    let bytes = STANDARD.decode(s.trim())?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("invalid public key length"))?;
    Ok(arr)
}

fn decode_ed25519_signature_base64(s: &str) -> Result<SignatureBytes> {
    let bytes = STANDARD.decode(s.trim())?;
    let arr: [u8; 64] = bytes
        .try_into()
        .map_err(|_| anyhow!("invalid signature length"))?;
    Ok(SignatureBytes(arr))
}

pub fn issuer_certificate_signing_payload_bytes(cert: &IssuerCertificate) -> Result<Vec<u8>> {
    let payload = IssuerCertificatePayload {
        certificate_id: cert.certificate_id.clone(),
        issuer_public_key: cert.issuer_public_key.clone(),
        organization_name: cert.organization_name.clone(),
        metadata: cert.metadata.clone(),
        valid_from: cert.valid_from.clone(),
        valid_to: cert.valid_to.clone(),
    };
    Ok(bincode::serialize(&payload)?)
}

pub fn issuer_certificate_signing_payload_bytes_legacy(
    cert: &IssuerCertificate,
) -> Result<Vec<u8>> {
    let payload = IssuerCertificatePayloadLegacy {
        certificate_id: cert.certificate_id.clone(),
        issuer_public_key: cert.issuer_public_key.clone(),
        organization_name: cert.organization_name.clone(),
        valid_from: cert.valid_from.clone(),
        valid_to: cert.valid_to.clone(),
    };
    Ok(bincode::serialize(&payload)?)
}

fn verify_certificate_ca_signature(
    cert: &IssuerCertificate,
    ca_public_key: &PublicKeyBytes,
) -> Result<()> {
    let sig = decode_ed25519_signature_base64(&cert.ca_signature)?;
    let payload_bytes = issuer_certificate_signing_payload_bytes(cert)?;
    if verify(&payload_bytes, &sig, ca_public_key).is_ok() {
        return Ok(());
    }

    let legacy_bytes = issuer_certificate_signing_payload_bytes_legacy(cert)?;
    verify(&legacy_bytes, &sig, ca_public_key)
}

fn verify_validity_window(cert: &IssuerCertificate, now: DateTime<Utc>) -> Result<()> {
    let valid_from = parse_rfc3339_utc(&cert.valid_from)?;
    let valid_to = parse_rfc3339_utc(&cert.valid_to)?;
    if valid_to < valid_from {
        return Err(anyhow!("invalid certificate validity window"));
    }
    if now < valid_from {
        return Err(anyhow!("certificate not yet valid"));
    }
    if now > valid_to {
        return Err(anyhow!("certificate expired"));
    }
    Ok(())
}

pub async fn fetch_certificates(url: &str) -> Result<Vec<IssuerCertificate>> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()?;

    let resp = client
        .get(url)
        .header(reqwest::header::CACHE_CONTROL, "no-cache")
        .header(reqwest::header::PRAGMA, "no-cache")
        .send()
        .await?;
    let resp = resp.error_for_status()?;

    let text = resp.text().await?;
    Ok(fetch_certificate_bundle_from_str(&text)?.certificates)
}

pub fn parse_certificates_json(json: &str) -> Result<Vec<IssuerCertificate>> {
    Ok(fetch_certificate_bundle_from_str(json)?.certificates)
}

pub async fn fetch_certificate_bundle(url: &str) -> Result<IssuerCertificateBundle> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()?;

    let resp = client
        .get(url)
        .header(reqwest::header::CACHE_CONTROL, "no-cache")
        .header(reqwest::header::PRAGMA, "no-cache")
        .send()
        .await?;
    let resp = resp.error_for_status()?;
    let text = resp.text().await?;
    fetch_certificate_bundle_from_str(&text)
}

pub fn fetch_certificate_bundle_from_str(json: &str) -> Result<IssuerCertificateBundle> {
    let value = serde_json::from_str::<serde_json::Value>(json)?;
    match value {
        serde_json::Value::Array(_) => Ok(IssuerCertificateBundle {
            ca_public_key_base64: None,
            certificates: serde_json::from_str::<Vec<IssuerCertificate>>(json)?,
        }),
        serde_json::Value::Object(ref map) => {
            if map.contains_key("certificates") {
                Ok(serde_json::from_str::<IssuerCertificateBundle>(json)?)
            } else {
                Ok(IssuerCertificateBundle {
                    ca_public_key_base64: None,
                    certificates: vec![serde_json::from_str::<IssuerCertificate>(json)?],
                })
            }
        }
        _ => Err(anyhow!("invalid certs.json format")),
    }
}

pub fn verify_issuer_certificate(
    certs: &[IssuerCertificate],
    issuer_certificate_id: &str,
    proof_creator_public_key: &PublicKeyBytes,
    ca_public_key: &PublicKeyBytes,
    now: DateTime<Utc>,
) -> Result<IssuerCertificationStatus> {
    match verify_issuer_certificate_detailed(
        certs,
        issuer_certificate_id,
        proof_creator_public_key,
        ca_public_key,
        now,
    )? {
        IssuerCertificationDetailed::Certified { organization_name } => {
            Ok(IssuerCertificationStatus::Certified { organization_name })
        }
        _ => Ok(IssuerCertificationStatus::Unverified),
    }
}

pub fn verify_issuer_certificate_detailed(
    certs: &[IssuerCertificate],
    issuer_certificate_id: &str,
    proof_creator_public_key: &PublicKeyBytes,
    ca_public_key: &PublicKeyBytes,
    now: DateTime<Utc>,
) -> Result<IssuerCertificationDetailed> {
    let cert = match certs
        .iter()
        .find(|c| c.certificate_id.trim() == issuer_certificate_id.trim())
    {
        Some(c) => c,
        None => return Ok(IssuerCertificationDetailed::NotFound),
    };

    if verify_certificate_ca_signature(cert, ca_public_key).is_err() {
        return Ok(IssuerCertificationDetailed::InvalidCaSignature);
    }
    if verify_validity_window(cert, now).is_err() {
        return Ok(IssuerCertificationDetailed::InvalidValidityWindow);
    }

    let issuer_pk = match decode_ed25519_public_key_base64(&cert.issuer_public_key) {
        Ok(pk) => pk,
        Err(_) => return Ok(IssuerCertificationDetailed::InvalidIssuerPublicKey),
    };
    if &issuer_pk != proof_creator_public_key {
        return Ok(IssuerCertificationDetailed::IssuerKeyMismatch);
    }

    Ok(IssuerCertificationDetailed::Certified {
        organization_name: cert.organization_name.clone(),
    })
}

pub async fn verify_issuer_certificate_via_network(
    issuer_certificate_id: &str,
    proof_creator_public_key: &PublicKeyBytes,
    ca_public_key: &PublicKeyBytes,
) -> IssuerCertificationStatus {
    let certs = match fetch_certificates(DEFAULT_CERTS_URL).await {
        Ok(certs) => certs,
        Err(_) => return IssuerCertificationStatus::Unverified,
    };

    match verify_issuer_certificate(
        &certs,
        issuer_certificate_id,
        proof_creator_public_key,
        ca_public_key,
        Utc::now(),
    ) {
        Ok(status) => status,
        Err(_) => IssuerCertificationStatus::Unverified,
    }
}
