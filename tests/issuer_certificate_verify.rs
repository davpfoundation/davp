use base64::{engine::general_purpose::STANDARD, Engine as _};
use davp::modules::issuer_certificate::{verify_issuer_certificate, IssuerCertificate, IssuerCertificationStatus};
use davp::modules::signature::{sign, KeypairBytes};

#[test]
fn issuer_certificate_verification_happy_path() {
    let ca_keypair = KeypairBytes::generate();
    let ca_public_key = ca_keypair.public_key_bytes().unwrap();

    let issuer_keypair = KeypairBytes::generate();
    let issuer_public_key = issuer_keypair.public_key_bytes().unwrap();

    let now = chrono::Utc::now();
    let valid_from = now - chrono::Duration::days(1);
    let valid_to = now + chrono::Duration::days(1);

    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
    struct Payload {
        certificate_id: String,
        issuer_public_key: String,
        organization_name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        metadata: Option<serde_json::Value>,
        valid_from: String,
        valid_to: String,
    }

    let certificate_id = "test-cert-1".to_string();
    let payload = Payload {
        certificate_id: certificate_id.clone(),
        issuer_public_key: STANDARD.encode(issuer_public_key),
        organization_name: "Test Org".to_string(),
        metadata: None,
        valid_from: valid_from.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        valid_to: valid_to.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    };

    let payload_bytes = bincode::serialize(&payload).unwrap();
    let sig = sign(&payload_bytes, &ca_keypair).unwrap();

    let cert = IssuerCertificate {
        certificate_id: certificate_id.clone(),
        issuer_public_key: payload.issuer_public_key.clone(),
        organization_name: payload.organization_name.clone(),
        metadata: None,
        valid_from: payload.valid_from.clone(),
        valid_to: payload.valid_to.clone(),
        ca_signature: STANDARD.encode(sig.0),
    };

    let status = verify_issuer_certificate(
        &[cert],
        &certificate_id,
        &issuer_public_key,
        &ca_public_key,
        now,
    )
    .unwrap();

    assert_eq!(status, IssuerCertificationStatus::Certified { organization_name: "Test Org".to_string() });
}

#[test]
fn issuer_certificate_verification_wrong_key_unverified() {
    let ca_keypair = KeypairBytes::generate();
    let ca_public_key = ca_keypair.public_key_bytes().unwrap();

    let issuer_keypair = KeypairBytes::generate();
    let issuer_public_key = issuer_keypair.public_key_bytes().unwrap();

    let other_keypair = KeypairBytes::generate();
    let other_public_key = other_keypair.public_key_bytes().unwrap();

    let now = chrono::Utc::now();
    let valid_from = now - chrono::Duration::days(1);
    let valid_to = now + chrono::Duration::days(1);

    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
    struct Payload {
        certificate_id: String,
        issuer_public_key: String,
        organization_name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        metadata: Option<serde_json::Value>,
        valid_from: String,
        valid_to: String,
    }

    let certificate_id = "test-cert-2".to_string();
    let payload = Payload {
        certificate_id: certificate_id.clone(),
        issuer_public_key: STANDARD.encode(issuer_public_key),
        organization_name: "Test Org".to_string(),
        metadata: None,
        valid_from: valid_from.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        valid_to: valid_to.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    };

    let payload_bytes = bincode::serialize(&payload).unwrap();
    let sig = sign(&payload_bytes, &ca_keypair).unwrap();

    let cert = IssuerCertificate {
        certificate_id: certificate_id.clone(),
        issuer_public_key: payload.issuer_public_key.clone(),
        organization_name: payload.organization_name.clone(),
        metadata: None,
        valid_from: payload.valid_from.clone(),
        valid_to: payload.valid_to.clone(),
        ca_signature: STANDARD.encode(sig.0),
    };

    let status = verify_issuer_certificate(
        &[cert],
        &certificate_id,
        &other_public_key,
        &ca_public_key,
        now,
    )
    .unwrap();

    assert_eq!(status, IssuerCertificationStatus::Unverified);
}
