use base64::{engine::general_purpose::STANDARD, Engine as _};
use davp::modules::issuer_certificate::{verify_issuer_certificate, IssuerCertificationStatus, IssuerCertificate};

#[test]
fn issuer_certificate_regression_sample_from_certs_json() {
    let cert_json = r#"{
  \"certificate_id\": \"H1NPkaUf1aNh2h8nCWiKwynpbe6kADhR5ByYLp4Z1EhQ\",
  \"issuer_public_key\": \"RR3CrSfBclADSuMkEl2nSEF4s6Q4RtPOXKrPxtBuEOU=\",
  \"organization_name\": \"Google Inc.\",
  \"valid_from\": \"2026-01-31T19:57:58Z\",
  \"valid_to\": \"2027-01-31T19:57:58Z\",
  \"ca_signature\": \"lMH1YXicwehe23pDjHi8WTf0EDTnkqthnUy1/K5AZlOYfMGgkqHGy+J4zucqIxb1UP+xYyU5x9bJ/grw0k+lCA==\"
}"#;

    let cert: IssuerCertificate = serde_json::from_str(cert_json).unwrap();

    let ca_public_key_base64 = "ZA3Vc0Aj5Wl6ZYKadXSJOtaMVwvR76j7EgjUFDS0rl0=";
    let ca_pk_bytes = STANDARD.decode(ca_public_key_base64).unwrap();
    let ca_pk: [u8; 32] = ca_pk_bytes.try_into().unwrap();

    let issuer_pk_bytes = STANDARD.decode(&cert.issuer_public_key).unwrap();
    let issuer_pk: [u8; 32] = issuer_pk_bytes.try_into().unwrap();

    let valid_from = chrono::DateTime::parse_from_rfc3339(&cert.valid_from)
        .unwrap()
        .with_timezone(&chrono::Utc);
    let now = valid_from + chrono::Duration::seconds(1);

    let status = verify_issuer_certificate(
        &[cert],
        "H1NPkaUf1aNh2h8nCWiKwynpbe6kADhR5ByYLp4Z1EhQ",
        &issuer_pk,
        &ca_pk,
        now,
    )
    .unwrap();

    assert_eq!(
        status,
        IssuerCertificationStatus::Certified {
            organization_name: "Google Inc.".to_string()
        }
    );
}
