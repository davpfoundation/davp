use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use clap::Parser;
use davp::modules::issuer_certificates::{
    decode_ca_public_key_base64, evaluate_proof_certification, CertificateRepository,
    ProofCertificationStatus,
};

const DEFAULT_CERT_REPO_URL: &str = "https://davpframework.github.io/site/certs.json";

#[derive(Parser, Debug)]
#[command(name = "davp_check_certified_issuer")]
struct Cli {
    #[arg(long)]
    issuer_certificate_id: String,

    /// Proof creator public key (base64)
    #[arg(long)]
    creator_public_key_base64: String,

    /// DAVP CA public key (base64)
    #[arg(long)]
    ca_public_key_base64: String,

    #[arg(long, default_value = DEFAULT_CERT_REPO_URL)]
    cert_repo_url: String,
}

fn decode_public_key_base64(s: &str) -> Result<[u8; 32]> {
    let bytes = STANDARD.decode(s.trim())?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("invalid public key length"))?;
    Ok(arr)
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.issuer_certificate_id.trim().is_empty() {
        println!("unverified issuer");
        return Ok(());
    }

    let creator_pk = match decode_public_key_base64(&cli.creator_public_key_base64) {
        Ok(pk) => pk,
        Err(_) => {
            println!("unverified issuer");
            return Ok(());
        }
    };

    let ca_pk = match decode_ca_public_key_base64(&cli.ca_public_key_base64) {
        Ok(pk) => pk,
        Err(_) => {
            println!("unverified issuer");
            return Ok(());
        }
    };

    let repo = match CertificateRepository::load_from_url(&cli.cert_repo_url).await {
        Ok(r) => r,
        Err(_) => {
            // network failures are non-fatal; treat as unverified
            println!("unverified issuer");
            return Ok(());
        }
    };

    let repo_by_id = repo.index_by_id();

    let status = evaluate_proof_certification(
        Some(cli.issuer_certificate_id.trim()),
        &creator_pk,
        Some(&repo_by_id),
        Some(&ca_pk),
        chrono::Utc::now(),
    );

    match status {
        ProofCertificationStatus::CertifiedIssuer {
            organization_name, ..
        } => {
            println!("certified issuer");
            println!("organization_name={}", organization_name);
        }
        _ => {
            println!("unverified issuer");
        }
    }

    Ok(())
}
