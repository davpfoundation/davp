use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use clap::Parser;
use davp::modules::issuer_certificate::{
    fetch_certificate_bundle, verify_issuer_certificate, DEFAULT_CERTS_URL, IssuerCertificationStatus,
};

#[derive(Parser, Debug)]
#[command(name = "davp_check_certified_issuer")]
struct Cli {
    #[arg(long)]
    issuer_certificate_id: String,

    /// Proof creator public key (base64)
    #[arg(long)]
    creator_public_key_base64: String,

    /// DAVP CA public key (base64)
    #[arg(long, default_value = "")]
    ca_public_key_base64: String,

    #[arg(long, default_value = DEFAULT_CERTS_URL)]
    cert_repo_url: String,
}

fn decode_public_key_base64(s: &str) -> Result<[u8; 32]> {
    let bytes = STANDARD.decode(s.trim())?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("invalid public key length"))?;
    Ok(arr)
}

fn print_unverified() {
    println!("unverified issuer");
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.issuer_certificate_id.trim().is_empty() {
        print_unverified();
        return Ok(());
    }

    let creator_pk = match decode_public_key_base64(&cli.creator_public_key_base64) {
        Ok(pk) => pk,
        Err(_) => {
            print_unverified();
            return Ok(());
        }
    };

    let bundle = match fetch_certificate_bundle(cli.cert_repo_url.trim()).await {
        Ok(b) => b,
        Err(_) => {
            // network failures are non-fatal; treat as unverified
            print_unverified();
            return Ok(());
        }
    };

    let ca_pk_b64_opt = {
        let override_b64 = cli.ca_public_key_base64.trim();
        if !override_b64.is_empty() {
            Some(override_b64)
        } else {
            let cert = bundle
                .certificates
                .iter()
                .find(|c| c.certificate_id.trim() == cli.issuer_certificate_id.trim());
            cert.and_then(|c| c.ca_public_key_base64.as_deref())
                .or(bundle.ca_public_key_base64.as_deref())
                .map(str::trim)
                .filter(|s| !s.is_empty())
        }
    };

    let Some(ca_pk_b64) = ca_pk_b64_opt else {
        print_unverified();
        return Ok(());
    };
    let ca_pk = match decode_public_key_base64(ca_pk_b64) {
        Ok(pk) => pk,
        Err(_) => {
            print_unverified();
            return Ok(());
        }
    };

    let status = verify_issuer_certificate(
        &bundle.certificates,
        cli.issuer_certificate_id.trim(),
        &creator_pk,
        &ca_pk,
        chrono::Utc::now(),
    )
    .unwrap_or(IssuerCertificationStatus::Unverified);

    match status {
        IssuerCertificationStatus::Certified { organization_name } => {
            println!("certified issuer");
            println!("organization_name={}", organization_name);
        }
        IssuerCertificationStatus::Unverified => print_unverified(),
    }

    Ok(())
}
