use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use davp::modules::signature::{sign, KeypairBytes};
use eframe::egui;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

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
struct IssuerCertificate {
    certificate_id: String,
    issuer_public_key: String,
    organization_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    metadata: Option<serde_json::Value>,
    valid_from: String,
    valid_to: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ca_public_key_base64: Option<String>,
    ca_signature: String,
}

fn parse_rfc3339_utc(s: &str) -> Result<chrono::DateTime<chrono::Utc>> {
    let dt = chrono::DateTime::parse_from_rfc3339(s.trim())?;
    Ok(dt.with_timezone(&chrono::Utc))
}

fn format_rfc3339_utc(dt: chrono::DateTime<chrono::Utc>) -> String {
    dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn validate_ed25519_public_key_base64(s: &str) -> Result<()> {
    let bytes = STANDARD.decode(s.trim())?;
    let _: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("invalid issuer_public_key length"))?;
    Ok(())
}

fn generate_certificate_id() -> String {
    let mut bytes = [0u8; 32];
    let mut rng = OsRng {};
    rng.fill_bytes(&mut bytes);
    bs58::encode(bytes).into_string()
}

#[derive(Default, Clone, Copy, PartialEq, Eq)]
enum Tab {
    #[default]
    Issue,
    Devtools,
}

struct App {
    tab: Tab,

    ca_keypair_base64: String,
    ca_public_key_base64: String,

    organization_name: String,
    issuer_public_key_base64: String,
    metadata_json: String,

    valid_from: String,
    valid_to: String,
    valid_days: i64,
    use_valid_days: bool,

    out_path: String,

    last_status: String,
    last_error: String,
    last_certificate_id: String,
    last_json: String,
}

impl Default for App {
    fn default() -> Self {
        Self {
            tab: Tab::default(),
            ca_keypair_base64: String::new(),
            ca_public_key_base64: String::new(),
            organization_name: String::new(),
            issuer_public_key_base64: String::new(),
            metadata_json: String::new(),
            valid_from: String::new(),
            valid_to: String::new(),
            valid_days: 365,
            use_valid_days: true,
            out_path: String::new(),
            last_status: String::new(),
            last_error: String::new(),
            last_certificate_id: String::new(),
            last_json: String::new(),
        }
    }
}

impl App {
    fn devtools_ui(&mut self, ui: &mut egui::Ui) {
        ui.heading("Devtools");
        ui.add_space(8.0);

        if ui.button("Generate CA_KEYPAIR_BASE64").clicked() {
            let keypair = KeypairBytes::generate();
            let pubkey = keypair.public_key_bytes();
            self.ca_keypair_base64 = keypair.to_base64();
            self.ca_public_key_base64 = match pubkey {
                Ok(pk) => STANDARD.encode(pk),
                Err(e) => {
                    self.last_error = e.to_string();
                    String::new()
                }
            };
        }

        ui.add_space(10.0);
        ui.label("CA_KEYPAIR_BASE64:");
        ui.add(
            egui::TextEdit::multiline(&mut self.ca_keypair_base64)
                .desired_rows(3)
                .desired_width(f32::INFINITY),
        );

        ui.add_space(6.0);
        ui.label("CA public key (base64):");
        ui.add(
            egui::TextEdit::multiline(&mut self.ca_public_key_base64)
                .desired_rows(2)
                .desired_width(f32::INFINITY),
        );
    }

    fn issue_ui(&mut self, ui: &mut egui::Ui) {
        ui.heading("Issue Issuer Certificate");
        ui.add_space(8.0);

        ui.label("CA_KEYPAIR_BASE64:");
        ui.add(
            egui::TextEdit::multiline(&mut self.ca_keypair_base64)
                .desired_rows(3)
                .desired_width(f32::INFINITY),
        );
        ui.add_space(8.0);

        ui.label("organization_name:");
        ui.text_edit_singleline(&mut self.organization_name);

        ui.add_space(8.0);
        ui.label("issuer_public_key (base64):");
        ui.text_edit_singleline(&mut self.issuer_public_key_base64);

        ui.add_space(8.0);
        ui.label("Metadata JSON*:");
        ui.add(
            egui::TextEdit::multiline(&mut self.metadata_json)
                .desired_rows(4)
                .desired_width(f32::INFINITY),
        );

        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.checkbox(&mut self.use_valid_days, "use valid_days");
            ui.add_enabled(
                self.use_valid_days,
                egui::DragValue::new(&mut self.valid_days).clamp_range(1..=36500),
            );
        });

        ui.add_space(6.0);
        ui.label("valid_from (RFC3339 UTC, optional; empty = now):");
        ui.text_edit_singleline(&mut self.valid_from);

        ui.add_space(6.0);
        ui.label("valid_to (RFC3339 UTC, required if not using valid_days):");
        ui.add_enabled(!self.use_valid_days, egui::TextEdit::singleline(&mut self.valid_to));

        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.label("output file:");
            ui.text_edit_singleline(&mut self.out_path);
            if ui.button("Browse").clicked() {
                if let Some(path) = rfd::FileDialog::new()
                    .set_file_name("issuer_certificate.json")
                    .save_file()
                {
                    self.out_path = path.to_string_lossy().to_string();
                }
            }
        });

        ui.add_space(10.0);
        if ui.button("Issue").clicked() {
            self.last_error.clear();
            self.last_status.clear();
            self.last_certificate_id.clear();
            self.last_json.clear();

            match self.issue_certificate() {
                Ok(()) => {}
                Err(e) => self.last_error = e.to_string(),
            }
        }

        if !self.last_error.is_empty() {
            ui.add_space(8.0);
            ui.colored_label(egui::Color32::LIGHT_RED, &self.last_error);
        }
        if !self.last_status.is_empty() {
            ui.add_space(8.0);
            ui.label(&self.last_status);
        }

        if !self.last_json.is_empty() {
            ui.add_space(10.0);
            ui.label("certificate JSON:");
            ui.add(
                egui::TextEdit::multiline(&mut self.last_json)
                    .desired_rows(10)
                    .desired_width(f32::INFINITY)
                    .code_editor(),
            );
        }
    }

    fn issue_certificate(&mut self) -> Result<()> {
        if self.ca_keypair_base64.trim().is_empty() {
            return Err(anyhow!("CA_KEYPAIR_BASE64 is required"));
        }
        if self.organization_name.trim().is_empty() {
            return Err(anyhow!("organization_name is required"));
        }
        if self.issuer_public_key_base64.trim().is_empty() {
            return Err(anyhow!("issuer_public_key is required"));
        }

        validate_ed25519_public_key_base64(self.issuer_public_key_base64.trim())?;

        let metadata = if self.metadata_json.trim().is_empty() {
            None
        } else {
            Some(serde_json::from_str::<serde_json::Value>(self.metadata_json.trim())?)
        };

        let valid_from_dt = if self.valid_from.trim().is_empty() {
            chrono::Utc::now()
        } else {
            parse_rfc3339_utc(self.valid_from.trim())?
        };

        let valid_to_dt = if self.use_valid_days {
            valid_from_dt + chrono::Duration::days(self.valid_days)
        } else {
            if self.valid_to.trim().is_empty() {
                return Err(anyhow!("valid_to is required when not using valid_days"));
            }
            parse_rfc3339_utc(self.valid_to.trim())?
        };

        if valid_to_dt <= valid_from_dt {
            return Err(anyhow!("valid_to must be after valid_from"));
        }

        let certificate_id = generate_certificate_id();
        let payload = IssuerCertificatePayload {
            certificate_id: certificate_id.clone(),
            issuer_public_key: self.issuer_public_key_base64.trim().to_string(),
            organization_name: self.organization_name.trim().to_string(),
            metadata,
            valid_from: format_rfc3339_utc(valid_from_dt),
            valid_to: format_rfc3339_utc(valid_to_dt),
        };

        let payload_bytes = bincode::serialize(&payload)?;
        let ca_keypair = KeypairBytes::from_base64(self.ca_keypair_base64.trim())?;
        let sig = sign(&payload_bytes, &ca_keypair)?;

        let ca_public_key_base64 = ca_keypair
            .public_key_bytes()
            .ok()
            .map(|pk| STANDARD.encode(pk));

        let cert = IssuerCertificate {
            certificate_id: certificate_id.clone(),
            issuer_public_key: payload.issuer_public_key,
            organization_name: payload.organization_name,
            metadata: payload.metadata,
            valid_from: payload.valid_from,
            valid_to: payload.valid_to,
            ca_public_key_base64,
            ca_signature: STANDARD.encode(sig.0),
        };

        let out_path = if self.out_path.trim().is_empty() {
            PathBuf::from(format!("issuer_certificate_{}.json", cert.certificate_id))
        } else {
            PathBuf::from(self.out_path.trim())
        };

        let json = serde_json::to_string_pretty(&cert)?;
        std::fs::write(&out_path, format!("{}\n", json))?;

        self.last_certificate_id = certificate_id;
        self.last_json = json;
        self.last_status = format!("Wrote {}", out_path.to_string_lossy());
        Ok(())
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.tab, Tab::Issue, "Issue Certificate");
                ui.selectable_value(&mut self.tab, Tab::Devtools, "Devtools");
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| match self.tab {
            Tab::Issue => self.issue_ui(ui),
            Tab::Devtools => self.devtools_ui(ui),
        });
    }
}

fn main() -> Result<()> {
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size(egui::vec2(820.0, 720.0)),
        ..Default::default()
    };
    eframe::run_native(
        "davp issuer certificate",
        native_options,
        Box::new(|_cc| Box::new(App::default())),
    )
    .map_err(|e| anyhow!(e.to_string()))?;
    Ok(())
}
