use crate::{
    config::{Config, read_bounded},
    health::Code,
    protocol,
    state::State,
};
use anyhow::{Context, Result, ensure};
use chrono::Utc;
use reqwest::blocking::Client;
use std::{io::Read, path::Path, time::Duration};

pub struct Sender {
    config: Config,
    client: Client,
    state: State,
    certificate_not_before: chrono::DateTime<Utc>,
    certificate_not_after: chrono::DateTime<Utc>,
}
impl Sender {
    pub fn open(directory: &Path, initialize: bool) -> Result<Self> {
        let config = Config::load(directory)?;
        ensure!(
            config.enrollment_mode == crate::config::EnrollmentMode::Preprovided,
            "identity requires enrollment"
        );
        let certificate = read_bounded(&directory.join("client.pem"), 32768)?;
        let ca = crate::config::read_ca(directory)?;
        let private_key = read_bounded(&directory.join("client.key"), 16384)?;
        if initialize {
            crate::credentials::validate_material(&certificate, &private_key)?;
        }
        Self::from_material(
            &directory.join("state"),
            crate::enrollment::Material {
                config,
                certificate,
                ca,
                private_key,
            },
            false,
            initialize,
        )
    }
    pub fn enrolled(directory: &Path, material: crate::enrollment::Material) -> Result<Self> {
        Self::from_material(directory, material, true, false)
    }
    fn from_material(
        directory: &Path,
        material: crate::enrollment::Material,
        enrolled: bool,
        initialize: bool,
    ) -> Result<Self> {
        let crate::enrollment::Material {
            config,
            certificate,
            ca,
            private_key,
        } = material;
        let (_, public) = x509_parser::pem::parse_x509_pem(&certificate)
            .map_err(|_| Code::ConfigurationInvalid)?;
        let (_, leaf) = x509_parser::parse_x509_certificate(&public.contents)
            .map_err(|_| Code::ConfigurationInvalid)?;
        let certificate_not_before =
            chrono::DateTime::<Utc>::from_timestamp(leaf.validity().not_before.timestamp(), 0)
                .ok_or(Code::ConfigurationInvalid)?;
        let certificate_not_after =
            chrono::DateTime::<Utc>::from_timestamp(leaf.validity().not_after.timestamp(), 0)
                .ok_or(Code::ConfigurationInvalid)?;
        let binding = config.binding(&certificate, &ca)?;
        let client = crate::credentials::client(&certificate, &private_key, &ca)?;
        let state = if enrolled {
            State::enrolled(directory, &binding).context(Code::StateUnavailable)?
        } else {
            State::open(directory, &binding, initialize).context(Code::StateUnavailable)?
        };
        Ok(Self {
            config,
            client,
            state,
            certificate_not_before,
            certificate_not_after,
        })
    }
    pub fn interval(&self) -> Duration {
        Duration::from_secs(self.config.interval_seconds)
    }

    pub fn report(&mut self, collect: impl FnOnce() -> Result<protocol::Sample>) -> Result<()> {
        self.report_receipt(collect).map(|_| ())
    }
    pub fn certificate_not_after(&self) -> chrono::DateTime<Utc> {
        self.certificate_not_after
    }
    pub fn report_receipt(
        &mut self,
        collect: impl FnOnce() -> Result<protocol::Sample>,
    ) -> Result<protocol::AcceptedReceipt> {
        let now = Utc::now();
        if now < self.certificate_not_before {
            return Err(Code::CertificateNotYetValid.into());
        }
        if now >= self.certificate_not_after {
            return Err(Code::CertificateExpired.into());
        }
        let (mut sequence, mut pending) = self.state.current().context(Code::StateUnavailable)?;
        if let Some(ref body) = pending {
            let age = Utc::now().signed_duration_since(protocol::collected_at(body)?);
            ensure!(age >= chrono::Duration::seconds(-30), Code::ClockInvalid);
            if age >= chrono::Duration::seconds(100) {
                self.state
                    .advance(sequence)
                    .context(Code::StateUnavailable)?;
                sequence += 1;
                pending = None;
            }
        }
        let body = if let Some(body) = pending {
            body
        } else {
            let sample = collect().context(Code::CollectionFailed)?;
            let body = protocol::frame(sequence, Utc::now(), sample)?;
            self.state
                .prepare(sequence, &body)
                .context(Code::StateUnavailable)?;
            body
        };
        let collected = protocol::collected_at(&body)?;
        let response = self
            .client
            .post(format!("{}{}", self.config.manager_origin, protocol::PATH))
            .header("Content-Type", "application/json")
            .body(body)
            .send()?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(match response.status().as_u16() {
                401 | 403 => Code::AuthenticationRejected,
                404 | 405 | 415 => Code::ProtocolUnavailable,
                _ => Code::ManagerRejected,
            }
            .into());
        }
        ensure!(
            response
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.split(';').next() == Some("application/json")),
            Code::ReceiptInvalid
        );
        let mut receipt = Vec::new();
        response.take(8193).read_to_end(&mut receipt)?;
        ensure!(receipt.len() <= 8192, Code::ReceiptInvalid);
        let accepted = protocol::validate_receipt_metadata(
            &receipt,
            &self.config.agent_id,
            sequence,
            collected,
            Utc::now(),
        )
        .context(Code::ReceiptInvalid)?;
        self.state
            .advance(sequence)
            .context(Code::StateUnavailable)?;
        Ok(accepted)
    }
}
