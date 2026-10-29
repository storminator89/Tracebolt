use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fs, io::Read, path::Path};

#[derive(Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum EnrollmentMode {
    #[default]
    Auto,
    Invitation,
    Preprovided,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Config {
    pub schema_version: String,
    pub manager_origin: String,
    #[serde(default)]
    pub agent_id: String,
    #[serde(default)]
    pub enrollment_mode: EnrollmentMode,
    #[serde(default)]
    pub agent_origin: String,
    pub basic_metrics_acknowledged: bool,
    pub interval_seconds: u64,
}

pub fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    ensure!(
        !fs::symlink_metadata(path)?.file_type().is_symlink(),
        "links are not supported"
    );
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= limit, "file exceeds limit");
    Ok(bytes)
}

pub fn read_ca(directory: &Path) -> Result<Vec<u8>> {
    let path = directory.join("server-ca.pem");
    if path.try_exists()? {
        read_bounded(&path, 32768)
    } else {
        Ok(Vec::new())
    }
}
pub fn tls_builder(ca: &[u8]) -> Result<reqwest::blocking::ClientBuilder> {
    let mut builder = reqwest::blocking::Client::builder()
        .use_rustls_tls()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .tls_built_in_root_certs(ca.is_empty())
        .min_tls_version(reqwest::tls::Version::TLS_1_3)
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(10));
    if !ca.is_empty() {
        builder = builder.add_root_certificate(reqwest::Certificate::from_pem(ca)?);
    }
    Ok(builder)
}

impl Config {
    pub fn load(directory: &Path) -> Result<Self> {
        let config: Self =
            serde_json::from_slice(&read_bounded(&directory.join("config.json"), 4096)?)
                .context("invalid Rust agent configuration")?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == "tracebolt.rust-windows-basic.v1",
            "unsupported config"
        );
        ensure!(
            self.basic_metrics_acknowledged,
            "basic metrics consent required"
        );
        ensure!(
            (30..=3600).contains(&self.interval_seconds),
            "interval must be 30..3600 seconds"
        );
        ensure!(
            (self.enrollment_mode != EnrollmentMode::Preprovided && self.agent_id.is_empty())
                || (!self.agent_id.is_empty()
                    && self.agent_id.len() <= 128
                    && self
                        .agent_id
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')),
            "invalid agent identity"
        );
        Self::validate_origin(&self.manager_origin)?;
        if !self.agent_origin.is_empty() {
            Self::validate_origin(&self.agent_origin)?;
        }
        Ok(())
    }

    pub fn validate_origin(origin: &str) -> Result<()> {
        let url = reqwest::Url::parse(origin)?;
        ensure!(
            url.scheme() == "https"
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none()
                && origin == url.origin().ascii_serialization(),
            "canonical HTTPS origin required"
        );
        Ok(())
    }

    // Certificate, trust, destination and consent are immutable for this ledger.
    pub fn binding(&self, certificate: &[u8], ca: &[u8]) -> Result<String> {
        let mut hash = Sha256::new();
        for part in [serde_json::to_vec(self)?.as_slice(), certificate, ca] {
            hash.update((part.len() as u64).to_be_bytes());
            hash.update(part);
        }
        Ok(format!("{:x}", hash.finalize()))
    }
}
