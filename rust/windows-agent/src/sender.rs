use crate::{
    config::{Config, read_bounded},
    protocol,
    state::State,
};
use anyhow::{Result, ensure};
use chrono::Utc;
use reqwest::{Identity, blocking::Client};
use std::{io::Read, path::Path, time::Duration};

pub struct Sender {
    config: Config,
    client: Client,
    state: State,
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
        let binding = config.binding(&certificate, &ca)?;
        let mut identity = certificate;
        identity.push(b'\n');
        identity.extend(private_key);
        let client = crate::config::tls_builder(&ca)?
            .identity(Identity::from_pem(&identity)?)
            .timeout(Duration::from_secs(15))
            .build()?;
        let state = if enrolled {
            State::enrolled(directory, &binding)?
        } else {
            State::open(directory, &binding, initialize)?
        };
        Ok(Self {
            config,
            client,
            state,
        })
    }
    pub fn interval(&self) -> Duration {
        Duration::from_secs(self.config.interval_seconds)
    }

    pub fn report(&mut self, collect: impl FnOnce() -> Result<protocol::Sample>) -> Result<()> {
        let (mut sequence, mut pending) = self.state.current()?;
        if let Some(ref body) = pending {
            let age = Utc::now().signed_duration_since(protocol::collected_at(body)?);
            ensure!(
                age >= chrono::Duration::seconds(-30),
                "local clock moved backwards"
            );
            if age >= chrono::Duration::seconds(100) {
                self.state.advance(sequence)?;
                sequence += 1;
                pending = None;
            }
        }
        let body = if let Some(body) = pending {
            body
        } else {
            let sample = collect()?;
            let body = protocol::frame(sequence, Utc::now(), sample)?;
            self.state.prepare(sequence, &body)?;
            body
        };
        let collected = protocol::collected_at(&body)?;
        let response = self
            .client
            .post(format!("{}{}", self.config.manager_origin, protocol::PATH))
            .header("Content-Type", "application/json")
            .body(body)
            .send()?;
        ensure!(
            response.status() == reqwest::StatusCode::OK,
            "server did not accept telemetry"
        );
        ensure!(
            response
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.split(';').next() == Some("application/json")),
            "invalid receipt media type"
        );
        let mut receipt = Vec::new();
        response.take(8193).read_to_end(&mut receipt)?;
        ensure!(receipt.len() <= 8192, "receipt exceeds limit");
        protocol::validate_receipt(
            &receipt,
            &self.config.agent_id,
            sequence,
            collected,
            Utc::now(),
        )?;
        self.state.advance(sequence)
    }
}
