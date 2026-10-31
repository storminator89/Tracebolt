//! Public protocol support is checked over the already selected TLS trust only.
//! This creates no local state and neither enrolls nor adopts advertised trust.
use crate::config::{Config, EnrollmentMode, tls_builder};
use serde::Deserialize;
use std::{fmt, io::Read};

pub const PATH: &str = "/v1/windows/rust-basic-capabilities";
const MAX_RESPONSE: u64 = 2048;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreflightError {
    Unsupported,
    Unavailable,
}
impl fmt::Display for PreflightError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unsupported => "MANAGER_PROTOCOL_UNSUPPORTED: use a matching Rust basic manager/frontend package and Windows TLS non-renewal enrollment configuration; no identity was created.",
            Self::Unavailable => "MANAGER_PREFLIGHT_UNAVAILABLE: check the manager address, selected TLS trust and network, then retry preflight; no identity was created.",
        })
    }
}
impl std::error::Error for PreflightError {}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Capabilities {
    schema_version: String,
    enrollment_protocol: String,
    collection_profile: String,
    agent_profile: String,
    telemetry_frame: String,
    receipt_schema: String,
    enrollment_origin: String,
    agent_origin: String,
    automatic_registration: bool,
}

/// One bounded, bodyless, credential-free request; never a trust or consent grant.
pub fn check(config: &Config, ca: &[u8]) -> Result<(), PreflightError> {
    config.validate().map_err(|_| PreflightError::Unsupported)?;
    // Advanced preprovided identities use a legacy telemetry-origin contract,
    // not this operator/enrollment advertisement. Never claim compatibility or
    // reinterpret their configured destination through this preflight.
    if config.enrollment_mode == EnrollmentMode::Preprovided {
        return Err(PreflightError::Unsupported);
    }
    let client = tls_builder(ca)
        .and_then(|builder| builder.build().map_err(Into::into))
        .map_err(|_| PreflightError::Unavailable)?;
    let response = client
        .get(format!("{}{}", config.manager_origin, PATH))
        .header("Accept", "application/json")
        .send()
        .map_err(|_| PreflightError::Unavailable)?;
    if response.status().as_u16() == 429 || response.status().is_server_error() {
        return Err(PreflightError::Unavailable);
    }
    if response.status() != reqwest::StatusCode::OK
        || response
            .headers()
            .get("Content-Type")
            .and_then(|v| v.to_str().ok())
            != Some("application/json")
        || response.content_length().is_some_and(|n| n > MAX_RESPONSE)
    {
        return Err(PreflightError::Unsupported);
    }
    let mut bytes = Vec::new();
    response
        .take(MAX_RESPONSE + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| PreflightError::Unavailable)?;
    if bytes.len() as u64 > MAX_RESPONSE {
        return Err(PreflightError::Unsupported);
    }
    let value: Capabilities =
        serde_json::from_slice(&bytes).map_err(|_| PreflightError::Unsupported)?;
    if value.schema_version != "tracebolt.rust-basic-manager-capabilities.v1"
        || value.enrollment_protocol != "tracebolt.enrollment.v2"
        || value.collection_profile != "windows-inventory-v1"
        || value.agent_profile != "rust-windows-basic-v1"
        || value.telemetry_frame != "tracebolt.agent-telemetry.windows.v1"
        || value.receipt_schema != "tracebolt.agent-receipt.v1"
        || value.enrollment_origin != config.manager_origin
        || Config::validate_origin(&value.agent_origin).is_err()
        || (!config.agent_origin.is_empty() && value.agent_origin != config.agent_origin)
        || (config.enrollment_mode == EnrollmentMode::Auto && !value.automatic_registration)
    {
        return Err(PreflightError::Unsupported);
    }
    Ok(())
}
