use anyhow::{Result, ensure};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::Deserialize;
use serde_json::{Value, json};

pub const MAX_SEQUENCE: u64 = (1 << 53) - 1;
pub const PATH: &str = "/v1/windows/agent/telemetry";

pub struct Sample {
    pub cpu: Option<f64>,
    pub memory: Option<f64>,
    pub disk: Option<f64>,
    pub uptime: String,
}

pub fn frame(sequence: u64, at: DateTime<Utc>, sample: Sample) -> Result<Vec<u8>> {
    ensure!((1..=MAX_SEQUENCE).contains(&sequence), "sequence exhausted");
    let at = at.to_rfc3339_opts(SecondsFormat::Secs, true);
    let metric = |value: Option<f64>, source: &str| {
        let value = value.filter(|v| v.is_finite() && (0.0..=100.0).contains(v));
        json!({"value":value,"unit":"%","quality":if value.is_some() {"healthy"} else {"unknown"},"source":source,"collectedAt":at})
    };
    let section = json!({"source":"Tracebolt Rust basic agent","scope":"Not collected by the basic metrics profile","quality":"unavailable","observedCount":0,"countExact":false,"complete":false,"truncated":false,"rows":[]});
    let result = json!({
        "schemaVersion":"tracebolt.agent-telemetry.windows.v1", "sequence":sequence,
        "windowsInventory":{
            "schemaVersion":"tracebolt.windows-inventory.v1","collectionProfile":"windows-inventory-v1",
            "generationId":format!("sample_{}",uuid::Uuid::new_v4().simple()),"collectedAt":at,
            "hostname":section,"processes":section,"services":section,"software":section,"network":section
        },
        "observation":{
            "schemaVersion":"tracebolt.support.v1","product":"Tracebolt","version":"0.1.0",
            "generatedAt":at,"platform":"windows","architecture":if cfg!(target_arch="aarch64") {"arm64"} else {"amd64"},
            "scope":"single-read-only-local-observation",
            "validation":{"platformExecution":"Rust native Windows basic metrics adapter","acceptance":"Native Windows installation and runtime acceptance must be tested separately."},
            "privacy":["Only CPU, physical memory, system-volume capacity and uptime are collected. No hostname, IP, processes, services, software, logs or actions."],
            "observation":{
                "id":"local-windows","name":"Local Windows","platform":"windows","os":"Windows",
                "site":"Local machine","group":"Local observations","ip":null,"status":"unknown",
                "source":"local","synthetic":false,"lastSeen":at,"agentVersion":"0.1.0-rust",
                "cpu":metric(sample.cpu,"GetSystemTimes: observed processor group"),
                "memory":metric(sample.memory,"GlobalMemoryStatusEx: physical memory"),
                "disk":metric(sample.disk,"GetDiskFreeSpaceExW: caller-quota system volume"),
                "uptime":sample.uptime,"tags":["read-only","native-unverified"],
                "capabilities":[],"evidence":[],"trend":[],"caseIds":[]
            }
        }
    });
    Ok(serde_json::to_vec(&result)?)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Receipt {
    schema_version: String,
    agent_id: String,
    sequence: u64,
    collected_at: DateTime<Utc>,
    received_at: DateTime<Utc>,
    duplicate: bool,
}

pub fn collected_at(body: &[u8]) -> Result<DateTime<Utc>> {
    let frame: Value = serde_json::from_slice(body)?;
    Ok(serde_json::from_value(
        frame["observation"]["observation"]["lastSeen"].clone(),
    )?)
}

pub fn validate_receipt(
    raw: &[u8],
    agent: &str,
    sequence: u64,
    collected: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<bool> {
    let receipt: Receipt = serde_json::from_slice(raw)?;
    ensure!(
        receipt.schema_version == "tracebolt.agent-receipt.v1"
            && receipt.agent_id == agent
            && receipt.sequence == sequence
            && receipt.collected_at == collected
            && receipt.received_at <= now + chrono::Duration::seconds(30)
            && receipt.received_at >= collected - chrono::Duration::seconds(30),
        "receipt identity/time mismatch"
    );
    Ok(receipt.duplicate)
}
