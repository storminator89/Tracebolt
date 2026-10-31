use chrono::{TimeZone, Utc};
use serde_json::json;
use tracebolt_windows_agent::{
    config::Config,
    protocol::{self, Sample},
    state::State,
};
mod common;

#[test]
fn state_survives_restart_and_never_reuses_sequence() {
    let dir = tempfile::tempdir().unwrap();
    let state = State::open(dir.path(), "identity-a", true).unwrap();
    state.prepare(1, b"exact pending bytes").unwrap();
    assert!(State::open(dir.path(), "identity-a", false).is_err());
    assert!(state.prepare(1, b"replacement").is_err());
    drop(state);
    let state = State::open(dir.path(), "identity-a", false).unwrap();
    assert_eq!(
        state.current().unwrap(),
        (1, Some(b"exact pending bytes".to_vec()))
    );
    state.advance(1).unwrap();
    assert!(state.advance(1).is_err());
    drop(state);
    assert!(State::open(dir.path(), "identity-b", false).is_err());
    assert!(State::open(dir.path(), "identity-a", true).is_err());
    assert_eq!(
        State::open(dir.path(), "identity-a", false)
            .unwrap()
            .current()
            .unwrap(),
        (2, None)
    );
}

#[test]
fn missing_state_is_not_reinitialized() {
    let dir = tempfile::tempdir().unwrap();
    assert!(State::open(dir.path(), "a", false).is_err());
}

#[test]
fn automatic_onboarding_needs_no_token_and_preserves_key_on_restart() {
    use tracebolt_windows_agent::enrollment::Enrollment;
    let manager = common::Manager::compatible();
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("state")).unwrap();
    std::fs::write(
        dir.path().join("config.json"),
        serde_json::to_vec(&json!({
            "schemaVersion":"tracebolt.rust-windows-basic.v1","managerOrigin":manager.origin,
            "basicMetricsAcknowledged":true,"intervalSeconds":60
        }))
        .unwrap(),
    )
    .unwrap();
    std::fs::write(dir.path().join("server-ca.pem"), &manager.ca).unwrap();
    assert!(Enrollment::open(dir.path(), false, None).is_err());
    let enrollment = Enrollment::open(dir.path(), true, None).unwrap();
    let status = enrollment.public_status().unwrap();
    assert_eq!(status["phase"], "awaiting-registration");
    assert_eq!(status["keyFingerprint"].as_str().unwrap().len(), 64);
    assert!(Enrollment::open(dir.path(), false, None).is_err());
    drop(enrollment);
    assert_eq!(
        Enrollment::open(dir.path(), false, None)
            .unwrap()
            .public_status()
            .unwrap(),
        status
    );
    assert!(Enrollment::open(dir.path(), true, None).is_err());
}

#[test]
fn sender_creation_requires_activation_and_cannot_reset_an_enrolled_ledger() {
    let dir = tempfile::tempdir().unwrap();
    let db = rusqlite::Connection::open(dir.path().join("enrollment.db")).unwrap();
    db.execute_batch("CREATE TABLE enrollment(id INTEGER PRIMARY KEY,activated INTEGER,sender_initialized INTEGER); INSERT INTO enrollment VALUES(1,0,0);").unwrap();
    assert!(State::enrolled(dir.path(), "binding").is_err());
    db.execute("UPDATE enrollment SET activated=1", []).unwrap();
    let sender = State::enrolled(dir.path(), "binding").unwrap();
    sender.prepare(1, b"retained exact bytes").unwrap();
    drop(sender);
    let sender = State::enrolled(dir.path(), "binding").unwrap();
    assert_eq!(
        sender.current().unwrap().1.unwrap(),
        b"retained exact bytes"
    );
    drop(sender);
    db.execute("DROP TABLE sender", []).unwrap();
    assert!(State::enrolled(dir.path(), "binding").is_err());
}

#[test]
fn receipt_binds_identity_sequence_and_original_time() {
    let now = Utc.with_ymd_and_hms(2026, 10, 29, 12, 0, 0).unwrap();
    let receipt = json!({"schemaVersion":"tracebolt.agent-receipt.v1","agentId":"fixture","sequence":7,"collectedAt":now,"receivedAt":now,"duplicate":true});
    let bytes = serde_json::to_vec(&receipt).unwrap();
    assert!(protocol::validate_receipt(&bytes, "fixture", 7, now, now).unwrap());
    assert!(protocol::validate_receipt(&bytes, "another", 7, now, now).is_err());
    assert!(protocol::validate_receipt(&bytes, "fixture", 8, now, now).is_err());
    assert!(
        protocol::validate_receipt(
            &bytes,
            "fixture",
            7,
            now + chrono::Duration::seconds(1),
            now
        )
        .is_err()
    );
    let duplicate = String::from_utf8(bytes)
        .unwrap()
        .replacen("{", "{\"sequence\":7,", 1);
    assert!(protocol::validate_receipt(duplicate.as_bytes(), "fixture", 7, now, now).is_err());
}

#[test]
fn invalid_metrics_are_unknown_and_inventory_is_not_claimed_complete() {
    let bytes = protocol::frame(
        1,
        Utc::now(),
        Sample {
            cpu: Some(f64::NAN),
            memory: Some(101.0),
            disk: None,
            uptime: "Unknown".into(),
        },
    )
    .unwrap();
    let frame: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        frame["observation"]["observation"]["cpu"]["quality"],
        "unknown"
    );
    assert!(frame["observation"]["observation"]["memory"]["value"].is_null());
    assert_eq!(frame["windowsInventory"]["hostname"]["complete"], false);
    assert_eq!(
        frame["windowsInventory"]["hostname"]["quality"],
        "unavailable"
    );
}

#[test]
fn config_rejects_plaintext_redirectable_paths_and_missing_consent() {
    let mut config = Config {
        schema_version: "tracebolt.rust-windows-basic.v1".into(),
        manager_origin: "https://manager.example:9443".into(),
        agent_id: "fixture".into(),
        enrollment_mode: tracebolt_windows_agent::config::EnrollmentMode::Preprovided,
        agent_origin: String::new(),
        basic_metrics_acknowledged: true,
        interval_seconds: 60,
    };
    config.validate().unwrap();
    for origin in [
        "http://manager.example",
        "https://manager.example/",
        "https://user@manager.example",
        "https://manager.example/path",
        "https://manager.example?query",
        "https://manager.example#fragment",
    ] {
        config.manager_origin = origin.into();
        assert!(config.validate().is_err(), "{origin}");
    }
    config.manager_origin = "https://manager.example".into();
    config.basic_metrics_acknowledged = false;
    assert!(config.validate().is_err());
}
