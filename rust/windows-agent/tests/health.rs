use chrono::{Duration as ChronoDuration, TimeZone, Utc};
use serde_json::{Value, json};
use std::{fs, time::Duration};
use tracebolt_windows_agent::{
    config::Config,
    health::{self, Code, Tracker},
    protocol::{self, AcceptedReceipt},
};

fn fixture() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("state")).unwrap();
    fs::write(root.path().join("config.json"), serde_json::to_vec(&json!({
        "schemaVersion":"tracebolt.rust-windows-basic.v1", "managerOrigin":"https://private-host-sentinel.invalid",
        "agentId":"private-identity-sentinel", "enrollmentMode":"preprovided",
        "basicMetricsAcknowledged":true,"intervalSeconds":60
    })).unwrap()).unwrap();
    root
}
fn now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 30, 20, 0, 0).unwrap()
}
fn encoded(directory: &std::path::Path, at: chrono::DateTime<Utc>) -> Value {
    serde_json::to_value(health::status(directory, at)).unwrap()
}
fn open_tracker(directory: &std::path::Path) -> Tracker {
    Tracker::open(directory, &Config::load(directory).unwrap()).unwrap()
}
fn accepted() -> AcceptedReceipt {
    AcceptedReceipt {
        sequence: 7,
        collected_at: now() - ChronoDuration::seconds(20),
        received_at: now() - ChronoDuration::seconds(2),
        duplicate: true,
    }
}

#[test]
fn readonly_status_and_bundle_do_not_initialize_state_or_claim_running_is_receipt() {
    let root = fixture();
    let config = fs::read(root.path().join("config.json")).unwrap();
    let status = encoded(root.path(), now());
    assert_eq!(status["state"], "not-observed");
    assert!(status["lastAcceptedReceipt"].is_null());
    assert_eq!(status["serviceState"], "not-inspected");
    assert_eq!(status["receiptFreshness"], "no-accepted-receipt-recorded");
    let bundle = String::from_utf8(health::support_bundle(root.path(), now()).unwrap()).unwrap();
    assert!(bundle.len() <= health::MAX_BYTES as usize);
    assert!(!bundle.contains("private-host-sentinel"));
    assert!(!bundle.contains("private-identity-sentinel"));
    assert!(!bundle.contains("configurationBinding"));
    assert!(!bundle.contains(root.path().to_str().unwrap()));
    assert_eq!(fs::read(root.path().join("config.json")).unwrap(), config);
    assert_eq!(fs::read_dir(root.path().join("state")).unwrap().count(), 0);
}

#[test]
fn original_validated_receipt_times_survive_failure_and_restart_without_refresh() {
    let root = fixture();
    let mut tracker = open_tracker(root.path());
    tracker.attempt(now()).unwrap();
    assert_eq!(encoded(root.path(), now())["state"], "attempt-in-progress");
    tracker
        .complete(
            Code::Accepted,
            Some(accepted()),
            now(),
            0,
            Duration::from_secs(60),
            Some(now() + ChronoDuration::days(2)),
        )
        .unwrap();
    drop(tracker);
    let initial = encoded(root.path(), now());
    assert_eq!(initial["state"], "accepted");
    assert_eq!(initial["lastAcceptedReceipt"]["sequence"], 7);
    assert_eq!(initial["lastAcceptedReceipt"]["duplicate"], true);
    assert_eq!(initial["receiptFreshness"], "recent-validated-receipt");
    let mut tracker = open_tracker(root.path());
    let later = now() + ChronoDuration::seconds(40);
    tracker.attempt(later).unwrap();
    tracker
        .complete(
            Code::TransportUnclassified,
            None,
            later,
            1,
            Duration::from_secs(67),
            Some(now() + ChronoDuration::days(2)),
        )
        .unwrap();
    let failed = encoded(root.path(), later);
    assert_eq!(failed["state"], "transport-unclassified");
    assert_eq!(
        failed["lastAcceptedReceipt"],
        initial["lastAcceptedReceipt"]
    );
    assert_eq!(failed["receiptObservedAt"], initial["receiptObservedAt"]);
    assert_eq!(failed["retryDelaySeconds"], 67);
    assert_eq!(
        encoded(root.path(), now() + ChronoDuration::hours(3))["receiptFreshness"],
        "stale-validated-receipt"
    );
}

#[test]
fn support_allowlist_rejects_injected_raw_fields_unknown_versions_and_oversized_state() {
    for raw in [
        br#"{"schemaVersion":"tracebolt.rust-agent-health.v1","token":"private-token-sentinel","telemetry":{"cpu":99}}"#.to_vec(),
        br#"{"schemaVersion":"private-key-sentinel"}"#.to_vec(),
        vec![b'x';health::MAX_BYTES as usize+1],
    ] {
        let root=fixture(); let path=root.path().join("state/health-v1.json");fs::write(&path,&raw).unwrap();
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let output=String::from_utf8(health::support_bundle(root.path(),now()).unwrap()).unwrap();
        assert_eq!(encoded(root.path(),now())["state"],"health-unavailable");
        for private in ["private-token-sentinel","private-key-sentinel","private-host-sentinel","private-identity-sentinel","telemetry"] { assert!(!output.contains(private)); }
        assert_eq!(fs::read(path).unwrap(),raw);
        assert!(Tracker::open(root.path(),&Config::load(root.path()).unwrap()).is_err());
    }
}

#[test]
fn diagnostic_failure_preserves_uncertain_temp_and_authoritative_ledger_bytes() {
    let root = fixture();
    let state = root.path().join("state");
    fs::write(
        state.join("sender.db"),
        b"private-ledger-sentinel; do not open or reset",
    )
    .unwrap();
    fs::write(state.join("health-v1.tmp"), b"retained uncertain temporary").unwrap();
    let mut tracker = open_tracker(root.path());
    assert!(tracker.attempt(now()).is_err());
    assert_eq!(
        fs::read(state.join("sender.db")).unwrap(),
        b"private-ledger-sentinel; do not open or reset"
    );
    assert_eq!(
        fs::read(state.join("health-v1.tmp")).unwrap(),
        b"retained uncertain temporary"
    );
    assert!(!state.join("health-v1.json").exists());
    assert!(
        !String::from_utf8(health::support_bundle(root.path(), now()).unwrap())
            .unwrap()
            .contains("private-ledger-sentinel")
    );
}

#[test]
fn certificate_expiry_and_clock_uncertainty_never_turn_old_acceptance_fresh() {
    let root = fixture();
    let mut tracker = open_tracker(root.path());
    tracker.attempt(now()).unwrap();
    tracker
        .complete(
            Code::Accepted,
            Some(accepted()),
            now(),
            0,
            Duration::from_secs(60),
            Some(now() + ChronoDuration::hours(23)),
        )
        .unwrap();
    assert_eq!(encoded(root.path(), now())["certificateStatus"], "expiring");
    let expired = encoded(root.path(), now() + ChronoDuration::days(1));
    assert_eq!(expired["state"], "certificate-expired");
    assert_eq!(expired["receiptFreshness"], "stale-validated-receipt");
    let moved_back = encoded(root.path(), now() - ChronoDuration::minutes(5));
    assert_eq!(moved_back["state"], "clock-invalid");
    assert_eq!(moved_back["receiptFreshness"], "clock-unknown");
}

#[test]
fn future_local_attempts_report_clock_uncertainty_without_changing_retained_state() {
    for completed in [false, true] {
        let root = fixture();
        let future = now() + ChronoDuration::seconds(31);
        let mut tracker = open_tracker(root.path());
        tracker.attempt(future).unwrap();
        if completed {
            tracker
                .complete(
                    Code::PendingApproval,
                    None,
                    future,
                    0,
                    Duration::from_secs(30),
                    None,
                )
                .unwrap();
        }
        drop(tracker);
        let path = root.path().join("state/health-v1.json");
        let original = fs::read(&path).unwrap();
        let status = encoded(root.path(), now());
        assert_eq!(status["state"], "clock-invalid");
        assert_eq!(status["lastAttemptAt"], json!(future));
        assert_eq!(
            status["lastAttemptResult"],
            if completed {
                "pending-approval"
            } else {
                "attempt-in-progress"
            }
        );
        assert_eq!(status["receiptFreshness"], "no-accepted-receipt-recorded");
        assert!(status["lastAcceptedReceipt"].is_null());
        let bundle: Value =
            serde_json::from_slice(&health::support_bundle(root.path(), now()).unwrap()).unwrap();
        assert_eq!(bundle["diagnostic"]["state"], "clock-invalid");
        assert_eq!(fs::read(&path).unwrap(), original);
    }
}

#[test]
fn later_impossible_attempt_does_not_keep_an_older_receipt_recent() {
    let root = fixture();
    let mut tracker = open_tracker(root.path());
    tracker.attempt(now()).unwrap();
    tracker
        .complete(
            Code::Accepted,
            Some(accepted()),
            now(),
            0,
            Duration::from_secs(60),
            None,
        )
        .unwrap();
    let accepted = encoded(root.path(), now());
    let future = now() + ChronoDuration::seconds(31);
    tracker.attempt(future).unwrap();
    tracker
        .complete(
            Code::TransportTimeout,
            None,
            future,
            1,
            Duration::from_secs(60),
            None,
        )
        .unwrap();
    drop(tracker);
    let status = encoded(root.path(), now());
    assert_eq!(status["state"], "clock-invalid");
    assert_eq!(status["receiptFreshness"], "clock-unknown");
    assert_eq!(status["lastAttemptResult"], "transport-timeout");
    assert_eq!(
        status["lastAcceptedReceipt"],
        accepted["lastAcceptedReceipt"]
    );
    assert_eq!(status["receiptObservedAt"], accepted["receiptObservedAt"]);
}

#[test]
fn clock_allowance_is_exact_and_scheduled_retry_is_not_a_future_observation() {
    let root = fixture();
    let mut tracker = open_tracker(root.path());
    let allowance = now() + ChronoDuration::seconds(30);
    tracker.attempt(allowance).unwrap();
    assert_eq!(encoded(root.path(), now())["state"], "attempt-in-progress");
    tracker
        .attempt(allowance + ChronoDuration::nanoseconds(1))
        .unwrap();
    assert_eq!(encoded(root.path(), now())["state"], "clock-invalid");
    tracker.attempt(now()).unwrap();
    tracker
        .complete(
            Code::TransportTimeout,
            None,
            now(),
            1,
            Duration::from_secs(3600),
            None,
        )
        .unwrap();
    let status = encoded(root.path(), now());
    assert_eq!(status["state"], "transport-timeout");
    assert_eq!(
        status["nextAttemptAt"],
        json!(now() + ChronoDuration::hours(1))
    );
}

#[test]
fn readonly_cli_reports_future_attempt_clock_uncertainty_without_a_receipt() {
    let root = fixture();
    let future = Utc::now() + ChronoDuration::minutes(5);
    let mut tracker = open_tracker(root.path());
    tracker.attempt(future).unwrap();
    drop(tracker);
    let path = root.path().join("state/health-v1.json");
    let original = fs::read(&path).unwrap();
    let binary = env!("CARGO_BIN_EXE_tracebolt-windows-agent");
    for command in ["status", "support-bundle"] {
        let mut cli = std::process::Command::new(binary);
        cli.args([command, "--directory"]).arg(root.path());
        if command == "status" {
            cli.arg("--json");
        }
        let output = cli.output().unwrap();
        assert!(output.status.success());
        assert!(output.stderr.is_empty());
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        let status = if command == "status" {
            &value
        } else {
            &value["diagnostic"]
        };
        assert_eq!(status["state"], "clock-invalid");
        assert_eq!(status["lastAttemptResult"], "attempt-in-progress");
        assert!(status["lastAcceptedReceipt"].is_null());
        let text = String::from_utf8(output.stdout).unwrap();
        for private in [
            "private-host-sentinel",
            "private-identity-sentinel",
            root.path().to_str().unwrap(),
        ] {
            assert!(!text.contains(private));
        }
        assert_eq!(fs::read(&path).unwrap(), original);
    }
}

#[test]
fn finite_error_classes_do_not_classify_secrets_by_text_or_equate_401_with_revocation() {
    let raw = anyhow::anyhow!("private-token-sentinel: DNS TLS revoked corruption body");
    assert_eq!(health::classify(&raw), Code::UnclassifiedFailure);
    let tagged = raw.context(Code::AuthenticationRejected);
    assert_eq!(health::classify(&tagged), Code::AuthenticationRejected);
    assert_ne!(health::classify(&tagged), Code::EnrollmentRevoked);
    assert!(
        !Code::AuthenticationRejected
            .to_string()
            .contains("private-token-sentinel")
    );
    let corrupt = rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_NOTADB),
        Some("private-database-path-sentinel".into()),
    );
    assert_eq!(
        health::classify(&anyhow::Error::new(corrupt)),
        Code::StateCorrupt
    );
}

#[test]
fn retry_backoff_and_jitter_are_capped_and_do_not_choose_new_identity_or_sequences() {
    assert_eq!(
        health::retry_delay(Duration::from_secs(30), 1, 0),
        Duration::from_secs(30)
    );
    assert_eq!(
        health::retry_delay(Duration::from_secs(30), 2, 7),
        Duration::from_secs(67)
    );
    assert_eq!(
        health::retry_delay(Duration::from_secs(60), 3, 255),
        Duration::from_secs(270)
    );
    for failures in [0, 1, 8, 16, u32::MAX] {
        for base in [0, 30, 60, 3600, u64::MAX] {
            let seconds = health::retry_delay(Duration::from_secs(base), failures, 255).as_secs();
            assert!((30..=health::MAX_RETRY_SECONDS).contains(&seconds));
        }
    }
}

#[test]
fn accepted_metadata_requires_the_unchanged_identity_sequence_and_time_contract() {
    let raw=serde_json::to_vec(&json!({"schemaVersion":"tracebolt.agent-receipt.v1","agentId":"private-id-sentinel","sequence":7,"collectedAt":now(),"receivedAt":now(),"duplicate":false})).unwrap();
    let receipt =
        protocol::validate_receipt_metadata(&raw, "private-id-sentinel", 7, now(), now()).unwrap();
    let exported = serde_json::to_string(&receipt).unwrap();
    assert!(!exported.contains("private-id-sentinel"));
    assert!(protocol::validate_receipt_metadata(&raw, "wrong", 7, now(), now()).is_err());
    assert!(
        protocol::validate_receipt_metadata(&raw, "private-id-sentinel", 8, now(), now()).is_err()
    );
}

#[cfg(unix)]
#[test]
fn symlinked_or_shared_health_inputs_are_not_followed_or_repaired() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let root = fixture();
    let target = root.path().join("secret.json");
    fs::write(&target, b"private-key-sentinel").unwrap();
    let path = root.path().join("state/health-v1.json");
    symlink(&target, &path).unwrap();
    assert_eq!(encoded(root.path(), now())["state"], "health-unavailable");
    assert_eq!(fs::read(&target).unwrap(), b"private-key-sentinel");
    fs::remove_file(path).unwrap();
    let mut tracker = open_tracker(root.path());
    tracker.attempt(now()).unwrap();
    fs::set_permissions(
        root.path().join("state/health-v1.json"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert_eq!(encoded(root.path(), now())["state"], "health-unavailable");
}

#[test]
fn status_and_support_cli_are_offline_json_and_create_no_lock_or_ledger() {
    let root = fixture();
    let binary = env!("CARGO_BIN_EXE_tracebolt-windows-agent");
    let output = std::process::Command::new(binary)
        .args(["status", "--directory"])
        .arg(root.path())
        .arg("--json")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let status: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(status["state"], "not-observed");
    assert_eq!(status["serviceState"], "not-inspected");
    let output = std::process::Command::new(binary)
        .args(["support-bundle", "--directory"])
        .arg(root.path())
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let bundle: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(bundle["schemaVersion"], "tracebolt.rust-agent-support.v1");
    let text = String::from_utf8(output.stdout).unwrap();
    for private in [
        "private-host-sentinel",
        "private-identity-sentinel",
        root.path().to_str().unwrap(),
    ] {
        assert!(!text.contains(private));
    }
    assert_eq!(fs::read_dir(root.path().join("state")).unwrap().count(), 0);
}

#[test]
fn extreme_strict_schema_times_fail_closed_without_panicking_or_repairing() {
    let root = fixture();
    let mut tracker = open_tracker(root.path());
    tracker.attempt(now()).unwrap();
    tracker
        .complete(
            Code::Accepted,
            Some(accepted()),
            now(),
            0,
            Duration::from_secs(60),
            Some(now() + ChronoDuration::days(2)),
        )
        .unwrap();
    let path = root.path().join("state/health-v1.json");
    let valid: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    for field in ["collectedAt", "receivedAt"] {
        let mut changed = valid.clone();
        changed["lastAcceptedReceipt"][field] = json!("-262143-01-01T00:00:00Z");
        let raw = serde_json::to_vec(&changed).unwrap();
        fs::write(&path, &raw).unwrap();
        assert_eq!(encoded(root.path(), now())["state"], "health-unavailable");
        assert_eq!(fs::read(&path).unwrap(), raw);
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_tracebolt-windows-agent"))
            .args(["status", "--directory"])
            .arg(root.path())
            .arg("--json")
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(output.stderr.is_empty());
    }
    assert_eq!(
        health::status(root.path(), chrono::DateTime::<Utc>::MAX_UTC).state,
        Code::ClockInvalid
    );
}

#[test]
fn typed_transport_results_round_trip_without_refreshing_receipts_or_exporting_causes() {
    for code in [
        Code::TransportDnsFailed,
        Code::TransportTlsFailed,
        Code::TransportConnectionRefused,
        Code::TransportUnreachable,
    ] {
        let root = fixture();
        let mut tracker = open_tracker(root.path());
        tracker.attempt(now()).unwrap();
        tracker
            .complete(
                Code::Accepted,
                Some(accepted()),
                now(),
                0,
                Duration::from_secs(60),
                None,
            )
            .unwrap();
        let original = encoded(root.path(), now());
        let later = now() + ChronoDuration::seconds(40);
        tracker.attempt(later).unwrap();
        tracker
            .complete(code, None, later, 1, Duration::from_secs(67), None)
            .unwrap();
        drop(tracker);
        let retained = encoded(root.path(), later);
        assert_eq!(retained["state"], code.as_str());
        assert_eq!(retained["lastAttemptResult"], code.as_str());
        assert_eq!(
            retained["lastAcceptedReceipt"],
            original["lastAcceptedReceipt"]
        );
        assert_eq!(retained["receiptObservedAt"], original["receiptObservedAt"]);
        assert_eq!(retained["retryDelaySeconds"], 67);
        let bundle =
            String::from_utf8(health::support_bundle(root.path(), later).unwrap()).unwrap();
        assert!(bundle.contains(code.as_str()));
        for private in [
            "private-",
            "localhost",
            "configurationBinding",
            "rawError",
            "sourceChain",
        ] {
            assert!(!bundle.contains(private));
        }
    }
}

#[test]
fn expired_retained_certificate_does_not_hide_current_failure_or_its_next_action() {
    for code in [
        Code::StateCorrupt,
        Code::StateUnavailable,
        Code::ConfigurationInvalid,
        Code::EnrollmentRevoked,
        Code::EnrollmentExpired,
        Code::TransportDnsFailed,
        Code::TransportTlsFailed,
        Code::TransportTimeout,
        Code::ProtocolUnavailable,
        Code::AuthenticationRejected,
        Code::ReceiptInvalid,
    ] {
        let root = fixture();
        let mut tracker = open_tracker(root.path());
        tracker.attempt(now()).unwrap();
        tracker
            .complete(
                Code::Accepted,
                Some(accepted()),
                now(),
                0,
                Duration::from_secs(60),
                Some(now() + ChronoDuration::minutes(1)),
            )
            .unwrap();
        let original = encoded(root.path(), now());
        let later = now() + ChronoDuration::minutes(2);
        tracker.startup_failure(code, later).unwrap();
        let failed = encoded(root.path(), later);
        assert_eq!(failed["state"], code.as_str());
        assert_eq!(failed["lastAttemptResult"], code.as_str());
        assert_eq!(failed["nextAction"], code.next_action());
        assert_eq!(failed["certificateStatus"], "expired");
        assert_eq!(
            failed["lastAcceptedReceipt"],
            original["lastAcceptedReceipt"]
        );
        assert_eq!(failed["receiptObservedAt"], original["receiptObservedAt"]);
    }
}
