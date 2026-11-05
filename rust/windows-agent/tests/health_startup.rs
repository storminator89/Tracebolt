use chrono::{Duration, Utc};
use fs2::FileExt;
use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose};
use serde_json::{Value, json};
use std::{fs, path::Path};
use tracebolt_windows_agent::{
    config::Config,
    health::{self, Code, Tracker},
    protocol::AcceptedReceipt,
    runtime::Runtime,
    sender::Sender,
};

fn fixture(preprovided: bool) -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("state")).unwrap();
    fs::write(
        root.path().join("config.json"),
        serde_json::to_vec(&json!({
            "schemaVersion":"tracebolt.rust-windows-basic.v1",
            "managerOrigin":"https://private-startup-host.invalid",
            "agentId":if preprovided {"private-startup-identity"} else {""},
            "enrollmentMode":if preprovided {"preprovided"} else {"auto"},
            "basicMetricsAcknowledged":true,"intervalSeconds":60
        }))
        .unwrap(),
    )
    .unwrap();
    if preprovided {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let certificate = params.self_signed(&key).unwrap();
        fs::write(root.path().join("client.pem"), certificate.pem()).unwrap();
        fs::write(root.path().join("client.key"), key.serialize_pem()).unwrap();
        drop(Sender::open(root.path(), true).unwrap());
    }
    root
}

fn status(root: &Path) -> Value {
    serde_json::to_value(health::status(root, Utc::now())).unwrap()
}

fn seed_receipt(root: &Path) -> Value {
    let at = Utc::now() - Duration::seconds(5);
    let mut tracker = Tracker::open(root, &Config::load(root).unwrap()).unwrap();
    tracker.attempt(at).unwrap();
    tracker
        .complete(
            Code::Accepted,
            Some(AcceptedReceipt {
                sequence: 7,
                collected_at: at - Duration::seconds(10),
                received_at: at,
                duplicate: true,
            }),
            at,
            0,
            std::time::Duration::from_secs(60),
            None,
        )
        .unwrap();
    status(root)
}

#[test]
fn failed_startup_records_missing_and_corrupt_state_without_a_receipt_or_retry() {
    for corrupt in [false, true] {
        let root = fixture(false);
        let ledger = root.path().join("state/enrollment.db");
        let original = b"private-startup-ledger-not-a-database";
        if corrupt {
            fs::write(&ledger, original).unwrap();
        }
        let error = Runtime::open(root.path()).err().expect("startup must fail");
        let expected = if corrupt {
            Code::StateCorrupt
        } else {
            Code::StateUnavailable
        };
        assert_eq!(health::classify(&error), expected);
        let observed = status(root.path());
        assert_eq!(observed["state"], expected.as_str());
        assert_eq!(observed["lastAttemptResult"], expected.as_str());
        assert!(observed["lastAttemptAt"].is_string());
        assert!(observed["lastAcceptedReceipt"].is_null());
        assert!(observed["receiptObservedAt"].is_null());
        assert_eq!(observed["retryDelaySeconds"], 0);
        assert!(observed["nextAttemptAt"].is_null());
        assert_eq!(observed["consecutiveFailures"], 1);
        assert_eq!(ledger.exists(), corrupt);
        if corrupt {
            assert_eq!(fs::read(ledger).unwrap(), original);
        }
        let output =
            String::from_utf8(health::support_bundle(root.path(), Utc::now()).unwrap()).unwrap();
        for private in [
            "private-startup-host",
            "private-startup-identity",
            "private-startup-ledger",
            root.path().to_str().unwrap(),
        ] {
            assert!(!output.contains(private));
        }
    }
}

#[test]
fn failed_sender_startup_retains_receipt_and_authority_and_does_not_claim_a_retry() {
    let root = fixture(true);
    let previous = seed_receipt(root.path());
    let ledger_path = root.path().join("state/sender.db");
    let ledger = fs::read(&ledger_path).unwrap();
    fs::remove_file(root.path().join("client.key")).unwrap();
    let error = Runtime::open(root.path())
        .err()
        .expect("missing credentials must fail");
    assert_eq!(health::classify(&error), Code::ConfigurationInvalid);
    let failed = status(root.path());
    assert_eq!(failed["state"], "configuration-invalid");
    assert_eq!(
        failed["lastAcceptedReceipt"],
        previous["lastAcceptedReceipt"]
    );
    assert_eq!(failed["receiptObservedAt"], previous["receiptObservedAt"]);
    assert_ne!(failed["lastAttemptAt"], previous["lastAttemptAt"]);
    assert_eq!(failed["retryDelaySeconds"], 0);
    assert!(failed["nextAttemptAt"].is_null());
    assert_eq!(fs::read(ledger_path).unwrap(), ledger);
}

#[test]
fn successful_startup_does_not_refresh_old_diagnostics_or_receipt_times() {
    let root = fixture(true);
    seed_receipt(root.path());
    let path = root.path().join("state/health-v1.json");
    let original = fs::read(&path).unwrap();
    drop(Runtime::open(root.path()).unwrap());
    assert_eq!(fs::read(path).unwrap(), original);
}

#[test]
fn a_second_open_cannot_overwrite_an_active_runtime_diagnostic() {
    for active_enabled in [false, true] {
        for foreground_enabled in [false, true] {
            let root = fixture(true);
            seed_receipt(root.path());
            let path = root.path().join("state/health-v1.json");
            let original = fs::read(&path).unwrap();
            let active = if active_enabled {
                Runtime::open(root.path())
            } else {
                Runtime::open_without_health(root.path())
            }
            .unwrap();
            let second = if foreground_enabled {
                Runtime::open(root.path())
            } else {
                Runtime::open_without_health(root.path())
            };
            assert_eq!(
                health::classify(&second.err().expect("single authoritative owner")),
                Code::StateUnavailable
            );
            assert_eq!(fs::read(&path).unwrap(), original);
            drop(active);
            assert!(Runtime::open(root.path()).is_ok());
            assert_eq!(fs::read(path).unwrap(), original);
        }
    }
}

#[test]
fn unavailable_optional_writer_lock_never_becomes_sender_authority() {
    let root = fixture(true);
    seed_receipt(root.path());
    let path = root.path().join("state/health-v1.json");
    let original = fs::read(&path).unwrap();
    let lock_path = root.path().join("state/health-v1.lock");
    fs::write(&lock_path, []).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&lock_path)
        .unwrap();
    lock.try_lock_exclusive().unwrap();
    let mut runtime = Runtime::open(root.path()).unwrap();
    assert!(runtime.health_requested());
    assert!(!runtime.health_available());
    let error = runtime
        .cycle(|| anyhow::bail!("private-source-failure"))
        .unwrap_err();
    assert_eq!(health::classify(&error), Code::CollectionFailed);
    assert_eq!(runtime.health_code(), Code::CollectionFailed);
    assert_eq!(fs::read(path).unwrap(), original);
}

#[test]
fn failed_startup_opt_out_and_invalid_diagnostics_preserve_existing_bytes() {
    for disabled in [false, true] {
        let root = fixture(false);
        let path = root.path().join("state/health-v1.json");
        let original = b"private-startup-token-cookie-invalid-diagnostic";
        fs::write(&path, original).unwrap();
        let opened = if disabled {
            Runtime::open_without_health(root.path())
        } else {
            Runtime::open(root.path())
        };
        assert_eq!(
            health::classify(&opened.err().unwrap()),
            Code::StateUnavailable
        );
        assert_eq!(fs::read(path).unwrap(), original);
        assert_eq!(status(root.path())["state"], "health-unavailable");
    }
    let root = fixture(false);
    assert!(Runtime::open_without_health(root.path()).is_err());
    assert!(!root.path().join("state/health-v1.json").exists());
}

#[test]
fn failed_startup_does_not_overwrite_uncertain_temporary_diagnostic_state() {
    let root = fixture(false);
    let temporary = root.path().join("state/health-v1.tmp");
    let original = b"retained-uncertain-private-diagnostic";
    fs::write(&temporary, original).unwrap();
    assert_eq!(
        health::classify(&Runtime::open(root.path()).err().unwrap()),
        Code::StateUnavailable
    );
    assert_eq!(fs::read(temporary).unwrap(), original);
    assert!(!root.path().join("state/health-v1.json").exists());
}

#[test]
fn invalid_configuration_is_read_only_and_cannot_adopt_a_previous_binding() {
    let root = fixture(false);
    fs::write(
        root.path().join("config.json"),
        b"private-invalid-config-token",
    )
    .unwrap();
    let original = fs::read(root.path().join("config.json")).unwrap();
    assert_eq!(
        health::classify(&Runtime::open(root.path()).err().unwrap()),
        Code::ConfigurationInvalid
    );
    assert_eq!(status(root.path())["state"], "configuration-invalid");
    assert_eq!(fs::read(root.path().join("config.json")).unwrap(), original);
    assert_eq!(fs::read_dir(root.path().join("state")).unwrap().count(), 0);
}
