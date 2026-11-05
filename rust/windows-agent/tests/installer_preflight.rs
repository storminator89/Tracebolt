mod common;
use common::Manager;
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use std::{fs, path::Path, process::Command};
use tracebolt_windows_agent::{
    config::{Config, EnrollmentMode},
    enrollment::{Enrollment, validate_initial_bootstrap},
    enrollment_wire::Bootstrap,
};

fn config(origin: &str, mode: EnrollmentMode) -> Config {
    Config {
        schema_version: "tracebolt.rust-windows-basic.v1".into(),
        manager_origin: origin.into(),
        agent_origin: String::new(),
        agent_id: if mode == EnrollmentMode::Preprovided {
            "approved-fixture".into()
        } else {
            String::new()
        },
        enrollment_mode: mode,
        basic_metrics_acknowledged: true,
        interval_seconds: 60,
    }
}

fn bootstrap(origin: &str) -> Bootstrap {
    let mut params = CertificateParams::new(vec![]).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let root_key = KeyPair::generate().unwrap();
    let root = params.self_signed(&root_key).unwrap();
    let issuer = Issuer::new(params, root_key);
    let mut params = CertificateParams::new(vec![]).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let issuer_key = KeyPair::generate().unwrap();
    let certificate = params.signed_by(&issuer_key, &issuer).unwrap();
    Bootstrap {
        schema_version: "tracebolt.enrollment-bootstrap.v2".into(),
        manager_instance_id: format!("manager_{}", "1".repeat(32)),
        profile: "tls".into(),
        enrollment_origin: origin.into(),
        agent_origin: "https://agent.fixture.example:9444".into(),
        collection_profile: "windows-inventory-v1".into(),
        invitation_id: format!("invite_{}", "2".repeat(32)),
        server_ca_pem: root.pem(),
        issuer_root_pem: root.pem(),
        issuer_pem: certificate.pem(),
        renewal_policy: String::new(),
    }
}

fn invalid_authority(ca: bool, expired: bool) -> String {
    let mut params = CertificateParams::new(vec![]).unwrap();
    if ca {
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    }
    if expired {
        params.not_before = rcgen::date_time_ymd(2019, 1, 1);
        params.not_after = rcgen::date_time_ymd(2020, 1, 1);
    }
    params
        .self_signed(&KeyPair::generate().unwrap())
        .unwrap()
        .pem()
}

// Include directories as well as exact bytes, so an empty staging directory or
// lock file is a failure too. All files/keys here are disposable synthetic input.
fn snapshot(directory: &Path) -> Vec<(std::path::PathBuf, Option<Vec<u8>>)> {
    fn collect(root: &Path, path: &Path, out: &mut Vec<(std::path::PathBuf, Option<Vec<u8>>)>) {
        for entry in fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                out.push((path.strip_prefix(root).unwrap().into(), None));
                collect(root, &path, out);
            } else {
                out.push((
                    path.strip_prefix(root).unwrap().into(),
                    Some(fs::read(path).unwrap()),
                ));
            }
        }
    }
    let mut result = Vec::new();
    collect(directory, directory, &mut result);
    result.sort();
    result
}

fn validate(
    directory: &Path,
    origin: &str,
    mode: &str,
    file: Option<&Path>,
) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_tracebolt-windows-agent"));
    command.args([
        "validate-config",
        "--manager-origin",
        origin,
        "--mode",
        mode,
    ]);
    if mode == "preprovided" {
        command.args(["--agent-id", "approved-fixture"]);
    }
    if let Some(file) = file {
        command.arg("--bootstrap").arg(file);
    }
    command.current_dir(directory).output().unwrap()
}

#[test]
fn valid_invitation_offline_preflight_is_repeatable_and_never_adopts_trust_or_state() {
    let directory = tempfile::tempdir().unwrap();
    let origin = "https://must-not-contact.invalid";
    let file = directory.path().join("bootstrap.json");
    let input = bootstrap(origin);
    fs::write(&file, serde_json::to_vec(&input).unwrap()).unwrap();
    fs::write(directory.path().join("foreign-file"), b"unchanged").unwrap();
    let before = snapshot(directory.path());
    for _ in 0..2 {
        let result = validate(directory.path(), origin, "invitation", Some(&file));
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(
            String::from_utf8_lossy(&result.stdout)
                .contains("Manager connectivity and approval not tested")
        );
        assert_eq!(before, snapshot(directory.path()));
    }
    for mode in [EnrollmentMode::Auto, EnrollmentMode::Preprovided] {
        assert!(validate_initial_bootstrap(&config(origin, mode), None).is_ok());
        assert!(validate_initial_bootstrap(&config(origin, mode), Some(&input)).is_err());
    }
    assert!(validate_initial_bootstrap(&config(origin, EnrollmentMode::Invitation), None).is_err());
    for mode in ["auto", "preprovided"] {
        assert!(
            !validate(directory.path(), origin, mode, Some(&file))
                .status
                .success()
        );
        assert_eq!(
            validate(directory.path(), origin, mode, None)
                .status
                .success(),
            mode == "auto"
        );
        assert_eq!(before, snapshot(directory.path()));
    }
    assert!(
        !validate(directory.path(), origin, "invitation", None)
            .status
            .success()
    );
    assert_eq!(before, snapshot(directory.path()));
}

#[test]
fn invalid_invitation_semantics_fail_before_network_state_or_key_creation() {
    let manager = Manager::compatible();
    let valid = bootstrap(&manager.origin);
    for case in [
        "schema",
        "profile",
        "renewal",
        "scope",
        "origin",
        "manager-id",
        "invitation-id",
        "zero-id",
        "uppercase-id",
        "agent-origin",
        "agent-pin",
        "root",
        "issuer",
        "expired-root",
        "expired-issuer",
        "non-ca-root",
        "non-ca-issuer",
        "signature",
        "server-ca",
    ] {
        let directory = tempfile::tempdir().unwrap();
        fs::create_dir(directory.path().join("state")).unwrap();
        fs::write(directory.path().join("state/foreign-file"), b"unchanged").unwrap();
        let mut config = config(&manager.origin, EnrollmentMode::Invitation);
        let mut input = valid.clone();
        match case {
            "schema" => input.schema_version = "future".into(),
            "profile" => input.profile = "http-test".into(),
            "renewal" => input.renewal_policy = "same-key-v1".into(),
            "scope" => input.collection_profile = "linux-basic-v1".into(),
            "origin" => input.enrollment_origin = "https://other.invalid".into(),
            "manager-id" => input.manager_instance_id = format!("manager_{}", "z".repeat(32)),
            "invitation-id" => input.invitation_id = "invite_short".into(),
            "zero-id" => input.invitation_id = format!("invite_{}", "0".repeat(32)),
            "uppercase-id" => input.invitation_id = format!("invite_{}", "A".repeat(32)),
            "agent-origin" => input.agent_origin = "http://agent.invalid".into(),
            "agent-pin" => config.agent_origin = "https://different.invalid".into(),
            "root" => input.issuer_root_pem = "private-looking-invalid-root".into(),
            "issuer" => input.issuer_pem = "private-looking-invalid-issuer".into(),
            "expired-root" => input.issuer_root_pem = invalid_authority(true, true),
            "expired-issuer" => input.issuer_pem = invalid_authority(true, true),
            "non-ca-root" => input.issuer_root_pem = invalid_authority(false, false),
            "non-ca-issuer" => input.issuer_pem = invalid_authority(false, false),
            "signature" => input.issuer_root_pem = bootstrap(&manager.origin).issuer_root_pem,
            "server-ca" => input.server_ca_pem = "private-looking-invalid-ca".into(),
            _ => unreachable!(),
        }
        fs::write(
            directory.path().join("config.json"),
            serde_json::to_vec(&config).unwrap(),
        )
        .unwrap();
        fs::write(directory.path().join("server-ca.pem"), &manager.ca).unwrap();
        let file = directory.path().join("bootstrap.json");
        fs::write(&file, serde_json::to_vec(&input).unwrap()).unwrap();
        let before = snapshot(directory.path());
        let error = Enrollment::open(directory.path(), true, Some(input))
            .err()
            .unwrap();
        if matches!(
            case,
            "expired-root" | "expired-issuer" | "non-ca-root" | "non-ca-issuer"
        ) {
            assert_eq!(error.to_string(), "invalid issuing authority", "{case}");
        }
        assert_eq!(before, snapshot(directory.path()), "library {case}");
        for operation in ["validate-config", "init"] {
            let mut command = Command::new(env!("CARGO_BIN_EXE_tracebolt-windows-agent"));
            command.arg(operation).arg("--bootstrap").arg(&file);
            if operation == "init" {
                command.arg("--directory").arg(directory.path());
            } else {
                command
                    .args([
                        "--mode",
                        "invitation",
                        "--manager-origin",
                        &manager.origin,
                        "--check-manager",
                        "--server-ca-file",
                    ])
                    .arg(directory.path().join("server-ca.pem"));
                if !config.agent_origin.is_empty() {
                    command.args(["--agent-origin", &config.agent_origin]);
                }
            }
            let result = command.current_dir(directory.path()).output().unwrap();
            assert!(!result.status.success(), "{operation} {case}");
            let stderr = String::from_utf8_lossy(&result.stderr);
            assert!(!stderr.contains("private-looking") && !stderr.contains("BEGIN CERTIFICATE"));
            assert_eq!(before, snapshot(directory.path()), "{operation} {case}");
        }
    }
    assert!(
        manager.requests().is_empty(),
        "invalid public input contacted manager"
    );
}

#[test]
fn initial_bootstrap_mode_errors_preserve_cli_and_library_inputs() {
    let manager = Manager::compatible();
    for mode in [
        EnrollmentMode::Auto,
        EnrollmentMode::Invitation,
        EnrollmentMode::Preprovided,
    ] {
        let directory = tempfile::tempdir().unwrap();
        fs::create_dir(directory.path().join("state")).unwrap();
        fs::write(directory.path().join("state/foreign-file"), b"unchanged").unwrap();
        fs::write(
            directory.path().join("config.json"),
            serde_json::to_vec(&config(&manager.origin, mode)).unwrap(),
        )
        .unwrap();
        fs::write(directory.path().join("server-ca.pem"), &manager.ca).unwrap();
        let input = (mode != EnrollmentMode::Invitation).then(|| bootstrap(&manager.origin));
        let file = directory.path().join("bootstrap.json");
        if let Some(input) = &input {
            fs::write(&file, serde_json::to_vec(input).unwrap()).unwrap();
        }
        let before = snapshot(directory.path());
        assert!(Enrollment::open(directory.path(), true, input).is_err());
        assert_eq!(before, snapshot(directory.path()));
        let mut command = Command::new(env!("CARGO_BIN_EXE_tracebolt-windows-agent"));
        command.args(["init", "--directory"]).arg(directory.path());
        if file.exists() {
            command.arg("--bootstrap").arg(&file);
        }
        assert!(!command.output().unwrap().status.success());
        assert_eq!(before, snapshot(directory.path()));
    }
    assert!(manager.requests().is_empty());
}

#[test]
fn bootstrap_parse_and_mode_errors_preserve_existing_files_without_network() {
    let origin = "https://must-not-contact.invalid";
    let valid = serde_json::to_string(&bootstrap(origin)).unwrap();
    let unknown = format!("{{\"unknown\":\"private-looking\",{}", &valid[1..]);
    let duplicate = format!("{{\"profile\":\"tls\",{}", &valid[1..]);
    for bytes in [
        b"not-json".to_vec(),
        b"null".to_vec(),
        vec![b' '; 65537],
        unknown.into_bytes(),
        duplicate.into_bytes(),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("bootstrap.json");
        fs::write(&file, bytes).unwrap();
        let before = snapshot(directory.path());
        let result = validate(directory.path(), origin, "invitation", Some(&file));
        assert!(!result.status.success());
        assert!(!String::from_utf8_lossy(&result.stderr).contains("private-looking"));
        assert_eq!(before, snapshot(directory.path()));
    }
}

#[test]
fn valid_invitation_init_rechecks_then_creates_a_single_bound_identity() {
    let manager = Manager::compatible();
    let directory = tempfile::tempdir().unwrap();
    fs::create_dir(directory.path().join("state")).unwrap();
    fs::write(
        directory.path().join("config.json"),
        serde_json::to_vec(&config(&manager.origin, EnrollmentMode::Invitation)).unwrap(),
    )
    .unwrap();
    fs::write(directory.path().join("server-ca.pem"), &manager.ca).unwrap();
    let file = directory.path().join("bootstrap.json");
    fs::write(
        &file,
        serde_json::to_vec(&bootstrap(&manager.origin)).unwrap(),
    )
    .unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_tracebolt-windows-agent"))
        .args(["init", "--directory"])
        .arg(directory.path())
        .arg("--bootstrap")
        .arg(&file)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(directory.path().join("state/enrollment.db").is_file());
    assert_eq!(manager.requests().len(), 2);
    // Reinitialization must not replace the original enrollment/key bytes.
    let before = snapshot(directory.path());
    assert!(Enrollment::open(directory.path(), true, Some(bootstrap(&manager.origin))).is_err());
    assert_eq!(before, snapshot(directory.path()));
}

#[test]
fn public_preflight_never_creates_installation_or_identity_state() {
    let directory = tempfile::tempdir().unwrap();
    for (origin, success) in [
        ("https://manager.example:9443", true),
        ("http://manager.example:9443", false),
        ("https://manager.example:9443/path", false),
        ("https://user:password@manager.example", false),
    ] {
        let result = Command::new(env!("CARGO_BIN_EXE_tracebolt-windows-agent"))
            .args(["validate-config", "--manager-origin", origin])
            .current_dir(directory.path())
            .output()
            .unwrap();
        assert_eq!(result.status.success(), success);
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
        assert!(!String::from_utf8_lossy(&result.stderr).contains("password"));
    }
    let ca = directory.path().join("invalid-ca.pem");
    std::fs::write(&ca, b"not a certificate").unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_tracebolt-windows-agent"))
        .args([
            "validate-config",
            "--manager-origin",
            "https://manager.example:9443",
            "--server-ca-file",
        ])
        .arg(ca)
        .current_dir(directory.path())
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
}
