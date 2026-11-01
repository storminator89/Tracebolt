use rcgen::{
    BasicConstraints, CertificateParams, CustomExtension, ExtendedKeyUsagePurpose, IsCa, Issuer,
    KeyPair, KeyUsagePurpose,
};
use std::{fs, path::Path, process::Command};
use tracebolt_windows_agent::{
    config::{Config, EnrollmentMode},
    credentials::validate_preprovided,
    health::{self, Code},
    sender::Sender,
    state::State,
};

fn config() -> Config {
    Config {
        schema_version: "tracebolt.rust-windows-basic.v1".into(),
        manager_origin: "https://must-not-contact.invalid".into(),
        agent_id: "approved-fixture".into(),
        enrollment_mode: EnrollmentMode::Preprovided,
        agent_origin: String::new(),
        basic_metrics_acknowledged: true,
        interval_seconds: 60,
    }
}

fn material(case: &str) -> (String, String) {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec![]).unwrap();
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    match case {
        "expired" => {
            params.not_before = rcgen::date_time_ymd(2019, 1, 1);
            params.not_after = rcgen::date_time_ymd(2020, 1, 1);
        }
        "future" => {
            params.not_before = rcgen::date_time_ymd(4095, 1, 1);
            params.not_after = rcgen::date_time_ymd(4096, 1, 1);
        }
        "ca-leaf" => params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained),
        "no-signature" => params.key_usages = vec![KeyUsagePurpose::KeyEncipherment],
        "no-usage" => params.key_usages.clear(),
        "no-eku" => params.extended_key_usages.clear(),
        "server-auth" => params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth],
        "mixed-role" => params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ServerAuth),
        "other-role" => params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::CodeSigning),
        "malformed-basic-constraints" => {
            params
                .custom_extensions
                .push(CustomExtension::from_oid_content(
                    &[2, 5, 29, 19],
                    vec![0x30, 0x02, 0x04, 0x00],
                ))
        }
        "malformed-subject-key-id" => {
            params
                .custom_extensions
                .push(CustomExtension::from_oid_content(
                    &[2, 5, 29, 14],
                    vec![0xff],
                ))
        }
        "duplicate-extension" => {
            for _ in 0..2 {
                params
                    .custom_extensions
                    .push(CustomExtension::from_oid_content(
                        &[1, 2, 3, 4],
                        vec![0x05, 0x00],
                    ));
            }
        }
        _ => {}
    }
    let certificate = params.self_signed(&key).unwrap().pem();
    let mut private_key = key.serialize_pem();
    let certificate = match case {
        "bad-certificate" => "not a certificate".into(),
        "certificate-prefix" => format!("garbage\n{certificate}"),
        "certificate-suffix" => format!("{certificate}\ngarbage"),
        "certificate-key" => format!("{certificate}\n{private_key}"),
        "non-ca-chain" => format!("{certificate}{certificate}"),
        "oversized-certificate" => "x".repeat(32769),
        _ => certificate,
    };
    match case {
        "bad-key" => private_key = "not a key".into(),
        "wrong-key" => private_key = KeyPair::generate().unwrap().serialize_pem(),
        "key-prefix" => private_key = format!("garbage\n{private_key}"),
        "key-suffix" => private_key.push_str("garbage"),
        "duplicate-key" => private_key = private_key.repeat(2),
        "oversized-key" => private_key = "x".repeat(16385),
        _ => {}
    }
    (certificate, private_key)
}

fn input(case: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let (certificate, private_key) = material(case);
    fs::write(dir.path().join("client.pem"), certificate).unwrap();
    fs::write(dir.path().join("client.key"), private_key).unwrap();
    fs::write(
        dir.path().join("config.json"),
        serde_json::to_vec(&config()).unwrap(),
    )
    .unwrap();
    fs::create_dir(dir.path().join("state")).unwrap();
    fs::write(
        dir.path().join("state/foreign-file"),
        b"preserve exact bytes",
    )
    .unwrap();
    dir
}

fn snapshot(directory: &Path) -> Vec<(std::path::PathBuf, Option<Vec<u8>>)> {
    fn collect(root: &Path, path: &Path, out: &mut Vec<(std::path::PathBuf, Option<Vec<u8>>)>) {
        for entry in fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            let relative = path.strip_prefix(root).unwrap().into();
            if path.is_dir() {
                out.push((relative, None));
                collect(root, &path, out);
            } else {
                out.push((relative, Some(fs::read(path).unwrap())));
            }
        }
    }
    let mut result = Vec::new();
    collect(directory, directory, &mut result);
    result.sort();
    result
}

fn validate(directory: &Path, mode: &str, credentials: bool) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_tracebolt-windows-agent"));
    command.args([
        "validate-config",
        "--manager-origin",
        &config().manager_origin,
        "--mode",
        mode,
    ]);
    if mode == "preprovided" {
        command.args(["--agent-id", &config().agent_id]);
    }
    if credentials {
        command.arg("--credential-directory").arg(directory);
    }
    command.current_dir(directory).output().unwrap()
}

#[test]
fn valid_preprovided_offline_validation_is_repeatable_and_never_writes_state() {
    let dir = input("valid");
    let before = snapshot(dir.path());
    for _ in 0..2 {
        validate_preprovided(&config(), dir.path(), &[]).unwrap();
        let result = validate(dir.path(), "preprovided", true);
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(
            String::from_utf8_lossy(&result.stdout)
                .contains("Manager connectivity and approval not tested")
        );
        assert_eq!(before, snapshot(dir.path()));
    }
    // Local material checks deliberately do not attest a chain or the configured
    // approved ID: the manager's independent original approval remains required.
}

#[test]
fn invalid_preprovided_material_fails_before_cli_or_library_sender_state() {
    for case in [
        "expired",
        "future",
        "malformed-basic-constraints",
        "malformed-subject-key-id",
        "duplicate-extension",
        "ca-leaf",
        "no-signature",
        "no-usage",
        "no-eku",
        "server-auth",
        "mixed-role",
        "other-role",
        "bad-certificate",
        "certificate-prefix",
        "certificate-suffix",
        "certificate-key",
        "non-ca-chain",
        "oversized-certificate",
        "bad-key",
        "wrong-key",
        "key-prefix",
        "key-suffix",
        "duplicate-key",
        "oversized-key",
        "missing-certificate",
        "missing-key",
    ] {
        let dir = input(case);
        if case == "missing-certificate" {
            fs::remove_file(dir.path().join("client.pem")).unwrap();
        }
        if case == "missing-key" {
            fs::remove_file(dir.path().join("client.key")).unwrap();
        }
        let before = snapshot(dir.path());
        assert!(
            validate_preprovided(&config(), dir.path(), &[]).is_err(),
            "{case}"
        );
        assert!(
            !validate(dir.path(), "preprovided", true).status.success(),
            "{case}"
        );
        assert!(Sender::open(dir.path(), true).is_err(), "{case}");
        let result = Command::new(env!("CARGO_BIN_EXE_tracebolt-windows-agent"))
            .args(["init", "--directory"])
            .arg(dir.path())
            .output()
            .unwrap();
        assert!(!result.status.success(), "{case}");
        assert_eq!(before, snapshot(dir.path()), "{case}");
        for secret in ["PRIVATE KEY", "BEGIN CERTIFICATE", "preserve exact bytes"] {
            assert!(
                !String::from_utf8_lossy(&result.stderr).contains(secret),
                "{case}"
            );
        }
    }
}

#[test]
fn credential_directory_is_required_only_for_preprovided_mode() {
    let dir = input("valid");
    let before = snapshot(dir.path());
    assert!(!validate(dir.path(), "preprovided", false).status.success());
    for mode in ["auto", "invitation"] {
        assert!(!validate(dir.path(), mode, true).status.success());
    }
    let mut automatic = config();
    automatic.agent_id.clear();
    automatic.enrollment_mode = EnrollmentMode::Auto;
    assert!(validate_preprovided(&automatic, dir.path(), &[]).is_err());
    assert_eq!(before, snapshot(dir.path()));
}

#[test]
fn valid_leaf_and_ca_chain_remain_supported_without_adopting_that_ca() {
    let dir = input("valid");
    let mut params = CertificateParams::new(vec![]).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let key = KeyPair::generate().unwrap();
    let ca = params.self_signed(&key).unwrap();
    let issuer = Issuer::new(params, key);
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec![]).unwrap();
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let leaf = params.signed_by(&key, &issuer).unwrap();
    fs::write(
        dir.path().join("client.pem"),
        format!("{}{}", leaf.pem(), ca.pem()),
    )
    .unwrap();
    fs::write(dir.path().join("client.key"), key.serialize_pem()).unwrap();
    let before = snapshot(dir.path());
    validate_preprovided(&config(), dir.path(), &[]).unwrap();
    assert!(validate(dir.path(), "preprovided", true).status.success());
    assert_eq!(before, snapshot(dir.path()));
    assert!(!dir.path().join("server-ca.pem").exists());
}

fn chain_input(certificate_count: usize, ca_case: &str) -> tempfile::TempDir {
    assert!(certificate_count >= 2);
    let dir = input("valid");
    let mut issuer = None;
    let mut certificates = Vec::new();
    for index in 0..certificate_count - 1 {
        let mut params = CertificateParams::new(vec![]).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        // Mutate a middle CA, not the leaf: every chain entry must be checked.
        if index == 1 {
            match ca_case {
                "expired" => {
                    params.not_before = rcgen::date_time_ymd(2019, 1, 1);
                    params.not_after = rcgen::date_time_ymd(2020, 1, 1);
                }
                "future" => {
                    params.not_before = rcgen::date_time_ymd(4095, 1, 1);
                    params.not_after = rcgen::date_time_ymd(4096, 1, 1);
                }
                "malformed-extension" => {
                    params
                        .custom_extensions
                        .push(CustomExtension::from_oid_content(
                            &[2, 5, 29, 14],
                            vec![0xff],
                        ))
                }
                "duplicate-extension" => {
                    for _ in 0..2 {
                        params
                            .custom_extensions
                            .push(CustomExtension::from_oid_content(
                                &[1, 2, 3, 4],
                                vec![0x05, 0x00],
                            ));
                    }
                }
                _ => {}
            }
        }
        let key = KeyPair::generate().unwrap();
        let certificate = match &issuer {
            Some(issuer) => params.signed_by(&key, issuer).unwrap(),
            None => params.self_signed(&key).unwrap(),
        };
        certificates.push(certificate.pem());
        issuer = Some(Issuer::new(params, key));
    }
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec![]).unwrap();
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let leaf = params.signed_by(&key, issuer.as_ref().unwrap()).unwrap();
    let mut chain = leaf.pem();
    for certificate in certificates.into_iter().rev() {
        chain.push_str(&certificate);
    }
    fs::write(dir.path().join("client.pem"), chain).unwrap();
    fs::write(dir.path().join("client.key"), key.serialize_pem()).unwrap();
    dir
}

#[test]
fn certificate_chain_count_and_each_ca_entry_are_checked_without_writes() {
    for count in [8, 9] {
        let dir = chain_input(count, "valid");
        let before = snapshot(dir.path());
        assert_eq!(
            validate_preprovided(&config(), dir.path(), &[]).is_ok(),
            count == 8
        );
        assert_eq!(
            validate(dir.path(), "preprovided", true).status.success(),
            count == 8
        );
        if count == 9 {
            assert!(Sender::open(dir.path(), true).is_err());
        }
        assert_eq!(before, snapshot(dir.path()));
    }
    for case in [
        "expired",
        "future",
        "malformed-extension",
        "duplicate-extension",
    ] {
        let dir = chain_input(4, case);
        let before = snapshot(dir.path());
        assert!(
            validate_preprovided(&config(), dir.path(), &[]).is_err(),
            "{case}"
        );
        assert!(
            !validate(dir.path(), "preprovided", true).status.success(),
            "{case}"
        );
        assert!(Sender::open(dir.path(), true).is_err(), "{case}");
        assert_eq!(before, snapshot(dir.path()), "{case}");
    }
}

#[test]
fn existing_expired_sender_keeps_its_diagnostic_and_exact_pending_state() {
    let dir = input("expired");
    let binding = config()
        .binding(&fs::read(dir.path().join("client.pem")).unwrap(), &[])
        .unwrap();
    // Model state created while the now-expired certificate was valid, without
    // weakening fresh initialization or changing any original certificate bytes.
    let state = State::open(&dir.path().join("state"), &binding, true).unwrap();
    state.prepare(1, b"original exact pending bytes").unwrap();
    state.advance(1).unwrap();
    state.prepare(2, b"second exact pending bytes").unwrap();
    drop(state);
    let before = snapshot(dir.path());
    for _ in 0..2 {
        assert!(Sender::open(dir.path(), true).is_err());
        let mut sender = Sender::open(dir.path(), false).unwrap();
        let error = sender
            .report(|| panic!("expired sender must not collect or send"))
            .unwrap_err();
        assert_eq!(health::classify(&error), Code::CertificateExpired);
        drop(sender);
        let state = State::open(&dir.path().join("state"), &binding, false).unwrap();
        assert_eq!(
            state.current().unwrap(),
            (2, Some(b"second exact pending bytes".to_vec()))
        );
        drop(state);
        assert_eq!(before, snapshot(dir.path()));
    }
}

// Source-order contract only: this does not execute PowerShell or Windows SCM.
#[test]
fn preprovided_inputs_precede_installer_and_sender_mutations() {
    fn order(source: &str, markers: &[&str]) {
        let mut last = None;
        for marker in markers {
            let at = source
                .find(marker)
                .unwrap_or_else(|| panic!("missing {marker}"));
            assert!(last.is_none_or(|last| at > last), "out of order: {marker}");
            last = Some(at);
        }
    }
    order(
        include_str!("../../../deploy/windows-rust/Install-Tracebolt.ps1"),
        &[
            "if ($mode -eq 'preprovided') { $validationArguments += '--credential-directory',$CredentialDirectory }",
            "& $Executable @validationArguments",
            "if ($LASTEXITCODE -ne 0)",
            "New-Service -Name",
            "New-Item -ItemType Directory",
        ],
    );
    let main = include_str!("../src/main.rs");
    order(
        &main[main.find("Command::ValidateConfig {").unwrap()..],
        &[
            "config.validate()?;",
            "validate_initial_bootstrap(&config, bootstrap.as_ref())?;",
            "tls_builder(&ca)?.build()?;",
            "match (enrollment_mode, credential_directory)",
            "tracebolt_windows_agent::credentials::validate_preprovided(",
            "if check_manager {",
        ],
    );
    order(
        include_str!("../src/sender.rs"),
        &[
            "pub fn open(",
            "if initialize {",
            "crate::credentials::validate_material(",
            "Self::from_material(",
            "fn from_material(",
            "crate::credentials::client(",
            "State::open(",
        ],
    );
    let credentials = include_str!("../src/credentials.rs");
    for forbidden in [
        "State::",
        "create_dir",
        "fs::write",
        "File::create",
        ".send()",
    ] {
        assert!(
            !credentials.contains(forbidden),
            "unexpected mutation/network marker {forbidden}"
        );
    }
}
