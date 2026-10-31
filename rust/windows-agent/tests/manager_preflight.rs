mod common;
use common::{Manager, capabilities, response};
use serde_json::json;
use std::{fs, process::Command};
use tracebolt_windows_agent::{
    compatibility::{self, PreflightError},
    config::{Config, EnrollmentMode},
    enrollment::Enrollment,
};

fn config(origin: &str) -> Config {
    Config {
        schema_version: "tracebolt.rust-windows-basic.v1".into(),
        manager_origin: origin.into(),
        agent_origin: String::new(),
        agent_id: String::new(),
        enrollment_mode: EnrollmentMode::Auto,
        basic_metrics_acknowledged: true,
        interval_seconds: 60,
    }
}
fn initialized_input(manager: &Manager) -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    fs::create_dir(directory.path().join("state")).unwrap();
    fs::write(
        directory.path().join("config.json"),
        serde_json::to_vec(&config(&manager.origin)).unwrap(),
    )
    .unwrap();
    fs::write(directory.path().join("server-ca.pem"), &manager.ca).unwrap();
    fs::write(
        directory.path().join("state/foreign-file"),
        b"unchanged foreign file",
    )
    .unwrap();
    directory
}
fn assert_no_state(directory: &std::path::Path) {
    assert_eq!(fs::read_dir(directory).unwrap().count(), 3);
    assert_eq!(fs::read_dir(directory.join("state")).unwrap().count(), 1);
    assert_eq!(
        fs::read(directory.join("state/foreign-file")).unwrap(),
        b"unchanged foreign file"
    );
}
#[test]
fn compatible_preflight_is_repeatable_nonmutating_and_does_not_enroll() {
    let manager = Manager::compatible();
    let directory = initialized_input(&manager);
    for _ in 0..2 {
        let result = Command::new(env!("CARGO_BIN_EXE_tracebolt-windows-agent"))
            .args([
                "validate-config",
                "--check-manager",
                "--manager-origin",
                &manager.origin,
                "--server-ca-file",
            ])
            .arg(directory.path().join("server-ca.pem"))
            .env("HTTPS_PROXY", "http://127.0.0.1:9")
            .env("https_proxy", "http://127.0.0.1:9")
            .env("ALL_PROXY", "http://127.0.0.1:9")
            .env("all_proxy", "http://127.0.0.1:9")
            .env("NO_PROXY", "")
            .env("no_proxy", "")
            .current_dir(directory.path())
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_no_state(directory.path());
    }
    let requests = manager.requests();
    assert_eq!(requests.len(), 2);
    for request in requests {
        assert!(request.starts_with("GET /v1/windows/rust-basic-capabilities HTTP/1.1\r\n"));
        let request = request.to_lowercase();
        for forbidden in [
            "cookie:",
            "authorization:",
            "origin:",
            "content-type:",
            "invitation",
            "claim_",
        ] {
            assert!(!request.contains(forbidden));
        }
    }
}
#[test]
fn compatible_cli_initialization_rechecks_before_creating_one_identity() {
    let manager = Manager::compatible();
    let directory = initialized_input(&manager);
    let result = Command::new(env!("CARGO_BIN_EXE_tracebolt-windows-agent"))
        .args(["init", "--directory"])
        .arg(directory.path())
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let status: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(status["phase"], "awaiting-registration");
    assert_eq!(status["keyFingerprint"].as_str().unwrap().len(), 64);
    assert!(directory.path().join("state/enrollment.db").is_file());
    assert_eq!(
        fs::read(directory.path().join("state/foreign-file")).unwrap(),
        b"unchanged foreign file"
    );
    assert_eq!(manager.requests().len(), 2);
    assert!(!directory.path().join("client.key").exists());
}
#[test]
fn incompatible_manager_is_rejected_before_cli_and_library_persistent_state() {
    for kind in [
        "404",
        "redirect",
        "html",
        "wrong-schema",
        "wrong-protocol",
        "wrong-profile",
        "wrong-frame",
        "wrong-receipt",
        "wrong-origin",
        "bad-agent-origin",
        "automatic-disabled",
        "missing",
        "unknown",
        "duplicate",
        "oversize",
        "unbounded-oversize",
    ] {
        let manager = Manager::new(|origin| {
            let mut value = capabilities(origin);
            let (mut status, mut content_type) = (200, "application/json");
            match kind {
                "404"=>status=404,"redirect"=>return b"HTTP/1.1 307 Temporary Redirect\r\nLocation: https://must-not-follow.invalid/private\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
                "html"=>content_type="text/html",
                "wrong-schema"=>value["schemaVersion"]=json!("future"),
                "wrong-protocol"=>value["enrollmentProtocol"]=json!("v1"),
                "wrong-profile"=>value["collectionProfile"]=json!("linux-basic-v1"),
                "wrong-frame"=>value["telemetryFrame"]=json!("v99"),
                "wrong-receipt"=>value["receiptSchema"]=json!("v99"),
                "wrong-origin"=>value["enrollmentOrigin"]=json!("https://other.invalid"),
                "bad-agent-origin"=>value["agentOrigin"]=json!("http://agent.invalid"),
                "automatic-disabled"=>value["automaticRegistration"]=json!(false),
                "missing"=>{value.as_object_mut().unwrap().remove("agentProfile");},
                "unknown"=>value["privateServerReply"]=json!("must-not-be-logged"),
                "duplicate"=>return response(200,content_type,format!("{{\"agentProfile\":\"rust-windows-basic-v1\",{}",&value.to_string()[1..]).as_bytes()),
                "oversize"=>return response(200,content_type,&vec![b' ';2049]),
                "unbounded-oversize"=>{let mut raw=b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n".to_vec();raw.extend(vec![b' ';2049]);return raw;},
                _=>panic!("unknown case"),
            }
            response(status, content_type, &serde_json::to_vec(&value).unwrap())
        });
        let directory = initialized_input(&manager);
        let before = fs::read(directory.path().join("config.json")).unwrap();
        let error = Enrollment::open(directory.path(), true, None)
            .err()
            .unwrap();
        assert_eq!(
            error.downcast_ref::<PreflightError>(),
            Some(&PreflightError::Unsupported),
            "{kind}"
        );
        assert_no_state(directory.path());
        let result = Command::new(env!("CARGO_BIN_EXE_tracebolt-windows-agent"))
            .args(["init", "--directory"])
            .arg(directory.path())
            .output()
            .unwrap();
        assert!(!result.status.success(), "{kind}");
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert!(
            stderr.contains("MANAGER_PROTOCOL_UNSUPPORTED"),
            "{kind}: {stderr}"
        );
        assert!(!stderr.contains("must-not-be-logged") && !stderr.contains("must-not-follow"));
        assert_no_state(directory.path());
        assert_eq!(
            before,
            fs::read(directory.path().join("config.json")).unwrap()
        );
        assert_eq!(manager.requests().len(), 2, "{kind}");
    }
}
#[test]
fn selected_tls_trust_and_agent_origin_are_not_adopted_from_advertisement() {
    let manager = Manager::compatible();
    let mut input = config(&manager.origin);
    assert_eq!(
        compatibility::check(&input, &[]),
        Err(PreflightError::Unavailable)
    );
    input.agent_origin = "https://different-agent.invalid".into();
    assert_eq!(
        compatibility::check(&input, &manager.ca),
        Err(PreflightError::Unsupported)
    );
    input.agent_origin = "https://agent.fixture.example:9444".into();
    compatibility::check(&input, &manager.ca).unwrap();
    let unavailable = Manager::new(|_| response(503, "application/json", b"private failure body"));
    assert_eq!(
        compatibility::check(&config(&unavailable.origin), &unavailable.ca),
        Err(PreflightError::Unavailable)
    );
}
#[test]
fn explicit_modes_cannot_silently_downgrade_automatic_registration() {
    let manager = Manager::new(|origin| {
        let mut value = capabilities(origin);
        value["automaticRegistration"] = json!(false);
        response(
            200,
            "application/json",
            &serde_json::to_vec(&value).unwrap(),
        )
    });
    let mut input = config(&manager.origin);
    assert_eq!(
        compatibility::check(&input, &manager.ca),
        Err(PreflightError::Unsupported)
    );
    input.enrollment_mode = EnrollmentMode::Invitation;
    compatibility::check(&input, &manager.ca).unwrap();
    input.enrollment_mode = EnrollmentMode::Preprovided;
    input.agent_id = "approved-fixture".into();
    assert_eq!(
        compatibility::check(&input, &manager.ca),
        Err(PreflightError::Unsupported)
    );
}
#[test]
fn temporary_server_failures_are_unavailable_not_protocol_downgrades() {
    for status in [429, 500, 503] {
        let manager =
            Manager::new(|_| response(status, "application/json", b"never log this private body"));
        let directory = initialized_input(&manager);
        let result = Command::new(env!("CARGO_BIN_EXE_tracebolt-windows-agent"))
            .args(["init", "--directory"])
            .arg(directory.path())
            .output()
            .unwrap();
        assert!(!result.status.success());
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert!(stderr.contains("MANAGER_PREFLIGHT_UNAVAILABLE"));
        assert!(
            !stderr.contains("private body") && !stderr.contains("MANAGER_PROTOCOL_UNSUPPORTED")
        );
        assert_no_state(directory.path());
        assert_eq!(manager.requests().len(), 1);
    }
}
#[test]
fn truncated_response_is_unavailable_without_new_state_or_raw_output() {
    let manager = Manager::new(|_| {
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1000\r\nConnection: close\r\n\r\nprivate incomplete response".to_vec()
    });
    let directory = initialized_input(&manager);
    let result = Command::new(env!("CARGO_BIN_EXE_tracebolt-windows-agent"))
        .args(["init", "--directory"])
        .arg(directory.path())
        .output()
        .unwrap();
    assert!(!result.status.success());
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(stderr.contains("MANAGER_PREFLIGHT_UNAVAILABLE"));
    assert!(!stderr.contains("private incomplete response"));
    assert_no_state(directory.path());
}
#[test]
fn existing_enrollment_read_does_not_depend_on_public_preflight_availability() {
    let manager = Manager::compatible();
    let directory = initialized_input(&manager);
    let enrollment = Enrollment::open(directory.path(), true, None).unwrap();
    let before = enrollment.public_status().unwrap();
    drop(enrollment);
    assert_eq!(manager.requests().len(), 1);
    drop(manager);
    let mut enrollment = Enrollment::open(directory.path(), false, None).unwrap();
    assert_eq!(enrollment.public_status().unwrap(), before);
    assert!(enrollment.step(None).is_err());
    assert_eq!(enrollment.public_status().unwrap(), before);
}
