use chrono::Utc;
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustls::{
    RootCertStore, ServerConfig, ServerConnection, StreamOwned, pki_types::PrivatePkcs8KeyDer,
    server::WebPkiClientVerifier,
};
use serde_json::{Value, json};
use std::{
    fs,
    io::{Read, Write},
    net::TcpListener,
    sync::Arc,
    thread,
    time::Duration,
};
use tracebolt_windows_agent::{health, protocol::Sample, runtime::Runtime, sender::Sender};

// Real local mutual TLS, using disposable test-only identities and invented data.
#[test]
fn mutual_tls_retries_exact_bytes_after_bad_receipt_and_restart() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join("state")).unwrap();
    let mut params = CertificateParams::new(vec![]).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_key = KeyPair::generate().unwrap();
    let ca = params.self_signed(&ca_key).unwrap();
    let issuer = Issuer::new(params, ca_key);
    let server_key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec!["localhost".into()]).unwrap();
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server_cert = params.signed_by(&server_key, &issuer).unwrap();
    let client_key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec![]).unwrap();
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let client_cert = params.signed_by(&client_key, &issuer).unwrap();
    fs::write(dir.path().join("client.pem"), client_cert.pem()).unwrap();
    fs::write(dir.path().join("client.key"), client_key.serialize_pem()).unwrap();
    fs::write(dir.path().join("server-ca.pem"), ca.pem()).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(ca.der().clone()).unwrap();
    let config = ServerConfig::builder()
        .with_client_cert_verifier(
            WebPkiClientVerifier::builder(Arc::new(roots))
                .build()
                .unwrap(),
        )
        .with_single_cert(
            vec![server_cert.der().clone()],
            PrivatePkcs8KeyDer::from(server_key.serialize_der()).into(),
        )
        .unwrap();
    let config = Arc::new(config);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    fs::write(dir.path().join("config.json"),serde_json::to_vec(&json!({"schemaVersion":"tracebolt.rust-windows-basic.v1","managerOrigin":format!("https://localhost:{port}"),"agentId":"fixture","enrollmentMode":"preprovided","basicMetricsAcknowledged":true,"intervalSeconds":30})).unwrap()).unwrap();
    let server = thread::spawn(move || {
        let mut bodies = Vec::new();
        for attempt in 0..4 {
            let (socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut stream =
                StreamOwned::new(ServerConnection::new(config.clone()).unwrap(), socket);
            let mut header = Vec::new();
            while !header.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                stream.read_exact(&mut byte).unwrap();
                header.push(byte[0]);
                assert!(header.len() < 8192);
            }
            assert!(
                stream
                    .conn
                    .peer_certificates()
                    .is_some_and(|c| !c.is_empty())
            );
            let header = String::from_utf8(header).unwrap();
            assert!(header.starts_with("POST /v1/windows/agent/telemetry HTTP/1.1\r\n"));
            let length: usize = header
                .lines()
                .find_map(|line| {
                    line.to_lowercase()
                        .strip_prefix("content-length: ")
                        .map(str::to_owned)
                })
                .unwrap()
                .parse()
                .unwrap();
            assert!(length < 72 * 1024);
            let mut body = vec![0; length];
            stream.read_exact(&mut body).unwrap();
            if attempt == 0 {
                write!(stream,"HTTP/1.1 307 Temporary Redirect\r\nLocation: https://localhost:{port}/must-not-follow\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
                stream.flush().unwrap();
                bodies.push(body);
                continue;
            }
            let frame: Value = serde_json::from_slice(&body).unwrap();
            let receipt=serde_json::to_vec(&json!({"schemaVersion":"tracebolt.agent-receipt.v1","agentId":if attempt==1 {"wrong-identity"} else {"fixture"},"sequence":frame["sequence"],"collectedAt":frame["observation"]["observation"]["lastSeen"],"receivedAt":Utc::now(),"duplicate":attempt==2})).unwrap();
            write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",receipt.len()).unwrap();
            stream.write_all(&receipt).unwrap();
            stream.flush().unwrap();
            bodies.push(body);
        }
        assert_eq!(bodies[0], bodies[1]);
        assert_eq!(bodies[1], bodies[2]);
        assert_eq!(
            serde_json::from_slice::<Value>(&bodies[3]).unwrap()["sequence"],
            2
        );
    });
    let sample = || {
        Ok(Sample {
            cpu: Some(10.0),
            memory: Some(20.0),
            disk: None,
            uptime: "fixture".into(),
        })
    };
    drop(Sender::open(dir.path(), true).unwrap());
    let mut disabled = Runtime::open_without_health(dir.path()).unwrap();
    assert!(!disabled.health_requested());
    assert!(!disabled.health_available());
    assert!(
        !disabled
            .cycle_until_stopped(|| panic!("stopped service must not collect"), || true)
            .unwrap()
    );
    drop(disabled);
    assert!(!dir.path().join("state/health-v1.json").exists());
    let mut sender = Runtime::open(dir.path()).unwrap();
    assert!(sender.cycle(sample).is_err());
    let first = health::status(dir.path(), Utc::now());
    assert!(first.last_accepted_receipt.is_none());
    assert_eq!(first.state, health::Code::ManagerRejected);
    drop(sender);
    let mut sender = Runtime::open(dir.path()).unwrap();
    assert!(sender.cycle(|| panic!("retry must not recollect")).is_err());
    let invalid = health::status(dir.path(), Utc::now());
    assert_eq!(invalid.state, health::Code::ReceiptInvalid);
    assert!(invalid.last_accepted_receipt.is_none());
    drop(sender);
    let mut sender = Runtime::open(dir.path()).unwrap();
    // Stop may arrive after a cycle starts but before telemetry is admitted.
    // Retain the same unacknowledged bytes, sequence, and previous receipt.
    let checks = std::cell::Cell::new(0);
    assert!(
        !sender
            .cycle_until_stopped(
                || panic!("stop checkpoint must not recollect pending bytes"),
                || {
                    checks.set(checks.get() + 1);
                    checks.get() > 1
                },
            )
            .unwrap()
    );
    assert_eq!(checks.get(), 2);
    let interrupted = health::status(dir.path(), Utc::now());
    assert_eq!(interrupted.state, health::Code::AttemptInterrupted);
    assert!(interrupted.last_accepted_receipt.is_none());
    drop(sender);
    let mut sender = Runtime::open(dir.path()).unwrap();
    assert!(sender.cycle(|| panic!("retry must not recollect")).unwrap());
    let accepted = health::status(dir.path(), Utc::now());
    assert_eq!(accepted.state, health::Code::Accepted);
    assert_eq!(accepted.last_accepted_receipt.as_ref().unwrap().sequence, 1);
    assert!(accepted.last_accepted_receipt.as_ref().unwrap().duplicate);
    let original_received = accepted.last_accepted_receipt.unwrap().received_at;
    drop(sender);
    assert_eq!(
        health::status(dir.path(), Utc::now())
            .last_accepted_receipt
            .unwrap()
            .received_at,
        original_received
    );
    let path = dir.path().join("state/health-v1.json");
    let mut malformed: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    malformed["lastAcceptedReceipt"]["collectedAt"] = json!("-262143-01-01T00:00:00Z");
    let corrupt = serde_json::to_vec(&malformed).unwrap();
    fs::write(&path, &corrupt).unwrap();
    let mut sender = Runtime::open(dir.path()).unwrap();
    assert!(!sender.health_available());
    assert!(sender.cycle(sample).unwrap());
    assert_eq!(
        fs::read(dir.path().join("state/health-v1.json")).unwrap(),
        corrupt
    );
    let bundle =
        String::from_utf8(health::support_bundle(dir.path(), Utc::now()).unwrap()).unwrap();
    for private in [
        "private-health-corruption-sentinel",
        "PRIVATE KEY",
        "localhost",
        "fixture",
    ] {
        assert!(!bundle.contains(private));
    }
    server.join().unwrap();
}
