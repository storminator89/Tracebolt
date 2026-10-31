//! Disposable Go/Rust TLS integration, not a manager or a Windows native test.
//! Requires the same-source tests/rustagent/cmd/nativefixture executable.
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use std::{
    cell::Cell,
    fs,
    path::Path,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use tracebolt_windows_agent::{enrollment::Enrollment, health, protocol::Sample, runtime::Runtime};

struct Peer(Child);
impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn wait_ready(peer: &mut Peer, path: &Path) -> Result<Value> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        ensure!(peer.0.try_wait()?.is_none(), "disposable peer exited");
        if let Ok(raw) = fs::read(path)
            && let Ok(value) = serde_json::from_slice::<Value>(&raw)
        {
            ensure!(value["loopbackOnly"] == true, "loopback peer required");
            for field in ["managerOrigin", "agentOrigin"] {
                let origin = value[field].as_str().unwrap_or_default();
                let url = reqwest::Url::parse(origin)?;
                ensure!(
                    url.scheme() == "https" && url.host_str() == Some("127.0.0.1"),
                    "loopback TLS peer required"
                );
            }
            return Ok(value);
        }
        ensure!(
            Instant::now() < deadline,
            "disposable peer readiness timed out"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

fn main() -> Result<()> {
    let fixture = std::env::args_os()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("same-source disposable peer executable required"))?;
    let directory = tempfile::tempdir()?;
    let peer_directory = directory.path().join("peer");
    let mut peer = Peer(
        Command::new(fixture)
            .arg("--directory")
            .arg(&peer_directory)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?,
    );
    let ready = wait_ready(&mut peer, &peer_directory.join("ready.json"))?;
    let endpoint = directory.path().join("endpoint");
    fs::create_dir(&endpoint)?;
    fs::create_dir(endpoint.join("state"))?;
    fs::write(
        endpoint.join("config.json"),
        serde_json::to_vec(&json!({
            "schemaVersion":"tracebolt.rust-windows-basic.v1",
            "managerOrigin":ready["managerOrigin"], "basicMetricsAcknowledged":true,
            "intervalSeconds":30
        }))?,
    )?;
    fs::copy(
        peer_directory.join("server-ca.pem"),
        endpoint.join("server-ca.pem"),
    )?;
    let enrollment = Enrollment::open(&endpoint, true, None)?;
    let status = enrollment.public_status()?;
    fs::write(
        peer_directory.join("expected-fingerprint.txt"),
        status["keyFingerprint"].as_str().unwrap_or_default(),
    )?;
    drop(enrollment);

    let database = endpoint.join("state/enrollment.db");
    let mut runtime = Runtime::open(&endpoint)?;
    let mut initialized = false;
    for _ in 0..10 {
        // The first poll admits the existing phase. Only the second poll, after
        // enrollment.step (including final activation), observes SCM stop.
        let checks = Cell::new(0);
        let sent = runtime.cycle_until_stopped(
            || panic!("stop after enrollment must prevent the collector and telemetry"),
            || {
                checks.set(checks.get() + 1);
                checks.get() > 1
            },
        )?;
        ensure!(!sent && checks.get() == 2, "stop checkpoint not reached");
        ensure!(
            !peer_directory.join("accepted.json").exists(),
            "telemetry reached the peer before resumed admission"
        );
        let db = rusqlite::Connection::open(&database)?;
        initialized = db.query_row(
            "SELECT activated AND sender_initialized FROM enrollment WHERE id=1",
            [],
            |row| row.get(0),
        )?;
        if initialized {
            break;
        }
    }
    ensure!(
        initialized,
        "activation did not reach the stopped sender boundary"
    );
    ensure!(
        runtime.health_code() == health::Code::AttemptInterrupted,
        "interrupted work was mislabeled accepted"
    );
    drop(runtime);
    let db = rusqlite::Connection::open(&database)?;
    let identity: (String, Vec<u8>, String) = db.query_row(
        "SELECT enrollment.binding,enrollment.payload,sender.binding FROM enrollment JOIN sender ON sender.id=enrollment.id",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    let floor: (i64, Option<Vec<u8>>) =
        db.query_row("SELECT next,pending FROM sender WHERE id=1", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })?;
    ensure!(floor == (1, None), "stop changed the fresh sender floor");

    // Reopen the same identity/ledger; invented metrics use actual mutual TLS,
    // the Go frame validator and the unchanged identity-bound receipt contract.
    let mut runtime = Runtime::open(&endpoint)?;
    ensure!(
        runtime.cycle(|| Ok(Sample {
            cpu: Some(10.0),
            memory: Some(20.0),
            disk: Some(30.0),
            uptime: "fixture".into()
        }))?,
        "resumed report not accepted"
    );
    drop(runtime);
    let retained: (String, Vec<u8>, String) = db.query_row(
        "SELECT enrollment.binding,enrollment.payload,sender.binding FROM enrollment JOIN sender ON sender.id=enrollment.id",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    ensure!(retained == identity, "resume changed the original identity");
    let floor: (i64, Option<Vec<u8>>) =
        db.query_row("SELECT next,pending FROM sender WHERE id=1", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })?;
    ensure!(
        floor == (2, None),
        "resumed receipt did not advance exactly once"
    );
    let status = health::status(&endpoint, chrono::Utc::now());
    ensure!(
        status.last_attempt_result == health::Code::Accepted
            && status
                .last_accepted_receipt
                .is_some_and(|receipt| receipt.sequence == 1),
        "resumed local receipt mismatch"
    );
    println!(
        "Disposable Go/Rust TLS activation-stop-resume accepted: no pre-stop collection, same identity, sequence 1 acknowledged exactly once. Not a native Windows test."
    );
    Ok(())
}
