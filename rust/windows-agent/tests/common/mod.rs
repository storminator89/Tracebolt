#![allow(dead_code)]
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustls::{ServerConfig, ServerConnection, StreamOwned, pki_types::PrivatePkcs8KeyDer};
use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

// Disposable loopback server-authenticated TLS. No production trust is changed.
pub struct Manager {
    pub origin: String,
    pub ca: Vec<u8>,
    requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}
pub fn capabilities(origin: &str) -> Value {
    json!({
        "schemaVersion":"tracebolt.rust-basic-manager-capabilities.v1",
        "enrollmentProtocol":"tracebolt.enrollment.v2",
        "collectionProfile":"windows-inventory-v1",
        "agentProfile":"rust-windows-basic-v1",
        "telemetryFrame":"tracebolt.agent-telemetry.windows.v1",
        "receiptSchema":"tracebolt.agent-receipt.v1",
        "enrollmentOrigin":origin,"agentOrigin":"https://agent.fixture.example:9444",
        "automaticRegistration":true
    })
}
pub fn response(status: u16, content_type: &str, body: &[u8]) -> Vec<u8> {
    let mut raw = format!("HTTP/1.1 {status} Fixture\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).into_bytes();
    raw.extend(body);
    raw
}
impl Manager {
    pub fn new(reply: impl FnOnce(&str) -> Vec<u8>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let origin = format!(
            "https://localhost:{}",
            listener.local_addr().unwrap().port()
        );
        let raw = reply(&origin);
        let mut params = CertificateParams::new(vec![]).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca_key = KeyPair::generate().unwrap();
        let ca = params.self_signed(&ca_key).unwrap();
        let issuer = Issuer::new(params, ca_key);
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec!["localhost".into()]).unwrap();
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let cert = params.signed_by(&key, &issuer).unwrap();
        let config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
            )
            .unwrap();
        let config = Arc::new(config);
        let stop = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let (done, seen) = (stop.clone(), requests.clone());
        let thread = thread::spawn(move || {
            while !done.load(Ordering::SeqCst) {
                let (socket, _) = match listener.accept() {
                    Ok(value) => value,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(error) => panic!("fixture accept failed: {error}"),
                };
                socket
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut stream =
                    StreamOwned::new(ServerConnection::new(config.clone()).unwrap(), socket);
                let mut header = Vec::new();
                while !header.ends_with(b"\r\n\r\n") && header.len() < 8192 {
                    let mut byte = [0];
                    if stream.read_exact(&mut byte).is_err() {
                        break;
                    }
                    header.push(byte[0]);
                }
                if header.ends_with(b"\r\n\r\n") {
                    seen.lock()
                        .unwrap()
                        .push(String::from_utf8(header).unwrap());
                    let _ = stream.write_all(&raw);
                    let _ = stream.flush();
                }
            }
        });
        Self {
            origin,
            ca: ca.pem().into_bytes(),
            requests,
            stop,
            thread: Some(thread),
        }
    }
    pub fn compatible() -> Self {
        Self::new(|origin| {
            response(
                200,
                "application/json",
                &serde_json::to_vec(&capabilities(origin)).unwrap(),
            )
        })
    }
    pub fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }
}
impl Drop for Manager {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.thread.take().unwrap().join().unwrap();
    }
}
