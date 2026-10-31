use reqwest::dns::{Name, Resolve, Resolving};
use std::{io, sync::Arc, time::Duration};
use tracebolt_windows_agent::{
    config::tls_builder,
    health::{self, Code},
};

#[derive(Debug)]
struct FailingResolver(io::ErrorKind);
impl Resolve for FailingResolver {
    fn resolve(&self, _: Name) -> Resolving {
        let kind = self.0;
        Box::pin(async move {
            Err(
                Box::new(io::Error::new(kind, "private-dns-TLS-offline-sentinel"))
                    as Box<dyn std::error::Error + Send + Sync>,
            )
        })
    }
}

#[test]
fn reqwest_typed_io_causes_are_distinct_without_guessing_dns_or_offline() {
    // Injected errors exercise the actual reqwest wrapper, not native DNS or
    // routing. Other/NotFound are ambiguous and must not become DNS/TLS claims.
    for (kind, expected) in [
        (io::ErrorKind::Other, Code::TransportUnclassified),
        (io::ErrorKind::NotFound, Code::TransportUnclassified),
        (
            io::ErrorKind::ConnectionRefused,
            Code::TransportConnectionRefused,
        ),
        (
            io::ErrorKind::NetworkUnreachable,
            Code::TransportUnreachable,
        ),
        (io::ErrorKind::HostUnreachable, Code::TransportUnreachable),
    ] {
        let client = tls_builder(&[])
            .unwrap()
            .dns_resolver(Arc::new(FailingResolver(kind)))
            .build()
            .unwrap();
        let error = anyhow::Error::new(
            client
                .get("https://private-host-sentinel.invalid")
                .send()
                .unwrap_err(),
        )
        .context("private-context-sentinel: DNS TLS offline");
        assert_eq!(health::classify(&error), expected);
        let public = format!("{} {}", expected, expected.next_action());
        assert!(!public.contains("private-"));
        assert!(!matches!(
            expected,
            Code::EnrollmentRevoked | Code::Accepted
        ));
    }
}

#[derive(Debug)]
struct TlsCauseResolver;
impl Resolve for TlsCauseResolver {
    fn resolve(&self, _: Name) -> Resolving {
        Box::pin(async {
            // Rust's io::Error::source can omit the held error itself. Retain
            // classification through get_ref without formatting private prose.
            Err(Box::new(io::Error::other(rustls::Error::General(
                "private-peer-sentinel".into(),
            ))) as Box<dyn std::error::Error + Send + Sync>)
        })
    }
}
#[test]
fn typed_tls_cause_survives_reqwest_io_and_anyhow_wrappers() {
    let client = tls_builder(&[])
        .unwrap()
        .dns_resolver(Arc::new(TlsCauseResolver))
        .build()
        .unwrap();
    let error = anyhow::Error::new(
        client
            .get("https://private-host-sentinel.invalid")
            .send()
            .unwrap_err(),
    )
    .context("private-outer-sentinel");
    assert_eq!(health::classify(&error), Code::TransportTlsFailed);
    // Explicit operation-level failure classes keep their existing precedence.
    assert_eq!(
        health::classify(&error.context(Code::AuthenticationRejected)),
        Code::AuthenticationRejected
    );
}

#[derive(Debug)]
struct PendingResolver;
impl Resolve for PendingResolver {
    fn resolve(&self, _: Name) -> Resolving {
        Box::pin(std::future::pending())
    }
}
#[test]
fn resolver_deadline_stays_timeout_not_dns_or_offline() {
    let client = tls_builder(&[])
        .unwrap()
        .dns_resolver(Arc::new(PendingResolver))
        .connect_timeout(Duration::from_millis(100))
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    let error = client
        .get("https://private-host-sentinel.invalid")
        .send()
        .unwrap_err();
    assert!(error.is_timeout());
    assert_eq!(health::classify(&error.into()), Code::TransportTimeout);
}

#[test]
fn actual_loopback_tls_rejection_is_not_an_offline_or_revocation_claim() {
    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
        KeyUsagePurpose,
    };
    use rustls::{ServerConfig, ServerConnection, pki_types::PrivatePkcs8KeyDer};
    use std::{net::TcpListener, thread};
    for wrong_trust in [true, false] {
        let mut params = CertificateParams::new(vec![]).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let ca_key = KeyPair::generate().unwrap();
        let ca = params.self_signed(&ca_key).unwrap();
        let issuer = Issuer::new(params, ca_key);
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec![
            if wrong_trust {
                "localhost"
            } else {
                "private-wrong-name-sentinel.invalid"
            }
            .into(),
        ])
        .unwrap();
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let cert = params.signed_by(&key, &issuer).unwrap();
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
            )
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            let mut socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(e)
                        if e.kind() == io::ErrorKind::WouldBlock
                            && std::time::Instant::now() < deadline =>
                    {
                        thread::sleep(Duration::from_millis(5))
                    }
                    Err(_) => panic!("bounded local TLS fixture did not receive a connection"),
                }
            };
            socket.set_nonblocking(false).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let _ = ServerConnection::new(Arc::new(config))
                .unwrap()
                .complete_io(&mut socket);
        });
        let ca = if wrong_trust {
            Vec::new()
        } else {
            ca.pem().into_bytes()
        };
        let client = tls_builder(&ca)
            .unwrap()
            .resolve("localhost", address)
            .build()
            .unwrap();
        let error = client
            .get(format!("https://localhost:{}", address.port()))
            .send()
            .unwrap_err();
        assert_eq!(health::classify(&error.into()), Code::TransportTlsFailed);
        server.join().unwrap();
    }
}

#[test]
fn bare_tls_and_io_errors_outside_reqwest_remain_unclassified() {
    let tls = anyhow::Error::new(rustls::Error::General(
        "private-nontransport-sentinel".into(),
    ));
    assert_eq!(health::classify(&tls), Code::UnclassifiedFailure);
    for kind in [
        io::ErrorKind::ConnectionRefused,
        io::ErrorKind::NetworkUnreachable,
        io::ErrorKind::HostUnreachable,
    ] {
        let local = anyhow::Error::new(io::Error::new(kind, "private-local-file-sentinel"));
        assert_eq!(health::classify(&local), Code::UnclassifiedFailure);
    }
    let nested = anyhow::Error::new(io::Error::other(rustls::Error::General(
        "private-local-sentinel".into(),
    )));
    assert_eq!(health::classify(&nested), Code::UnclassifiedFailure);
}
