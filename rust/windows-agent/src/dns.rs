//! Tag failures at the actual system name-resolution boundary. This retains
//! reqwest's existing getaddrinfo backend, worker/cancellation semantics and
//! connector address handling; it does not perform a diagnostic lookup or retry.
use hyper_util::client::legacy::connect::dns::{GaiResolver, Name as SystemName};
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use std::{error::Error, fmt, io};
use tower_service::Service;

type BoxError = Box<dyn Error + Send + Sync>;

/// Only a resolver-stage failure, not an NXDOMAIN, offline or revocation claim.
/// Do not retain the original OS text, hostname or addresses in this marker.
#[derive(Debug)]
pub(crate) struct ResolutionFailure;
impl fmt::Display for ResolutionFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("system name resolution failed")
    }
}
impl Error for ResolutionFailure {}

pub(crate) struct SystemResolver;
impl Resolve for SystemResolver {
    fn resolve(&self, name: Name) -> Resolving {
        match name.as_str().parse() {
            Ok(name) => resolve_system(name),
            Err(_) => Box::pin(async { Err(Box::new(ResolutionFailure) as BoxError) }),
        }
    }
}

fn resolve_system(name: SystemName) -> Resolving {
    Box::pin(async move {
        GaiResolver::new()
            .call(name)
            .await
            .map(|addresses| Box::new(addresses) as Addrs)
            .map_err(tag_failure)
    })
}

fn tag_failure(error: io::Error) -> BoxError {
    match error.kind() {
        // Preserve reqwest's existing timeout precedence and worker-cancel
        // uncertainty, without retaining OS prose. Neither establishes DNS
        // failure independently of an interrupted/expired request.
        io::ErrorKind::TimedOut | io::ErrorKind::Interrupted => {
            Box::new(io::Error::from(error.kind()))
        }
        _ => Box::new(ResolutionFailure),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::tls_builder,
        health::{self, Code},
    };
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    struct InvalidSystemName(Arc<AtomicUsize>);
    impl Resolve for InvalidSystemName {
        fn resolve(&self, _: Name) -> Resolving {
            self.0.fetch_add(1, Ordering::SeqCst);
            // An injected interior NUL is rejected locally by the real system
            // getaddrinfo adapter: deterministic, no external DNS dependency.
            // URL validation never accepts this name in production requests.
            resolve_system(
                "private-key-token-cookie-sentinel\0.invalid"
                    .parse()
                    .unwrap(),
            )
        }
    }

    #[test]
    fn system_lookup_failure_survives_real_request_wrapper_as_typed_static_diagnostic() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let client = tls_builder(&[])
            .unwrap()
            .dns_resolver(Arc::new(InvalidSystemName(attempts.clone())))
            .build()
            .unwrap();
        let error = anyhow::Error::new(
            client
                .get("https://private-host-sentinel.invalid")
                .send()
                .unwrap_err(),
        )
        .context("private-outer-sentinel TLS offline revoked");
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        let code = health::classify(&error);
        assert_eq!(code, Code::TransportDnsFailed);
        let public = format!("{code}: {}", code.next_action());
        assert!(!public.contains("private-"));
        assert_eq!(
            health::classify(&error.context(Code::AuthenticationRejected)),
            Code::AuthenticationRejected
        );
    }

    struct InterruptedLookup(io::ErrorKind);
    impl Resolve for InterruptedLookup {
        fn resolve(&self, _: Name) -> Resolving {
            let kind = self.0;
            Box::pin(async move {
                Err(tag_failure(io::Error::new(
                    kind,
                    "private-timeout-cancel-sentinel",
                )))
            })
        }
    }

    #[test]
    fn system_timeout_and_cancellation_keep_request_precedence_without_raw_errors() {
        for (kind, expected) in [
            (io::ErrorKind::TimedOut, Code::TransportTimeout),
            (io::ErrorKind::Interrupted, Code::TransportUnclassified),
        ] {
            let tagged = tag_failure(io::Error::new(kind, "private-cause-sentinel"));
            assert!(!tagged.to_string().contains("private-"));
            assert!(tagged.source().is_none());
            let client = tls_builder(&[])
                .unwrap()
                .dns_resolver(Arc::new(InterruptedLookup(kind)))
                .build()
                .unwrap();
            let error = client
                .get("https://private-host-sentinel.invalid")
                .send()
                .unwrap_err();
            assert_eq!(error.is_timeout(), kind == io::ErrorKind::TimedOut);
            assert_eq!(health::classify(&error.into()), expected);
        }
    }

    #[test]
    fn system_localhost_resolution_reaches_selected_port_without_a_probe() {
        use std::{
            io,
            net::TcpListener,
            thread,
            time::{Duration, Instant},
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                match listener.accept() {
                    Ok((socket, _)) => {
                        // Reaching this port proves resolution succeeded. Close
                        // before TLS rather than introducing fixture trust.
                        drop(socket);
                        break;
                    }
                    Err(error)
                        if error.kind() == io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        thread::sleep(Duration::from_millis(5))
                    }
                    Err(_) => panic!("bounded localhost fixture did not receive a connection"),
                }
            }
        });
        let client = tls_builder(&[]).unwrap().build().unwrap();
        let error = client
            .get(format!("https://localhost:{port}"))
            .send()
            .unwrap_err();
        assert_ne!(health::classify(&error.into()), Code::TransportDnsFailed);
        server.join().unwrap();
    }

    #[test]
    fn lookup_marker_retains_no_raw_cause_or_host_and_bare_marker_is_not_a_transport_result() {
        let marker = ResolutionFailure;
        assert!(marker.source().is_none());
        assert_eq!(marker.to_string(), "system name resolution failed");
        assert_eq!(
            health::classify(&anyhow::Error::new(marker)),
            Code::UnclassifiedFailure
        );
    }
}
