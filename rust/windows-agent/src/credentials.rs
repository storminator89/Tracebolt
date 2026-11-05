//! Local preprovided input checks only: no enrollment, approval, trust adoption or state.
use crate::config::{Config, EnrollmentMode, read_bounded, tls_builder};
use anyhow::{Result, ensure};
use reqwest::{Identity, blocking::Client};
use std::{path::Path, time::Duration};

pub fn validate_preprovided(config: &Config, directory: &Path, ca: &[u8]) -> Result<()> {
    config.validate()?;
    ensure!(
        config.enrollment_mode == EnrollmentMode::Preprovided,
        "credentials require preprovided mode"
    );
    let certificate = read_bounded(&directory.join("client.pem"), 32768)?;
    let private_key = read_bounded(&directory.join("client.key"), 16384)?;
    validate_material(&certificate, &private_key)?;
    // Use the sender's actual TLS identity construction, including key matching.
    client(&certificate, &private_key, ca)?;
    Ok(())
}

pub(crate) fn validate_material(certificate: &[u8], private_key: &[u8]) -> Result<()> {
    let now = chrono::Utc::now().timestamp();
    let mut remaining = certificate.trim_ascii();
    let mut count = 0;
    while !remaining.is_empty() {
        ensure!(
            remaining.starts_with(b"-----BEGIN CERTIFICATE-----") && count < 8,
            "bounded certificate chain required"
        );
        let (rest, pem) = x509_parser::pem::parse_x509_pem(remaining)
            .map_err(|_| anyhow::anyhow!("invalid client certificate PEM"))?;
        ensure!(pem.label == "CERTIFICATE", "certificate block required");
        let (trailing, cert) = x509_parser::parse_x509_certificate(&pem.contents)
            .map_err(|_| anyhow::anyhow!("invalid client certificate"))?;
        // is_ca() alone maps malformed BasicConstraints to false. Check every
        // extension's parse result and uniqueness before applying role checks.
        cert.extensions_map()?;
        ensure!(
            cert.extensions()
                .iter()
                .all(|extension| extension.parsed_extension().error().is_none()),
            "malformed certificate extension"
        );
        ensure!(
            trailing.is_empty()
                && now >= cert.validity().not_before.timestamp()
                && now < cert.validity().not_after.timestamp(),
            "current client certificate required"
        );
        if count == 0 {
            ensure!(
                !cert.is_ca()
                    && cert
                        .key_usage()?
                        .is_some_and(|v| v.value.digital_signature())
                    && cert.extended_key_usage()?.is_some_and(|v| {
                        let use_ = v.value;
                        use_.client_auth
                            && !use_.any
                            && !use_.server_auth
                            && !use_.code_signing
                            && !use_.email_protection
                            && !use_.time_stamping
                            && !use_.ocsp_signing
                            && use_.other.is_empty()
                    }),
                "dedicated client-auth leaf required"
            );
        } else {
            ensure!(cert.is_ca(), "chain certificate must be a CA");
        }
        count += 1;
        remaining = rest.trim_ascii();
    }
    ensure!(count > 0, "client certificate required");

    let key = private_key.trim_ascii();
    ensure!(
        [
            b"-----BEGIN PRIVATE KEY-----".as_slice(),
            b"-----BEGIN RSA PRIVATE KEY-----".as_slice(),
            b"-----BEGIN EC PRIVATE KEY-----".as_slice(),
        ]
        .iter()
        .any(|prefix| key.starts_with(prefix)),
        "one unencrypted supported private key required"
    );
    let (rest, pem) = x509_parser::pem::parse_x509_pem(key)
        .map_err(|_| anyhow::anyhow!("invalid private key PEM"))?;
    ensure!(
        rest.iter().all(u8::is_ascii_whitespace)
            && matches!(
                pem.label.as_str(),
                "PRIVATE KEY" | "RSA PRIVATE KEY" | "EC PRIVATE KEY"
            ),
        "one private key required"
    );
    Ok(())
}

pub(crate) fn client(certificate: &[u8], private_key: &[u8], ca: &[u8]) -> Result<Client> {
    let mut identity = certificate.to_vec();
    identity.push(b'\n');
    identity.extend(private_key);
    Ok(tls_builder(ca)?
        .identity(Identity::from_pem(&identity)?)
        .timeout(Duration::from_secs(15))
        .build()?)
}
