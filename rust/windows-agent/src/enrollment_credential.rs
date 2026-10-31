//! Fixed Go enrollment leaf verification. This is credential validation, not a
//! local collection grant, current revocation lookup or agent attestation.
//! It relies on the existing authenticated bootstrap issuer, not a standalone
//! trust engine or a reimplementation of Go's general X.509 constraint policy.

use crate::{enrollment_wire as wire, health::Code};
use anyhow::{Result, ensure};
use chrono::{DateTime, Utc};
use x509_parser::{extensions::ParsedExtension, prelude::*};

const MAX_CERTIFICATE_BYTES: usize = 8192;

fn parse(bytes: &[u8]) -> Result<X509Certificate<'_>> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_CERTIFICATE_BYTES,
        "invalid certificate size"
    );
    let (rest, cert) = parse_x509_certificate(bytes)
        .map_err(|_| anyhow::anyhow!("invalid enrollment certificate"))?;
    ensure!(rest.is_empty(), "trailing certificate bytes");
    // Never let a first-match extension accessor hide a second extension.
    cert.extensions_map()?;
    ensure!(
        cert.extensions().iter().all(|e| {
            !matches!(e.parsed_extension(), ParsedExtension::ParseError { .. })
                // Parsing a recognized OID is not equivalent to handling a
                // critical extension. Preserve Go's closed handled-OID set;
                // SKI, AKI and AIA are explicitly noncritical in Go as well.
                && (!e.critical || matches!(e.oid.to_id_string().as_str(),
                    "2.5.29.15" | "2.5.29.19" | "2.5.29.17" | "2.5.29.30"
                    | "2.5.29.31" | "2.5.29.36" | "2.5.29.37" | "2.5.29.32"
                    | "2.5.29.33" | "2.5.29.54"))
                && !(e.critical
                    && matches!(
                        e.parsed_extension(),
                        ParsedExtension::UnsupportedExtension { .. } | ParsedExtension::Unparsed
                    ))
        }),
        "invalid enrollment certificate extension"
    );
    Ok(cert)
}

fn client_only(cert: &X509Certificate<'_>) -> Result<bool> {
    // The parser's boolean projection deduplicates repeated purpose OIDs. Match
    // the actual Go template's single canonical clientAuth purpose as well.
    const CLIENT_AUTH_DER: &[u8] = &[
        0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02,
    ];
    Ok(cert.extended_key_usage()?.is_some_and(|e| {
        let u = e.value;
        u.client_auth
            && !u.any
            && !u.server_auth
            && !u.code_signing
            && !u.email_protection
            && !u.time_stamping
            && !u.ocsp_signing
            && u.other.is_empty()
            && cert
                .extensions()
                .iter()
                .any(|e| e.oid.to_id_string() == "2.5.29.37" && e.value == CLIENT_AUTH_DER)
    }))
}

fn serial_hex(cert: &X509Certificate<'_>) -> Result<String> {
    let raw = cert.raw_serial();
    ensure!(
        !raw.is_empty()
            && raw[0] & 0x80 == 0
            && (raw.len() == 1 || raw[0] != 0 || raw[1] & 0x80 != 0),
        "positive certificate serial required"
    );
    let raw = raw.strip_prefix(&[0]).unwrap_or(raw);
    ensure!(
        !raw.is_empty() && raw.len() <= 16 && raw.iter().any(|b| *b != 0),
        "invalid enrollment certificate serial"
    );
    Ok(format!(
        "{:0>32}",
        raw.iter().map(|b| format!("{b:02x}")).collect::<String>()
    ))
}

/// Match the actual fixed leaf template in Go enrollmentcrypto.VerifyIssued.
/// The intent must already be bound to the trusted bootstrap, original claim,
/// approval and issuance snapshot by Enrollment::verify_credential.
pub(crate) fn verify(
    der: &[u8],
    issuer_der: &[u8],
    intent: &wire::Intent,
    now: DateTime<Utc>,
) -> Result<()> {
    ensure!(
        now.timestamp() > 0 && now.timestamp() <= 253_402_300_799,
        Code::ClockInvalid
    );
    let cert = parse(der)?;
    let issuer = parse(issuer_der)?;
    let before = cert.validity().not_before.timestamp();
    let after = cert.validity().not_after.timestamp();
    ensure!(now.timestamp() >= before, Code::CertificateNotYetValid);
    ensure!(now.timestamp() < after, Code::CertificateExpired);
    ensure!(
        intent.not_before > 0
            && intent.not_after > intent.not_before
            && intent.not_after <= 253_402_300_799
            && intent.not_after - intent.not_before <= 30 * 86400
            && before == intent.not_before
            && after == intent.not_after
            && now.timestamp() >= issuer.validity().not_before.timestamp()
            && now.timestamp() < issuer.validity().not_after.timestamp()
            && before >= issuer.validity().not_before.timestamp()
            && after <= issuer.validity().not_after.timestamp(),
        "invalid enrollment certificate validity"
    );
    ensure!(
        cert.signature_algorithm.algorithm.to_id_string() == "1.3.101.112"
            && cert.signature_algorithm.parameters.is_none()
            && cert.tbs_certificate.signature == cert.signature_algorithm
            && issuer.public_key().algorithm.algorithm.to_id_string() == "1.3.101.112"
            && issuer.public_key().algorithm.parameters.is_none()
            && issuer
                .basic_constraints()?
                .is_some_and(|b| b.value.ca && b.value.path_len_constraint == Some(0))
            && issuer.key_usage()?.is_some_and(|u| u.value.key_cert_sign())
            && client_only(&issuer)?,
        "invalid enrollment issuing authority"
    );
    ensure!(
        cert.basic_constraints()?
            .is_some_and(|b| !b.value.ca && b.value.path_len_constraint.is_none())
            && cert.key_usage()?.is_some_and(|u| u.value.flags == 1)
            && client_only(&cert)?
            && cert.subject().iter_attributes().count() == 1
            && cert
                .subject()
                .iter_common_name()
                .next()
                .and_then(|v| v.as_str().ok())
                == Some(intent.device_id.as_str())
            && cert.issuer() == issuer.subject()
            && serial_hex(&cert)? == intent.serial_hex
            && wire::hash(cert.public_key().raw) == intent.key_fingerprint
            && wire::encode(cert.public_key().raw) == intent.public_key_der_base64
            && wire::hash(issuer_der) == intent.issuer_fingerprint,
        "issued certificate differs from fixed enrollment intent"
    );
    ensure!(
        cert.extensions().iter().all(|e| matches!(
            e.oid.to_id_string().as_str(),
            "2.5.29.14" | "2.5.29.15" | "2.5.29.19" | "2.5.29.35" | "2.5.29.37"
        )),
        "unexpected enrollment leaf extension"
    );
    let issuer_id = issuer.extensions().iter().find_map(|e| {
        if let ParsedExtension::SubjectKeyIdentifier(k) = e.parsed_extension() {
            Some(k.0)
        } else {
            None
        }
    });
    let authority_id = cert.extensions().iter().find_map(|e| {
        if let ParsedExtension::AuthorityKeyIdentifier(a) = e.parsed_extension() {
            a.key_identifier.as_ref().map(|k| k.0)
        } else {
            None
        }
    });
    ensure!(
        authority_id.unwrap_or(&[]) == issuer_id.unwrap_or(&[]),
        "enrollment authority identifier mismatch"
    );
    cert.verify_signature(Some(issuer.public_key()))
        .map_err(|_| anyhow::anyhow!("issued signature rejected"))?;
    Ok(())
}

#[cfg(test)]
pub(crate) mod fixture {
    use super::*;
    use chrono::Datelike;
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose,
        IsCa, Issuer, KeyPair, KeyUsagePurpose, PKCS_ED25519,
    };

    pub(crate) struct Fixture {
        pub(crate) root_pem: String,
        pub(crate) issuer_der: Vec<u8>,
        pub(crate) issuer: Issuer<'static, KeyPair>,
        pub(crate) leaf_params: CertificateParams,
        pub(crate) key: KeyPair,
        pub(crate) der: Vec<u8>,
        pub(crate) intent: wire::Intent,
        pub(crate) csr: Vec<u8>,
    }

    fn day(offset: i64) -> rcgen::CertificateParams {
        let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
        let now = Utc::now() + chrono::Duration::days(offset);
        p.not_before = rcgen::date_time_ymd(now.year(), now.month() as u8, now.day() as u8);
        p
    }

    impl Fixture {
        pub(crate) fn new() -> Self {
            Self::with_issuer_edit(|_| {})
        }
        pub(crate) fn with_issuer_edit(edit: fn(&mut CertificateParams)) -> Self {
            let mut root_params = day(-30);
            root_params.not_after = day(90).not_before;
            root_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
            root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
            root_params.distinguished_name = DistinguishedName::new();
            root_params
                .distinguished_name
                .push(DnType::CommonName, "Disposable root");
            let root_key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
            let root = root_params.self_signed(&root_key).unwrap();
            let root_issuer = Issuer::new(root_params, root_key);
            let mut p = day(-10);
            p.not_after = day(60).not_before;
            p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
            p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
            p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
            p.distinguished_name = DistinguishedName::new();
            p.distinguished_name
                .push(DnType::CommonName, "Disposable client issuer");
            edit(&mut p);
            let issuer_key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
            let issuer_der = p
                .signed_by(&issuer_key, &root_issuer)
                .unwrap()
                .der()
                .to_vec();
            let issuer = Issuer::new(p, issuer_key);
            let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
            let csr = CertificateParams::new(Vec::<String>::new())
                .unwrap()
                .serialize_request(&key)
                .unwrap()
                .der()
                .to_vec();
            let mut p = day(-1);
            p.not_after = day(7).not_before;
            p.is_ca = IsCa::ExplicitNoCa;
            p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
            p.serial_number = Some(vec![9; 16].into());
            p.use_authority_key_identifier_extension = true;
            p.distinguished_name = DistinguishedName::new();
            p.distinguished_name
                .push(DnType::CommonName, format!("agent_{}", "7".repeat(32)));
            let der = p.signed_by(&key, &issuer).unwrap().der().to_vec();
            let spki = wire::spki(
                &ring::signature::Ed25519KeyPair::from_pkcs8(&key.serialize_der()).unwrap(),
            );
            let intent: wire::Intent = serde_json::from_value(serde_json::json!({
                "managerInstanceId":format!("manager_{}","1".repeat(32)), "profile":"tls",
                "origin":"https://manager.fixture.invalid", "collectionProfile":wire::COLLECTION,
                "invitationId":format!("invite_{}","2".repeat(32)),
                "claimId":format!("claim_{}","3".repeat(32)),
                "requestId":format!("request_{}","4".repeat(32)),
                "deviceId":format!("agent_{}","7".repeat(32)),
                "intentId":format!("intent_{}","8".repeat(32)),
                "keyFingerprint":wire::hash(&spki),
                "publicKeyDerBase64":wire::encode(&spki),
                "csrHash":wire::hash(&csr), "claimHash":"c".repeat(64),
                "issuerFingerprint":wire::hash(&issuer_der), "serialHex":"09".repeat(16),
                "templateVersion":"tracebolt.enrollment.client.v2", "keyGeneration":1,
                "notBefore":p.not_before.unix_timestamp(), "notAfter":p.not_after.unix_timestamp()
            }))
            .unwrap();
            Self {
                root_pem: root.pem(),
                issuer_der,
                issuer,
                leaf_params: p,
                key,
                der,
                intent,
                csr,
            }
        }
        pub(crate) fn sign(&self, p: &CertificateParams) -> Vec<u8> {
            p.signed_by(&self.key, &self.issuer).unwrap().der().to_vec()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{fixture::Fixture, *};
    use rcgen::{CustomExtension, DnType, ExtendedKeyUsagePurpose, IsCa, KeyUsagePurpose};

    #[test]
    fn actual_go_issuer_public_fixture_matches_the_rust_fixed_leaf_contract() {
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct PublicFixture {
            now: DateTime<Utc>,
            certificate_der: String,
            issuer_der: String,
            intent: wire::Intent,
        }
        let f: PublicFixture = serde_json::from_str(include_str!(
            "../../../tests/rustagent/credential-fixture.json"
        ))
        .unwrap();
        verify(
            &wire::decode(&f.certificate_der).unwrap(),
            &wire::decode(&f.issuer_der).unwrap(),
            &f.intent,
            f.now,
        )
        .unwrap();
    }

    #[test]
    fn fixed_leaf_is_accepted_and_original_serial_key_and_validity_are_required() {
        let f = Fixture::new();
        verify(&f.der, &f.issuer_der, &f.intent, Utc::now()).unwrap();
        for mutate in [
            |i: &mut wire::Intent| i.serial_hex = "08".repeat(16),
            |i: &mut wire::Intent| i.device_id = format!("agent_{}", "6".repeat(32)),
            |i: &mut wire::Intent| i.key_fingerprint = "f".repeat(64),
            |i: &mut wire::Intent| i.public_key_der_base64 = wire::encode(b"different key"),
            |i: &mut wire::Intent| i.issuer_fingerprint = "e".repeat(64),
            |i: &mut wire::Intent| i.not_before -= 1,
            |i: &mut wire::Intent| i.not_after += 1,
            |i: &mut wire::Intent| i.not_before = i64::MIN,
            |i: &mut wire::Intent| i.not_after = i64::MAX,
        ] {
            let mut i = f.intent.clone();
            mutate(&mut i);
            assert!(verify(&f.der, &f.issuer_der, &i, Utc::now()).is_err());
        }
    }

    #[test]
    fn certificate_template_expansion_and_duplicate_extensions_are_denied() {
        let f = Fixture::new();
        let mutations: [fn(&mut rcgen::CertificateParams); 10] = [
            |p| p.key_usages.push(KeyUsagePurpose::KeyEncipherment),
            |p| {
                p.extended_key_usages
                    .push(ExtendedKeyUsagePurpose::ServerAuth)
            },
            |p| {
                p.extended_key_usages
                    .push(ExtendedKeyUsagePurpose::CodeSigning)
            },
            |p| {
                p.distinguished_name
                    .push(DnType::OrganizationName, "not the fixed subject")
            },
            |p| p.is_ca = IsCa::NoCa,
            |p| p.use_authority_key_identifier_extension = false,
            |p| {
                p.custom_extensions
                    .push(CustomExtension::from_oid_content(&[1, 2, 3, 4], vec![5, 0]))
            },
            |p| {
                p.custom_extensions.push(CustomExtension::from_oid_content(
                    &[2, 5, 29, 19],
                    vec![48, 0],
                ))
            },
            |p| {
                p.custom_extensions.push(CustomExtension::from_oid_content(
                    &[2, 5, 29, 14],
                    vec![255],
                ))
            },
            |p| {
                p.extended_key_usages.clear();
                p.custom_extensions.push(CustomExtension::from_oid_content(
                    &[2, 5, 29, 37],
                    vec![
                        0x30, 0x14, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02,
                        0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02,
                    ],
                ));
            },
        ];
        for (index, mutate) in mutations.into_iter().enumerate() {
            let mut p = f.leaf_params.clone();
            mutate(&mut p);
            assert!(
                verify(&f.sign(&p), &f.issuer_der, &f.intent, Utc::now()).is_err(),
                "{index}"
            );
        }
    }

    #[test]
    fn invalid_bytes_signature_issuer_clock_and_original_expiry_fail_closed() {
        let f = Fixture::new();
        let now = Utc::now();
        let error = verify(
            &f.der,
            &f.issuer_der,
            &f.intent,
            DateTime::from_timestamp(f.intent.not_after, 0).unwrap(),
        )
        .unwrap_err();
        assert_eq!(
            error.downcast_ref::<Code>(),
            Some(&Code::CertificateExpired)
        );
        let error = verify(
            &f.der,
            &f.issuer_der,
            &f.intent,
            DateTime::from_timestamp(f.intent.not_before - 1, 0).unwrap(),
        )
        .unwrap_err();
        assert_eq!(
            error.downcast_ref::<Code>(),
            Some(&Code::CertificateNotYetValid)
        );
        assert!(
            verify(
                &f.der,
                &f.issuer_der,
                &f.intent,
                DateTime::from_timestamp(0, 0).unwrap()
            )
            .is_err()
        );
        let mut trailing = f.der.clone();
        trailing.push(0);
        let mut broken_signature = f.der.clone();
        *broken_signature.last_mut().unwrap() ^= 1;
        for der in [Vec::new(), vec![0; 8193], trailing, broken_signature] {
            assert!(verify(&der, &f.issuer_der, &f.intent, now).is_err());
        }
        let other = Fixture::new();
        assert!(verify(&f.der, &other.issuer_der, &f.intent, now).is_err());
    }

    #[test]
    fn absent_issuer_and_leaf_key_identifiers_preserve_the_go_contract() {
        let f = Fixture::with_issuer_edit(|p| {
            // Avoid rcgen's automatic CA SKI while keeping the exact CA=true,
            // pathLen=0 issuer constraints required by the real Go contract.
            p.is_ca = IsCa::NoCa;
            p.custom_extensions.push(CustomExtension::from_oid_content(
                &[2, 5, 29, 19],
                vec![0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x00],
            ));
        });
        let mut p = f.leaf_params.clone();
        p.use_authority_key_identifier_extension = false;
        verify(&f.sign(&p), &f.issuer_der, &f.intent, Utc::now()).unwrap();
        // An absent issuer ID does not permit a nonempty, mismatched leaf ID.
        assert!(verify(&f.der, &f.issuer_der, &f.intent, Utc::now()).is_err());
    }

    #[test]
    fn duplicated_client_auth_inside_one_issuer_eku_is_not_deduplicated() {
        let f = Fixture::with_issuer_edit(|p| {
            p.extended_key_usages.clear();
            p.custom_extensions.push(CustomExtension::from_oid_content(
                &[2, 5, 29, 37],
                vec![
                    0x30, 0x14, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02, 0x06,
                    0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02,
                ],
            ));
        });
        assert!(verify(&f.der, &f.issuer_der, &f.intent, Utc::now()).is_err());
    }

    #[test]
    fn recognized_but_go_unhandled_critical_extensions_are_rejected() {
        let f = Fixture::new();
        // Noncritical SKI is allowed in the fixed leaf; critical SKI is not.
        let mut p = f.leaf_params.clone();
        // Avoid rcgen's automatic SKI while preserving explicit CA=false.
        p.is_ca = IsCa::NoCa;
        p.custom_extensions.push(CustomExtension::from_oid_content(
            &[2, 5, 29, 19],
            vec![0x30, 0],
        ));
        let mut ski = CustomExtension::from_oid_content(&[2, 5, 29, 14], vec![4, 1, 1]);
        p.custom_extensions.push(ski.clone());
        verify(&f.sign(&p), &f.issuer_der, &f.intent, Utc::now()).unwrap();
        p.custom_extensions.pop();
        ski.set_criticality(true);
        p.custom_extensions.push(ski);
        assert!(verify(&f.sign(&p), &f.issuer_der, &f.intent, Utc::now()).is_err());

        // Copy the real matching AKI, changing only its criticality.
        let cert = parse(&f.der).unwrap();
        let aki = cert
            .extensions()
            .iter()
            .find(|e| e.oid.to_id_string() == "2.5.29.35")
            .unwrap();
        let mut p = f.leaf_params.clone();
        p.use_authority_key_identifier_extension = false;
        let mut aki = CustomExtension::from_oid_content(&[2, 5, 29, 35], aki.value.to_vec());
        aki.set_criticality(true);
        p.custom_extensions.push(aki);
        assert!(verify(&f.sign(&p), &f.issuer_der, &f.intent, Utc::now()).is_err());

        let f = Fixture::with_issuer_edit(|p| {
            let mut ian =
                CustomExtension::from_oid_content(&[2, 5, 29, 18], vec![0x30, 3, 0x82, 1, b'x']);
            ian.set_criticality(true);
            p.custom_extensions.push(ian);
        });
        assert!(verify(&f.der, &f.issuer_der, &f.intent, Utc::now()).is_err());
    }
}
