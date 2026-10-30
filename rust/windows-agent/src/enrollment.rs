use crate::{
    config::{Config, EnrollmentMode},
    enrollment_wire as wire,
};
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use fs2::FileExt;
use hmac::{Hmac, Mac};
use rcgen::{CertificateParams, DistinguishedName, KeyPair, PKCS_ED25519};
use reqwest::blocking::Client;
use ring::signature::Ed25519KeyPair;
use rusqlite::{Connection, OpenFlags, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Sha256;
use std::{
    fs::{File, OpenOptions},
    io::Read,
    path::{Path, PathBuf},
};
use x509_parser::prelude::*;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Ledger {
    key: String,
    csr: String,
    invitation_id: String,
    claim_id: String,
    claim_request: String,
    status_request: String,
    credential_request: String,
    activation_request: String,
    bootstrap: Option<wire::Bootstrap>,
    claim_hash: String,
    claimed: bool,
    revision: u64,
    certificate: Option<String>,
    intent: Option<wire::Intent>,
    terminal: bool,
    issued_snapshot: Option<Value>,
    reconcile_claim: bool,
}

#[derive(Debug)]
struct EnrollmentHttp(u16);
impl std::fmt::Display for EnrollmentHttp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "enrollment request not acknowledged")
    }
}
impl std::error::Error for EnrollmentHttp {}

pub struct Enrollment {
    directory: PathBuf,
    pub config: Config,
    ca: Vec<u8>,
    client: Client,
    connection: Connection,
    ledger: Ledger,
    _lock: File,
}
pub struct Material {
    pub config: Config,
    pub ca: Vec<u8>,
    pub certificate: Vec<u8>,
    pub private_key: Vec<u8>,
}
fn cert_der(pem: &str) -> Result<Vec<u8>> {
    let (rest, pem) =
        parse_x509_pem(pem.as_bytes()).map_err(|_| anyhow::anyhow!("invalid certificate PEM"))?;
    ensure!(
        rest.iter().all(|b| b.is_ascii_whitespace()) && pem.label == "CERTIFICATE",
        "one certificate required"
    );
    Ok(pem.contents)
}
fn parse_cert(bytes: &[u8]) -> Result<X509Certificate<'_>> {
    let (rest, cert) =
        parse_x509_certificate(bytes).map_err(|_| anyhow::anyhow!("invalid certificate"))?;
    ensure!(rest.is_empty(), "trailing certificate bytes");
    Ok(cert)
}

impl Enrollment {
    pub fn open(
        directory: &Path,
        initialize: bool,
        bootstrap: Option<wire::Bootstrap>,
    ) -> Result<Self> {
        let config = Config::load(directory)?;
        ensure!(
            config.enrollment_mode != EnrollmentMode::Preprovided,
            "preprovided identity mode"
        );
        let ca = crate::config::read_ca(directory)?;
        if initialize {
            crate::compatibility::check(&config, &ca)?;
        }
        let client = crate::config::tls_builder(&ca)?.build()?;
        let state = directory.join("state");
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(state.join("enrollment.lock"))?;
        lock.try_lock_exclusive()?;
        let path = state.join("enrollment.db");
        if initialize {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)?
                .sync_all()?;
        }
        let mut connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        connection.execute_batch("PRAGMA synchronous=FULL; PRAGMA journal_mode=DELETE;")?;
        let binding = config.binding(&[], &ca)?;
        if initialize {
            ensure!(
                (config.enrollment_mode == EnrollmentMode::Invitation) == bootstrap.is_some(),
                "invitation bootstrap required only in invitation mode"
            );
            let key = KeyPair::generate_for(&PKCS_ED25519)?;
            let mut params = CertificateParams::new(Vec::<String>::new())?;
            params.distinguished_name = DistinguishedName::new();
            let csr = params.serialize_request(&key)?;
            let invitation_id = bootstrap
                .as_ref()
                .map(|b| b.invitation_id.clone())
                .unwrap_or_else(|| wire::random_id("invite_"));
            let ledger = Ledger {
                key: wire::encode(&key.serialize_der()),
                csr: wire::encode(csr.der()),
                invitation_id,
                claim_id: wire::random_id("claim_"),
                claim_request: wire::random_id("request_"),
                status_request: wire::random_id("request_"),
                credential_request: wire::random_id("request_"),
                activation_request: wire::random_id("request_"),
                bootstrap,
                claim_hash: String::new(),
                claimed: false,
                revision: 0,
                certificate: None,
                intent: None,
                terminal: false,
                issued_snapshot: None,
                reconcile_claim: false,
            };
            let tx = connection.transaction()?;
            tx.execute_batch("CREATE TABLE enrollment(id INTEGER PRIMARY KEY CHECK(id=1),binding TEXT NOT NULL,payload BLOB NOT NULL,activated INTEGER NOT NULL DEFAULT 0,sender_initialized INTEGER NOT NULL DEFAULT 0);")?;
            tx.execute(
                "INSERT INTO enrollment(id,binding,payload) VALUES(1,?1,?2)",
                params![binding, serde_json::to_vec(&ledger)?],
            )?;
            tx.commit()?;
        }
        let (stored, raw): (String, Vec<u8>) = connection.query_row(
            "SELECT binding,payload FROM enrollment WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        ensure!(
            stored == binding && raw.len() < 65536,
            "enrollment state binding mismatch"
        );
        let ledger = serde_json::from_slice(&raw)?;
        let result = Self {
            directory: directory.into(),
            config,
            ca,
            client,
            connection,
            ledger,
            _lock: lock,
        };
        if let Some(bootstrap) = &result.ledger.bootstrap {
            result.validate_bootstrap(bootstrap)?;
        }
        Ok(result)
    }
    fn save(&self) -> Result<()> {
        self.connection.execute(
            "UPDATE enrollment SET payload=?1 WHERE id=1",
            [serde_json::to_vec(&self.ledger)?],
        )?;
        Ok(())
    }
    fn key(&self) -> Result<Ed25519KeyPair> {
        Ed25519KeyPair::from_pkcs8(&wire::decode(&self.ledger.key)?)
            .map_err(|_| anyhow::anyhow!("invalid saved key"))
    }
    fn post(&self, path: &str, body: Value) -> Result<Value> {
        let bytes = serde_json::to_vec(&body)?;
        ensure!(bytes.len() <= 16384, "enrollment request too large");
        let response = self
            .client
            .post(format!(
                "{}{}{path}",
                self.config.manager_origin,
                wire::PREFIX
            ))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .body(bytes)
            .send()?;
        if response.status() != reqwest::StatusCode::OK {
            let status = response.status().as_u16();
            let code = match status {
                401 | 403 => crate::health::Code::AuthenticationRejected,
                404 | 405 | 415 => crate::health::Code::ProtocolUnavailable,
                _ => crate::health::Code::ManagerRejected,
            };
            return Err(anyhow::Error::new(EnrollmentHttp(status)).context(code));
        }
        ensure!(
            response
                .headers()
                .get("content-type")
                .and_then(|h| h.to_str().ok())
                .is_some_and(|s| s.split(';').next() == Some("application/json")),
            "invalid enrollment response type"
        );
        let mut raw = Vec::new();
        response.take(65537).read_to_end(&mut raw)?;
        ensure!(raw.len() <= 65536, "enrollment response too large");
        Ok(serde_json::from_slice(&raw)?)
    }
    fn validate_bootstrap(&self, b: &wire::Bootstrap) -> Result<()> {
        ensure!(
            b.schema_version == "tracebolt.enrollment-bootstrap.v2"
                && b.profile == "tls"
                && b.renewal_policy.is_empty()
                && b.collection_profile == wire::COLLECTION
                && b.enrollment_origin == self.config.manager_origin
                && b.invitation_id == self.ledger.invitation_id,
            "bootstrap scope mismatch"
        );
        ensure!(
            b.manager_instance_id.starts_with("manager_") && b.manager_instance_id.len() == 40,
            "invalid manager identity"
        );
        Config::validate_origin(&b.agent_origin)?;
        ensure!(
            self.config.agent_origin.is_empty() || self.config.agent_origin == b.agent_origin,
            "telemetry destination mismatch"
        );
        let root_der = cert_der(&b.issuer_root_pem)?;
        let issuer_der = cert_der(&b.issuer_pem)?;
        let root = parse_cert(&root_der)?;
        let issuer = parse_cert(&issuer_der)?;
        ensure!(
            root.is_ca()
                && issuer.is_ca()
                && root.validity().is_valid()
                && issuer.validity().is_valid(),
            "invalid issuing authority"
        );
        issuer
            .verify_signature(Some(root.public_key()))
            .map_err(|_| anyhow::anyhow!("issuer signature rejected"))?;
        Ok(())
    }
    fn challenge(&self, purpose: &str) -> Result<wire::Context> {
        let body=self.post("challenge",json!({"invitationId":self.ledger.invitation_id,"claimId":self.ledger.claim_id,"purpose":purpose}))?;
        ensure!(
            body["schemaVersion"] == "tracebolt.enrollment-challenge.v2"
                && body["purpose"] == purpose,
            "wrong challenge purpose"
        );
        let now: DateTime<Utc> = serde_json::from_value(body["serverNow"].clone())?;
        ensure!(
            (Utc::now() - now).num_seconds().abs() <= 60,
            "manager clock mismatch"
        );
        let context: wire::Context = serde_json::from_value(body["context"].clone())?;
        context.validate(
            self.ledger.bootstrap.as_ref().unwrap(),
            &self.ledger.claim_id,
        )?;
        Ok(context)
    }
    fn accept_snapshot(&mut self, s: &Value) -> Result<()> {
        let boot = self.ledger.bootstrap.as_ref().unwrap();
        let key = self.key()?;
        ensure!(
            s["version"] == "tracebolt.enrollment-state.v2"
                && s["binding"]["instanceID"] == boot.manager_instance_id
                && s["binding"]["origin"] == boot.enrollment_origin
                && s["binding"]["profile"] == "tls"
                && s["binding"]["collectionProfile"] == wire::COLLECTION
                && s["platform"] == "windows"
                && s["invitationID"] == self.ledger.invitation_id,
            "snapshot binding mismatch"
        );
        ensure!(
            s["claim"]["claimID"] == self.ledger.claim_id
                && s["claim"]["keyFingerprint"] == wire::hash(&wire::spki(&key))
                && s["claim"]["csrHash"] == wire::hash(&wire::decode(&self.ledger.csr)?)
                && s["claim"]["claimHash"] == self.ledger.claim_hash,
            "snapshot key mismatch"
        );
        let revision = s["revision"]
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("missing revision"))?;
        ensure!(
            revision >= self.ledger.revision && revision > 0,
            "enrollment revision rollback"
        );
        self.ledger.revision = revision;
        self.ledger.claimed = true;
        if matches!(
            s["state"].as_str(),
            Some("expired" | "canceled" | "rejected" | "revoked")
        ) {
            self.ledger.terminal = true;
        }
        self.save()?;
        if self.ledger.terminal {
            return Err(match s["state"].as_str() {
                Some("revoked") => crate::health::Code::EnrollmentRevoked,
                Some("expired") => crate::health::Code::EnrollmentExpired,
                _ => crate::health::Code::EnrollmentTerminated,
            }
            .into());
        }
        Ok(())
    }
    pub fn public_status(&self) -> Result<Value> {
        let activated: bool =
            self.connection
                .query_row("SELECT activated FROM enrollment WHERE id=1", [], |r| {
                    r.get(0)
                })?;
        let key = self.key()?;
        let comparison = self.ledger.bootstrap.as_ref().map(|b| {
            wire::hash(&wire::transcript(
                "Tracebolt enrollment comparison v2",
                &[
                    &b.manager_instance_id,
                    &b.invitation_id,
                    &self.ledger.claim_id,
                    &wire::hash(&wire::spki(&key)),
                ],
            ))[..32]
                .to_owned()
        });
        Ok(
            json!({"phase":if self.ledger.terminal {"terminated"} else if activated {"activated"} else if self.ledger.claimed {"waiting-for-manager-approval"} else {"awaiting-registration"},"keyFingerprint":wire::hash(&wire::spki(&key)),"comparisonCode":comparison}),
        )
    }
    pub fn step(&mut self, invitation_secret: Option<&str>) -> Result<Option<Material>> {
        ensure!(
            !self.ledger.terminal,
            crate::health::Code::EnrollmentTerminated
        );
        let activated: bool =
            self.connection
                .query_row("SELECT activated FROM enrollment WHERE id=1", [], |r| {
                    r.get(0)
                })?;
        if activated {
            return self.material().map(Some);
        }
        if self.ledger.bootstrap.is_none() {
            ensure!(
                self.config.enrollment_mode == EnrollmentMode::Auto,
                "invitation bootstrap missing"
            );
            let value = self.post(
                "self-bootstrap",
                json!({"invitationId":self.ledger.invitation_id}),
            )?;
            let bootstrap = serde_json::from_value(value)?;
            self.validate_bootstrap(&bootstrap)?;
            self.ledger.bootstrap = Some(bootstrap);
            self.save()?;
            return Ok(None);
        }
        if !self.ledger.claimed {
            if self.ledger.reconcile_claim {
                let context = self.challenge("status")?;
                match self.post(
                    "status",
                    wire::status(
                        &context,
                        "status",
                        &self.ledger.status_request,
                        &self.key()?,
                    ),
                ) {
                    Ok(snapshot) => {
                        self.accept_snapshot(&snapshot)?;
                        self.ledger.reconcile_claim = false;
                        self.save()?;
                        return Ok(None);
                    }
                    Err(error)
                        if error
                            .downcast_ref::<EnrollmentHttp>()
                            .is_some_and(|e| e.0 == 401) =>
                    {
                        // Only retry the identical semantic claim; never change key/IDs/secret or reset its expiry.
                        self.ledger.reconcile_claim = false;
                        self.save()?;
                        return Ok(None);
                    }
                    Err(error) => return Err(error),
                }
            }
            let secret = if self.config.enrollment_mode == EnrollmentMode::Auto {
                let mut mac = Hmac::<Sha256>::new_from_slice(&wire::decode(&self.ledger.key)?)
                    .map_err(|_| anyhow::anyhow!("invalid key"))?;
                mac.update(b"Tracebolt Rust automatic enrollment invitation v1");
                URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
            } else {
                invitation_secret
                    .ok_or_else(|| anyhow::anyhow!("optional invitation input required"))?
                    .to_owned()
            };
            let context = self.challenge("claim")?;
            let (claim, hash) = wire::claim(
                &context,
                &self.ledger.claim_request,
                &wire::decode(&self.ledger.csr)?,
                &secret,
                &self.key()?,
            )?;
            ensure!(
                self.ledger.claim_hash.is_empty() || self.ledger.claim_hash == hash,
                "invitation differs from saved claim"
            );
            self.ledger.claim_hash = hash;
            self.ledger.reconcile_claim = true;
            self.save()?;
            let path = if self.config.enrollment_mode == EnrollmentMode::Auto {
                "self-claim"
            } else {
                "claim"
            };
            let snapshot = self.post(path, claim)?;
            self.accept_snapshot(&snapshot)?;
            self.ledger.reconcile_claim = false;
            self.save()?;
            return Ok(None);
        }
        if self.ledger.issued_snapshot.is_none() {
            let context = self.challenge("status")?;
            let snapshot = self.post(
                "status",
                wire::status(
                    &context,
                    "status",
                    &self.ledger.status_request,
                    &self.key()?,
                ),
            )?;
            self.accept_snapshot(&snapshot)?;
            if matches!(snapshot["state"].as_str(), Some("issued" | "activated")) {
                self.ledger.issued_snapshot = Some(snapshot);
                self.save()?;
            }
            return Ok(None);
        }
        if self.ledger.certificate.is_none() {
            let context = self.challenge("credential")?;
            let response = self.post(
                "credential",
                wire::status(
                    &context,
                    "credential",
                    &self.ledger.credential_request,
                    &self.key()?,
                ),
            )?;
            ensure!(
                response["schemaVersion"] == "tracebolt.enrollment-credential.v2",
                "wrong credential schema"
            );
            let intent: wire::Intent = serde_json::from_value(response["intent"].clone())?;
            let cert = wire::decode(
                response["certificateDer"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("missing certificate"))?,
            )?;
            let issuer = wire::decode(
                response["issuerDer"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("missing issuer"))?,
            )?;
            self.verify_credential(
                &intent,
                &cert,
                &issuer,
                self.ledger.issued_snapshot.as_ref().unwrap(),
            )?;
            self.ledger.intent = Some(intent);
            self.ledger.certificate = Some(wire::encode(&cert));
            self.save()?;
            return Ok(None);
        }
        let context = self.challenge("activation")?;
        let intent = self.ledger.intent.as_ref().unwrap();
        let cert = wire::decode(self.ledger.certificate.as_ref().unwrap())?;
        let response = self.post(
            "activate",
            wire::activation(
                &context,
                intent,
                &self.ledger.activation_request,
                &cert,
                &self.key()?,
            ),
        )?;
        self.accept_snapshot(&response)?;
        ensure!(
            response["state"] == "activated"
                && response["activation"]["requestID"] == self.ledger.activation_request,
            "activation not confirmed"
        );
        self.connection
            .execute("UPDATE enrollment SET activated=1 WHERE id=1", [])?;
        self.material().map(Some)
    }
    fn verify_credential(
        &self,
        i: &wire::Intent,
        der: &[u8],
        issuer: &[u8],
        snapshot: &Value,
    ) -> Result<()> {
        let b = self.ledger.bootstrap.as_ref().unwrap();
        let key = self.key()?;
        ensure!(
            issuer == cert_der(&b.issuer_pem)?
                && wire::hash(issuer) == i.issuer_fingerprint
                && wire::hash(der) == snapshot["issuance"]["certificateHash"],
            "certificate issuer/hash mismatch"
        );
        ensure!(
            i.manager_instance_id == b.manager_instance_id
                && i.profile == "tls"
                && i.origin == b.enrollment_origin
                && i.collection_profile == wire::COLLECTION
                && i.invitation_id == b.invitation_id
                && i.claim_id == self.ledger.claim_id
                && i.key_fingerprint == wire::hash(&wire::spki(&key))
                && i.public_key_der_base64 == wire::encode(&wire::spki(&key))
                && i.csr_hash == wire::hash(&wire::decode(&self.ledger.csr)?)
                && i.claim_hash == self.ledger.claim_hash
                && i.template_version == "tracebolt.enrollment.client.v2"
                && i.key_generation == 1
                && i.device_id == snapshot["approval"]["deviceID"]
                && i.intent_id == snapshot["intent"]["intentID"]
                && i.request_id == snapshot["intent"]["requestID"]
                && i.not_before == snapshot["intent"]["notBefore"]
                && i.not_after == snapshot["intent"]["notAfter"]
                && i.serial_hex == snapshot["intent"]["serialHex"],
            "credential intent mismatch"
        );
        let cert = parse_cert(der)?;
        let issuer = parse_cert(issuer)?;
        ensure!(
            !cert.is_ca()
                && cert.validity().is_valid()
                && cert.validity().not_before.timestamp() == i.not_before
                && cert.validity().not_after.timestamp() == i.not_after
                && i.not_after - i.not_before <= 30 * 86400
                && cert.public_key().raw == wire::spki(&key)
                && cert
                    .subject()
                    .iter_common_name()
                    .next()
                    .and_then(|a| a.as_str().ok())
                    == Some(i.device_id.as_str())
                && cert.issuer() == issuer.subject(),
            "issued certificate mismatch"
        );
        ensure!(
            cert.extended_key_usage()?
                .is_some_and(|v| v.value.client_auth && !v.value.server_auth && !v.value.any)
                && cert.subject_alternative_name()?.is_none(),
            "unexpected certificate use"
        );
        cert.verify_signature(Some(issuer.public_key()))
            .map_err(|_| anyhow::anyhow!("issued signature rejected"))?;
        Ok(())
    }
    fn material(&self) -> Result<Material> {
        let mut config = self.config.clone();
        let intent = self
            .ledger
            .intent
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing activated intent"))?;
        config.agent_id = intent.device_id.clone();
        config.manager_origin = self.ledger.bootstrap.as_ref().unwrap().agent_origin.clone();
        let mut certificate = wire::pem(&wire::decode(
            self.ledger
                .certificate
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("missing activated certificate"))?,
        )?);
        certificate.push_str(&self.ledger.bootstrap.as_ref().unwrap().issuer_pem);
        let key = KeyPair::try_from(wire::decode(&self.ledger.key)?.as_slice())?;
        Ok(Material {
            config,
            ca: self.ca.clone(),
            certificate: certificate.into_bytes(),
            private_key: key.serialize_pem().into_bytes(),
        })
    }
    pub fn state_directory(&self) -> PathBuf {
        self.directory.join("state")
    }
}
