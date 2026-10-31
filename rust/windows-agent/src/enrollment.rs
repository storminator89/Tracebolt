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

/// Validate fresh enrollment inputs without opening state or generating a key.
/// An offline call checks local semantics only; it neither adopts bootstrap trust
/// nor proves manager availability, invitation validity or operator approval.
pub fn validate_initial_bootstrap(
    config: &Config,
    bootstrap: Option<&wire::Bootstrap>,
) -> Result<()> {
    ensure!(
        (config.enrollment_mode == EnrollmentMode::Invitation) == bootstrap.is_some(),
        "invitation bootstrap required only in invitation mode"
    );
    if let Some(bootstrap) = bootstrap {
        validate_bootstrap(config, bootstrap)?;
    }
    Ok(())
}

fn valid_id(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(|suffix| {
        suffix.len() == 32
            && suffix
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && suffix.bytes().any(|b| b != b'0')
    })
}

fn validate_bootstrap(config: &Config, b: &wire::Bootstrap) -> Result<()> {
    ensure!(
        b.schema_version == "tracebolt.enrollment-bootstrap.v2"
            && b.profile == "tls"
            && b.renewal_policy.is_empty()
            && b.collection_profile == wire::COLLECTION
            && b.enrollment_origin == config.manager_origin,
        "bootstrap scope mismatch"
    );
    ensure!(
        valid_id(&b.manager_instance_id, "manager_") && valid_id(&b.invitation_id, "invite_"),
        "invalid bootstrap identity"
    );
    Config::validate_origin(&b.agent_origin)?;
    ensure!(
        config.agent_origin.is_empty() || config.agent_origin == b.agent_origin,
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
    // Advertised server trust is public input, never a replacement for the
    // independently selected CA/WebPKI trust used by the client.
    crate::config::tls_builder(b.server_ca_pem.as_bytes())?.build()?;
    Ok(())
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
            validate_initial_bootstrap(&config, bootstrap.as_ref())?;
        }
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
        validate_bootstrap(&self.config, b)?;
        ensure!(
            b.invitation_id == self.ledger.invitation_id,
            "bootstrap invitation mismatch"
        );
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
    // Validate the original server binding without mutating retained state.
    fn verify_snapshot_binding(&self, s: &Value) -> Result<u64> {
        let boot = self.ledger.bootstrap.as_ref().unwrap();
        let key = self.key()?;
        ensure!(
            s["version"] == "tracebolt.enrollment-state.v2"
                && s["binding"]["instanceID"] == boot.manager_instance_id
                && s["binding"]["origin"] == boot.enrollment_origin
                && s["binding"]["profile"] == "tls"
                && s["binding"]["collectionProfile"] == wire::COLLECTION
                && s["binding"]["issuerFingerprint"] == wire::hash(&cert_der(&boot.issuer_pem)?)
                && s["platform"] == "windows"
                && s["invitationID"] == self.ledger.invitation_id,
            "snapshot binding mismatch"
        );
        ensure!(
            s["claim"]["claimID"] == self.ledger.claim_id
                && s["claim"]["requestID"] == self.ledger.claim_request
                && s["claim"]["keyFingerprint"] == wire::hash(&wire::spki(&key))
                && s["claim"]["csrHash"] == wire::hash(&wire::decode(&self.ledger.csr)?)
                && s["claim"]["claimHash"] == self.ledger.claim_hash,
            "snapshot key mismatch"
        );
        let revision = s["revision"]
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("missing revision"))?;
        ensure!(revision > 0, "invalid enrollment revision");
        Ok(revision)
    }
    fn accept_snapshot(&mut self, s: &Value) -> Result<()> {
        let revision = self.verify_snapshot_binding(s)?;
        ensure!(
            revision >= self.ledger.revision,
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
            valid_id(&i.manager_instance_id, "manager_")
                && valid_id(&i.invitation_id, "invite_")
                && valid_id(&i.claim_id, "claim_")
                && valid_id(&i.request_id, "request_")
                && valid_id(&i.device_id, "agent_")
                && valid_id(&i.intent_id, "intent_"),
            "invalid credential intent identity"
        );
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
                && i.key_fingerprint == snapshot["approval"]["keyFingerprint"]
                && i.device_id == snapshot["intent"]["deviceID"]
                && i.key_fingerprint == snapshot["intent"]["keyFingerprint"]
                && i.template_version == snapshot["intent"]["templateVersion"]
                && i.intent_id == snapshot["intent"]["intentID"]
                && i.request_id == snapshot["intent"]["requestID"]
                && i.not_before == snapshot["intent"]["notBefore"]
                && i.not_after == snapshot["intent"]["notAfter"]
                && i.serial_hex == snapshot["intent"]["serialHex"],
            "credential intent mismatch"
        );
        crate::enrollment_credential::verify(der, issuer, i, Utc::now())?;
        Ok(())
    }
    fn material(&self) -> Result<Material> {
        // Activated is not a substitute for revalidating the original saved
        // profile/claim/issuance on every resume. No state is repaired or adopted.
        let activated: bool =
            self.connection
                .query_row("SELECT activated FROM enrollment WHERE id=1", [], |r| {
                    r.get(0)
                })?;
        ensure!(
            activated && !self.ledger.terminal,
            "enrollment not activated"
        );
        let bootstrap = self
            .ledger
            .bootstrap
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing activated bootstrap"))?;
        self.validate_bootstrap(bootstrap)?;
        let snapshot = self
            .ledger
            .issued_snapshot
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing original issuance snapshot"))?;
        let issuance_revision = self.verify_snapshot_binding(snapshot)?;
        ensure!(
            issuance_revision <= self.ledger.revision
                && matches!(snapshot["state"].as_str(), Some("issued" | "activated")),
            "invalid retained issuance state"
        );
        let mut config = self.config.clone();
        let intent = self
            .ledger
            .intent
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing activated intent"))?;
        let der = wire::decode(
            self.ledger
                .certificate
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("missing activated certificate"))?,
        )?;
        self.verify_credential(intent, &der, &cert_der(&bootstrap.issuer_pem)?, snapshot)?;
        config.agent_id = intent.device_id.clone();
        config.manager_origin = self.ledger.bootstrap.as_ref().unwrap().agent_origin.clone();
        let mut certificate = wire::pem(&der);
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

#[cfg(test)]
mod authority_tests {
    use super::*;
    use crate::enrollment_credential::fixture::Fixture;

    // An invented already-activated private ledger. No enrollment endpoint,
    // native API, SCM service, host grant or production credential is used.
    fn fixture() -> (tempfile::TempDir, Enrollment) {
        let f = Fixture::new();
        let directory = tempfile::tempdir().unwrap();
        let state = directory.path().join("state");
        std::fs::create_dir(&state).unwrap();
        let config = Config {
            schema_version: "tracebolt.rust-windows-basic.v1".into(),
            manager_origin: f.intent.origin.clone(),
            agent_id: String::new(),
            enrollment_mode: EnrollmentMode::Auto,
            agent_origin: String::new(),
            basic_metrics_acknowledged: true,
            interval_seconds: 60,
        };
        std::fs::write(
            directory.path().join("config.json"),
            serde_json::to_vec(&config).unwrap(),
        )
        .unwrap();
        let bootstrap = wire::Bootstrap {
            schema_version: "tracebolt.enrollment-bootstrap.v2".into(),
            manager_instance_id: f.intent.manager_instance_id.clone(),
            profile: "tls".into(),
            enrollment_origin: f.intent.origin.clone(),
            agent_origin: "https://agent.fixture.invalid".into(),
            collection_profile: wire::COLLECTION.into(),
            invitation_id: f.intent.invitation_id.clone(),
            server_ca_pem: String::new(),
            issuer_root_pem: f.root_pem,
            issuer_pem: wire::pem(&f.issuer_der),
            renewal_policy: String::new(),
        };
        let claim_request = format!("request_{}", "5".repeat(32));
        let snapshot = json!({
            "version":"tracebolt.enrollment-state.v2", "binding":{
                "instanceID":f.intent.manager_instance_id, "origin":f.intent.origin, "profile":"tls",
                "collectionProfile":wire::COLLECTION, "issuerFingerprint":f.intent.issuer_fingerprint
            }, "platform":"windows", "invitationID":f.intent.invitation_id, "revision":5, "state":"issued",
            "claim":{"claimID":f.intent.claim_id, "requestID":claim_request,
                "keyFingerprint":f.intent.key_fingerprint, "csrHash":f.intent.csr_hash, "claimHash":f.intent.claim_hash},
            "approval":{"deviceID":f.intent.device_id, "keyFingerprint":f.intent.key_fingerprint},
            "intent":{"deviceID":f.intent.device_id, "keyFingerprint":f.intent.key_fingerprint,
                "templateVersion":f.intent.template_version, "intentID":f.intent.intent_id, "requestID":f.intent.request_id,
                "notBefore":f.intent.not_before, "notAfter":f.intent.not_after, "serialHex":f.intent.serial_hex},
            "issuance":{"certificateHash":wire::hash(&f.der)}
        });
        let ledger = Ledger {
            key: wire::encode(&f.key.serialize_der()),
            csr: wire::encode(&f.csr),
            invitation_id: f.intent.invitation_id.clone(),
            claim_id: f.intent.claim_id.clone(),
            claim_request,
            status_request: format!("request_{}", "6".repeat(32)),
            credential_request: format!("request_{}", "a".repeat(32)),
            activation_request: format!("request_{}", "b".repeat(32)),
            bootstrap: Some(bootstrap),
            claim_hash: f.intent.claim_hash.clone(),
            claimed: true,
            revision: 6,
            certificate: Some(wire::encode(&f.der)),
            intent: Some(f.intent),
            terminal: false,
            issued_snapshot: Some(snapshot),
            reconcile_claim: false,
        };
        let connection = Connection::open(state.join("enrollment.db")).unwrap();
        connection.execute_batch("CREATE TABLE enrollment(id INTEGER PRIMARY KEY CHECK(id=1),binding TEXT NOT NULL,payload BLOB NOT NULL,activated INTEGER NOT NULL DEFAULT 0,sender_initialized INTEGER NOT NULL DEFAULT 0);").unwrap();
        connection
            .execute(
                "INSERT INTO enrollment VALUES(1,?1,?2,1,0)",
                params![
                    config.binding(&[], &[]).unwrap(),
                    serde_json::to_vec(&ledger).unwrap()
                ],
            )
            .unwrap();
        drop(connection);
        let enrollment = Enrollment::open(directory.path(), false, None).unwrap();
        (directory, enrollment)
    }

    fn retained(e: &Enrollment) -> (String, Vec<u8>, bool, bool) {
        e.connection
            .query_row(
                "SELECT binding,payload,activated,sender_initialized FROM enrollment WHERE id=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap()
    }

    #[test]
    fn activated_resume_revalidates_original_binding_without_rewriting_v1_state() {
        let (directory, mut e) = fixture();
        let before = retained(&e);
        let material = e.step(None).unwrap().unwrap();
        assert_eq!(
            material.config.schema_version,
            "tracebolt.rust-windows-basic.v1"
        );
        assert_eq!(
            material.config.manager_origin,
            "https://agent.fixture.invalid"
        );
        assert!(material.config.basic_metrics_acknowledged);
        assert_eq!(before, retained(&e));
        drop(e);
        let mut e = Enrollment::open(directory.path(), false, None).unwrap();
        e.step(None).unwrap().unwrap();
        assert_eq!(before, retained(&e));
        assert!(!directory.path().join("state/sender.db").exists());
    }

    #[test]
    fn saved_profile_and_local_consent_cannot_be_changed_on_resume() {
        let (directory, e) = fixture();
        let before = retained(&e);
        let changes: [fn(&mut Value); 21] = [
            |v| v["intent"]["collectionProfile"] = json!("windows-basic-metrics-v1"),
            |v| v["intent"]["collectionProfile"] = json!("managed-operations-v3"),
            |v| v["intent"]["profile"] = json!("http-test"),
            |v| v["intent"]["deviceId"] = json!(format!("agent_{}", "9".repeat(32))),
            |v| v["intent"]["requestId"] = json!("caller-selected"),
            |v| v["intent"]["notAfter"] = json!(i64::MAX),
            |v| v["intent"]["serialHex"] = json!("08".repeat(16)),
            |v| v["certificate"] = json!(wire::encode(b"not a certificate")),
            |v| v["issuedSnapshot"] = Value::Null,
            |v| v["issuedSnapshot"]["state"] = json!("claimed_pending"),
            |v| v["issuedSnapshot"]["revision"] = json!(7),
            |v| {
                v["issuedSnapshot"]["binding"]["collectionProfile"] =
                    json!("windows-basic-metrics-v1")
            },
            |v| v["issuedSnapshot"]["binding"]["issuerFingerprint"] = json!("f".repeat(64)),
            |v| v["issuedSnapshot"]["platform"] = json!("linux"),
            |v| {
                v["issuedSnapshot"]["claim"]["requestID"] =
                    json!(format!("request_{}", "9".repeat(32)))
            },
            |v| v["issuedSnapshot"]["claim"]["claimHash"] = json!("e".repeat(64)),
            |v| v["issuedSnapshot"]["approval"]["keyFingerprint"] = json!("d".repeat(64)),
            |v| v["issuedSnapshot"]["intent"]["deviceID"] = json!("another-device"),
            |v| v["issuedSnapshot"]["intent"]["templateVersion"] = json!("expanded-template"),
            |v| v["issuedSnapshot"]["issuance"]["certificateHash"] = json!("b".repeat(64)),
            |v| v["terminal"] = json!(true),
        ];
        drop(e);
        let db = Connection::open(directory.path().join("state/enrollment.db")).unwrap();
        for (index, change) in changes.into_iter().enumerate() {
            let mut v: Value = serde_json::from_slice(&before.1).unwrap();
            change(&mut v);
            let raw = serde_json::to_vec(&v).unwrap();
            db.execute("UPDATE enrollment SET payload=?1 WHERE id=1", [&raw])
                .unwrap();
            let mut e = Enrollment::open(directory.path(), false, None).unwrap();
            let retained_before = retained(&e);
            assert!(e.step(None).is_err(), "change {index}");
            assert_eq!(
                retained_before,
                retained(&e),
                "denial changed state {index}"
            );
            assert!(!directory.path().join("state/sender.db").exists());
        }
        // Consent is still the original Basic config; a new capability flag is
        // not recognized, and changing consent breaks the original DB binding.
        db.execute("UPDATE enrollment SET payload=?1 WHERE id=1", [&before.1])
            .unwrap();
        let path = directory.path().join("config.json");
        let mut config: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        config["serviceInventoryAcknowledged"] = json!(true);
        std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
        assert!(Enrollment::open(directory.path(), false, None).is_err());
        config
            .as_object_mut()
            .unwrap()
            .remove("serviceInventoryAcknowledged");
        config["basicMetricsAcknowledged"] = json!(false);
        std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
        assert!(Enrollment::open(directory.path(), false, None).is_err());
    }

    #[test]
    fn resume_rejects_unactivated_missing_and_corrupt_issuance_without_state_repair() {
        let (directory, mut e) = fixture();
        let original = retained(&e);
        e.connection
            .execute("UPDATE enrollment SET activated=0 WHERE id=1", [])
            .unwrap();
        assert!(e.material().is_err());
        e.connection
            .execute("UPDATE enrollment SET activated=1 WHERE id=1", [])
            .unwrap();
        for mutate in [
            |e: &mut Enrollment| e.ledger.intent = None,
            |e: &mut Enrollment| e.ledger.bootstrap = None,
            |e: &mut Enrollment| e.ledger.certificate = None,
        ] {
            e.ledger = serde_json::from_slice(&original.1).unwrap();
            mutate(&mut e);
            assert!(e.material().is_err());
            assert_eq!(original, retained(&e));
        }
        assert!(!directory.path().join("state/sender.db").exists());
    }
}
