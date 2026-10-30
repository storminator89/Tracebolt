use anyhow::{Result, ensure};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE_NO_PAD},
};
use chrono::Utc;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub const PREFIX: &str = "/v2/windows/enrollment/";
pub const COLLECTION: &str = "windows-inventory-v1";
pub fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
pub fn encode(bytes: &[u8]) -> String {
    STANDARD_NO_PAD.encode(bytes)
}
pub fn decode(value: &str) -> Result<Vec<u8>> {
    Ok(STANDARD_NO_PAD.decode(value)?)
}
pub fn random_id(prefix: &str) -> String {
    format!("{prefix}{}", uuid::Uuid::new_v4().simple())
}
pub fn transcript(domain: &str, fields: &[&str]) -> Vec<u8> {
    let mut out = Vec::new();
    for field in std::iter::once(domain).chain(fields.iter().copied()) {
        out.extend_from_slice(&(field.len() as u32).to_be_bytes());
        out.extend_from_slice(field.as_bytes());
    }
    out
}
pub fn spki(key: &Ed25519KeyPair) -> Vec<u8> {
    let mut out = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    out.extend_from_slice(key.public_key().as_ref());
    out
}
pub fn pem(der: &[u8]) -> String {
    let text = STANDARD.encode(der);
    let lines = text
        .as_bytes()
        .chunks(64)
        .map(|line| std::str::from_utf8(line).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    format!("-----BEGIN CERTIFICATE-----\n{lines}\n-----END CERTIFICATE-----\n")
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Bootstrap {
    pub schema_version: String,
    pub manager_instance_id: String,
    pub profile: String,
    pub enrollment_origin: String,
    pub agent_origin: String,
    pub collection_profile: String,
    pub invitation_id: String,
    pub server_ca_pem: String,
    pub issuer_root_pem: String,
    pub issuer_pem: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub renewal_policy: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Context {
    pub manager_instance_id: String,
    pub profile: String,
    pub origin: String,
    pub collection_profile: String,
    pub invitation_id: String,
    pub claim_id: String,
    pub challenge: String,
    pub expires_at: i64,
}
impl Context {
    pub fn validate(&self, boot: &Bootstrap, claim: &str) -> Result<()> {
        let now = Utc::now().timestamp();
        ensure!(
            self.manager_instance_id == boot.manager_instance_id
                && self.profile == "tls"
                && self.origin == boot.enrollment_origin
                && self.collection_profile == COLLECTION
                && self.invitation_id == boot.invitation_id
                && self.claim_id == claim
                && self.expires_at > now
                && self.expires_at <= now + 90,
            "invalid enrollment challenge binding"
        );
        ensure!(
            URL_SAFE_NO_PAD.decode(&self.challenge)?.len() == 32,
            "invalid nonce"
        );
        Ok(())
    }
    fn base(&self) -> Value {
        json!({"managerInstanceId":self.manager_instance_id,"profile":self.profile,"origin":self.origin,"collectionProfile":self.collection_profile,"invitationId":self.invitation_id,"claimId":self.claim_id,"challenge":self.challenge})
    }
}

pub fn claim(
    c: &Context,
    request: &str,
    csr: &[u8],
    secret: &str,
    key: &Ed25519KeyPair,
) -> Result<(Value, String)> {
    let raw_secret = URL_SAFE_NO_PAD.decode(secret)?;
    ensure!(raw_secret.len() == 32, "invalid invitation");
    let mut verifier = b"tracebolt.invitation.v2\0".to_vec();
    verifier.extend(raw_secret);
    let (key_hash, csr_hash, invitation_hash, expiry) = (
        hash(&spki(key)),
        hash(csr),
        hash(&verifier),
        c.expires_at.to_string(),
    );
    let fields = [
        c.manager_instance_id.as_str(),
        &c.profile,
        &c.origin,
        &c.collection_profile,
        &c.invitation_id,
        &c.claim_id,
        request,
        &key_hash,
        &csr_hash,
        &invitation_hash,
    ];
    let claim_hash = hash(&transcript(
        "Tracebolt enrollment semantic claim v2",
        &fields,
    ));
    let mut proof_fields = fields.to_vec();
    proof_fields.extend([c.challenge.as_str(), &expiry]);
    let proof = key.sign(&transcript(
        "Tracebolt enrollment claim possession v2",
        &proof_fields,
    ));
    let mut body = c.base();
    body["schemaVersion"] = json!("tracebolt.enrollment-claim.v2");
    body["requestId"] = json!(request);
    body["invitationSecret"] = json!(secret);
    body["csr"] = json!(encode(csr));
    body["proof"] = json!(encode(proof.as_ref()));
    Ok((body, claim_hash))
}
pub fn status(c: &Context, purpose: &str, request: &str, key: &Ed25519KeyPair) -> Value {
    let (key_hash, expiry) = (hash(&spki(key)), c.expires_at.to_string());
    let message = transcript(
        "Tracebolt enrollment status possession v2",
        &[
            &c.manager_instance_id,
            &c.profile,
            &c.origin,
            &c.collection_profile,
            &c.invitation_id,
            &c.claim_id,
            &key_hash,
            purpose,
            request,
            &c.challenge,
            &expiry,
        ],
    );
    let mut body = c.base();
    body["schemaVersion"] = json!("tracebolt.enrollment-status.v2");
    body["keyFingerprint"] = json!(key_hash);
    body["requestId"] = json!(request);
    body["purpose"] = json!(purpose);
    body["proof"] = json!(encode(key.sign(&message).as_ref()));
    body
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Intent {
    pub manager_instance_id: String,
    pub profile: String,
    pub origin: String,
    pub collection_profile: String,
    pub invitation_id: String,
    pub claim_id: String,
    pub request_id: String,
    pub device_id: String,
    pub intent_id: String,
    pub key_fingerprint: String,
    pub public_key_der_base64: String,
    pub csr_hash: String,
    pub claim_hash: String,
    pub issuer_fingerprint: String,
    pub serial_hex: String,
    pub template_version: String,
    pub key_generation: u64,
    pub not_before: i64,
    pub not_after: i64,
}
impl Intent {
    pub fn digest(&self) -> String {
        hash(&transcript(
            "Tracebolt enrollment issuance intent v2",
            &[
                &self.manager_instance_id,
                &self.profile,
                &self.origin,
                &self.collection_profile,
                &self.invitation_id,
                &self.claim_id,
                &self.request_id,
                &self.device_id,
                &self.intent_id,
                &self.key_fingerprint,
                &self.public_key_der_base64,
                &self.csr_hash,
                &self.claim_hash,
                &self.issuer_fingerprint,
                &self.serial_hex,
                &self.template_version,
                &self.key_generation.to_string(),
                &self.not_before.to_string(),
                &self.not_after.to_string(),
            ],
        ))
    }
}
pub fn activation(
    c: &Context,
    intent: &Intent,
    request: &str,
    certificate: &[u8],
    key: &Ed25519KeyPair,
) -> Value {
    let cert_hash = hash(certificate);
    let message = transcript(
        "Tracebolt enrollment activation possession v2",
        &[
            &intent.digest(),
            &intent.manager_instance_id,
            &intent.profile,
            &intent.origin,
            &intent.collection_profile,
            &intent.device_id,
            &intent.intent_id,
            &intent.key_fingerprint,
            &cert_hash,
            request,
            &c.challenge,
            &c.expires_at.to_string(),
        ],
    );
    json!({"schemaVersion":"tracebolt.enrollment-activation.v2","managerInstanceId":c.manager_instance_id,"profile":c.profile,"origin":c.origin,"deviceId":intent.device_id,"intentId":intent.intent_id,"certificateHash":cert_hash,"requestId":request,"challenge":c.challenge,"proof":encode(key.sign(&message).as_ref())})
}
