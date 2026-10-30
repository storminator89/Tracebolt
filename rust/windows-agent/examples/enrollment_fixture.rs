// Disposable, invented public interoperability fixture. Never a runtime identity.
use chrono::{TimeZone, Utc};
use rcgen::{CertificateParams, DistinguishedName, KeyPair, PKCS_ED25519};
use ring::signature::Ed25519KeyPair;
use serde_json::json;
use tracebolt_windows_agent::enrollment_wire as wire;
fn main() {
    let now = Utc.with_ymd_and_hms(2026, 10, 29, 12, 0, 0).unwrap();
    let generated = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let key = Ed25519KeyPair::from_pkcs8(&generated.serialize_der()).unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.distinguished_name = DistinguishedName::new();
    let csr = params.serialize_request(&generated).unwrap();
    let context = json!({"managerInstanceId":"manager_11111111111111111111111111111111","profile":"tls","origin":"https://fixture.example:9443","collectionProfile":"windows-inventory-v1","invitationId":"invite_22222222222222222222222222222222","claimId":"claim_33333333333333333333333333333333","challenge":"REREREREREREREREREREREREREREREREREREREREREQ","expiresAt":now.timestamp()+60});
    let c: wire::Context = serde_json::from_value(context.clone()).unwrap();
    let (claim, claim_hash) = wire::claim(
        &c,
        "request_44444444444444444444444444444444",
        csr.der(),
        "VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVU",
        &key,
    )
    .unwrap();
    let status = wire::status(
        &c,
        "status",
        "request_55555555555555555555555555555555",
        &key,
    );
    let intent:wire::Intent=serde_json::from_value(json!({"managerInstanceId":c.manager_instance_id,"profile":"tls","origin":c.origin,"collectionProfile":"windows-inventory-v1","invitationId":c.invitation_id,"claimId":c.claim_id,"requestId":"request_66666666666666666666666666666666","deviceId":"agent_77777777777777777777777777777777","intentId":"intent_88888888888888888888888888888888","keyFingerprint":wire::hash(&wire::spki(&key)),"publicKeyDerBase64":wire::encode(&wire::spki(&key)),"csrHash":wire::hash(csr.der()),"claimHash":claim_hash,"issuerFingerprint":wire::hash(b"fixture issuer"),"serialHex":"99999999999999999999999999999999","templateVersion":"tracebolt.enrollment.client.v2","keyGeneration":1,"notBefore":now.timestamp()-60,"notAfter":now.timestamp()+86400})).unwrap();
    let activation = wire::activation(
        &c,
        &intent,
        "request_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        b"fixture certificate hash input",
        &key,
    );
    println!(
        "{}",
        json!({"now":now,"context":context,"publicKeyDer":wire::encode(&wire::spki(&key)),"claim":claim,"claimHash":claim_hash,"status":status,"intent":intent,"intentDigest":intent.digest(),"activation":activation,"certificateHash":wire::hash(b"fixture certificate hash input")})
    );
}
