# Optional guided-enrollment runtime configuration

This is an opt-in Linux code/test profile, not permission to provision or deploy
real credentials. Default manual-v1 startup is unchanged. Guided-v2 is mutually
exclusive with it; there is no automatic adoption or identity migration.

## Startup

The additional argument is `--enrollment-config /absolute/path/enrollment.json`
on `cmd/lan-manager`, together with its required `--lan-config` argument.
Preparing real issuer material, importing private keys, granting device access,
exposing listeners or installing services requires its own authorized workflow.
The implementation never generates a CA automatically or changes global trust.

The enrollment file is a strict bounded flat JSON object:

```json
{
  "schemaVersion": "tracebolt.enrollment-config.v2",
  "profile": "tls",
  "instanceId": "manager_<32-lowercase-hex-digits>",
  "issuerCertificateFile": "/run/tracebolt/client-issuer.pem",
  "issuerPrivateKeyFile": "/run/tracebolt/client-issuer.key",
  "issuerRootFile": "/run/tracebolt/offline-root-public.pem",
  "expectedIssuerFingerprint": "<64-lowercase-hex-SHA256-of-issuer-DER>",
  "bootstrapServerCAFile": "/run/tracebolt/operator-server-ca.pem"
}
```

Placeholders intentionally fail validation. `profile` must exactly match the LAN
profile. HTTP test requires `bootstrapServerCAFile` to be empty and keeps its
separate disposable identity/state. Both exact origins come from the existing
LAN config, never from a client or forwarded header.

The LAN config's `agentClientCAFile` must contain exactly this dedicated issuing
intermediate, not the offline root or a combined/sibling issuer pool. The agent
listener performs ordinary TLS 1.3 client verification under that dedicated
anchor. For HTTP test, the existing leaf-only signed protocol remains unchanged;
its public certificate authorizer resolves only activated durable enrollment
records. A public certificate alone is not a possession proof.

The online intermediate must be a distinct Ed25519 client-auth-only CA with
path length zero, directly chained to the explicitly supplied public root. The
root private key is not accepted or loaded. The intermediate signing key must be
PKCS#8, runtime-owned, private 0400/0600, regular and single-linked. Config/public
certificates cannot be replaceable by another account. All paths are absolute;
symlinks, ambiguous PEM content, incompatible roles and expired material fail
closed. Bootstrap server trust uses the same strong-key/time policy as the native
client plus ordinary chain and SAN validation for both configured listener names.

## Durable separation

Before creating the enrollment database, startup requires the legacy registry to
be empty, including tombstones. A private `identity-mode-v2.json` marker binds the
profile, instance ID, operator and agent origins, collection profile, issuer,
issuer root and bootstrap server trust. An existing marker must match exactly.
An existing enrollment database or any WAL/SHM/journal sidecar without that marker
is rejected unchanged. Once v2 state exists, manual startup is rejected. There is
no reverse migration or sequence reset path.

The v2 database retains at most 25 records including terminal states. Approval,
issuance intent/DER, delivery and observation replay are durable and bounded.
The root/private intermediate distinction does not imply hardware key isolation:
a compromised runtime UID can use the online issuer. Filesystem protection is
not encryption. Backup rollback and issuer replacement require a separately
reviewed recovery procedure; an old structurally valid full backup cannot be
detected automatically.

## Current evidence and remaining gates

Generated-key tests cover protected loading, matching mode restart, manual-mode
refusal, legacy tombstone refusal and unmarked partial-file preservation. The
independent config suite covers both server SANs, explicit anchor/key/time policy,
strict public/private material, exact binding, concurrent marker creation and
torn-marker failure. HTTP and ingress tests use real ephemeral loopback TLS or the
explicit HTTP test profile, without browser warning bypass or system trust edits.

Native bootstrap client, combined process acceptance, UI acceptance and service
installation/reboot are separate gates. Do not claim an installed background
service from successful foreground reporting or a manager preparation test.
