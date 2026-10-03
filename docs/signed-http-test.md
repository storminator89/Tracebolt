# Explicit insecure HTTP LAN test protocol

This is an opt-in test surface. HTTP sends operator credentials, sessions and telemetry in plaintext and does not authenticate the manager/UI to an endpoint. A network attacker can read, replace or suppress server responses and browser UI. Compromise of the plaintext operator session can also undermine the approval registry. Agent request signatures do **not** remedy those risks. Do not use this profile for production, sensitive observations, a shared/untrusted network, or Internet exposure.

`internal/signedhttp` is intentionally separate from `internal/lantrust`'s mTLS request authentication. Its verifier refuses requests containing TLS state. The HTTPS agent surface must continue requiring verified mTLS and must never call this verifier as a fallback. No automatic scheme change, retry-over-HTTP or certificate-verification bypass exists. Backend configuration must explicitly opt into the insecure profile and maintain separate state/listeners from the HTTPS profile.

This implementation opens no listener, sends no request, generates no credentials and reads no private-key files. Verification uses only ephemeral credentials, temporary database fixtures and loopback test listeners. Real provisioning, installation and network exposure require separate authorization and review.

## Identity and allowed key

An operator must already have manually approved a public ClientAuth certificate through the registry. The HTTP test protocol permits Ed25519 leaf keys only. There is no negotiation or attacker-selected algorithm field. The leaf certificate must be currently valid, chain to the explicit configured CA, have the required exclusive ClientAuth role, and map to an active approved SHA-256 fingerprint. Subject, CN, SAN, headers and observation IDs never select the agent ID.

The `X-Tracebolt-Certificate` header carries only the single DER leaf, encoded with canonical unpadded standard Base64. Its encoded length is at most 4 KiB, within the manager's 8 KiB complete-header budget. This initial profile does not carry intermediates: the leaf's issuing CA must be among the explicitly configured trust anchors. The complete approval still binds the full DER leaf, not merely the public key. Renewing or re-signing a certificate requires fresh manual approval and a new opaque agent ID.

`Registry.AuthorizePublicCertificate` validates the chain and active approval only. It is not proof of private-key possession, and its result is not request authentication without a separately verified signature. It cannot substitute for `Registry.Authenticate` on HTTPS.

## Fixed wire contract

- Method and path: `POST /v1/agent/telemetry`
- Audience: one exact locally configured canonical `http://host[:port]` origin. No path, query, fragment, userinfo, alternate host case, ambiguous port or default `:80` spelling
- Media type: exactly `application/json`
- Body: original raw bytes, nonempty, at most 72 KiB (the existing frame ceiling; embedded support bundle remains at most 64 KiB)
- Framing: known positive Content-Length matching the body; no chunking, trailers or content encoding
- Browser/session/proxy identity: no Cookie, Authorization/Proxy-Authorization, Origin, Sec-Fetch or forwarded headers
- Each signature header occurs exactly once, without comma merging or case-folded duplicates

Headers:

| Header | Value |
| --- | --- |
| `X-Tracebolt-Certificate` | Unpadded standard Base64 of the public DER leaf |
| `X-Tracebolt-Sequence` | Canonical decimal integer from 1 through 2^63−1, without sign/leading zeros/whitespace |
| `X-Tracebolt-Signed-At` | Canonical UTC RFC3339Nano ending in `Z`, matching the frame's GeneratedAt exactly |
| `X-Tracebolt-Signature` | Canonical unpadded standard Base64 of the 64-byte Ed25519 signature |

The signed timestamp must be at most two minutes old and at most 30 seconds in the future. Its nanosecond precision is retained. The verifier checks the window and current certificate approval both before and after reading the bounded body, so a slow body cannot extend a signature's validity or bypass an intervening revocation.

## Signed transcript

The Ed25519 message is the concatenation of the following nine UTF-8 strings. Each field is prefixed with its length as a four-byte unsigned big-endian integer. There are no optional fields, separators or normalization beyond the rules above.

1. `Tracebolt insecure HTTP agent telemetry; Ed25519; v1`
2. The locally configured origin
3. `POST`
4. `/v1/agent/telemetry`
5. `application/json`
6. Lowercase hexadecimal SHA-256 of the complete DER leaf
7. Canonical sequence header
8. Canonical signed-at header
9. Lowercase hexadecimal SHA-256 of the original body bytes

The exact configured audience is used, never a forwarded or request-derived audience. Changing body whitespace also changes the signed digest. Replacing a leaf with a renewed certificate that uses the same key changes the signed fingerprint. A signature for another profile/version/origin/path/method cannot be repurposed here.

This is a narrow experimental protocol with an allowlisted algorithm and explicit domain separation. It is not TLS or a substitute for a reviewed standard secure transport.

## Required backend commit contract

```go
verifier, err := signedhttp.New(signedhttp.Config{
    Origin: configuredInsecureAgentOrigin,
    Registry: registry,
})
verified, err := verifier.Verify(r)
```

`Verified` contains a detached `Agent`, original `Body`, `Sequence` and `SignedAt`. It means the signature and current in-memory approval passed. It is not a receipt and does not mean an observation or replay sequence was committed.

The handler must:

1. Strictly validate `verified.Body` with the existing frame/schema rules.
2. Require `verified.Sequence == frame.Sequence` and `verified.SignedAt.Equal(frame.Observation.GeneratedAt)`.
3. Use only `verified.Agent.ID` as identity, irrespective of body/header names.
4. Call the existing atomic `lanstore.SaveObservation` transaction, which rechecks durable approval/revocation and commits observation, sequence, digest and observation timestamps together.
5. Treat an identical sequence/body digest as the original receipt without refreshing its ReceivedAt. Reject lower sequences and same-sequence conflicting bodies, including after restart.
6. Keep revoked tombstones and replay state durable. A previously verified request must still fail its transaction if revocation has committed in the meantime. Report storage failure instead of success.

There is deliberately no separate durable "claim" before observation commit: it could burn a sequence on later validation/storage failure. Calling `Verify` twice by itself does not establish replay protection; the atomic durable transaction is mandatory. Separate insecure-profile storage prevents a test request/approval from becoming a credential for another deployment profile.

A public signing helper is available for disposable tests or a future explicitly selected native sender:

```go
request, err := signedhttp.NewSignedRequest(ctx, origin, preprovidedKeyPair,
    frame.Sequence, frame.Observation.GeneratedAt, rawFrame)
```

The helper creates no credential and sends nothing. It copies the body before signing, verifies the supplied Ed25519 private key matches the leaf public key and prepares the fixed headers. A sender must use an explicit HTTP transport with proxies disabled and redirects refused. It must not interpret an unsigned HTTP response as cryptographic proof of manager identity or durable acceptance.

## Verification evidence and remaining limits

Tests cover valid and unapproved keys; foreign CAs; expired/revoked approvals; signatures changed by body, sequence, time, origin, domain or same-key certificate substitution; duplicate headers and noncanonical Base64; exact path/Host/media/framing/browser boundaries; refusal of TLS fallback; revocation during body reads; concurrent verify/revoke; actual loopback HTTP; and durable replay/revocation across temporary-database restarts without freshness refresh.

Run `go test -race ./internal/signedhttp ./internal/lantrust ./internal/lanstore` and `go vet ./internal/signedhttp ./internal/lantrust`. Independent API tests must additionally verify the required frame/signature equality checks, profile separation, operator warning/session behavior and the absence of any HTTP fallback on HTTPS ingress.
