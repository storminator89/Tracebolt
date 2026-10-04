# LAN agent trust foundation

Status: isolated implementation and disposable loopback verification. This document is a trust contract, **not authorization to expose a listener or provision credentials**. The published development/AI/loopback-transport snapshot remains separate. There is no online CA, enrollment token, CSR issuer, automatic installation, system trust modification, or remote-command capability here.

`internal/lantrust` establishes identity for a separate agent mTLS telemetry surface. The backend integration owns listener configuration, operator authentication, protected approval/revocation routes, exact origins, body limits, durable SQLite storage, and telemetry validation. `lantrust` opens no listener and performs no filesystem reads or writes.

## Trust and identity

1. An administrator supplies explicit public CA certificates, an already provisioned manager TLS certificate/private key, and an already provisioned client certificate/private key on each endpoint. Provisioning is a separate approval-gated operation. Do not generate or import real credentials merely to run these tests.
2. The agent verifies the manager's CA chain and DNS/IP subject alternative name. `ClientTLSConfig` requires the exact server name and an explicit private root pool. System roots are never a fallback. The HTTP transport must use an exact HTTPS origin, disable environment proxies, and refuse redirects. These HTTP transport constraints belong to the integration.
3. The manager requires TLS 1.3 and `tls.RequireAndVerifyClientCert` against only the explicit agent CA pool. Session tickets are disabled; `VerifyConnection` additionally checks the client certificate's current validity, role and key strength. A CA-valid certificate is not automatically an approved endpoint.
4. An authenticated operator verifies the physical/logical endpoint and the full leaf SHA-256 fingerprint out of band, then manually approves its public certificate chain with a display label.
5. The registry generates an opaque `agent_` ID using 128 random bits. Its mapping is SHA-256 over the complete DER leaf certificate. It never uses Subject, CN, SAN, IP address, HTTP headers, a hostname or a body-supplied device ID as endpoint identity.
6. Every HTTP request re-verifies the current chain/validity and consults the current approval/revocation map. Authentication succeeds only for the exact, active approved leaf. This applies to reused keepalive connections as well as new TLS handshakes.

Approvals accept one leaf followed by optional intermediate/CA certificates. Public PEM is capped at 64 KiB and eight certificates, with no private-key blocks, other PEM types, headers, leading/trailing garbage, duplicate certificates or malformed block ambiguity. A private key must never be submitted to the approval API.

Leaves must be non-CA certificates with digital-signature usage and exactly one explicit role EKU: ClientAuth for an endpoint, ServerAuth for a manager. Missing/Any/combined role EKUs are rejected. Accepted public keys are RSA with at least 2048 bits and an odd exponent of at least 65537, ECDSA P-256/P-384/P-521, or Ed25519. SHA-1/MD5 signatures are rejected. CA certificates must have valid CA constraints, certificate-signing usage, current validity and the same key/signature strength checks. Expired and not-yet-valid leaves and chains fail closed. Manager certificates must include DNS/IP SANs, and their supplied private key must match the leaf public key. The client verifies the actual manager chain and SAN during TLS.

The configured CA is the application's trust boundary. This library does not fetch CRLs/OCSP or change global trust. A compromised approved endpoint key can impersonate that endpoint until its approval is revoked; private key custody remains essential. CA compromise requires replacing the explicit CA configuration and re-reviewing approvals.

## Exported integration contract

```go
// Implemented by the backend's durable public-metadata store.
type Store interface {
    Load(context.Context) ([]lantrust.Agent, error)
    Save(context.Context, lantrust.Agent) error
}

registry, err := lantrust.NewRegistry(ctx, agentCAPEM, approvalStore)
agentTLS, err := registry.TLSConfig(preprovidedServerKeyPair)
// Use agentTLS only on the dedicated agent listener. No operator routes here.

approved, err := registry.Approve(ctx, publicLeafAndChainPEM, displayLabel)
err = registry.Revoke(ctx, approved.ID)
publicApprovals := registry.List()
```

`Agent` contains only `ID`, `Label`, `FingerprintSHA256`, `ApprovedAt`, `NotBefore`, `ExpiresAt` and `RevokedAt`. Zero `RevokedAt` means active. A list contains both active records and revocation tombstones. Returned values/slices are snapshots and cannot mutate the registry. No descriptor contains a certificate, private key, bearer token, operator session or TLS config. Error responses are generic and do not reproduce submitted material or storage errors.

A handler should be wrapped with `registry.Middleware`. Inside the handler, take identity solely from `lantrust.FromContext(r.Context())`. Decode bounded strict JSON, validate the telemetry contract and monotonic sequence, and store only against that ID. Reject an incompatible claimed device ID or ignore the claim; never use it to select another device. Certificate validation does not make telemetry contents trustworthy.

```go
agentMux.Handle("POST /api/agent/telemetry", registry.Middleware(
    http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        agent, ok := lantrust.FromContext(r.Context())
        if !ok { http.Error(w, "unauthorized", 401); return }
        // Strictly decode/validate the bounded observation.
        // Store only for agent.ID, never for an observation's claimed ID.
    }),
))
```

Keep the agent listener separate from the operator UI/API. An approved endpoint certificate must not provide operator privileges, approval/revocation access, case mutation, AI-provider credentials or visibility into another device. The LAN profile must disable the development session and unauthenticated development telemetry routes; the loopback development profile must retain its existing boundaries. Do not share cookies, credentials or listener handlers between these surfaces.

## Persistence and revocation semantics

- Use a single `Registry` and a single owning manager process per durable Store. Direct external database edits, concurrent registry instances and multiple manager writers are unsupported. `NewMemoryStore` is intentionally disposable and is not an acceptable LAN-pilot persistence strategy.
- `Load` must return every row without truncation. Loading missing, unreadable or malformed configured storage must fail, not silently reset approvals. The registry rejects duplicate IDs/fingerprints, malformed opaque IDs, labels, timestamps and fingerprints.
- `Save` must atomically insert/update exactly one public descriptor and return success only after durable commit. Enforce a unique ID and unique fingerprint; prevent fingerprint/ID reassignment or changes to immutable approval metadata. Revocation tombstones cannot be deleted or changed back to active. The registry mutex serializes save and identity-map changes.
- An approval becomes active in memory only after `Save` succeeds. A revocation is acknowledged only after `Save` succeeds. Any save error makes the live registry unavailable and rejects all subsequent agent telemetry with HTTP 503, because the commit outcome may be uncertain.
- After a storage failure, keep the listener unavailable while reconciling the durable state. In particular, ensure a failed revocation's tombstone is durably present before deliberately reloading/recovering the manager. A restart alone is not a successful revocation. Do not automatically restart into a potentially stale approval set.
- A request whose authentication completed before revocation can finish. Every authentication decision after successful revocation observes the revoked state, including on an already-open connection. This library does not cancel requests already executing. Stronger final-write ordering would need a separate backend transaction/lock around ingestion and revocation.
- There are at most 1,000 lifetime approval records, including tombstones. This is a bounded early-pilot limit, not an indefinite production lifecycle implementation. Hitting the limit fails closed; do not discard tombstones as a workaround.

The database is public-credential metadata but **security-critical configuration**: write access can alter which endpoints are approved. Keep its directory private to the manager account (POSIX 0700), database and WAL/SHM files private (0600), and exclude them from source, public artifacts and ordinary telemetry. Reject symlink/nonregular paths and unsafe parent directories; use a dedicated private directory and one owning process. On Windows, use a directory/file ACL restricted to that account and administrators; POSIX mode bits alone do not establish Windows access control. Backend storage tests must exercise these path and permission expectations with temporary fixtures.

The library deliberately has no key-path API. The integration must treat server/agent private-key files as secrets: restrictive account-only permissions/ACLs, protected parent directories, no symlinks or nonregular files, no logging, uploads, exports or public descriptors. Public CA and certificate files need integrity protection even though their contents are public. Loading public CA material here does not add it to the OS trust store.

## Renewal, replacement and revocation

The first version does not renew or issue certificates. A new certificate, including a re-signature using the same key or the same Subject/SAN, has a different leaf fingerprint and requires a fresh manual approval. The old fingerprint remains a tombstone once revoked and cannot be reapproved. The new approval receives a new opaque agent ID. Historical device merging or stable-ID certificate rotation is explicitly deferred rather than inferred from an untrusted hostname.

For a planned replacement:

1. Provision the new endpoint key/certificate through an approved external process; keep the private key on the endpoint. Check the manager's expected DNS/IP SAN and trust configuration.
2. Present only the new public leaf/chain, and verify its full fingerprint with the operator out of band.
3. Approve that fingerprint under an explicit display label. Record the newly returned server-assigned ID on the endpoint through the authorized installation/configuration workflow.
4. Revoke the previous approval and verify that a new request on its existing connection is denied. A short overlap must be a conscious operator choice; avoid it when a key may be compromised.
5. Confirm persistence across a controlled restart before accepting a pilot deployment. Do not relabel a different certificate into the old ID or silently resurrect its approval.

For suspected compromise, revoke first. The endpoint must remain denied even if it reconnects, changes its hostname or submits another device ID. Compromised-key recovery, endpoint installation and CA replacement need their own reviewed operational procedures.

## Verification

```sh
go test -race ./internal/lantrust
go test -cover ./internal/lantrust
go vet ./internal/lantrust
```

Tests generate fresh, disposable keys/certificates in memory and bind only `httptest` loopback TLS listeners. They do not access real user credentials, create persistent credentials, modify system trust or open a LAN listener. Integration filesystem fixtures must live under test temporary directories.

Coverage includes approved/unapproved certificates; wrong CA, expired/future validity, wrong/missing/Any/dual EKU, weak keys; empty/malformed/private-key PEM and ambiguous blocks; opaque identity and claimed-ID/header spoofing; mandatory client authentication; TLS 1.2 rejection; normal manager hostname/root verification; wrong or typed-nil server keys; revocation and expiry on a demonstrably reused connection; concurrent auth/revoke under the race detector; persistence reload and tombstones; save-failure fail-closed behavior; malformed/duplicate persisted records; public-only descriptors; and immutable returned snapshots.

These tests are necessary evidence for the library, not independent deployment approval, native endpoint installation acceptance or production security assurance. Before any real pilot, require the backend/operator integration tests, temporary-file permission tests, independent boundary review, audit/retention decisions, native packaging and installation acceptance, and explicit deployment/provisioning approval.

References: Go [`crypto/tls.Config`](https://pkg.go.dev/crypto/tls#Config) and [`crypto/x509.Certificate.Verify`](https://pkg.go.dev/crypto/x509#Certificate.Verify). Normal TLS verification is preserved rather than replaced by a fingerprint-only custom handshake.
