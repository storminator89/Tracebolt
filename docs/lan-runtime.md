# Single-environment LAN runtime

This is a code/test pilot for one administrator with two mutually exclusive identity modes: manual public-certificate approval (default) and optional guided enrollment v2. The separate `cmd/lan-manager` binary never starts the development manager or seeds synthetic devices. The Linux sender supports one-shot and bounded foreground reporting; operating-system service installation/reboot acceptance remains pending. The actual runtime tests use temporary loopback listeners, credentials and certificates; they do not provision a real LAN deployment.

## Explicit configuration

Build with `go build -buildvcs=false -o bin/lan-manager ./cmd/lan-manager`. The required startup argument is `--lan-config /absolute/path/lan.json`. Optional guided mode adds `--enrollment-config /absolute/path/enrollment.json`; it requires a dedicated preprovided issuer and an empty legacy registry. See [enrollment runtime configuration](enrollment-v2/runtime-config.md). All referenced filesystem paths are absolute. Config is bounded strict JSON; unknown/duplicate keys, null values, malformed ports and noncanonical origins are rejected. Omitting `profile` selects `tls`; there is no automatic fallback.

Configuration fields:

- `schemaVersion`: `tracebolt.lan-config.v1`.
- `profile`: `tls` or the explicit `http-test` profile.
- `operatorListen` and `agentListen`: distinct literal IP and port pairs, for example separate configured ports8443/8444. They may bind a selected local address or an explicitly chosen container interface.
- `operatorOrigin` and `agentOrigin`: distinct exact public origins, HTTPS for TLS or HTTP for test, with no path, query, credentials, trailing slash or explicit default port. Host/Origin checks remain exact. Docker host-port mappings can differ from internal listener ports; this is transport-level forwarding with unchanged TLS/Host, not a trusted reverse-proxy header contract.
- `tlsCertificateFile`, `tlsPrivateKeyFile`: preprovided server material for TLS. Both configured origin names/IPs must match the leaf SAN before any listener starts. The leaf must meet the exclusive server-auth role and key policy. HTTP test rejects these fields when nonempty.
- `agentClientCAFile`: explicit CA roots for manually approved public client certificates. No ambient/system-root fallback. This remains required for HTTP public-key approvals.
- `operatorAuthFile`: private JSON containing `schemaVersion: tracebolt.operator-auth.v1`, a matching `profile`, and `passwordHash`. Only bounded Argon2id version19 PHC values are accepted: memory64–128MiB, iterations2–4, parallelism1–4, salt16–32bytes and output32bytes. This application does not generate a persistent credential. The optional strict named-only v2 format is [documented separately](named-operator-auth.md); existing v1 configuration remains supported.
- `stateDirectory`: a private runtime-owned directory. A durable profile marker prevents TLS/HTTP state reuse. Existing nonempty unmarked directories are rejected, as are insecure files, symlinks, mismatched stored identities and unsafe SQLite sidecars. The server does not chmod an insecure supplied directory into acceptance.
- `webDirectory`: built frontend assets.
- `insecureHTTPAcknowledged`: must be true for HTTP test, false/omitted for TLS.

Server key and authentication files must be owned by the runtime UID, regular single-link files with no group/world access (normally0400 or0600). Public config/certificate/CA files may be0644 but cannot be group/world writable. Paths and ancestors cannot be symlinks or replaceable by another account. Root-owned sticky temporary ancestors are accepted for isolated tests. Runtime state must be0700 or tighter. The Docker packaging documents UID65532 volume/material ownership separately. Same-UID/root compromise is outside this process boundary.

## Default manual identity mode over TLS

Operator and agent traffic have separate listeners and routers. Operator HTTPS uses normal server verification and session authentication, while agent ingress requires TLS 1.3 mutual authentication against the explicitly configured client CA. In default manual mode there is no certificate issuer or enrollment. Optional guided-v2 has a separately configured fixed-policy issuer; neither mode performs discovery scans, account hierarchy management or OS trust-store changes.

The administrator approves a public leaf certificate and checks its complete DER SHA256 fingerprint through an independent channel. The server assigns an opaque agent ID. Certificate subjects and body role labels are not fleet identity. Registry approval/revocation is checked on every request, including reused TLS connections, and again when committing telemetry. Approval/revocation and bounded latest-observation/replay state persist in SQLite. Certificate renewal requires a new explicit approval; revoked entries are tombstones.

The operator session cookie is Secure/HttpOnly/SameSite=Strict with a `__Host-` name. Origin, CSRF, body limits, resource-bounded password verification and absolute session expiry are enforced. Logout cancels session-owned analysis and linearizes with admitted short state mutations; concurrent logout cannot return before those mutations drain. Long provider calls never hold the mutation lease. Browser TLS warnings must not be bypassed: supply normally trusted TLS material before actual use.

## Explicit HTTP LAN test profile

HTTP is useful for deliberate testing but exposes telemetry, operator passwords and sessions to network observers. An active network attacker can impersonate the server/UI or hijack the operator session. Signed telemetry does not repair these missing protections. The frontend receives authoritative transport metadata and shows a permanent warning, including before login.

This profile has a distinct non-Secure cookie name, matching separate auth-file profile and a separate state directory/profile marker. Use disposable test-only operator and agent material; never reuse production credentials. No HTTPS listener silently downgrades and the TLS agent endpoint never accepts a signed HTTP request as an mTLS substitute.

The test agent request uses a preapproved Ed25519 public certificate directly issued by a configured root. A versioned, length-prefixed signature transcript binds the exact locally configured origin, POST method, fixed path, content type, certificate fingerprint, sequence, canonical observation timestamp and SHA256 of the raw body. The private key is never transmitted. The verifier is read-only; only a successful atomic observation commit consumes the sequence. Invalid body/schema, signature mismatch or failed storage cannot advance replay state. An exact retry returns its original receipt without refreshing freshness, including after a manager restart. Revocation is rechecked by the durable commit.

No actual credentials are generated or entered by this implementation work. `signedhttp.NewSignedRequest` accepts preprovided material, constructs one request, and performs no file access or network calls.

## Telemetry protocol and current limits

`POST /v1/agent/telemetry` accepts at most72KiB of strict JSON: `schemaVersion: tracebolt.agent-telemetry.v1`, a positive bounded monotonic `sequence`, and `observation` containing the bounded support-bundle schema. The application build version is distinct from protocol/schema version. All observation/field timestamps must be at most2minutes old and no more than30seconds ahead. The authenticated registry identity replaces local collector role identity server-side.

Only latest observations are retained. Staleness degrades quality without fabricating a fresh sample, agent process liveness, or healthy host verdict. There is no collector fallback, synthetic fleet, history retention, update/CVE integration or automatic remediation in this LAN runtime yet. Native `lan-agent --foreground` schedules bounded reports; the manager does not initiate collection or establish that an OS service is installed. Existing rules are explicitly synthetic-demo rules and do not generate real LAN incidents. Current AI configuration also still rejects private LAN model origins; trusted private model support needs its separate transport policy.

## Verification

`go test -race ./cmd/lan-manager ./internal/lanconfig ./internal/lanstore ./internal/operatorauth ./internal/lantrust ./internal/signedhttp ./internal/api ./tests/security` exercises protected profile files, auth/session ordering, strict telemetry/replay, and real loopback HTTP/HTTPS listeners. TLS clients use explicit ephemeral CA pools with normal verification, never `InsecureSkipVerify`. The runtime profile test logs in, approves a public certificate, collects a bounded Linux sample, ingests it, retries without refreshing receipt age, revokes the agent and logs out. Tests print no raw sample values, secrets or certificates. Container execution is a separate opt-in gate; building the image or compiling skipped tests is not runtime evidence.


## Optional guided identity mode

The dedicated intermediate's private key is runtime-owned and private; the root
private key stays offline. Configuration validates the exact issuer/root chain,
server trust and both listener SAN names before startup. Guided mode retains at
most25 enrollment records including tombstones and does not combine its identity
store with manual approvals. It rejects a nonempty legacy registry, disables
manual mutations, and persists an exact mode/instance/origin/issuer marker.
Unmarked partial enrollment databases or sidecars require explicit recovery;
there is no silent repair, trust migration or fallback.

A fresh bound-key proof can claim an invitation, inspect pending state, receive
the same committed certificate after a lost response and activate the approved
identity. Only activated exact certificates may commit telemetry; lifecycle,
revocation and sequence/observation state are checked in the same SQLite
transaction. HTTP test keeps its original 2-minute signed timestamp window;
clients discard stale pending observations while preserving the consumed sequence
rather than retimestamping or indefinitely replaying them.

See [HTTP contract](enrollment-v2/http-contract.md),
[durability review](enrollment-v2/durability-security-review.md) and
[issuer custody](enrollment-v2/issuer.md). Pure/service/HTTP fixture checks,
runtime preparation tests and native end-to-end installation acceptance are
separate evidence gates. No fixture key may be reused for deployment.

## Optional named operator authority

Existing v1 shared login and administration remain unchanged. The optional
[protected static v2 named configuration](named-operator-auth.md) adds explicit
actor identity, read/query access and currently inert maintenance grants. It
requires a separately provisioned configuration and manager restart; no migration,
credential generation, live reload or privileged action is automatic.
