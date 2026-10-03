# Enrollment agent ingress

This internal adapter is exclusive to the configured enrollment-v2 runtime. It
keeps `/v1/agent/telemetry` and the existing bounded basic v1 telemetry frame;
enrollment version does not change that agent wire contract.

`New(store, issuerDER, agentOrigin)` requires the concrete durable enrollment
store, its exact pinned dedicated issuer, a profile-matching canonical agent
origin, and a retained-record limit of at most 25. The caller must validate and
securely provision the issuer before construction. No keys, credentials, trust
configuration, listener, or deployment are created here. Manager integration
must exclude all legacy manual approvals, including revoked tombstones, and
must disable manual mutations when selecting this mode.

The TLS profile uses `TLSConfig(server)` with ordinary Go TLS1.3 client-chain
verification under only that dedicated issuer. The offline root is not an
agent trust anchor. An empty ephemeral registry supplies existing certificate
policy checks solely while constructing TLS configuration; it never supplies
approval authority. Normal server SAN verification remains the client's duty.

Each request checks the exact authority, path, framing and bounded headers/body.
It rejects browser, bearer, forwarded-authority and encoding inputs. Two
nonblocking in-flight slots bound admission before any durable-store lookup;
additional requests receive 429. The listener still needs ordinary read,
header, write and idle timeouts configured by its owner.

TLS authentication and explicit plaintext-only Ed25519 signed HTTP are separate
possession proofs. Every authorization lookup reads committed activated state,
exact certificate DER/hash and current expiry from SQLite. The same store's
`SaveObservation` transaction finally rechecks identity, revocation, expiry and
replay before committing telemetry. Connections and request-local snapshots
never cache an authorization decision. Storage errors produce 503, not a
revocation claim or a legacy fallback.

TLS can retry an exact previously committed frame after its ordinary sample-age
window, retaining its first receipt and collection times. The unchanged signed
HTTP-test v1 protocol also requires a fresh signed timestamp equal to the frame's
original generation time, so it cannot submit such an old exact retry after its
two-minute window. HTTP-test clients must follow their explicit pending-frame
policy, retaining consumed sequence floors and collecting a genuinely new
observation rather than refreshing timestamps on an old sample. Plaintext still
provides no confidentiality or manager authenticity.

Tests use disposable ordinary generated keys and real loopback TLS/HTTP only.
They do not provision actual credentials, expose a LAN listener, install trust,
or establish production signer custody or deployment readiness.
