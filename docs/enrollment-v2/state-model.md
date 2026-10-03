# Enrollment model implementation scope

> Historical design/model baseline. Subsequent isolated implementation now includes the durable store, fixed issuer, application service and optional HTTP handler. See [durable store](durable-store.md), [issuer](issuer.md) and [HTTP integration contract](http-contract.md) for current boundaries. The original statements below describe their earlier stage; they are not native installation or deployment acceptance. Inspection JSON still cannot restore authority; RestoreTrustedLedger is an explicitly trusted local-storage boundary.


This page documents the isolated lifecycle and cryptographic-policy model. The current checkpoint also has separately reviewed durable store/service, opt-in manager wiring, Linux native enrollment and UI integration; see [runtime configuration](runtime-config.md), [durable store](durable-store.md) and [native client](native-client.md). Those layers have distinct verification gates. OS installers, service lifecycle and credential renewal remain unimplemented.

## Packages

- `internal/enrollmentcrypto` validates strict claim input, PKCS#10 and separate challenge-bound key-possession proofs. It validates an externally supplied certificate against a complete recorded intent, and requires a separate fresh private-key proof for activation. Trusted challenge/intent context must come from server-side records, never untrusted request fields.
- `internal/enrollmentstate` models created, pending, approved, issuance-intent, issued, activated and terminal states. It enforces one claim, exact semantic retries, bounded quotas, fingerprint confirmation, immutable signing metadata, CAS revisions, expiry and cancellation ordering. Snapshots are inspection-only immutable copies; no restore API exists.
- `internal/keyvalidation` supplies defensive canonical, nonidentity, prime-order Ed25519 public-key validation through the pinned upstream-derived curve package. This is checked before keys enter enrollment proof or intent boundaries; it is not a new signing algorithm.

No production file/network access, key generation, signer, certificate delivery, secret-bearing download, installer, service, renewal, recovery or state migration is provided by these packages. The test fixtures generate disposable keys and certificates only in memory.

## Important state semantics

Invitation expiry controls the initial unclaimed grant. A successful claim gets a separate bounded pending-approval deadline. An exact semantic retry with a fresh challenge may retrieve that same pending outcome within its deadline; it cannot create another grant, switch keys or resurrect a terminal record. Comparison values include the manager, invitation, server-assigned claim and public-key fingerprint.

Issuance intent fixes all context, identity, public key, issuer fingerprint, serial, template version and validity before a signing result can be accepted. The current model retains only the certificate hash and intent, not certificate DER or a delivery ledger. Activation validates possession for that exact issued identity and complete intent; it is not proof of a running service, connection or successful telemetry collection.

The engine is bounded and process-local. Copying an engine handle shares the same protected state; diagnostic formatting and JSON redact internal contents. Cancellation observed before the locked commit leaves state unchanged. After a commit, cancellation cannot undo it. Terminal records are retained and capacity failures are explicit, without silent tombstone eviction.

## Mandatory next integration boundary

A production adapter must atomically persist the intent, certificate DER, lifecycle revision, approval/revocation decision and delivery/replay metadata before returning a credential. Calling the in-memory engine and then writing a separate database is not a safe adapter. Durable transactions, restart reconciliation, interrupted signing/delivery, backup rollback and credential renewal require their own implementation and adversarial tests.

The current listener and credential boundaries stay unchanged. No invitation can act as an operator session or telemetry credential, no certificate alone can stand in for private-key possession, and no body-controlled identity or trust flag may create a validated proof.

## Checks and remaining gates

Focused race, concurrency, expiry, strict JSON and fuzz tests exercise the model with synthetic ephemeral material. Independent review has already identified a key-acceptance edge, prompting defensive subgroup validation rather than treating generic signature verification as sufficient proof of possession. Final review and full aggregate evidence are required before this phase is marked accepted. Those checks do not replace future real installer/service lifecycle acceptance or authorize actual provisioning and deployment.
