# Rust inventory authority: resume prerequisite, not activation

This increment **does not make Rust Read admin functional or equivalent to Go**.
It tightens production credential/profile validation before an activated Rust
enrollment hands material to its unchanged Basic sender. The bounded SCM port
in `rust/windows-agent/src/inventory_services.rs` remains `#[cfg(test)]` only.
No host collection scope, server domain, service, installer or release is enabled.

## Implemented prerequisite

- Every activated resume rechecks the saved bootstrap and original issuance
  snapshot's manager, TLS origin, collection profile, issuer, Windows platform,
  invitation, claim/request, key, CSR and claim hashes. Approval and intent must
  match the original device/key/template/serial/lifetime and certificate hash.
  The original issuance revision may precede activation but cannot be zero or
  exceed the retained revision. Missing, corrupt, terminal or unactivated state
  fails closed, without resetting, adopting or rewriting a ledger.
- The private fixed-leaf verifier follows the actual Go enrollment template:
  bounded single DER leaf/issuer, exact positive 128-bit serial, one device CN,
  original SPKI, digital-signature-only usage, exactly one clientAuth purpose,
  explicit non-CA constraints, allowed unique leaf extensions, matching issuer
  and key identifiers, current validity within the issuer and original lifetime,
  and Ed25519 signature. Absent/empty key identifiers retain Go's byte-equality
  semantics; repeated EKU purposes are not silently deduplicated.
- Current `tracebolt.rust-windows-basic.v1`, consent, configuration binding,
  enrollment/sender schemas, exact retry bytes, sequence floors, wire frames,
  telemetry routes and installer are unchanged. No new flag is accepted to turn
  Basic collection into service inventory. Advanced preprovided identity mode
  remains outside this enrollment-only change.

This verifies retained enrollment evidence; it is **not** live manager
authorization, revocation detection, a native API grant or attestation of the
installed program. The existing authenticated ingress must still check current
leaf/activation/revocation/expiry and replay state in its final transaction.
The verifier relies on the existing authenticated, prevalidated bootstrap issuer;
it does not reimplement Go's general X.509 parser, name-constraint policy or trust
engine, and does not claim global certificate-acceptance equivalence.

## Why service collection is still blocked

The existing Rust Basic program and Go Windows inventory enrollment both use
`windows-inventory-v1`. A locally smaller collector, agent label or compatibility
advertisement cannot restrict that server authority. The merged #179/#148
`windows-basic-metrics-v1` contract is inert, not an active Basic-only domain.
This patch does not fix that server-domain gap or relabel old credentials.

A safe next functional increment must deliver these pieces together:

1. A reviewed narrow service-observation profile, explicitly enabled server-side,
   with its own create-only immutable domain marker and bounded enrollment DB.
   Define crash/readback/disabled-retention behavior; never reuse old Basic,
   inventory, tombstone, credential or counter state.
2. Matching public bootstrap/compatibility, proof, approval, issuance and
   activation binding for that profile. A capability read is never a grant.
   Reject incompatible managers before endpoint key/state or installer mutation.
3. One exact TLS telemetry route and strict service-only frame; server-side
   profile/platform/leaf checks at ingress **and** final retaining transaction.
   Deny all software/process/network/event/action/update/MSI routes, including
   direct store calls and profile/capability spoofing, without freshness or replay
   side effects. Implement the #148 Basic domain and its negative matrix rather
   than treating existing inventory credentials as Basic-restricted.
4. A fresh Rust configuration/enrollment/sender schema with unchecked, explicit
   local disclosure of caller-visible Win32 names/display names/status/PID.
   Bind the exact profile, scopes, manager/origins, original identity, certificate
   and consent to a new create-only ledger. The current Basic acknowledgment
   grants no service reads. Additional scopes each require explicit admission;
   a future label/capability cannot inherit them.
5. Integrate the bounded collector only behind those gates; enforce the aggregate
   frame budget, original capture time and durable exact retries. Never promote
   missing scope/provider access into empty complete inventory.
6. Show server-bound support, local consent and actual observation separately in
   the UI. Independently review final routing, transactions and consent/ledger
   bindings. Build same-source artifacts and obtain the separately authorized
   Windows native/installed-service/shared-manager acceptance before publication.

Portable tests here use invented state, disposable local keys, loopback TLS and
public fixtures. `credential-fixture.json` contains only a fixed public leaf,
public issuer, intent and clock emitted by the actual Go issuer; Rust and Go
both verify it. None of this establishes Windows compilation/native acceptance,
an active service profile, a compatible release, or Go parity.
