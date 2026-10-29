# Customer-bound device onboarding: proposed contract

Status: **design and unexposed source candidates only**. There is no customer-bound installer, share link,
PowerShell install command or customer-bound pending enrollment in the current
source or the published Windows preview. This document does not authorize a
host installation, credential creation, trust change or release. For the current
invitation-based workflow and native acceptance limits, see
[installation.md](installation.md), [windows-status.md](windows-status.md) and
[windows-read-admin-setup.md](windows-read-admin-setup.md).

The current source has a shared-administrator customer catalog and a separate
organizational assignment for an **already activated** Windows identity. Its
existing Windows approval list shows invitation claims without a verified
customer. See [customer-records.md](customer-records.md). Guided enrollment v2
uses a single-use invitation secret and its own proof and lifecycle; it has no
customer hierarchy. See [enrollment-v2/http-contract.md](enrollment-v2/http-contract.md).
Neither feature is a reusable customer installer. Source availability does not
establish inclusion in a published package or a successful native test.
The independent `internal/customerclaim`, `internal/customerchallenge`,
`internal/customerpending`, `internal/customeradmission` and
`internal/customerprofiles` packages provide source candidates for public
profiles, bounded challenges, proof verification and pending-only persistence.
The admission candidate connects challenge consumption, verification and pending
storage in fixtures. The source also contains a purpose-bound status proof,
a pending-review lease and an adapter that compares profile and customer
authority. Review uses the expressly observed customer revision; a rename
invalidates that review. A source-only status coordinator checks a pending
claim's retained key, and a separate candidate record describes a reviewed
binding. An isolated transaction fixture persists that binding while holding its
review lease; it cannot authorize issuance. A separate source-only issuance
intent binds that record to a fixed client template, original public key,
issuer and validity window. An isolated v3 owner can commit approval and intent
together while holding review and actor/issuer leases, and the existing issuer
handle can sign and verify the fixed v3 leaf in synthetic tests. Neither is
connected to the manager, delivery, activation or telemetry authority. The
source-only owner can retain the verified DER and exact intent hash in its own
transaction while rechecking current profile and issuer authority. Isolated
read callbacks can hand off only the public projection and the exact retained
certificate after the corresponding possession proofs; callback failure or an
unconfirmed edge is uncertain, and no HTTP delivery has been established. The
same isolated owner can record a one-use activation after a
purpose-bound proof by the original key; that fixture does not authorize
telemetry or establish a running device. A later customer rename does not require the original
operator session to remain open or replace the original identity. The leaf
does not itself encode customer or intent binding; the eventual authoritative
store must retain and check the exact intent and certificate hash together.
The fixed leaf also has no v3-specific X.509 marker: an otherwise identical v2
leaf cannot be distinguished from it by certificate bytes alone. V3 admission,
activation and observation must use their own committed identity binding and
must never adopt a v2 identity or its grants.
The source also contains a minimal public intent projection, local-binding
comparison, client proof construction and fixed-leaf validation. Internal
operator review data is omitted. The projection's opaque intent digest is not
proven by the leaf itself; authenticated distribution, protected original
binding and the current lifecycle are required before using these components.
The unexposed projection v2 includes the public intent routing ID needed by
credential retrieval and activation. The owner checks that ID and the intent
digest against the same committed intent. The existing possession transcript
does not separately sign the public ID, and the certificate authenticates neither
the ID nor the intent digest. A client therefore needs an authenticated,
lifecycle-guarded handoff of the entire projection; a digest or an ID alone is
not proof of approval. Source fixtures exercise this binding but do not supply
the protected client state or authenticated transport.
An unregistered native HTTP adapter
covers challenge and claim only. Its limits are process-local, and the live
lifecycle guard at the response edge remains a prerequisite for its use. The
pending-only claim response includes the exact originally committed `deadlineAt`
as a UTC Unix timestamp in seconds, not a new retry window. The device must
authenticate the manager and protect that original claim/identity and deadline
before relying on it; the response itself neither establishes device activation
nor proves that its bytes reached the client. The source adapter still lacks the
live response-edge lifecycle guard and is not registered for real use. The
handler can reveal whether a public profile is available: generic failure bodies
do not make successful and failed challenges indistinguishable. Public profile
IDs and availability are not credentials. A bounded admission strategy and
response-edge check are required before exposing it. These
packages are not connected to the running manager, Setup or certificate issuance. They require protected
storage, durable used markers, real authority leases, alias-safe lock ordering and
an independently trusted profile distribution path before they can be exposed.
The unregistered `customerhttpservice` candidate composes challenge and claim
admission against the same supplied pool, proof budget and profile/customer
stores. Fixture tests use real temporary SQLite stores and a synthetic TLS
request state; they do not prove a TLS handshake, protected production storage,
revocation exclusion at the response edge or cross-process limits. Its bounded
contexts also cannot forcibly interrupt a driver or callback that ignores
cancellation. No route is registered by this candidate.
The proof verifier alone does not consume a challenge or enforce replay protection.
Status verification likewise grants no status read: a future endpoint must
consume a status-purpose challenge, hold current claim and authority leases, and
check the original claim binding and deadline immediately before responding.
The present coordinator returns only `pending` and cannot account for a future
approval or terminal enrollment state. It is not an HTTP response implementation;
the final response edge must also enforce the original deadline and authority.
Admission and status can share an explicit bounded in-process proof budget;
the source-only `customerproofdomain` owner constructs both paths with one budget.
Production integration must retain and use exactly one owner for both paths.
The existing standalone constructors use separate budgets and are not sufficient
for a combined public ingress. This does not provide cluster-wide limits.
The approval candidate contains no authenticated operator identity: the eventual
transaction must bind the actual session actor or record that a shared
administrator session made the decision, without inventing an individual
identity. It must not accept an actor from the device or treat a boolean as
proof of human review.
The pending and profile fixtures reject schema changes and keep retained limits;
the source-only operator customer lease checks a specific catalog revision while
holding the operator transaction. Its caller still must supply the actual live
session/issuer guard and establish protected, non-aliased databases. None of
these components admits an enrolled device or authorizes a certificate.
The profile store checks public trust material at the original creation and
profile-expiry times without constructing a network client. Its retained `Get`
result is still untrusted reconciliation data, not authority or a downloadable
profile: a digest is not proof of origin. Active leases separately validate
current trust.

## Intended experience

1. A shared administrator selects a customer and obtains its Windows installer,
   or deliberately shares a link to that installer. A future PowerShell option
   may download and run the **same** installer after the stated provenance and
   trust checks. It must not put an enrollment secret in a command or URL.
2. The user verifies the publisher and package provenance, starts the installer
   and deliberately accepts each disclosed local scope and required elevation.
   The relevant checkboxes start unchecked. No existing grant is expanded.
3. The installer establishes manager trust from independently provisioned public
   trust material, generates a device identity with protected private state and
   submits a proof bound to the selected customer. It reports that approval is
   pending. A customer identifier or download link is not a credential.
4. An authenticated shared administrator reviews the exact customer, claim,
   device-key fingerprint and independently compared value. Only an explicit
   approval of that exact pending revision allows credential issuance. Rejection,
   expiry and uncertain responses must be shown honestly.
5. The device proves possession, receives and validates its bound credential,
   activates, and sends its first authenticated fresh observation only within
   its separately accepted local scopes. Until then it remains pending or in its
   accurately reported intermediate state, not online or successfully inventoried.

This removes the separate per-device invitation and bootstrap handoff from the
intended user journey. The reusable installer still needs public configuration:
the exact manager identity and origin, trust and issuer pins, profile and the
immutable customer identifier. It may embed or obtain that configuration only
through an authenticated, independently trusted channel; downloading a trust
root from the same unauthenticated connection does not establish trust. No
invitation secret, bearer credential or private key belongs in an installer,
download link, command, environment, log or chat. Exact packaging and delivery
remain to be designed and tested; do not expose a copyable command until that
path exists and its integrity and failure behavior have been reviewed.

## Proposed security and lifecycle contract

Customers are organizational records, not security tenants: customer selection
does not grant device collection, actions, cross-customer isolation or external
data sharing. A reusable public installer can be copied. Its customer identifier
does not authenticate the person or device and must not authorize enrollment,
data collection or certificate issuance by itself. An operator must compare a
device identity with an independently obtained value; a hostname alone is not
proof of identity.

Customer and installer-profile identifiers and profile availability are public
configuration: a person with a reusable installer may learn whether their own
request can be admitted. Their unpredictable IDs reduce blind guessing but are
not secrets or access controls. Public responses must not disclose customer names,
another device's claim, key, approval or telemetry; a status read requires proof
of possession of that claim's original stored key. Unknown claims, wrong keys and
unavailable or terminated identities need generic errors. Equal error codes and
bodies are not a guarantee of timing-indistinguishability. Receipt, pending,
approval and an actually running agent must be presented as distinct states.

Use a separately versioned customer-claim protocol and durable lifecycle. A
strict, bounded, TLS-only admission endpoint accepts a fresh single-use challenge
and a proof of possession for the device's key. The domain-separated signed
transcript must bind the exact manager identity, origin, customer ID, installer
profile, claim/request identity, key and challenge; it must reject malformed,
ambiguous and altered data. The challenge has a server-defined lifetime and is
consumed once. A retry of the same semantic claim uses a fresh challenge and the
same bound identity; it must not create a second claim or switch customer or key.
Manager restart, challenge loss and request interruption have explicit outcomes.
A successfully verified proof structure does not expire or consume its challenge
by itself. At acceptance and again at the durable commit boundary the caller must
check the current time, the manager-owned challenge and the current claim state;
single-use consumption and claim acceptance must be protected against concurrent
requests and restart. A cached `Verified` value is not an authorization lease.

Unapproved claims are untrusted pending requests, not enrolled devices. Bound
per-peer, global and per-customer rates and retained records, work concurrency,
body sizes and lifetimes so a public reusable installer cannot create an
unbounded queue. Use the actual socket peer, not an untrusted forwarding header.
Public responses must not disclose unrelated claims or private operator data.
The design needs explicit profile expiry/revocation, capacity and cleanup rules
that do not erase used-state evidence or allow replay. An invalid or retired
profile, revoked issuer, expired challenge or unavailable durable store must
fail closed. Do not silently fall back to another manager, customer or HTTP.

The pending record retains its original immutable customer ID, manager/profile
binding, claim and key fingerprint, along with a server-owned revision and
deadline. The stable customer ID and the explicitly managed installer-profile
binding are distinct from the catalog revision: a customer rename alone does
not invalidate a reusable installer or change an existing claim's customer.
The operator reviews the **current** customer name and catalog revision when
approving. A concurrent rename invalidates that particular review and requires a
fresh read and deliberate confirmation; it does not by itself retire the
installer or reject the pending claim. Profile retirement and issuer changes
must instead follow their own explicit lifecycle rules.

The pending record has no certificate, activated identity, collection authority or
telemetry admission. Operator reads and writes use the existing authenticated,
same-origin and CSRF boundaries. Approval requires an initially unchecked,
explicit confirmation of the exact customer, original claim/key and current
revision, plus an independent fingerprint comparison. Session, clock, issuer,
customer and claim authority must still hold at the durable commit. A later
customer rename must not rebind an identity; removal or retirement behavior
requires its own explicit contract.

Approval must durably bind the original customer and key to the approved device
identity **in the same enrollment transaction** that permits issuance. The
issuer, activation and telemetry paths must verify that exact binding and current
credential/revocation state, not a mutable hostname or a later best-effort
assignment. The device's explicit local consent remains independent of the
operator's approval. A loss of state or unknown outcome must never promote a
claim or reconstruct a consumed grant.

A CSR may contain client-supplied sensitive information; do not log raw requests
or treat a CSR as generally safe to publish. A CSR proves possession of its key;
its subject, subject alternative names and
extensions must not be copied into certificate policy or treated as authorized
certificate contents. The issuer must construct an independently constrained
certificate from the approved original identity and validated public key under a
reviewed issuance contract.

## Transaction and compatibility requirements

The customer catalog currently lives in the operator database; the v2 enrollment
lifecycle lives in a separate database. Writing approval first and assigning the
customer afterward is unsafe: an approved v2 claim can already proceed to
issuance. A read of the customer followed by an enrollment commit is also
insufficient if the customer changes between them.

A new coordinator must either make customer-binding authority and approval one
atomic durable transaction, or prove an equivalent cross-database protocol. If
using leases, acquire enrollment then operator authority in a documented stable
order; hold a customer revision/existence lease that excludes conflicting
customer mutations until the enrollment transaction has **actually committed**.
Recheck the live session, claim and time at the commit boundary. A nested read
whose lease ends before the outer commit is not enough. Establish and test lock
ordering, database alias detection, timeouts and rollback on every failure; do
not create a deadlock with existing customer-assignment flows. If a longer-lived
fence is used instead, issuance and activation must remain blocked until durable
reconciliation establishes the exact binding. Neither a browser-only fence nor
an unassigned read proves that an interrupted write failed.

On a lost approval response, the UI must show an uncertain state and use a
read-only reconciliation of the original claim and revision. It must not
automatically repeat the mutation or infer failure from an unchanged pending
read while a delayed commit is possible. Design durable server-side recovery
before claiming this works across browser, manager or process restarts.

Existing v2 endpoints, serialized ledgers, grants and proof bytes remain
unchanged. The new claim cannot be approved through the old unscoped v2 route,
or use an issuance/activation path that accepts an unbound v2 approval. Old
invitations and existing identities are not implicitly converted or granted
additional scopes. Any storage version change needs explicit downgrade and
state-loss behavior; no migration or upgrade of existing Windows installations
is assumed for this fresh-install target.

## Closing Setup while approval is pending: design only

The current fresh Read admin transaction waits for the v2 identity to activate,
then applies and verifies the exact local grants while the owned observation
service is stopped and disabled. Only after those checks does it transition
startup and request Start. The existing pending-service loop and the separate
v2 recovery controller do not implement an unattended customer-profile setup.

For a future installer that can close before approval and finish afterward, one
candidate design separates a bounded pending worker from a local finalizer. The
worker would use the original protected device key and customer-profile binding
only for purpose-bound status polling; it would not collect observations, create
another identity, change grants or control services. The observation service
would remain stopped and disabled while pending.

An optional finalizer would require a **separate, initially unchecked local
acknowledgement** describing its installation and its authority to complete
the exact locally approved scopes and startup transition after manager approval.
It must be a separately identified, narrowly scoped local component, not an
automatic privilege expansion of the observation agent. Exact account, Windows
ACLs, SCM rights, IPC and whether the necessary rights can be limited remain to
be designed and tested. Manager approval alone never provides local consent or
permission to invoke arbitrary commands, grants or service operations.

Before each irreversible step the finalizer would verify the original installation
and executable, service SID and disabled configuration, retained consent and
scope list, current manager/customer/profile/claim/key binding, issuer and
credential authority, deadline and durable phase receipt. It would record a
one-attempt fence, apply only the originally acknowledged scopes under the
existing guarded grant contracts, read them back and durably finish the receipt.
Only then could it transition and start the observation service. An interrupted
or uncertain native mutation must remain visible and must not be automatically
repeated or reset. These components, their receipts, permissions, secure handoff
and native acceptance are not implemented; this proposal grants no host access.
The separate `windowscustomerflow` source candidate only models transitions with
synthetic evidence. A receipt adapter tests create-only and compare-and-write
transitions against an in-memory `windowsstate` backend. It cannot perform native
work or establish that a protected receipt, worker or finalizer exists on a device.
The pending-candidate constructor also checks that the public customer profile,
verified claim and separately supplied local public key have matching bindings,
before using the existing consent model. It cannot establish the provenance or
durable retention of the supplied profile digest, manager deadline or local key;
claim verification alone does not establish a consumed challenge or committed
pending state. Those remain prerequisites for connecting it to Setup.
The adapter requires an external durable write fence and explicit reconciliation
even when a receipt write returns successfully. Reading a receipt after a lost
response does not prove that the write or its final authority checks completed;
the required protected fence owner has not been implemented.
The existing `WindowsCapabilityIdentity` and guided handoff validate the v2
invitation ledger; they cannot establish this new customer identity or be used to
adopt v2 grants. A v3 handoff must bind the original manager, customer, profile,
claim, key, issuer, activated certificate and protected sender state. Grant and
SCM readback must then be checked against that same identity before a real
finalizer can reconcile an uncertain write or authorize startup.

## Verification and delivery gates

Before enabling the design, source tests must cover strict canonical parsing,
tampering of every signed binding, key mismatch, challenge replay/expiry,
duplicate and exact retry behavior, rate/capacity bounds, rejection and expiry,
and the absence of credential or telemetry admission while pending. Test
customer revision races, concurrent approvals, credential/issuer revocation,
session expiry, commit failure and lost responses, process restart, durable
reconciliation and database alias/lock ordering. Preserve v2 fixture bytes and
exercise issuer, activation and observation paths with the new binding. Test
English and German UI loading, empty, expired and uncertain states and confirm
scope and approval controls are initially unchecked.

Delivery additionally requires a trustworthy installer origin, reproducible
artifact-to-source provenance, a deliberate signing and publisher-trust policy,
compatible manager/client versions, usable documented recovery and uninstall,
and a reviewed download/PowerShell path. An unsigned development artifact or a
hash without a trusted distribution channel does not establish publisher trust.
Test the actual fresh workflow on a separately authorized native Windows VM:
download, user consent and UAC, pending approval, independently verified key,
approval, authenticated activation and first fresh non-synthetic observation,
including interrupted installation and safe recovery. Cross-builds, synthetic
fixtures and browser screenshots cannot establish those native results. Release
and deployment require their own authorization and evidence.
