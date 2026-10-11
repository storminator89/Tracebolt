# Selected Windows event content request contract

This is the pure request contract paired with the bounded
[event-message reader](windows-event-content.md). The newer
[runtime](windows-event-content-runtime.md), [manager](windows-event-content-manager.md)
and [wire](windows-event-content-wire.md) implement its integration responsibilities.
Those are source candidates, not published-preview features or native acceptance.
Existing headers and the five-scope Windows Setup remain unchanged.

`internal/windowseventrequest` defines the independent boundary without putting message
content in the durable Windows telemetry frame. Its pure state machine models
pending, claimed, accepted, canceled and expired work. It does not open a source,
write consent, commit a consumed marker or prove that an operator has approved a
request. Those responsibilities belong to the runtime and manager, not this pure package.

## Independent consent and exact selection

The new scope is `windows-selected-application-system-event-content-v1`, with a
new consent schema. It requires a separately generated grant ID, the existing
sender binding, a trusted TLS or HTTP-test profile and an explicit content-risk
acknowledgement. HTTP-test additionally requires the plaintext-content warning;
a header grant or any existing combined consent cannot be promoted to this scope.
Disabled consent retains its identity and acknowledgements. Enabling a new grant
must be a deliberate, separately protected local operation, not a manager toggle.
No account, group, ACL, privilege or service change is included.

The trusted local context separately binds device ID and certificate hash as
well as destination/sender binding and transport. Request values never substitute
for local identity. Consent must be read and authorized again before capture and
before releasing content. Disabled or replaced consent rejects the old request.

Selections are resolved from one validated, already accepted Application/System
header snapshot, using canonical decimal record IDs. All six original native
header fields are retained in the selection, including full-width record IDs.
The request commits the exact header generation, original capture, canonical
snapshot digest, selected identities, device/certificate, content grant and fixed
budgets. No custom XPath, channel name, XML, path or query expression exists.
The native reader independently verifies all six fields before formatting.

A source record can disappear or change between sample and request. Missing or
mismatched records remain unavailable; no nearest-match search or ID-only fallback
is allowed. This first selection model is not retained history or source paging.

## Lifetime, bounded content and consumption

One request expires exactly 15 minutes after its creation. Its source header
snapshot must be younger than 24 hours at creation. Source age and request expiry
never move when work is claimed, accepted, retried, canceled or displayed. The
fixed v1 budgets are 16 selected events, 16 KiB per message, 64 KiB total message
text and a five-second cooperative collection budget. Synchronous Windows calls
are not claimed to have a hard timeout.

A claim transitions only a matching pending identity. Repeated or ambiguous
claims cannot become another capture. Cancellation and expiry are terminal;
backward time samples cannot reopen them. Acceptance validates exact ordered
selected identities, source/result shape and capture time, then records only a
SHA-256 result digest, policy digest and original-expiry receipt. Message text and
OS-formatted error strings never enter the authority record. The result remains
content-bearing only in the separately bounded reader report.

Request metadata includes private event-header fields. A durable adapter must
expire/purge that detail according to the existing metadata privacy envelope while
preserving the non-content monotonic sequence floor. This package does not imply
unlimited retention of header details.

## Required before a usable end-to-end feature

1. A protected, create-only Windows local grant command under the existing
   activated identity, preserving sender state and all old grants. Preview must
   remain nonmutating. The service must not gain a broader token or event rights.
2. Authenticated, purpose-separated manager request/claim/result/status routes.
   Create must resolve selections against the current operator-visible accepted
   header generation and require a deliberate content acknowledgement. Recheck
   current certificate, device, session/origin/CSRF, revocation and local scope.
3. Atomic durable manager claim and endpoint consumption floors committed before
   handing out work and before the one source read. Never initialize over used,
   missing or ambiguous state. The pure `Claim` return is not persistence evidence.
4. Memory-only content caching tied to a committed receipt and the immutable
   original expiry. Exact retained-byte delivery retry may be supported; a lost
   cache or process restart never authorizes recapture or a successful empty
   result. No message text in SQLite, normal telemetry, logs or failure artifacts.
5. Operator-only bounded plain-text rendering in the shared Logs UI, with stale,
   missing, denied, partial and truncated states; cancellation, session/navigation
   loss and expiry must discard content. No HTML execution or external-AI export.
6. Fixture integration, interoperability and separately authorized exact-source
   native acceptance under the installed LocalService identity. Cross-builds and
   simulated readers are not native event-content acceptance.

The [Windows priorities](windows-admin-roadmap.md) tracks the larger goal.
The published preview and its exact tested assets are not modified by this work.
