# Selected Windows event-message wire contract

`internal/windowseventwire` is the portable, synthetic-tested wire/DTO boundary
for the selected-event content integration candidate. It is not a host grant,
listener, source reader, persistent ledger, or native acceptance result. The
separate [request authority](windows-event-content-request.md) and
[message reader](windows-event-content.md) retain their existing contracts.
Existing event-header and five-scope grants authorize no message content.

## Authenticated routes and purpose

All endpoint routes are bounded POST requests under
`/v3/agent/windows-event-content/`: `capability`, `peek`, `claim`, `result`, and
`status`. Production uses the existing mutually authenticated HTTPS connection.
The explicit HTTP-test profile uses a separate Ed25519 proof domain and the
`X-Tracebolt-Windows-Event-Content-{Certificate,Sequence,Signed-At,Signature}`
headers. Proofs bind the canonical origin, POST method, exact operation path,
content type, certificate fingerprint, canonical decimal sequence, original
proof timestamp, and SHA-256 digest of the exact body bytes. Linux journal proofs
cannot be translated into this scope, even by renaming all headers and paths.

HTTP-test is plaintext. These request signatures provide neither confidentiality
nor server authentication. **Manager responses are not signed.** An endpoint must
validate all returned descriptions/grants against its independent protected local
identity, consent, original request bindings, and consume-once state. The separate
plaintext-content acknowledgement remains mandatory. This verifier cannot be an
authentication fallback on the production TLS surface.

Shape validation rejects query strings, alternate URL encodings, fragments,
cookies, browser-origin/fetch headers, forwarded or proxy-authorization metadata,
compression, chunked framing, trailers, duplicate proof headers, inconsistent
lengths, and out-of-purpose Tracebolt headers. Header size is bounded to 8 KiB;
the certificate header to 4 KiB. Proof age is at most two minutes, with at most
30 seconds of future clock skew. Time and current certificate authorization are
checked again after reading the body.

Verification is intentionally stateless: it establishes possession, framing and
proof freshness, not replay consumption. The manager still must commit capability
sequence/exact-retry state and request transitions atomically, rechecking current
identity, certificate, revocation, profile and grant binding. A valid proof may be
retried; it cannot authorize another read or refresh the captured data's age.

## Canonical envelopes and browser-safe identities

Private protocol decoding requires canonical UTF-8 JSON byte-for-byte. Unknown,
duplicate, missing and case-folded keys, noncanonical numbers or timestamps,
trailing bytes/objects, and inappropriate nulls are rejected. Errors are fixed
codes and never print supplied body values. `peek` is exactly `{}`.

All uint64 request/capability sequences are canonical decimal JSON strings.
Native `windowsevents.Event.RecordID` is converted to `EventDTO.recordId`, also a
canonical decimal string, before any transport/browser serialization. The other
five original fields are `eventId`, `level`, `provider`, `timestamp` and `channel`.
No record ID is rounded through a JavaScript number. UTC RFC3339Nano timestamps
retain their full original 100-nanosecond event precision. Browser code must not
rebuild request identities from a millisecond-normalized `Date` value.

`DescriptionDTO`, `RequestDTO`, `ReportDTO`, `EventResultDTO`, `GrantDTO` and
`RecordDTO` provide explicit browser shapes. `DescriptionForBrowser`,
`ReportForBrowser` and `RecordForBrowser` validate before converting; DTO `Native`
methods validate the inverse. Public `Grant`, `Result` and `Status` envelopes
also have custom JSON codecs, so ordinary JSON marshaling cannot accidentally
emit their nested native record IDs as numbers. Use `EncodeDescription` rather
than directly serializing the foundation's native `Description`.

- `Capability` contains schema, authenticated device/certificate, its independent
  monotonic sequence, consent metadata, canonical policy digest and original
  `collectedAt`. Disabled consent is reportable and retains its grant identity.
  A report grants no rights. `CapabilityFresh` requires
  `collectedAt <= now < collectedAt + 5 minutes` for creation and disclosure;
  receipt/retry time is irrelevant. A newer valid capability can renew that
  metadata lease without changing an existing request, selection or expiry.
  The receiver checks device, certificate and profile against the authenticated
  activated endpoint and pins the exact signed consent/policy metadata. The opaque
  sender binding is an endpoint attestation: the manager cannot independently
  prove a local protected grant. The endpoint rereads its protected identity and
  consent before claim, capture and result release; the report is never a host
  permission grant.
- `Claim` binds exact request ID, sequence and query digest plus policy digest,
  device, certificate, content grant and immutable original `expiresAt`.
- `Grant` contains the validated original description, policy digest and original
  claim time. It validates as a foundation claimed record. It is not a new local
  permission or evidence of a durable endpoint consumption mark.
- `Result` contains that claim and the report. `ValidateResult` checks exact
  ordered original selected events and description bindings;
  `ValidateResultForGrant` additionally checks policy and original claim time.
  Capture before creation/claim or at/after original expiry is rejected.
- `StatusInput` contains the same complete claim binding plus a fixed local
  status: empty, `checking`, `disabled`, `denied`, `reader_unavailable`,
  `result_lost`, `expired`, or `canceled`. No free-form OS errors are accepted.
  `Status` contains the validated authority record, local status and
  `available`/`unavailable` content status. Only accepted work can claim available
  content. `EncodeReceipt`/`DecodeReceipt` preserve foundation receipt semantics.

The request still expires exactly 15 minutes after creation. This wire layer does
not alter header age limits, allowed channels, native selection identity, consent
scope, source permissions or the existing fixed budgets.

## Independent text and encoded-body bounds

Message reports retain the reader's maximum 16 events, 16 KiB UTF-8 text per event,
64 KiB aggregate text and five-second cooperative collection budget. Those text
bounds are not an encoded JSON byte limit: a permitted byte such as U+0001 becomes
six JSON bytes. The result envelope therefore has a separately checked **512 KiB**
encoded cap. Metadata envelopes have a **32 KiB** encoded cap. Decoders bound the
input before decoding; encoders separately validate both content and total bytes.

Reports preserve fixed source/warning, exact requested order, per-event quality,
completeness/truncation and fixed reason taxonomy. A valid partial report remains
usable when the native reader also returns a nonnil fixed error: successful rows
are not discarded merely because another selected record failed. Validation does
not turn a partial or bounded report into a complete result.

## Memory and digest boundaries

Reports and encoded results are content-bearing, operator-only memory. Do not
write them to SQLite, durable retries, telemetry, diagnostics, notifications or AI
provider input. Content-bearing wire/DTO structs redact every ordinary `fmt`
format verb. Explicit JSON serialization is still content-bearing; redaction is
not permission to log it. Render message text as untrusted plain text only.

`ResultDigest` hashes the exact canonical encoded **complete wire result** for an
integration's durable digest-only exact-retry check. It is distinct from
`ReportDigest`, which exactly matches the foundation `Accept` receipt's native
report digest. Keep the original foundation receipt unchanged and store the
canonical wire digest separately. Digest-only durable state is not a content
cache; lost process memory never authorizes recapture. The original expiry bounds
all endpoint/manager/browser retention and is never extended by retry or display.

## Synthetic verification and remaining responsibility

Portable tests cover uint64 boundaries including 2^53+1 and maximum uint64, native
100ns timestamps, safe ordinary JSON marshaling, unknown/duplicate/noncanonical
fields, all request/result identity bindings, disabled/original-age capabilities,
worst-case sixfold escaping of the entire 64 KiB text budget, valid partial
reports, both digest meanings, and diagnostic redaction. HTTP fixtures cover
cross-purpose/path/body/identity replay, stale/future/modified proof times,
authentication recheck after slow bodies, TLS fallback rejection and framing.

These tests use generated ephemeral synthetic certificates and invented event
metadata/text. No native event was read, persistent credential/grant created,
privilege changed, service installed, or release performed. Additional runtime,
manager, real TLS/signed-HTTP listener and configured operator-route fixtures now
exercise atomic one-use claims, protected consume-before-read ordering, local
consent rechecks, memory-only retries and operator UI lifecycle. The same invented
Go DTO fixture is validated by both Go and the TypeScript parser suite.

Real-browser acceptance, native Event Log reads under the intended installed
identity, real Windows-to-Linux-manager interoperability and installed-host
lifecycle remain distinct gates. Source tests do not replace or authorize them.
