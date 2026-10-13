# macOS log-window contract preparation

Inactive source only. `internal/macoslogwindow` has no native reader, command,
provider callback, listener, grant, ledger, profile activation, transport, cache or
UI integration. Production log collection remains unavailable. Synthetic fixtures
are not Apple output, native acceptance, service/log parity or authorization to
read a host. Basic macOS, inventory, Linux and Windows behavior is unchanged.

## What this slice implements

- Proposed fresh scope `macos-unified-log-window-v1`, with exact request schema
  `tracebolt.macos-log-window-request.v1` and TLS-only contract validation. The
  transport string is not authenticated TLS or local consent.
- Typed UTC `[start, end)` bounds: fixed last five minutes by default; maximum
  fifteen minutes, wholly within the preceding twenty-four hours measured from
  original creation. The original expiry is exactly creation plus fifteen minutes.
  A retry, filter, page or renewal cannot alter either anchor.
- `EncodeRequest`/`DecodeRequest` and `EncodeProjection`/`DecodeProjection` accept
  exact canonical internal JSON only. Unknown fields, duplicate keys, alternate
  casing, trailing documents, invalid UTF-8/surrogates and wrong scopes fail closed.
  Decode failure returns no rows. This is not an Apple machine-output parser.
- At most 500 projected rows and 512 KiB encoded projection including JSON escaping
  and the request envelope, with 4 KiB/message and 256 bytes per source label.
  Values are not silently shortened or dropped by the parser. Explicit per-row
  `messageTruncated` preserves a future adapter's declared truncation.
- Timestamp, process label, subsystem, category and message only. Null means
  unavailable; an observed empty string remains distinct. No PID, executable path,
  service identity, native cursor, severity inference or cross-capture row identity.
  Duplicate rows/timestamps remain legitimate; strings are untrusted text data.
- `observed` (including zero rows), `partial` with a fixed reason, `denied`,
  `unavailable`, and `result_lost` stay distinct. Failed/lost states contain no
  capture time or rows. Observed means this accessible bounded query ended normally,
  never proof of complete retained history. Partial may contain zero rows.
- Live validation rejects pre-creation clocks and expiry; capture must fall between
  original creation and the current live check. It does not schedule eviction or
  detect every backwards clock. Formatting these structs redacts content; that is
  not permission to marshal them into logs or durable storage.

The parser validates a representation, not the authenticity of result-state claims.
The expected request must come from independently accepted metadata. There is no
authority decoder: no consent document, basic scope or inventory profile can be
activated through this package. A future fresh consent/admission implementation
must establish identity and authorization separately before any source read.

`MaxCandidateEntries = 4096` and `MaxCandidateBytes = 8 MiB` are requirements for a
future native adapter. No raw reader or raw schema exists here, so these constants
are not a claim that native limits are already enforced. Current internal parsing
is capped at 512 KiB; the eventual adapter must apply its separate raw byte and
entry limits before allocation/decoding and before projection.

## Source evidence and blocking native questions

Apple identifies the `log` CLI and OSLog framework as extraction routes, rather
than direct access to the custom on-disk store ([Apple DTS](https://developer.apple.com/forums/thread/773369)).
Apple's timestamp/predicate examples are a useful design reference, not a portable
machine-output schema or endpoint-inclusivity guarantee ([TN3163](https://developer.apple.com/documentation/technotes/tn3163-understanding-the-synchronization-of-nspersistentcloudkitcontainer)).
No stable Apple raw JSON format is accepted or registered by this change.

The OSLogStore reference's admin/private-entitlement wording and Apple's DTS
clarification for unsandboxed admin callers do not prove useful visibility for a
dedicated non-admin reporting identity ([reference](https://developer.apple.com/documentation/oslog/oslogstore/local()),
[DTS clarification](https://developer.apple.com/forums/thread/666679)).
Do not add a private entitlement, switch the main identity, elevate, add group
memberships or request TCC/Full Disk Access to make apparent coverage improve.

Before implementing or enabling a provider, obtain separately authorized native
evidence for exact artifacts, supported macOS versions/architectures and the actual
caller identity. Resolve the exact Apple-supplied flags, framing/schema, bounded
timestamp/offset interpretation, inclusive/exclusive edges, field availability,
denial versus empty behavior, privacy markers, partial/error behavior, resource
bounds and cancellation/reaping. Reject unsupported versions/shapes without a
permissive text fallback. Admin-only success cannot pass the non-admin gate.

## Implementation-ready request and private UI plan

The following is planned work, not implemented behavior or an enabled route.

1. **Fresh local authority.** Define a create-only protected content grant with its
   own original identity/destination binding, grant ID, used markers and monotonic
   consume floor. Require fresh unchecked local disclosure of sensitive unified-log
   text/labels, the bounded historical window, exact manager destination, memory-only
   retention and no AI/export. Old basic/inventory/Linux/Windows authority must
   remain byte-for-byte inadequate. TLS admission must be independently enforced;
   no HTTP mode or manager-side scope expansion. Decide fresh-profile composition
   separately; this preparation introduces no identity change or CLI flag.
2. **One explicit request.** Only a deliberate authenticated operator POST creates
   a request. Resolve typed bounds and creation/expiry once against the trusted
   manager clock. Bind a new purpose-specific request ID/sequence, exact query
   digest, original enrollment, local grant and server-derived operator session.
   Check current leaf, revocation, fresh capability and exact authority again in
   the commit transaction. Do not derive source predicates from display filters.
3. **Consume before any read.** Manager durable claim and endpoint independent
   durable consumption must succeed before a future native edge. Missing used
   state, ambiguous writes or lost claims stop; never reset, rearm or reread.
   Keep all durable records content-free. Recheck current local authority, caller
   cancellation and original expiry around capture. Lost memory means `result_lost`.
4. **One bounded adapter after the evidence gate.** Follow the fixed-absolute-
   executable pattern in `macosinventory/command_darwin.go`: no shell, caller paths,
   ambient environment or stdin; an explicit short deadline, combined output cap,
   cancellation and synchronous kill/reap. Review the exact deadline and flags with
   native evidence. Enforce 8 MiB raw/4,096 candidate entries, then 500 rows/512 KiB
   projection/4 KiB message. Count stderr without retaining it. Malformed framing
   or invalid data discards the result. Preserve a prefix only when the reviewed
   adapter can prove independently valid complete rows and an explicit partial
   reason; never call a cutoff successful empty or complete.
5. **Private delivery.** Publish a bounded non-content digest receipt before
   session-owned memory. Keep at most one exact byte result per endpoint/session
   until original expiry, with an explicit finite manager-wide memory quota and
   rejection at capacity. Retry retained bytes only. Manager/endpoint restart,
   memory loss, session end, replacement, cancellation, disable, terminal rejection,
   expiry or clock regression clears bytes without restoring native-read authority.
   Renewal preserves original grant/request/floors and never refreshes content age.
6. **Private Logs experience.** Present “Recent diagnostics” and UTC start/end with
   the five-minute default and visible limits. Keep content consent unchecked.
   Before availability show “Source unavailable”; opening the view/chooser never
   captures. After explicit capture, derive literal process/subsystem/category
   facets from accepted rows and label them “Seen in this capture.” Empty facets
   and unavailable labels remain distinct. No launchd chooser, PID joins, arbitrary
   predicates, auto-refresh or implicit reread. Ten-row display paging/filtering
   uses only accepted memory, with ephemeral ordinal display keys, not source IDs.
7. **UI privacy and failures.** Render labels/messages through text nodes only;
   never HTML, links generated from log strings, native commands or DOM selectors.
   Show capture/expiry, bounded/partial and per-message truncation, denied,
   unavailable, observed-empty, expired and lost states separately. Abort requests
   and discard private state on navigation, hide, Close, Back/Forward, logout,
   session invalidation or original expiry. Fence late responses by exact request
   and session. An uncertain create gets read-only reconciliation, never automatic
   POST retry. No local/session storage, URLs, analytics, durable telemetry,
   diagnostics, notifications, support bundles, AI/provider export or download.

Design references only: Windows bounded-history request/cache and
`web/src/windows-event-history-resource.ts` supply lifecycle examples, not Mac
authority or native format assumptions. Do not refactor them for this slice.

## Verification and follow-on gates

Portable synthetic tests cover UTC limits, original expiry/request substitution,
old scopes/HTTP rejection, strict canonical encoding, malformed/native-looking
inputs, byte/row/UTF-8 limits, XSS/predicate text preserved as data, redacted
formatting and explicit empty/denied/partial/lost outcomes. The package has no
provider path for tests to accidentally execute.

Future integration requires separate consume-once/restart/uncertainty tests,
protected authority and current-leaf guards, memory/session isolation and eviction,
exact retry, clock rollback and cancellation tests, plus hosted EN/DE desktop/mobile
UI fixtures for repeated clicks, interrupted create and late-response cleanup.
Those tests, native reads and real UI execution have not run in this preparation.
No native provider, keys, credentials, grants, services or release are authorized.

Publication metadata follow-ups only: link this document from macOS status/AGENTS
and regenerate the applicable allowlist digest during separately reviewed assembly.
This focused patch deliberately changes neither those shared files nor README,
workflows, release artifacts or paused fleet-label work.
