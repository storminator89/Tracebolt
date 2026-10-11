# Windows complete Win32 service generation: source contract

This is a new default-off source slice, not a host grant or native acceptance.
It enumerates the Win32 services visible through SCM to the existing LocalService
identity. Drivers, ACL-invisible services, paths, accounts, startup/configuration
and all software sources remain outside it. Selected-service health continues to
read the old bounded telemetry preview under its existing counters and limits.

## Bounded capture and transfer

A complete generation may contain at most 8,192 rows and 8 MiB of canonical row
JSON. Native enumeration uses one 256 KiB buffer, at most 256 API pages / 64 MiB
aggregate buffer work, and a 15-second cooperative capture budget. Exceeding a
limit fails the attempt; a prefix is never promoted as complete. Native-sized
names/display names retain up to 256 UTF-16 code units / 1,024 UTF-8 bytes.

A frozen pack is at most 12 MiB; each message carries at most 128 rows / 64 KiB,
with at most 256 chunks. Each sending burst permits 64 operations / 20 seconds.
Unfinished packs drain over later bursts without recapture or refreshed age.
Captures are at least one minute apart. Original retention is 24 hours.
Manager reservation is bounded to 24 MiB per device and 128 MiB globally, with
at most three current/staging/garbage generations per device. The existing
physical database/WAL caps remain enforced. Background reclamation runs a
bounded step each second; rapid test replacements invoke that same maintenance
entrypoint instead of deleting rows or relaxing quotas.

## Operator JSON API

Read-only POST `/api/devices/{agent_id}/windows-full-services/query` uses existing
operator session, Origin and CSRF checks. No labels/cursors go into URLs.
The exact Go JSON DTO is `internal/windowsfullservices/types.go`: Query and Page.
Request: {"search":"","sort":"name-asc","limit":100,"cursor":""}.
Sorts: name-asc, name-desc, pid-asc, pid-desc, state-asc, state-desc.
Search is literal Unicode case-insensitive over name/display/state/PID, up to
256 UTF-8 bytes. A cursor pins device, current grant/revision, exact generation,
manifest, query/sort/limit, matching offset and original cursor/source/authority
expiry. Initial requests select current; continuation never silently replaces it.
Pages contain at most 100 rows and 256 KiB. Full matching count covers the whole
bounded captured generation. Missing display/state/PID fields sort last in either
direction; names are exact and unique per generation. Rows may be empty only for
a truthful unavailable status, complete healthy-empty capture, or zero matches.

Page schema is `tracebolt.windows-full-services-page.v1`. All members are required.
`status`: not_configured, disabled, awaiting, ready, unavailable. `complete` is
non-null only for ready and includes the immutable manifest and original final
receipt time. `latestAttempt` is independent, never rewrites complete's original
capture/expiry/receipt; status pending/complete/source_failed/expired. Failed
reasons: access_denied, unavailable, unsupported, source_changed, malformed_source,
resource_limit, deadline, canceled. `authorityUntil`, `grantId`, `grantRevision`
are nullable before any acknowledged scope. `cursorExpiresAt` is non-null for
ready pages, including final pages; other statuses have no rows or cursors.
`nextCursor` is empty at the end. Offset indexes the matching sorted result set.
Initial cursor expiry is min(serverNow+15min, original source expiry, certificate
expiry); following pages retain exactly that deadline. New captures replace old
current data immediately; continuation then returns restart_required. No retired
page grace or promise of fitting every maximum-size device simultaneously.

Error codes: 400 windows_full_services_invalid; 403 agent_unauthorized (revoked,
expired or inactive identity); 404 not_found; 409 windows_full_services_restart_required
(changed/expired cursor or changed generation/grant); 429 inventory_busy;
503 storage_unavailable. Every error hides rows and preserves source age.
The UI must clear data/cursors on pending requests, device/tab/session/navigation
changes, visibility/focus loss, untrusted time and original expiry. Never append
across page generations. Never present these rows as an expanded alarm chooser.

## Shared endpoint/store transport interface

New package `windowsfullservices` owns immutable typed manifests/messages and
bounded canonical validation. Three operations: scope, chunk, failure. Scope is
signed local consent state with independent monotonic revision. Runtime sends
scope status before rows, and only scope state while disabled. A stopped endpoint
cannot announce local disable until it next runs; manager labels its last
acknowledged scope and still checks current certificate revocation on every call.
Scope state is not a manager-created grant. A higher local revision disables or
replaces authority for old data; reenable creates a new grant without resetting
capture sequence. Retained disabled pending rows never get delivered or refreshed.

Chunk messages repeat their immutable manifest plus hash, ordinal and row offset;
all canonical request bodies fit 64 KiB and 128 rows. First chunk reserves the
whole manifest budget, advances the independent durable floor, and stages.
Exact duplicates get the original receipt. Different bytes at the same ordinal
fail. Final chunk atomically verifies exact canonical rows/digest/count/bytes/order
and promotes. Zero-row complete is one explicit empty chunk. Failure messages
consume a sequence, record latest finite failure and retain previous complete.
A receipt binds operation/device/grant/revision/sequence/request digest/index and
original receipt time. No telemetry frame/counter or old local grant is reused.

Store seam: InitializeWindowsFullServices(ctx); ApplyWindowsFullServices(ctx,
invitationID, certificateHash, Message, rawCanonicalMessage, now) (Receipt,error);
WindowsFullServicesPage(ctx, deviceID, Query, now) (Page,error).
All production ingress calls install the exact configured agent-listener origin,
which may differ from the enrollment/UI origin. All ingress/operator calls
install a trusted clock; current authority,
reservations and replay checks share the same transaction, with response-time
original-expiry recheck. Storage integrity and physical DB/WAL caps stay enforced.
No used optional floor may be reconstructed from missing state.

## Explicit local opt-in and irreversible used-state fence

The owned installed service must already be stopped and its existing enrollment
activated. The source CLI paths are:

- `windows-service.exe --full-services-preview`
- `windows-service.exe --full-services-enable --apply --complete-win32-services`
- `windows-service.exe --full-services-disable --apply`

An existing HTTP-test identity also requires `--insecure-http-test` and the
complete plaintext warning. These are documented source commands, not permission
to run them on a host. Fresh five-scope Setup remains unchanged and does not enable
this extension. Manager schema initialization cannot grant endpoint collection.

First enable durably places an irreversible full-services-used marker in a new
version of the existing mandatory protected sender record before creating the
new sidecar. The old fixed Windows file schema and 128 KiB primary-record ceiling
stay unchanged. Unopted-in v1 records retain their exact encoding. The explicit
transition preserves identity, telemetry counter, pending frame bytes and digest;
it neither grants old scopes nor re-enrolls. Older executables that do not know
the opt-in record version fail closed. Do not downgrade or reset this state.

A missing whole extension root after that marker, a missing marker with an
existing sidecar, interrupted initialization, or missing used sender/pack bytes
requires preserved-state diagnosis. It is never treated as fresh/default-off.
Disable keeps the marker, sequence floor and original pending data. Reenable
creates a new consent revision and grant, never a new floor. Source capture is
claimed before enumeration; interrupted capture either resumes an already frozen
pack or records a finite failed attempt under the consumed sequence.

Native PID is available only for the Win32 states where SERVICE_STATUS_PROCESS
specifies a valid PID: running, continue-pending, pause-pending and paused.
Stopped, start-pending, stop-pending and unknown states carry unavailable PID.
Optional unavailable fields retain service identity; uncertain enumeration never
promotes a prefix. The 15-second cooperative budget includes opening SCM, but it
cannot hard-cancel an in-flight native API call and no goroutine is abandoned.

## Verification boundary

Invented integration data crosses both old ceilings with 2,049+ service rows,
real local TLS and purpose-signed HTTP, exact lost-ack retries, both-end restarts,
complete-generation server search and pages, local disable and identity
revocation. Inert parsing tests execute malformed bounded buffers and UTF-16 on
Linux. Cross-builds only establish Windows compilation. Native LocalService
visibility, real SCM resume behavior, protected Windows ACL state and service
shutdown remain a separately approved disposable-Windows gate. No host grant,
privilege change, service control, provider call or browser launch follows from
these source tests. Hosted browser and final reviewed source gates remain separate.

The separately gated executable collector stage and remaining installed CLI,
manager and browser observations are specified in
[the later native acceptance plan](windows-full-services-native-acceptance.md).
They are not enabled by the unchanged five-scope Setup GUI or existing native pins.
