# First-report display candidate

UI-only, held source candidate based on reviewed fleet-tool-order tree
`f150b3cab9ca391dca768e178895262f42173a85`. Browser acceptance is still required.
No API, native collector, scope, enrollment mutation, invitation, authentication,
refresh interval or release behavior changes. A deliberate status check now also
refreshes the existing overview evidence; automatic polls do not add that read.

## Evidence and wording

The manager's existing enrollment projection starts approved devices with Go's
zero last-seen time and unavailable metrics. A stored accepted observation sets
that time; separately accepted macOS inventory contact also sets it, even when
CPU and memory remain unavailable. Missing metrics therefore never select a
first-report state. OS descriptions and capability prose are not parsed.

Fleet and device views use “No report recorded yet” / “Noch keine Meldung erfasst”
when the real LAN device has the explicit Go zero-time sentinel. This is a
conservative record-display fallback, not a claim that the device has never
reported in its history. Malformed/missing timestamps and loading/failure use
unavailable wording instead. Existing valid time strings, full dates and relative
ages remain unchanged, including old reports and
macOS inventory-only contact. CSV data is untouched.

The enrollment review joins only one matching existing device to the validated
invitation's approval device ID. It can say “Waiting for first report” only while:

- The operator is authenticated in LAN mode, the device read succeeded, and the
  existing enrollment request and its clock/configuration remain available.
- The exact enrollment state is `activated` and the validated current credential
  is unexpired. The original identity anchor is not a renewed leaf expiry.
- The matching real LAN device has exactly one `agent_identity` capability with
  explicit `supported` status and a valid guided-enrollment certificate view.
- The certificate was checked no later than the anchored manager time and has
  not expired at either that check or the current enrollment-clock time.
- The report time is the explicit Go zero-time sentinel. Invalid or missing
  metadata never proves an absent report.

Approved/issuing/issued identities say “Activation pending”. A failed read,
unverified session/clock, terminated or denied identity, and expiry all take
precedence over waiting. Missing, foreign, synthetic or duplicate matching devices and incomplete identity
evidence remain unavailable; they cannot prove the zero timestamp. Original timestamps remain visible as historical evidence even beside
an unavailable/denied/expired state. A small closed disclosure distinguishes a
recorded report from current reachability. No Online/Offline state is added and
stale measurement semantics remain unchanged.

## Current-leaf evidence and consistent read-only presentation

The prior candidate compared an activated identity to `intent.notAfter`, which is
its immutable original anchor. `devices.go` projects the currently activated leaf
and renewal generation, and the existing renewal regression accepts Windows
telemetry beyond original-anchor expiry. The display now requires the existing
strict certificate guard, guided source, non-future manager check, exact matching
real device and one supported identity capability. A later leaf additionally
requires a valid renewal envelope with credential generation at least two and
its exact `currentNotAfter`/authority bounds. An arbitrary later expiry, missing
renewal evidence, a generation-one leaf or future check cannot assert activation.
Disabled future renewal does not invalidate an already current credential.

One shared read-only interpretation drives the activated invitation's row label,
review status, active setup step, next-step guidance and pure expiry warning.
A valid renewed leaf is no longer paired with an expired label or warning just
because its original anchor ended. Missing evidence withdraws the activation
assertion and active step. The original expiry remains visible, explicitly
labeled, separately from a verified current expiry. All mutation, approval,
revocation and original deadline conditions remain unchanged; this helper must
never authorize an action.

Manual Check status and the enrollment refresh button now refresh the existing
overview even when invitation IDs/revisions stay the same. Telemetry does not
revise that snapshot. Automatic enrollment polls preserve their existing
revision-change behavior and never unconditionally refetch the fleet. Enrollment
reads and overview reads coalesce while pending; the explicit overview callback
does not advance unrelated fleet-detail refresh revisions; the manual check stays disabled
until its overview result settles. A failed read withdraws waiting/activation
claims while retaining a valid historical timestamp. No interval, endpoint,
collection scope, session contract or write is added.

## Verification boundary

Focused tests cover English/German states, Go zero/invalid timestamps, admitted
versus limited/denied/expired identity, mismatched or absent device/certificate,
original old timestamps, macOS inventory contact without CPU/RAM, failure,
pagehide/navigation and session invalidation. Existing enrollment, invitation,
focus/history, certificate and metadata-refresh suites remain acceptance guards.

These tests use invented DTOs. This packet does not establish hosted browser,
native OS, installed-service, deployment, performance or release acceptance.
The existing hosted browser gates must run on the final published source before
visual acceptance; no browser launch or dependency installation was attempted in
this isolated task.

## Integration and hosted visual gate

This base is a composed, unpublished first-device/lazy-route/fleet-order tree,
not `main`. Apply only after verifying the exact destination and coordinating
those other packets; do not copy its entire source over a newer checkout.

`web/scripts/capture-first-report-fixtures.mjs --check` checks invented DTOs,
write/external-request blocking and production compilation without launching a
browser. The separate hosted-only `run-first-report-ci.mjs` prepares 28 captures:
activation pending, waiting, renewed waiting, denied, expired, malformed time and old macOS
inventory contact, each in English/German at desktop/mobile sizes. It checks
original timestamps, unavailable CPU/RAM, closed details, no secret fields,
viewport bounds, Escape/focus restoration, renewed row/progress/warning consistency,
unchanged-revision manual report refresh and failure clearing the waiting state.
The existing Focused source checks browser job now selects this hosted-only driver
for first-report/enrollment display changes and shared UI changes. The shared
fleet fixture compiler selects both owners. The job reuses its pinned Node,
locked Playwright/Chromium setup, read-only permissions and successful-public-safe
artifact upload; it adds no workflow, dispatch, secret or native grant. The
existing suites, quarantines and separate full Validate workflow are unchanged.

The driver refuses non-hosted execution before loading Playwright or creating a
profile. Successful evidence must match the exact clean checked-out source SHA
and Git tree, the complete canonical compiled-source inventory and its input
hashes (including the package lock, selector, workflow and validation scripts).
The bounded validator rejects extra/missing fields, scenes, assertions, captures,
source inputs, path substitutions, symlinks and wrong PNG bytes or viewport
sizes. PNG checks validate every chunk CRC, the exact 8-bit non-interlaced RGB/RGBA
screenshot format, complete IDAT inflation within the exact scanline budget
(maximum 6 MiB), valid scanline filters and actual decoding through the existing
locked Playwright PNG decoder. Compressed files remain capped at 8 MiB; unsupported
chunks, missing/truncated/corrupt streams and trailing compressed data fail.
All 28 files must be synthetic, public-safe and viewport-only. It never
repairs producer trust flags or screenshot hashes. Invalid or partial captures
are removed, the result stays failed, and raw exceptions/DTOs remain withheld;
failed metadata retains only finite phase/scene/locale/width coordinates.

The focused UI tier runs the inert recipe and contract fixtures with one Node
test worker. Contract PNG byte fixtures are not screenshots. This source-only
integration has not executed a browser: final published-source hosted captures
and an actual screenshot review remain required before visual acceptance.

The pre-existing cold `device-page` component test starts an authenticated App
and immediately spends its one-second DOM wait while Vite is still transforming
the lazy detail module. This reproduces on an unmodified copy of the base tree.
Its helper now lets authentication settle and explicitly awaits the render's
actual dynamic import inside React `act` before making the unchanged DOM, focus
and navigation assertions. It does not preload the module before authentication,
change test timeouts or alter production lazy-loading behavior. The independent
controlled-promise route lifecycle suite still exercises delayed imports.
