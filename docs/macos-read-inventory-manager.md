# macOS inventory manager source integration

This unreleased source slice connects the reviewed macOS inventory wire contract
to an explicitly enabled, TLS-only manager domain. It is not native macOS
acceptance, installation or release evidence. The collector, wire and separate
sender-state foundations remain independently reviewable. The subsequent
[fresh endpoint runtime](macos-read-inventory-runtime.md) now connects explicit
local consent, protected handoff and foreground reporting for matching reviewed
source builds. The generic enrollment client still rejects this expanded profile;
only the distinct fresh inventory entry point selects it. There is no installer
or published Mac download command.

## Fresh authority and coexistence

The protected LAN flag `macosInventoryEnabled` defaults to false. When enabled
with guided TLS enrollment, the manager allocates a separate immutable
`darwin` / `macos-read-inventory-v1` domain in
`<stateDirectory>/enrollment-macos-inventory.db`. The primary Linux domain,
Windows inventory and basic macOS domain keep their existing profiles, state,
wire bytes and enrollment routes. One manager and device list compose the four
bounded domains; identity collisions fail closed rather than joining devices.
No existing basic Mac, Linux or Windows grant is promoted.

The configuration, origin, issuer and renewal policy are fenced by
`identity-mode-macos-inventory-initializing-v1.json` and
`identity-mode-macos-inventory-ready-v1.json`. First creation is exclusive;
reopen requires both exact markers and the nonempty existing database. Orphan
SQLite fragments, missing used state, schema changes and interrupted
initialization are blockers. Disabling the config cannot make old state fresh.
The maximum remains 25 retained enrollment identities in this separate domain.

The operator enrollment routes are `/api/macos-inventory/enrollment`; the
client lifecycle/renewal prefix is `/v2/macos-inventory/enrollment/`. Creating
an invitation requires the new profile's explicit inventory acknowledgement.
The operator privacy token is `macos_inventory_metadata_may_be_sensitive`.
This acknowledgement does not replace local endpoint consent, fingerprint
comparison, credential provisioning or native acceptance.

All supported OS/transport/collection-profile combinations are enumerated.
Unknown combinations and macOS inventory over HTTP-test fail closed. In
particular, registering a new profile does not make it an implicit Linux scope.

## Dedicated ingress and atomic transactions

Two exact routes accept canonical JSON under the existing TLS 1.3,
dedicated-issuer, global and per-certificate ingress bounds:

- `POST /v1/macos/inventory/control`, at most 2 KiB
- `POST /v1/macos/inventory/report`, at most 520 KiB

The report embeds the existing at-most-512-KiB typed snapshot. The old 72-KiB
telemetry cap is unchanged. Requests require exact method/path/origin authority,
content type and declared length. Encoded paths, queries, compressed/chunked
bodies, forwarded/browser authority, legacy signed-HTTP headers and
noncanonical/duplicate/unknown JSON fields are rejected. Errors contain fixed
codes only, never process labels, receipt IDs, addresses or parser diagnostics.

The original sender binding is SHA-256 over this exact UTF-8 sequence:

`tracebolt.sender-binding.macos-inventory.v1\nmacos-read-inventory-v1\ntls\n`
followed by the configured agent origin, newline, original enrollment leaf
fingerprint, newline, original device ID. The independently authenticated
transport leaf is passed separately. Same-key renewal changes the current
credential, never the original binding, scope, floor, report bytes or age.

Each control/report operation uses the enrollment database's existing
`BEGIN IMMEDIATE` transaction. Current-leaf validity, activation/revocation,
original identity/grant, durable clock, terminal control, floor, latest body and
exact receipt are checked/committed together. The final clock and current-leaf
checks run immediately before commit and again at the final ingress output
boundary. Only stored committed canonical receipts are returned.

Fresh enable uses revisions (1,1), initial floor zero and one grant ID. The
manager's original enable receipt must predate every admitted capture. There is
no grant replacement or reenable. Exact enable/report/disable retries return
original receipt bytes and received time. Altered same-sequence bodies, sequence
rollback and faster-than-one-minute advancing captures conflict. Skips remain
possible for independently consumed sender failures/loss; the manager cannot
reconstruct reservations that the sender never reported.

Terminal disable uses revision (1,2) and an exact final sender reservation floor
no lower than the manager's accepted floor. Once committed, every report is
rejected, including old exact retries. Disable and report admissions serialize
on the same database writer lock. The credential's irreversible used marker
requires the corresponding record even if all report rows are gone. Missing
used records/tables/clocks never trigger initialization. A complete historical
backup cannot be detected as transparent rollback recovery and is unsupported.

## Latest-only retention and private reads

There is one latest canonical report per identity, with its exact original
24-hour capture expiry. Replacement drops the older logical report body.
Expiry never refreshes through retry, restart, renewal, navigation or disable.
After expiry, bounded non-row metadata and the original receipt/floor survive
as an explicit expired tombstone. Source coverage (`full`, `partial`, `unknown`)
is separate from evidence freshness (`fresh`, `stale`, `expired`). A failed source
never becomes an observed empty inventory.

Private reads use `POST /api/devices/{id}/macos-inventory/query` with the exact
body fields `section`, `generationId`, `offset`, `limit`. Sections are `summary`,
`hardware`, `receipts`, `processes`, `ipv4`, `ipv6`. Summary uses empty generation
and zero offset; detail reads pin the returned generation. Limits are 1–100 rows
and 32 KiB per response. Whole rows are reduced to fit the byte budget and
`nextOffset` continues the same generation; identifiers/addresses are never
truncated. Legacy four-field queries and v1 response bytes are unchanged.

Receipts and processes also accept one explicit six-field lookup shape:
`schemaVersion: "tracebolt.macos-read-inventory-query.v2"`, `section`,
`generationId`, `offset`, `limit`, `search`. Summary, hardware and network retain
v1. Search is canonical lowercase printable ASCII, at most 256 bytes, without
outer ASCII spaces; noncanonical input is rejected. Matching is a literal
case-insensitive substring of a receipt identifier, or independently of an
observed process accounting label, decimal PID or decimal PPID. Unavailable-name
placeholders never match. Empty search matches every captured row.

The v2 page adds the exact `search` and `matchingCount`; `total` remains the
captured source-row count. Offsets address the matching sequence in original
source order, with the same 100-row/32-KiB whole-row bounds and 1-KiB request cap.
Observed processes may have zero matches despite a positive captured total;
denied/unavailable sources retain their unknown status and zero row counts.
Only the bounded, already-retained latest report is scanned in memory. This
lookup adds no native read, grant, index, storage, SQL search or export, and never
changes capture age, source coverage or the pinned generation.

Every read requires the live authenticated operator session, CSRF admission,
current credential, original enrollment/sender/grant and generation. Unexported
output guards preserve these exact bindings through response marshaling and the
final transaction. `authorityUntil` is clipped by session, current credential and
original report lifetime. Expiry, logout, revocation, disable or replacement
cannot return a prepared stale private page. Device-list projections expose only
platform and scope capability, with no process/receipt/address rows. There is no
AI, global search, health, action, external-provider or log export of inventory data.

The manager performs logical expiry cleanup before serving on startup, then
once per minute. An existing fenced inventory database remains open solely for
maintenance when its config flag is off; enrollment, ingress, private reads and
device merging stay off. Fresh disabled configuration creates no database.
Private reads reject at the exact original deadline even between cleanup ticks.
An offline/stopped manager cannot run cleanup until next startup. Logical
payload removal is not a guarantee of immediate physical-media, SQLite WAL,
filesystem snapshot or backup erasure.

## Verification and remaining gates

Synthetic, inert tests cover dedicated profile/TLS admission, canonical bounds,
reports larger than the unchanged legacy telemetry frame, missing/foreign/expired
credentials, original-anchor renewal, exact retry/conflict, disable serialization,
used-state loss, transaction rollback, final clocks/sessions, bounded private
paging and logical expiry cleanup. Manager/API tests use response recorders,
in-memory fixture keys and protected temporary databases, without listeners or
native macOS reads.

The matching shared UI now exposes explicit inventory enrollment and bounded
private inventory views in English and German. It preserves source quality,
original age and receipt-only software semantics. Source-only runtime and UI
integration do not establish native acceptance.

Still required: protected native persistence and cancellation/join; separately
approved Apple Silicon/Intel source/permission behavior; one-minute performance
and resource checks; exact-artifact end-to-end TLS/renewal/disable/restart and
retention acceptance. No installation, launchd, TCC, Full Disk Access, account,
privilege, certificate trust, native credential or native collection action is
authorized or performed by these source tests.
