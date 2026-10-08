# Windows service and software browsing

This incremental source candidate improves the existing Windows inventory UI.
It does not implement complete-host inventory or change collection consent.

## Current usable slice

Services and Software now have literal, case-insensitive search, ascending and
descending sorting, and 25-row local pages. Services sort by name, numeric PID or
translated status. Software sorts by name, literal version text or publisher;
version order is not update order. Missing source values sort last in either
direction. Equal values use the complete source row and original row ordinal for
stable ordering; equal names and duplicate uninstall registrations are retained.
Search covers the reported fields, including raw and translated service status
and registry view. It does not query a host, join process details or treat labels
as markup, regular expressions, commands or destinations.

Pages cover only the already accepted snapshot, at most 128 rows per section and
potentially fewer under its 48 KiB shared encoding limit. Captured, matching,
visible and observed counts remain distinct. A lower-bound count stays a lower
bound, and truncated, denied, unavailable and healthy-empty sections keep their
original meaning. The original capture/receipt times are never changed by pages,
search or sorting. No UI action collects more rows or adds service startup data.

Controls remain during a same-generation refresh, but all private rows and
controls are hidden while its request is pending. A changed device, original
capture, generation, tab, session or nonloading absent snapshot clears controls.
Visibility loss, authentication loss, untrusted time and original 24-hour expiry
continue to clear data through the existing protected resource. No new cache,
persistent browser state, request, endpoint, schema, frame or grant is added.

Both languages have native keyboard controls outside the mobile-hidden table
header, bounded live counts, disabled end-page buttons, column sort metadata and
mobile cell labels. Hosted fixtures cover English/German at 1440 and 390 pixels
inside the existing restricted loopback runner. Source/DOM checks do not establish
that a browser or Windows endpoint passed; those results must be reported
separately. No local browser, native collector, service or permission change is
part of this candidate.

## Complete-inventory follow-on design, not implemented

The native `windowsinventory` provider currently caps process, service and
software enumeration at 2,048 rows; service enumeration also has one 256 KiB
buffer. `windowsmanaged` then trims transmission to 128 rows per section under
48 KiB. Local pagination cannot restore omitted rows. The Linux
`completeoverview`/`overviewgeneration`/`overviewwire` and
`systeminventory`/`fullinventory` paths are useful patterns, but their Linux
schemas and authority cannot be relabeled as Windows approval.

The smallest actual complete-generation vertical slice should be one section,
processes, through consent, native enumeration, durable sender, signed transport,
authority store and operator UI together. Services and software can reuse that
reviewed path afterward. Do not publish a pure reassembly library as completed
inventory support. The following is a review plan, not an implemented contract:

- Introduce a separate default-off local scope, provisionally
  `windows-complete-inventory-v1`, and a new versioned complete-generation wire
  contract. Explicit disclosure includes every selected section, its retained
  labels, destination/HTTP risk, cadence and limits. Fresh installer selections
  need a new acknowledged profile version. Never extend the old five-scope
  approval, increase v1-v5 limits or promote old grants/receipts. A manager upgrade
  cannot enable endpoint capture. Existing identities and counters stay intact.
- Capture only the approved caller-visible API scope under the existing limited
  identity. A fully enumerated Toolhelp snapshot is not a whole-machine access
  claim. SCM can omit inaccessible services; registry coverage is machine
  uninstall registrations in the disclosed views, excluding per-user, Store,
  portable and unregistered applications. Startup mode, executable paths,
  account identity, configuration and other service details require separate
  disclosure and are outside this work.
- Freeze one generation before transfer. Preserve capture start/finish, source,
  scope, field outcomes and count truth. Stable ordering must retain duplicate
  registration rows without inventing a cross-generation application identity.
  Denied/read-failed/changed/time-limited enumeration cannot become complete
  zero or a promoted prefix. A successful scoped zero requires positive complete
  enumeration evidence. Per-field denial is distinct from enumeration failure.
- Each section gets an independent identity/grant-bound durable sequence floor,
  deterministic generation binding, manifest digest, declared count and byte
  reservations. Chunks carry generation, manifest digest, index and count. A
  duplicate must be byte-identical; changed bytes at the same position fail.
  Promotion requires all rows, exact count/order and final digest, atomically.
  Failed/incomplete work retains the previous completed generation with its
  original age plus a separate latest-attempt status.
- Restart drains the protected original pending generation before recapture;
  lost acknowledgments replay the exact bytes and preserve original times.
  Revoke/disable suppresses capture and delivery without resetting sequence
  floors or adopting an uncertain store. Server authorization is rechecked in
  the same transaction as reads/writes. Re-enabling cannot refresh a dormant
  capture or grant it another lifetime. Old/expired pending generations fail
  closed under the original expiry; cleanup never resets floors.
- Operator cursors bind device, section, exact generation/sequence/hash, literal
  query, sort, row position, original expiry and current grant through an
  authenticated cursor. No page can splice generations. A replaced generation
  either remains available within explicit retired-generation grace or returns
  a restart-required error; it never silently reads the current replacement.
  Revoked/expired/unknown data is not an empty successful page. Search over a
  bounded scan may return an empty nonterminal continuation.
- Proposed fail-closed ceilings: 32,768 processes, 8,192 services, 32,768 machine
  registrations; 128 MiB total source work and 16 MiB encoded per section; one
  15-second cooperative collection attempt. Native API blocking/cancellation
  behavior needs independent verification; a cooperative deadline is not hard
  cancellation. No unbounded registry walk, SCM resume loop or goroutine escape
  is acceptable. Ceiling exhaustion records failure, never complete truncation.
- Proposed transport ceilings: 128 rows and 64 KiB fully encoded per chunk,
  whichever binds first; one shared 20-second/64-operation transfer burst.
  Proposed operator pages: 100 rows/256 KiB, 15-minute cursor/grace, original
  24-hour capture retention. Proposed store ceilings: three retained generations
  per section/device, 48 MiB per device, 128 MiB global, 200,000 reserved rows and
  4,096 chunks globally. These are rejection limits, not supported-size promises;
  lower byte/count limits may bind first. Reservations precede writes; admission
  failure cannot mutate the current pointer. Reuse reviewed physical DB/WAL
  admission only after proving its Windows authority integration.

Before publication, independently review the composed consent/native/wire/store/UI
slice and run invented 513+ row end-to-end TLS and signed-HTTP fixtures, loss and
exact retry, restart, revocation, expiry, source change, duplicates, denied fields,
complete zero, malformed chunks/cursors, budget exhaustion and prior-generation
preservation. Separately approved disposable Windows execution must verify real
LocalService visibility, paging, native bounded work and shutdown. A real manager
and hosted UI gate must prove generation-consistent display. No such new native
acceptance or runtime grant is claimed by this UI-only change.
