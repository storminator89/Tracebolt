# Read-only cross-platform incident work queue

In LAN mode, **Investigations** (`#/cases`) brings together existing Linux Health
incidents and the combined Windows incident inbox. The original Windows inbox
under Devices remains available for separately authorized acknowledgement and
service-review work. The queue does not create another incident lifecycle.

## Bounded source pages and honest counts

**Open** requests Linux `open` and Windows `active`; **All retained** requests
`all` from both sources. Recovery, monitoring-stopped closure and Windows policy
changes retain their native meanings. Seen never means recovered or resolved.

Each source has independent coverage, read time, totals and paging controls:
50 Linux rows or 25 Windows rows per source page. Only those two current pages
are merged by original opening time, with source-qualified identity as the stable
tie-breaker. This is live paging, not a pinned snapshot or global newest-first
pagination. Refresh restarts both sources at page one.

**Platform, source and seen filters apply to loaded pages only**, not the whole
retained history. Displayed-row counts are separate from source totals. Browse
other source pages for more history. Device-table search and fleet-group filters
do not narrow this fleet-wide queue. A zero displayed-row count is not a
whole-fleet health verdict.

An unavailable, expired or invalid source stays unknown. Its rows and counts are
not replaced with empty success. If the other source is available, its rows remain
visible with a partial-coverage notice. Source coverage is explicitly qualified
by its own read time. The overview count remains Linux Health only, and the
navigation badge labels that limitation.

## Existing boundaries remain authoritative

The queue uses the existing private GET projections, strict parsers and resource
hooks. No backend API, collector, evaluator, policy, permission, notification,
acknowledgement, AI request or action preview is added. Windows is explicitly
configured read-only even for a shared administrator. Its row presentation omits
both acknowledgement/service-review controls and their embedded review readers.

Linux identity includes its device, incident, check and original opening time.
Windows retains its opaque original-identity target, exact domain and explicit
assessment or complete-service source kind. Mutable names and matching local
incident IDs never merge independent domains. Complete-service opening, last-bad,
recovery and qualified-current provenance remain independently expandable.

Original observation, confirmation, capture, receipt, evaluation, closure and
seen times are never refreshed by queue reads. Existing Linux cross-page clock
lower bounds and Windows authority/current-source deadlines remain intact;
current unknown evidence cannot recover retained incidents. Session, visibility,
logout and route guards remain owned by the existing readers. One session-bound
Linux workspace reader supplies both Overview and the queue, retaining the same
open query, original clock lower bound, navigation badge and recent Settings
readiness. The Overview shortcut resets retained-history filters and Linux paging
to open page one. The parent remounts the Windows queue reader by actor, session
and navigation revision; leaving both incident views suspends the Linux reader.

Health links use the existing identity-addressed device routes. Linux service-log
links retain exact journal-unit validation and do not start a log capture. Manager
readiness and configured capability descriptions never substitute for incident
source authority, freshness, coverage or recovery evidence.

## Small targeted checks

`cd web && ./node_modules/.bin/vitest run --config vitest.incident-queue.config.ts`
runs six Node-only contracts using synthetic source fixtures and static React
markup. They cover exact scope mapping, source identity collisions, counts,
page-local filters, partial results, evidence aging, inert names, deep links and
read-only controls. TypeScript checking is separate. These checks use no browser
or DOM harness and establish no native collection, installed-service acceptance,
hosted CI, deployment or release readiness.
