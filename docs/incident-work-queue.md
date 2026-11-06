# Read-only cross-platform incident work queue

The authenticated LAN queue also offers an on-demand, read-only
[Manager status panel](manager-status-panel.md) for bounded core checks and
loaded certificate expiry dates. Its separate evidence never changes an incident
outcome or claims endpoint health.

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

## Investigate an exact retained episode

Each loaded row has an **Incident timeline** (**Vorfall-Zeitverlauf**) disclosure.
It presents the existing episode's retained checkpoints chronologically, with
both a local display date and the exact original UTC timestamp. Equal timestamps
retain their independent meanings; fractional timestamps keep nanosecond ordering.
This is not a continuous event log. Intermediate samples, raw history and missed
manager evaluations are not reconstructed, and checkpoint gaps do not prove an
uninterrupted failure.

- **Linux:** original opening, last retained incident evidence, any closure and
  acknowledgement. Disk/service evidence can predate manager confirmation, and
  the last incident evidence may be the final recovery sample. Contact history's
  last evidence timestamp is a **manager evaluation**, not an agent capture or
  report receipt. Its separate current check shows the original accepted-report
  receipt. No separate opening/recovery raw sample is invented.
- **Windows assessment:** last-bad capture where available, original acceptance,
  opening/last confirmation, recovery capture/acceptance and exact closure reason.
  Contact has accepted-report receipt timing, not an invented capture. Reports
  resuming is not a whole-host health verdict.
- **Windows complete services:** independent opening, last-bad and recovery
  generation references retain source kind, exact grant ID/revision, generation,
  sequence, manifest digest, capture start/finish, original acceptance/expiry and
  row count. A later current grant never replaces a historical reference.

The **Current check, separate from this episode** section cannot rewrite history.
A later good or bad check can belong to another episode or policy. Existing source
aging can only withhold current confidence and the qualified current generation;
historical checkpoints remain unchanged while their source reader remains
available. Seen never confirms recovery. Linux monitoring removal and Windows
policy changes are explicitly **closed without confirmed recovery**. Maintenance
is not reconstructed as an episode event; its domain-specific rules remain in
Health. The disclosures are manager-local views, not exports or security audits.

Expanding/collapsing a timeline, filtering and searching issue no new request.
Health links retain the exact device ID. Linux log links require the exact valid
unit name; following one uses the existing view's permission checks and may start
an already-authorized retained-log search. It does not grant a new capture scope
or service/action authority. No acknowledgement, action preview or execution is
started by the timeline. Existing session, navigation, visibility and source-loss
clearing removes its private content with the source rows.

## Find work on the loaded pages

The **Episode outcome on loaded pages** filter separates still-open episodes,
selected-check recovery/reports-resumed outcomes and administrative closure without
confirmed recovery. This presentation does not add a shared lifecycle or modify
source totals. The displayed outcome counts describe only the rows currently
shown after all local filters, not source-wide counts or a fleet verdict.

**Search loaded incidents** matches literal case-insensitive text in the existing
device name/identity, source/platform, incident identity/key and check target.
Input is limited to 160 characters. It does not interpret regular expressions,
search AI prose or log content, fetch more pages, or persist the query. **Clear
page filters** resets only these local filters; source scope and independent
source paging remain unchanged. Refresh still restarts each source at page one.
A zero-match result leaves missing source coverage explicitly unknown.

## Focused timeline checks

`cd web && ./node_modules/.bin/vitest run src/incident-timeline.test.tsx`
uses synthetic Go-derived source fixtures and a DOM component harness, not a
browser. It covers original contact/source meanings, delayed and simultaneous
checkpoints, fractional ordering, independent current evidence/grants, closure
versus recovery/seen, stale/invalid elapsed time, safe EN/DE text and exact links,
literal bounded search, repeated disclosure, filter/reset/refresh, source loss
and zero additional requests or mutations. The existing queue/workspace/resource,
navigation and Windows inbox regressions remain relevant. Typecheck, environment
classification and production build are separate checks. No native or browser
acceptance, deployment, release or full-repository pass follows from these tests.

## Compare exact episodes

Select two to four visible episodes with **Compare episode** (**Episode
vergleichen**), then open the comparison. Each selected episode retains its
source-qualified identity, device, check target, native outcome, original source
read time and separate current check. Its existing detailed timeline remains
available. The combined chronology labels every checkpoint with its owning
episode and source. Equal timestamps are retained independently, and ordering
preserves the source's UTC precision through nine fractional digits.

This is a live, read-only comparison of the current source pages, not a pinned
snapshot, a merged incident or a correlation engine. Source clocks can differ.
Time order or overlap does not establish a shared cause, uninterrupted failure,
complete evidence, or remediation. Seen remains independent of recovery, and
administrative closure never becomes confirmed recovery. Current evidence can
age to unknown without changing the retained episode or its original checkpoints.
No raw samples, AI text or log content are added.

Selection stores only the exact opaque row identities in component memory. Page,
source-scope, local-filter, search and session changes clear it. Losing a source
or an exact visible episode removes the affected choice, with no automatic
reselection when the source returns. An ordinary live refresh keeps choices only
while the same exact episodes remain visible, then displays the refreshed source
projection. Closing and reopening the comparison does not make data younger.
Removing a choice below two closes the detailed comparison. Four choices never
silently replace one another. Nothing is persisted, exported or transmitted, and
selection, removal, opening and closing start no requests or mutations. Existing
Health/Logs links keep their original permission and collection boundaries.

`cd web && ./node_modules/.bin/vitest run src/incident-comparison.test.tsx`
covers source-domain collisions, bounds, nanosecond/tied chronology, original
provenance, stale current evidence, exact selection across live refreshes,
source-loss pruning, session/page/filter/search changes, repeated choices,
close/reopen/remove/reset and inert EN/DE rendering. These are synthetic component
checks, not browser or native acceptance.

## Find episodes by their separate current check

**Current check on loaded pages** (**Aktuelle Prüfung auf geladenen Seiten**)
filters the loaded episode rows using the same current-check projection as their
existing timelines. Options are all current checks, missing or stale evidence,
current attention, awaiting confirmation, and monitoring disabled or removed.

This is independent of the episode outcome and seen status. An old open episode
can have unknown current evidence; a recovered or administratively closed
episode can have a different current check. No filter turns a current value
into evidence of that episode's recovery or uninterrupted failure. The disabled
or removed option keeps those two native reasons intact in each timeline.
An absent device remains unknown, not an inferred monitoring removal.

Only rows from the current source pages are eligible. Filtering cannot reveal
unloaded episodes or individual devices from an unavailable source. Existing
partial-source notices and source totals remain visible, and zero matches never
prove whole-fleet health or complete monitoring coverage. The Linux source's
existing aging and the Windows source's original validity deadlines remain
authoritative. No extra timer, reader, snapshot, storage or action is introduced.

Changing this filter clears exact comparison choices as other page filters do.
If aging or source changes remove a matching row, its choices and disclosures
disappear; later evidence does not reselect it. **Clear page filters** restores
all current checks without changing source scope or paging. Refresh and paging
keep the selected filter, while remounting the queue restores all checks.
The filter has a visible label and native keyboard control; its icon is decorative
and non-focusable. EN/DE copy explains the episode/current-evidence distinction.

`cd web && ./node_modules/.bin/vitest run src/incident-current-check-filter.test.tsx`
uses synthetic contract-validated source fixtures and DOM interactions to test
current-state/outcome independence, source aging and loss, native disabled versus
removed states, filtering/reset, exact choices, repeated interactions and no
requests or writes. These checks do not establish browser, screen-reader, native,
deployment or release acceptance.
