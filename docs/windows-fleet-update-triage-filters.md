# Local Windows fleet update triage filters

The manual Windows fleet worklist can filter and order its already-read cached
update groups. This is a presentation aid, not a new patching policy, online scan,
compliance score, or update permission. The existing
[per-device review and approval](windows-selected-update-jobs.md#manual-fleet-worklist-and-saved-outcomes)
remains authoritative.

## Operator behavior

After deliberately reading cached updates for the frozen Windows device selection:

- Search retained titles, KBs, update GUIDs, revisions and reported severity text.
- Filter reported vendor severity, including explicitly unspecified severity.
- Filter the source row's downloaded or not-downloaded flag.
- Order by exact GUID/revision, highest reported vendor severity, or number of
  reporting devices. Exact GUID/revision breaks ties; unspecified severity is last.
- Reset the view locally to all groups, default ordering and the first page,
  returning keyboard focus to search.

All filter predicates must match the **same original device report**. A critical
report on device A and a downloaded low-severity report on device B do not together
match "critical and downloaded". A matching card still retains every original
report for that exact GUID/revision. Its device and downloaded counts do not shrink
to the matching rows. Highest-severity ordering uses every retained original
report, even when another report made the group match the filters.

Filtering does not change the selected update or its reporting-device selection.
If filters hide a currently retained selected group, the view explicitly says the
selection is unchanged. Each device still requires its own current exact review
and approval. There is no batch approval or download/install action in the filters.

The matching-group count is separate from the source read, partial/truncated,
stale and unavailable counts. Those source counts remain visible when no group
matches. Empty results do not establish compliance, and a cached download flag
does not establish current installation readiness.

## Boundaries and evidence

The filter state is component-local and uses only the existing bounded in-memory
reports. Search, filtering, ordering and resetting make no requests and store
nothing in the browser. New reads and the existing cancel/clear lifecycle reset
the view. Existing loss-of-focus, navigation, session and retention handling clears
the report-backed controls and their filter state. No API, resource, collector,
source age, grant, worklist target, schedule or mutation behavior changes.

The original maximum of 50 devices, four simultaneous reads, five-minute memory
retention and original capture-age limit are unchanged. This remains bounded cache
evidence; it is not a fleet-wide completeness or real-time claim.

## Targeted validation

`windows-fleet-update-triage-filters.test.tsx` covers same-report conjunction,
original-group preservation, literal search, deterministic ordering, unspecified
severity, bilingual controls/counts, local reset/focus, hidden selection notice,
GET-only reads, private-state clearing and unchanged source warnings. The existing
resource suite covers its unchanged read/expiry fences. The worklist integration
suite checks that filtering a mixed-severity group still preserves both reporting
devices and their independent exact scheduled approvals and uncertain-write rules.

These are source and synthetic UI checks. They do not establish browser rendering,
native Windows/WUA acceptance, deployed behavior, release readiness or compliance.
