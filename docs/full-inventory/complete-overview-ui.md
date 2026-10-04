# Complete process and mount UI (held candidate)

The authenticated device Inventory workspace defaults to **Processes**, followed
by **Mounts**, Packages, Services, Connections and the secondary Bounded preview.
The software overview count and direct Packages route remain intact. Existing
operational-preview tests explicitly select the preview before testing that lane.

## Data contract and display

- GET `/api/devices/{agent}/inventory/overview` reads independent process and
  volume status metadata. It never starts a capture.
- JSON POST `/api/devices/{agent}/inventory/overview/query` requests the selected
  section, exact generation, opaque cursor, search and a limit of 100. Searches
  and cursors stay out of URLs and use the existing session/CSRF helper.
- A page is at most 100 rows and may be smaller due to response byte limits.
  A server search scans at most 2,048 rows per request. An empty non-exhausted
  page is a continuation, not proof of no matches. Whole-generation counts,
  cumulative scanned counts, matches found so far and current-page rows are
  separate. Refresh explicitly restarts paging and clears the search.
- Pages pin the original section binding, manifest, capture interval, completion
  time, retention deadline and cursor deadline. A newer section generation does
  not silently replace the selected pages. Section captures can differ; mixed
  captures and their original times are labelled.
- Process rows include PID, name, state, parent PID, resident bytes, cumulative
  CPU seconds and thread count. Missing fields retain the observed PID and
  explicit denied/exited/invalid/unsupported/unavailable outcome. Numeric zero
  is displayed as a value. Successful zero enumeration is distinct from a
  missing or rejected capture.
- Mount pages preserve the server's order: measured local, unavailable local,
  memory-backed, remote, unclassified and virtual/pseudo filesystems. Group
  headers explicitly refer to the current page. Virtual capacity is N/A,
  zero measured capacity remains zero with N/A percentage, and denied or
  unsupported measurements are labelled separately. Filesystem groups are
  shown without capacity totals; equal or layered groups can overlap.
- This is the agent-visible Linux namespace, not physical-host process/disk
  coverage. Enumeration counts and field-availability counts are distinct.
  Failed/pending latest attempts do not update retained capture ages.
- Legacy bounded process/volume samples remain secondary and cannot establish
  absence. They are not relabelled as complete generations.

## Lifecycle boundaries

No row cache survives section, device or session identity changes. Protected
request epochs, abort controllers, request timeouts, visibility, focus, BFCache,
navigation and auth invalidation clear private rows and suppress late results.
Clock disagreement, server-time rollback, original retention expiry, cursor
expiry/repetition/renewal, binding changes and malformed responses fail closed.
There are no AI, export, install, scan or collection hooks in these components.

## Synthetic verification

The exact Go-encoded fixture is
`internal/api/testdata/complete-overview-synthetic.json`, maintained by
`TestCompleteOverviewGoldenFixture`. Browser type tests import that encoding
rather than guessing DTO names. ASCII search match validation follows Go simple
lowercase, including U+0130, and an already-expired late upload retains its
original deadline even when that deadline precedes upload start. Additional invented fixtures cover 350 processes,
85 mounts and a 2,200-row search spanning scan windows. Coverage includes row
outcomes, zeros, grouping, independent capture ages, old-complete/new-failure,
pending transfer, expiration, auth/CSRF, bounded responses, section/device/session
changes, visibility/BFCache, cancellation and clock rollback.

The existing locked dependency tree was reused only after the package-lock files
matched. Commands use installed tools with explicit npm offline mode and update
notifications disabled; no installation or audit was performed. Local browser,
real host collection and deployment were not run. The existing v3 browser harness
has only its two source-navigation assumptions updated and syntax-checked; it is
not evidence of an executed browser gate for this candidate.
