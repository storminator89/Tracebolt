# Read-only journal page triage

Linux service Logs provides **Review this page** for both the original bounded
captured snapshot and scoped retained browsing. It organizes the already-loaded
display page only, at most 100 messages. It does not read another page, change
the source query, capture logs, or add access to an endpoint.

## Review a loaded page

- Select a severity button to show only that exact severity. Counts always cover
  the loaded display page, including messages currently hidden by this filter.
- Choose source order, oldest first or newest first. Original UTC timestamps,
  including sub-millisecond precision, are preserved. Equal-time occurrences
  keep their original result order and are never deduplicated.
- Choose **Group identical messages** to group exact displayed message text,
  severity and service. Each group shows its count on this page, earliest and
  latest occurrence on this page, and an expandable list of all occurrences.
  Result row numbers refer to the current filtered capture/source-query result,
  not a journal cursor or source-event identity.
- **Reset page view** restores all severities, individual messages and source
  order. These controls are independent of the existing source/capture search.

Grouping compares the already-masked display projection. Different original
messages can therefore look identical. A group is not one event, an incident,
a root-cause finding, a rate or a whole-journal frequency measurement.

## Boundaries and lifetime

Source coverage, partial gaps, retained-source continuation and the original
content expiry remain visible and unchanged. A local filter does not show that
the rest of the journal is empty or that an error has recovered. Counts do not
include undisplayed rows from the same capture, an earlier source page or older
retained entries. Continue using the existing paging and explicitly authorized
source-query controls to read other rows.

All content is derived from the current accepted page in memory. Filters,
ordering, grouping and expanded occurrence lists reset when the operator session,
device, request identity, snapshot digest, display offset or applied search
changes. Existing interruption, access loss, expiry and resource clearing remove
the triage view with the message page. A same-page status refresh does not clear
the operator's page controls or refresh content expiry.

There is no additional request, storage, persistent bookmark, clipboard/export,
AI analysis, notification, collection, permission or host action. Message text
remains inert text. Source search and new reads keep their existing independent
scope and authority rules.

## Verification

Model and interaction tests cover exact timestamp ordering, equal-time duplicate
occurrences, exact grouping, page-only counts, severity filtering, both languages,
inert markup, synchronous authority/page resets, resource clearing and zero added
request/action callbacks in both journal workflows. Existing journal regressions,
typecheck, production build and test-discovery checks are run separately. These
source and component checks do not establish browser or native journal acceptance.
