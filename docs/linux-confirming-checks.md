# Inspect Linux checks before an incident opens

Investigations exposes **Linux checks awaiting confirmation** when its current
authorized Linux source contains pending checks. It makes developing conditions
discoverable even when the incident queue is empty. This is separate from the
unknown-check coverage work in #273 and retained delivery outcome guidance in #269.

The expandable worklist groups confirming agent-contact, root-filesystem and
selected-service checks by exact device identity. Search names, identities and
check targets; narrow by check type; clear filters to return to all pending checks.
Duplicate names retain distinct identity-addressed Health links. These local
filters do not change incident filters or paging, and incident filters do not
narrow this source-derived worklist.

Pending is not an open incident or confirmed failure. The existing manager
evaluator owns confirmation. Neither its start nor remaining duration is exposed
by the source, so the view adds no countdown or inferred progress. Original
manager-evaluation and source-observation timestamps remain separate; contact
uses accepted-report receipt time. Root allocation is shown only when supplied.
Refreshing does not advance confirmation or make old evidence fresh. Unknown,
open and clear checks are excluded. A transition out of pending removes the row;
that disappearance alone is not a recovery claim.

The existing guarded and aged Investigations resource is the sole evidence
source. There is no additional reader, snapshot, persistence, collection, API,
policy, notification, acknowledgement, AI call or host action. Device metadata
only supplies display/search names for nonsynthetic LAN Linux devices already
in the authorized source. Session and authority-set changes reset local filters
and disclosures; source loss, lock and loss of all pending checks unmount the
panel. The source is bounded by the existing 25-device and ten-check limits.

EN/DE labels, native controls and disclosure elements, explicitly semantic lists,
decorative icons and visible focus outlines keep the interface keyboard-readable.
Source/DOM tests do not establish rendered mobile, screen-reader, native-host,
deployment or external-notification acceptance.
