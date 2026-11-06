# Shared parent PID references

The complete Windows process inventory offers a collapsed **Shared parent PID
references** disclosure. It groups two or more rows with exactly the same reported
parent PID on the currently admitted page. Groups follow the first member's
server order; members retain that order, original name, snapshot PID and thread
count. Missing names stay unavailable. PID zero has no special root meaning.

This is a diagnostic aid for inspecting repeated captured references, not a
verified process tree, family, parent identity or live relationship. PIDs can be
reused. It does not look up parent rows or join another generation, the bounded
preview, metrics, service inventory or network observations. No CPU/RAM totals,
process control or inferred application health are added.

Only the existing page of at most 100 rows is used. Search and paging can split
groups; counts are rows on this page, never endpoint-wide totals. Empty groups
mean no repeated value on this page, not an absence of related processes.

Native disclosures and English/German copy keep the default view compact.
Changing the admitted source, query, sort, page or rows resets disclosures.
Closing the outer disclosure removes the group view. The existing inventory
owner clears the component on drafts, refresh/loading, tab/device/session changes,
privacy interruption, source loss and original expiry. No source lifetime changes.

No request, endpoint, parser, collector, grant, storage, export, clipboard,
timer, dependency or host change is introduced. Fixture/DOM checks are not
native Windows, real-browser, accessibility-device, deployment or release
acceptance. See [the source contract](windows-full-processes-contract.md).
