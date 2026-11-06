# Focus loaded incidents by device

The read-only incident work queue has a **Devices on loaded pages** disclosure.
It groups the rows admitted by the current platform, source, seen, outcome and
literal search filters. Select **Focus device** to inspect exactly one platform
and device identity in the existing queue; **Show all matching devices** removes
only that choice. Choosing a device collapses the overview and returns keyboard
focus to its summary so the focused queue is directly below. **Clear page filters** also clears device focus.

Each group shows the original separate episode count, open episodes, open unseen
episodes, check recovery/report resumption and closure without confirmed recovery.
These are counts of the matching loaded source pages, not whole-history totals,
current device health or correlated causes. Windows assessment and complete-service
episodes remain independent, including overlapping targets or local incident IDs.
Names never establish identity; platform and full device ID stay visible.

The selected device links to its existing exact-ID Health route. Following it does
not acknowledge incidents, configure monitoring, preview an action or grant any
new permission. Existing Health readers and authority checks remain responsible
for their own reads. No new request, capture, export, storage, timer or mutation is
introduced by grouping, focusing, clearing or disclosure.

The choice is memory-only. Source-availability, scope, session, page or filter changes, missing device
rows, lock loss, visibility loss, blur and navigation clear it. Private group data
is derived on every render from the existing guarded rows; no source snapshot is
retained. Existing partial/unavailable-source notices and source totals remain
visible. Device focus changes clear comparison choices and expanded comparisons.
Refresh and source paging retain their existing behavior.

This is a bounded device-triage workflow, not Datto feature parity or native
acceptance. Datto's device-centric Alerts and Device Summary workflows are a useful
reference: https://rmm.datto.com/help/en/Content/3NEWUI/Alerts/Alerts.htm

Focused checks: `cd web && ./node_modules/.bin/vitest run src/incident-device-focus.test.tsx --maxWorkers=1`.
TypeScript/build and existing incident/resource suites are separate checks. No
browser, screen-reader, real-session, endpoint, deployment or release acceptance
follows from source/DOM fixtures.
