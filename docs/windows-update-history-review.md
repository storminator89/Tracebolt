# Review retained Windows update events

In a Windows device's **Updates → Patch context → Details**, the existing
retained-history table now has compact English/German review controls:

1. Choose an exact result, such as **Failed** or **Succeeded with errors**.
2. Optionally narrow to installation/uninstallation, enter a title, update ID
   or HRESULT, or select an inclusive UTC date range.
3. Review twenty events per page, newest or oldest first. Expand an event's
   details to see its original update ID and revision. **Clear filters** resets
   all controls and returns to the first page.

Search is a literal case-insensitive substring, not a regular expression or
wildcard query. A full eight-digit HRESULT also accepts a leading `0x`. Dates
refer to recorded event times in UTC, not the manager's receipt or capture time.
The start and end days are both included; a reversed or invalid range produces
an explicit correction message, not a successful empty search. Displayed event
timestamps continue to use the interface's normal date formatting.

## Evidence and scope

This is local review of the already authorized
[`windows-patch-context-v1`](windows-patch-context.md) snapshot. It adds no API,
request, collector, grant, monitor, retained history, export, AI input, action or
host change. It does not search beyond the existing maximum of 64 retained rows.
Source retained counts and incomplete/truncated-history warnings remain separate
from the number matching the filters and the current page.

Repeated events for the same update ID/revision remain distinct. The original
WUA source indexes preserve source order, including equal-time events. Result
codes and outcomes remain literal observations; no later success is inferred
to resolve an earlier failure. A failed historical event does not establish a
current fault, and a successful event does not establish current installation.
No matching row does not prove absence, success or complete patch coverage.

The controls and query exist only in component memory. They are discarded when
the original resource disappears, including its existing refresh cycle, a
navigation/access/visibility interruption, error or expiry. A different device,
grant or source generation starts with clear controls. Existing current and
previous captures remain separate panels; neither comparison nor merged history
is introduced. Original 24-hour privacy expiry, current source/identity/session
checks and stale/partial/unavailable states are unchanged. Filtering never
renews an evidence timestamp or causes a new request.

The current source remains distinct from released endpoint packages. Focused
model/DOM tests, TypeScript and a frontend build do not establish browser pixels,
native Windows provider access, deployment or release acceptance.

## Product reference

Datto's [Patch Management Activity report](https://rmm.datto.com/help/en/Content/3NEWUI/Analytics/Reports/Reports.htm)
supports date-range and failed/succeeded filtering. This smaller private workflow
provides comparable review controls over Tracebolt's existing bounded on-device
observations. It is not a fleet report, scheduled report, export or full patch
management implementation.
