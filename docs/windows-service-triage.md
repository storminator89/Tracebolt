# Review captured Windows services

The bounded Windows Services preview offers five local review presets: all
captured rows, stopped services, services in a transition, automatic startup plus
stopped state, and unknown startup configuration. Use the existing text filter
and sort to narrow a preset, then review at most 25 matching rows per page.
Preset counts cover all captured rows before text filtering; they are not counts
for the complete service generation or the whole device.

This is private, read-only review of already admitted evidence. It makes no new
requests, persists nothing, grants no scope, performs no action and exports no
names. The independent complete-service inventory, alarms and action approvals
are unchanged. Metadata remains bound to its original base row index, generation,
row count and digest. Duplicate names are not merged, and PIDs do not join other
sources. Missing, trimmed, denied or unavailable startup metadata stays unknown.
A known automatic mode remains known when only delayed-auto status is unknown.

The automatic-and-stopped preset is a troubleshooting lead, not a fault finding.
Startup and state are captured separately, not atomically; delayed and triggered
starts may be normal. No failure, boot outcome, dependency or remediation is
inferred. In-transition covers only the four observed pending state codes;
paused, running and stopped do not become pending because of their names or PID.

Presets intersect the existing literal text filter and preserve the selected
sort. Choosing a preset returns to page one. All captured removes only the preset
and leaves text and sort intact. Source counts, truncated coverage and stale
warnings remain visible. Controls follow the existing device/session, tab,
original-generation, navigation/visibility and expiry cleanup; same-source
loading hides rows and controls without extending their original lifetime.

Datto's [Agent Browser tools](https://rmm.datto.com/help/en/Content/5AGENT/AgentBrowserTools.htm)
include service inspection/control and task termination. This increment improves
Tracebolt's captured-service inspection only. It does not provide process
termination, service start/stop, unattended remediation or Datto control parity.
Those operations need their own explicit authority and native acceptance.

Source/DOM tests and a frontend build do not establish native Windows reads,
real-browser accessibility, deployment or release acceptance.
