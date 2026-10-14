# Overview working start

This is a presentation-only slice of the approved Tracebolt redesign. It keeps
local Inter, semantic light/dark colors, the existing shell and all routes.

## Information order

- Overview heading and unchanged inventory entry.
- Source context and the exact `Overview.generatedAt` timestamp, labelled
  **Overview generated**. This is not endpoint freshness or health.
- Genuine empty LAN source: left-aligned device-setup entry, with the same
  capability checks and existing focus destination. A retained empty response
  during refresh/failure still renders its established loading/error state.
- Existing open cases. Linux Health incidents remain their own source;
  Windows incidents retain their existing separate Devices destination.
- Existing fleet counts, compact inside the fleet comparison; exact source
  values, unchanged filters and sort. Unknown investigation count stays `—`.
- Independently owned application checks, unchanged and still mounted when
  the fleet is empty. No automatic check activation or new read is added.
- Recent activity, visually secondary.

The redundant zero-row fleet table is omitted for empty LAN sources. Open
cases and checks are not omitted or inferred from the device count. A populated
fleet with no open cases is a different tested state.

At narrow widths the overview table repeats the existing source and ReportTime
below device identity because the desktop time column is hidden. Exact capture
times, zero-report and unavailable distinctions are inherited from ReportTime.
The Devices inventory does not receive this extra row.

## Design contract

Modern-minimal operational workbench: readable left alignment, one primary work
section, compact contextual counts, quiet dividers, no illustrations or motion.
Existing Inter and semantic palette take precedence over Hallmark's catalog
font/theme rotation. The new typography/spacing roles live in `web/src/tokens.css`;
only `.overview-workspace` uses them. This slice does not migrate global CSS.
The eight interaction states remain owned by the existing controls. Navigation
never adopts optimistic writes, unchecked approvals or implicit recovery.

No new routes, endpoint queries, counters, refresh timer, data model, OS policy,
authorization, enrollment, consent, identity binding or operational action is
introduced. Data/resource owners and callbacks remain in App and the original
panels. No parked manager/agent fixes, release bytes or global numeric/focus
changes are included.

## Checks and honest limits

- `web/src/overview-workspace.test.tsx`: actual App composition, EN/DE,
  open/no-open/unavailable work, first setup with independently active checks,
  retained loading/error and timestamp semantics, keyboard route/filter entry.
- Existing first-device, navigation, components, investigations and application
  checks suites guard the unchanged source/consent/lifecycle boundaries.
- `tests/e2e-review/overview-work-start-browser.test.mjs`: synthetic-only input
  boundary, no-open-work projection and capture wiring contract.
- Existing concise-shell gallery adds exact before/after filename-compatible
  1440/390 captures, light/dark keyboard focus, source/report visibility and
  CSS-viewport reflow at 320/375/414/720/768. The 720×500 scene offers the layout
  space associated with doubling a 1440×1000 CSS viewport; it is not native
  browser zoom. No deviceScaleFactor/pageScaleFactor substitutes for zoom.
- Existing first-device captures retain the original 1440/390 EN/DE filenames
  and add dark and 320 CSS px scenes plus DOM-order/left-alignment/absent-zero-table assertions.
- Loading, initial fetch failure, retained refresh failure and populated/no-work
  are separately intercepted synthetic-only states. Capture cleanup restores
  the original fixture; no new test cases or suite result schema are added.

The capture helpers have not been run locally. Hosted browser execution,
independent pixel review, actual browser 200% zoom, text-resize, Forced Colors
and screen-reader checks remain acceptance gates, not implied by jsdom/source
checks or an inherited screenshot.
