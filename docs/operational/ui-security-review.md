# Operational panel: isolated UI review

Date: 2026-10-03. Scope: the operational component, decoder, scoped CSS and
component tests. The reviewed consent ID is `managed-operations-v1`; the snapshot
schema and implemented collector remain Linux-only. This review does not
establish main-application, authenticated API, retention or browser integration.

## Verified boundaries

- Responses bind the requested device, known schema/profile and section
  generations. Unknown fields and malformed required values fail closed, with
  fixed local errors and no synthetic fallback.
- Decoder checks preserve meaningful null/unknown/denied/partial states, event
  aggregate counts, bounded safe numbers/strings, retained chronology and encoded
  size limits. A combined 128 KiB client consistency limit supplements 48 KiB
  snapshot/section limits; it does not implement backend storage quotas.
- Future timestamps cannot become fresh by clamping their age to zero. Freshness
  uses a server-time anchor and monotonic elapsed time, not the browser wall clock.
  Hiding/suspending the page invalidates that anchor; restoration requires a new
  read. A response started before suspension cannot restore it.
- Old device/request results are not promoted into the current view. Last-good
  sections are explicitly retained/stale evidence with their original metadata,
  not a merged fresh snapshot. No update/CVE information is shown as zero or safe.
- Metadata remains text. The isolated component has no HTML-rendering,
  external-link, AI/provider, browser-storage or data-export sink.
- English/German notices describe agent-visible namespace limits, partial
  journal coverage and loaded system-service scope. Collection availability is
  not represented as whole-device security health.

## Review fixes

The initial decoder rejected legitimate non-service journal unit types.
Independent regressions also caught future-time freshness, pre-response
pagehide/persisted-pageshow races, incomplete metric combinations, incorrect
grouped-event counts and missing retained-section bounds/chronology checks.
Those regressions now pass. Positive controls verify that each fixture starts
from a valid response and that truthful partial samples remain accepted.
No authentication bypass or external exfiltration was demonstrated by these
component defects.

## Evidence and exact files

Independent checks passed on the final isolated slice:

- 99 focused tests: 55 owner tests plus 44 independent regressions;
- typecheck;
- complete then-current web suite: 226/226;
- production build.

The five component/test hashes stayed unchanged during the full rerun:

- `operational.tsx`: `6e7c7e83d21208976cfa524b663b6fc05c9c9a199c2e4cdbec0e338f1bae51ea`
- `operational-types.ts`: `c4ead6a74372538ba00346b2633fea9a6339a5cdd0a7843b42bef73984af20c2`
- `operational.test.tsx`: `195be3b10e1493cafe0d260030efd7e430443ac043d3269d764634e0ee166a58`
- `operational.css`: `5ff09109a87d49e9944dd49687fc50a4e84def5a14766d8829265bb3d6f0278b`
- `operational-security-review.test.tsx`: `43a34a638ba34a1544db9b7809a4624a993bf31d4a008e2058d57009a8c75cc3`

The component was isolated from the application at this checkpoint; a successful
build is not evidence that the new view was reachable in the shipped bundle.
Later main-drawer/enrollment-consent changes require their own matching tests.
All data here was synthetic component/mock data. No real browser or operational
inventory was collected for this review. Real-handler/native/browser acceptance,
fresh-profile authorization and atomic backend quotas/expiry remain separate
gates.
