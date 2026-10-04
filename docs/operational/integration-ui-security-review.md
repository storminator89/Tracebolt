# Operational UI integration: boundary review

Date: 2026-10-04 UTC. This review covers the device inventory drawer and fresh
enrollment consent for `managed-operations-v1`. The implemented operational
collector and accepted snapshot remain Linux-only. This is source and component
test evidence; real-browser, native transport, storage and installed-service
acceptance are separate gates.

## Exact candidate

The final 15-file `operational-integration-v2` candidate supersedes the original
v1 candidate. Its immutable JSON manifest has SHA-256
`120be5c04f29da60fb788a0f6df07e9501b93830b521e81e3debd3df4ac1217a`.
The same per-file hashes are recorded in
[`integration-ui-source.sha256`](integration-ui-source.sha256). All 15 source
and test files matched before and after independent validation.

The previously reviewed isolated panel and decoder are unchanged; their detailed
sampling, freshness and rendering boundaries are described in
[`ui-security-review.md`](ui-security-review.md).

## Boundaries checked

- The inventory panel is mounted only for the appropriate LAN Linux/awaiting
  device and selected inventory tab. Tab, device, route and session changes
  cancel old reads; unsupported sources do not silently fetch substitute data.
- Enrollment accepts the exact known collection profile and privacy metadata
  pair. Malformed or unknown current configuration disables creation.
- Managed-profile enrollment requires a fresh unchecked acknowledgement of the
  expanded metadata scope. Basic enrollment preserves its original two-field
  request; managed enrollment adds only `collectionAcknowledged: true`.
- The returned invitation must match the selected profile and trusted context
  before a secret is displayed or a public bootstrap is offered. Closing or
  hiding the view resets consent and removes the displayed secret.
- Record approval and termination remain revision/context-bound. Uncertain
  mutations are not automatically repeated and closing a dialog does not imply
  server rollback.
- Text remains inert React content. Operational metadata is not added to AI
  requests, browser storage or the public-bootstrap export. Metadata labels may
  themselves be sensitive; this UI is not a secret-removal mechanism.
- English/German scope notices explain agent-visible namespace and loaded
  system-service limitations. Unknown update/vulnerability assessment and
  retained/stale observations are not presented as a clean security assessment.

## Finding and verified repair

The original v1 integration had one stale-configuration/consent defect. After a
managed creation dialog was acknowledged, a failed or malformed periodic
configuration read disabled the outer toolbar but left the existing dialog's
old consent and clock usable. An already pending creation response could also
restore its secret after invalidation. Independent tests reproduced missing
privacy metadata, unknown profile, failed reads, pending creation, late success
and recovery/out-of-order read variants. This did not demonstrate a server
authorization bypass; the server still enforces its configured profile.

V2 synchronously aborts the old configuration context, clears data and clock,
closes the dialog, and prevents stale mutation results from restoring a secret
or export. Pending actions retain an explicit ambiguous-outcome notice. A fresh
valid read creates a new context; reopening requires fresh unchecked consent.
Older reads cannot restore a newer invalidated context. The equivalent pending
record-action edge is covered as well. The original failing assertions were
preserved and pass against the repaired candidate.

## Independent evidence

- Targeted integration suite: **73/73 tests passed**, four files.
- Complete frontend suite: **269/269 tests passed**, twelve files.
- TypeScript typecheck and production build: passed.
- Frozen/live source and test hashes before and after validation: identical.
- Independent integration file: 24 tests,
  `web/src/operational-integration-security.test.tsx`, SHA-256
  `daa9cfe41c0847bd8bbab85ecd97e8f5d96f2b0b0f045c61e1782258770a3a4a`.
- Repaired `web/src/enrollment.tsx`: SHA-256
  `74bc4e1998371c36f53fa910bdb757930952510b89e3feca0f58f242454b0047`.

These checks use synthetic mocked component responses in JSDOM. They do not
establish browser layout, actual browser transport, real machine inventory,
deployment, or production security. The combined operational backend and
exact-source hosted browser gate must be reported separately. Previously
quarantined enrollment-browser cases are not restored or counted as passing by
this component review.
