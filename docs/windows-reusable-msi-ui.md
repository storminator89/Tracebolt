# Fresh reusable MSI jobs: operator UI

See the [core reusable contract and fresh setup](windows-reusable-managed-msi.md).

This is a source candidate for explicitly fresh reusable grants. Existing singleton
v1 and fleet v2 workflows retain their original wire fields and one-package limits.
No previous grant is promoted, and UI/source fixtures establish no native acceptance.

## One deliberately reviewed job at a time

The existing fleet worklist recognizes only the strict v3 shared artifact projection
with `reusable: true`. Its upload review JSON additionally requires `publisherStatus`
(`unsigned` or `unverified`) and a `publisherEvidenceDigest`. A reviewed digest never
claims a verified publisher, trusted signature or safe custom action. Reservation
uses `/api/windows-managed-msi/artifact/reserve-reusable`; v2 continues to use
`/reserve` with its unchanged body.

Every device retains separate unchecked delivery, package/risk/terms/maintenance
review, synchronous-action review, readiness and installation approval. The frozen
reference includes the complete package, artifact, target binding and publisher
review evidence. An observed change disables the old reference instead of silently
selecting another package. No automatic next device or next job is scheduled.

## Review the result before retiring bytes

A reusable device displays its original consent expiry, job sequence, retired floor,
publisher truth and at most eight recent retired summaries. Hashes and retained
result/retirement evidence remain in initially collapsed details. Native result and
machine-registration truth remain independent. Unknown returns, unexpected restart,
unverified 3010 registration or unresolved shared ownership cannot retire a job.

Only `canRetire` with a settled result, fresh exact idle-owner evidence and unexpired
original consent exposes an initially unchecked result-review acknowledgement. The
explicit device retirement request binds artifact ID, binding digest and result
digest. A pending or unconfirmed response permits read-only reconciliation of that
same job; it cannot retry installation or unlock a different job. Retirement pending,
retired and intervention-required states remain visibly distinct.

The shared payload action is separate and initially unchecked. Its current v3
`canRetire` and `retirementBlocked` projection reports whether all actually assigned
device jobs have retired. The server rechecks this before accepting the action.
Only a confirmed shared retirement makes the next reviewed package upload available.
Selecting a file still starts nothing. The operator must explicitly upload B, freeze
a new device selection and approve every phase again.

Retirement removes only app-owned package payload. It never uninstalls, cancels,
rolls back, renews consent or resets replay floors. Installation approval cannot be
recalled here. Uncertainty retains custody/evidence and blocks another job. Payload
custody is bounded to 128 MiB on each side, 256 MiB for a manager plus one endpoint;
eight recent summaries and the retirement chain remain retained.

## Source verification and browser evidence

`web/src/windows-reusable-managed-msi.test.tsx` covers strict publisher/schema truth,
explicit result-bound retirement, fresh owner/session/capability checks, uncertain
responses, late responses, shared eligibility, bounded history and manual B upload.
Existing fleet v2, singleton MSI and mutation/status regressions remain required.

`node web/scripts/capture-windows-reusable-msi-fixtures.mjs --check` validates four
invented states and fixed GET-only route isolation, and compiles the production App
in memory. It starts no browser/server and captures no screenshot. The exported
capture function accepts an already-authorized browser for EN/DE 1440px/390px
retirement-review, retired, next-package and intervention scenes. It never launches
a browser and rejects all manager mutations/external requests. Use the exact-source
Checks and retained screenshot/manifest artifacts to establish actual rendered
viewport evidence; source compilation alone does not establish it. The separately
approved Windows native setup/package/retirement acceptance gate remains pending.
