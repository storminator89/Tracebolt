# Fresh reusable central MSI jobs

Source candidate only. No native Windows setup, installer call, credential, ACL,
SCM or host grant was performed by the source fixtures. Exact-package approval
and separately authorized native acceptance remain required.

## Fresh consent and setup

The manager prepare/finalize CLI accepts `--fleet --reusable-jobs` for a fresh
v3 registry. Retain these same flags and original protected LAN inputs through
both phases. It emits the new v3 public offer. This offer requires the fresh
coordinated MSI/cached-WUA endpoint setup; standalone setup cannot apply it.
Existing singleton, prepared and fleet-v2 state is never adopted or promoted.

The paired endpoint plan names separate delivery/install permissions, original
identity and absolute expiry, LocalSystem/network/custom-action risk and repeated
central selection. Apply requires `--acknowledge-reusable-managed-jobs` in place
of `--acknowledge-one-managed-install`, alongside the existing separate delivery,
coordinated-mutation, update, LocalSystem, relay and process-query acknowledgements.
All start/activation operations retain their own explicit approval gates.

V3 offer, registration, manager/service config and service receipt versions are
separate. The v2 shared fence uses a versioned plan, roster and activation. Its
participant digest pins the full fresh grant. Existing versions retain their JSON
bytes. Per-job signed permits and reports use the distinct reusable-v3 signature
domain. No renewal or migration is performed by retirement.

The bounded [recent-package chooser](windows-software-catalogue.md) reuses exact
current/recent review metadata. Missing payload bytes always require explicit re-upload.

## One job at a time

Upload one reviewed x64 machine MSI, then explicitly deliver it to one named
endpoint. Each package fixes complete selection, terms-review reference, package
hash, native-acceptance digest and publisher-evidence digest. Publisher status is
an operator-supplied `unsigned` or `unverified` review label. Tracebolt does not
validate an Authenticode signer or assert verified publisher trust.

Delivery does not accept terms or approve execution. Review, fresh readiness and
one named installation approval remain separate for every package. Grant-wide
JobSequence increases monotonically; readiness refresh Sequence is independent.
No group, queue, saved history or earlier package approval approves another job.
Unselected device Y receives neither a transfer nor a package.

Repeated uploads of the same reviewed package retain their content-derived
`artifactId` but are separate occurrences. The existing monotonic artifact
`retiredCount` identifies the current custody occurrence. Each selected manager
record retains that floor separately from its signed transfer and job sequence;
legacy singleton/fleet-v2 records and signed permit/report bytes are unchanged.
Older retired device records are projected as unselected for a later occurrence,
including A → B on another device → A. Reading never advances the durable job.

Reusable artifact reserve/upload/complete/retire requests pin `retiredCount`.
Reserve pins the pre-request floor and `expectedArtifactId` (empty for initial
custody, the displayed content identity for retired custody); the response
advances the floor only when replacing a retired artifact. Reusable device views and delivery requests include
`artifactRetiredCount`; review, approval and device retirement also pin exact
`transferId` and `jobSequence`. These pins are checked inside mutation boundaries.
A stale same-content request cannot approve or delete a newer occurrence. A
retired device cannot receive a second job within the same global occurrence. Current
unresolved assignments still block retirement; older retired reports do not count
as assignments to the new payload. Missing or contradictory occurrence evidence
fails closed rather than reconstructing an assignment.

After a known settled result, the exact durable shared-owner receipt must finish
release. Explicit result-bound retirement then deletes only the imported app-owned
payload and compacts only that released MSI owner. It retains the original result,
retirement report and metadata. Only the next explicit delivery may advance to
another package; it never reconstructs or repeats native installation.

The manager's global artifact can retire only after every assigned job has a
signed retirement report. An offline, revoked or uncertain assigned device blocks
cleanup; another successful device cannot discard its evidence. Unassigned
devices impose no fictitious approval requirement. A new upload and per-device
approval are always explicit. Switching rows or closing the UI does not cancel
an issued permit. There is no cancel, rollback, uninstall or repair workflow in
this slice, including after install approval has been issued.

## Bounded retention and replay

The manager retains at most one 128 MiB payload. Each configured endpoint retains
at most one separate 128 MiB payload. This is 256 MiB for the manager plus one
endpoint, not a fleet-wide 256 MiB limit: up to 25 delivered endpoints may each
hold their own copy. Uncertain work retains its payload and blocks replacement.
No 4 GiB default or 25 × 32 × 256 KiB metadata expansion is introduced.

Manager spool custody records its original app-created inode before the first
payload bytes are written. Endpoint retirement binds the original protected NTFS
import receipt. Retirement has a durable intent before removal, rechecks current
authority after waits and operates only on fixed app-owned custody. No arbitrary
path, recursive deletion, TTL unlock, reboot unlock or missing-state repair exists.
Unconfirmed deletion/write remains intervention-required; it is never retried as
an automatic cleanup operation.

Each endpoint retains its current complete evidence and up to eight prior compact
job summaries. Each summary includes package/native/publisher references and
original result/retirement digests. The chained retirement digest commits to all
older summaries and the monotonic retired floor survives compaction. The shared
fence likewise retains the monotonic MSI floor and chained exact released-owner
evidence. There is no lifetime MSI-job quota. Existing WUA limits are unchanged.
The enrollment database remains capped at 192 MiB and each MSI record at 256 KiB;
package bytes never enter it.

## Time and uncertainty

Original grant expiry and immutable enrollment identity stay unchanged across
jobs and restarts. A later job binds the current authenticated leaf. An in-flight
permit bound to a replaced or expired leaf cannot silently continue, refresh or
extend itself. Automatic TLS renewal does not renew these fixed grants or their
package authority. Operators must plan for this fixed-lifetime source limitation.

Unknown return, unexpected restart (1641), uncertain code-0 registration, 3010
without verified registration, lost result, incomplete cleanup or retirement
failure prevents the next job. A known 1618 remains a consumed busy attempt; a
known failed result is not a success claim. Exact release proves only the reviewed
synchronous native-return/cleanup boundary, never application health, rollback or
the absence of arbitrary malicious custom-action behavior.

## Verification boundary

Synthetic endpoint/fence fixtures exercise A → result → release → explicit
retirement → restart → independently approved B, replay rejection, uncertainty
blocking and bounded retirement beyond the former single-MSI allowance. Manager,
protected inert spool, store, API and UI checks are reported with exact source
artifacts. Source tests/cross-builds do not establish real MSI/NTFS/SCM acceptance.
Use the exact-source CI Checks and attached capture artifacts for hosted viewport
evidence; a source-fixture `--check` alone captures no browser pixels.


## Saved selection and deliberate batches

Configured reusable-v3 registries can expose the manager-owned
[saved worklist contract](windows-saved-msi-worklists.md).
It retains the exact artifact occurrence, target bindings, group snapshot and
compact stage audit. One unchecked stage confirmation enumerates separate exact
per-device requests; it does not authorize a later stage, scheduler, canary release,
new target or native retry. Reopening performs GETs only. Stop closes unsent
requests with the latest revision and never claims to cancel already issued work.

Historical outcome/result rendering does not restore current device authority.
The fourth saved-worklist stage, Review package cleanup, explicitly reviews exact
settled per-device results and dispatches the existing result-bound retirement
requests in the foreground. It retains native outcome and registration truth,
requires fresh idle shared-owner status, and does not resume after reload.
Shared payload retirement remains a separate explicit operation after all signed
endpoint retirement reports. Neither save, stop, completion nor archive clears unresolved
assignments or permits another payload. This manager/UI addition creates no new
endpoint grant, privilege, setup service or native execution operation.

## Fresh scheduled profile

A separate [scheduled MSI v4 profile](windows-scheduled-managed-msi.md) adds one
explicit prospective UTC installation approval for an already-imported exact
assignment. It requires fresh paired background setup and a separate scheduling
capability; reusable-v3 state and manual approvals never acquire that authority.
Delivery and both package-retirement operations remain explicit.
