# Windows fleet managed MSI worklist

This bounded source candidate adds one shared artifact and a manual device worklist.
It does not establish Windows native acceptance, authorize setup or install an MSI.
The existing [managed MSI security contract](windows-managed-msi-delivery.md) and
[coordinated MSI/WUA fence](windows-coordinated-mutations.md) still apply.

## One upload, independent devices

The manager owns one immutable reviewed x64 machine MSI, no larger than 128 MiB.
The complete package selection and native-acceptance digest identify it; matching
only the file hash is insufficient. An explicit protected fleet registry admits
at most `min(enrollment RecordLimit, 25)` independently configured endpoints.
Neither discovery, group membership, observation grants nor operator capabilities
create endpoint delivery or installation authority.

The fleet worklist sits beside the Windows update worklist. Its shared package
card accepts the exact MSI and its package-review JSON, verifies the file hash,
then reserves, uploads 32 KiB chunks and completes the artifact. Its original
checkpoint and pending-chunk digest permit only an exact-byte upload continuation.
An unconfirmed upload requires reading the saved artifact before continuing.
There is no delete, replacement, catalog, bulk approval or automatic deployment.

The package card shows upload progress, name, version and size. A single visible
line states one package, up to 25 devices, one attempt per device and pending
native acceptance. Group rules, close behavior and source limitations are under
one initially collapsed “Limits & behavior” disclosure (also localized in German).
Rows show shortened IDs; their full original identities remain in the collapsed
frozen-reference details. Delivery/install consent and uncertainty stay visible
at the action. Full package, terms-review and native-acceptance references remain
in collapsed evidence.
Uploading does not deliver the package, accept terms or approve installation.

## Explicit fresh fleet setup

The existing manager CLI prepare/finalize phases require an explicit `--fleet`.
Later targets additionally require `--additional-device`. Each phase must retain
its original reviewed LAN input; do not substitute a later generated LAN file for
that phase's reviewed source configuration.

The first fleet manager key is fixed at `windows-managed-msi-fleet/manager.key`.
Each device has separate protected records under
`windows-managed-msi-fleet-<deviceId>/`: `offer.json`, `manager.json`,
`registry.json`, `lan.json` and `complete.json`. Additional-device finalization
writes a new staged flat registry and LAN configuration. It never rewrites an
older target's configuration, key or receipts. Existing singleton v1 state is not
adopted or migrated.

Every fresh fleet target still needs the endpoint's separate local managed-MSI
setup and its independent delivery/install grants. That setup covers one package
and one attempt for that endpoint. Actual manager/endpoint host setup, persistent
keys, ACL/service changes and activation remain separately authorized operations;
this worklist and its fixtures perform none of them.

## Frozen manual selection

Only explicitly registered, visible admitted Windows identities appear in the
selection. Freezing it records the exact package/artifact, each target binding,
and the displayed group name and revision. Later group membership changes cannot
add targets or grant authority. A changed binding or artifact disables the frozen
row rather than silently substituting a new identity.

Only one device session is expanded. It reuses the existing managed MSI session,
including the unchanged coordinated-owner status component and independent native
result semantics. Each device requires its own initially unchecked delivery
acknowledgement. Fleet sessions never offer per-device upload. After protected
import, exact package review, terms, LocalSystem/custom-action risk and a bounded
maintenance window are separate unchecked acknowledgements. Coordinated setup
also retains its exact synchronous-actions review. Fresh readiness precedes the
separate initially unchecked one-install approval.

Delivery, review and approval carry the frozen artifact and binding references.
Before each write, the UI rechecks the exact named operator session, permission,
original server deadline and active view. The manager and endpoint remain the
actual authority and final native-admission boundary. A group or saved status is
never permission.

## Interruptions and saved outcomes

Switching rows, closing, blur, navigation, hidden visibility or authentication loss
stops further UI requests and clears acknowledgements. An in-flight write can still
commit, and an issued permit is not canceled. No next-device operation or native
installation retry is scheduled. Browser storage contains no package bytes,
reviews or approvals.

In-memory unconfirmed-write references retain the exact device, artifact, binding,
transfer and relevant readiness reference across row switches and close/reopen.
Reconciliation is a read of the same device. A different transfer cannot confirm
an uncertain request. A reload loses local worklist presentation, but rebuilding
it reads the manager's durable state; it does not replay an installation.

Rows label outcomes as saved state. An unavailable endpoint response removes the
cached result from the row's status and requires another successful read. A revoked
or expired device never appears as currently successful just because an earlier
response was saved. Another independently admitted target can still be opened and
reviewed. The UI adds no fleet-wide native-install lock.

Native 0, 3010, 1641 and 1618 meanings, unknown native return, independent machine
registration truth, consumed attempts and unresolved shared ownership are unchanged.
There is no automatic reboot, repair, removal, reset or second attempt.

## Wire contract

- `GET /api/windows-managed-msi/artifact` returns the strict v2 artifact projection,
  its original upload checkpoint and explicitly registered device/binding pairs.
- `POST` on the fixed `/reserve`, `/upload` and `/complete` artifact subroutes uses
  the existing reviewed selection, bounded chunk and empty completion bodies.
  Upload requires the separate managed-MSI delivery capability; status accepts
  delivery or installation capability.
- Existing per-device `windows-managed-msi` routes retain the v1 projection. Fleet
  views add both `artifactId` and `bindingDigest`; singleton fields remain absent.
  Before delivery, fleet projection exposes global custody without creating a
  per-device transfer. Explicit Deliver freezes it in that device's record.
- Fleet Deliver, review (including coordinated review) and approval include both
  exact references. Singleton requests keep their existing bodies.

## Source verification and remaining gate

Go tests cover separate SQLite records, shared physical spool custody, exact
registry loading and two authenticated TLS clients. Full CLI prepare/finalize
composition is source-reviewed; it has not been executed end to end.

Focused Vitest interactions cover registry-only selection, group revision freezing,
independent unchecked delivery/install acknowledgements, exact uncertainty references,
row switching and late responses, identity changes, permission removal, unavailable
reads, bounded upload and localized compact rendering. Existing standalone MSI and
fleet update tests remain part of the regression check.

`web/scripts/capture-windows-fleet-msi-fixtures.mjs --check` validates synthetic
DTOs, private fixed route isolation and an in-memory compiled production App. The
script exports English/German 1440px desktop and 390px mobile screenshot exercises
for a separately permitted existing browser. Source-only checking starts no browser
or server and captures no screenshots. Browser execution was not attempted because
this environment's browser/server launch is denied. Ordinary Validate CI now
invokes the hosted-only driver and requires 16 exact-source
EN/DE desktop/mobile PNGs. Use the exact-source commit’s Checks and its retained
artifact manifest/screenshots to establish hosted browser evidence; a different
source run is not evidence for this candidate. The separately approved [Windows native gate](windows-managed-msi-native-acceptance.md)
remain outstanding. No source fixture is host or exact-package native acceptance.
