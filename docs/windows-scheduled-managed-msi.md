# Fresh scheduled central MSI installation

The separate fresh manager-only [multi-package catalogue](windows-multi-package-msi-catalogue.md)
adds four retained payloads within the same aggregate budget. The earlier profiles
and contracts described below remain unchanged unless that fresh option is selected.

Source candidate only. Source fixtures and cross-builds do not authorize host
setup, credentials, keys, ACLs, SCM changes, MSI execution, Windows native
acceptance or release. The existing [managed MSI native gate](windows-managed-msi-native-acceptance.md)
remains separately approved and pending.

## One fresh setup, central operation afterward

This adds one prospective installation window for one already-imported exact
reusable MSI assignment. The observer remains LocalService and relays signed
messages to the existing LocalSystem deployment service. It uses the existing
shared mutation fence and paired background cached-WUA service. There is no new
service, generic task scheduler, command/path/property input, or observer right.
Delivery, endpoint package retirement, and shared payload retirement remain
separate explicit operations.

Fresh manager prepare and finalize require all of `--fleet --reusable-jobs
--scheduled-jobs` and their original protected LAN inputs. The new MSI v4
manager offer, grant, registration, manager/registry configuration, endpoint
configuration and service receipt have distinct strict versions. The grant
requires separate `scheduledEnabled` and `scheduledAcknowledged` fields. Old
v1/v2/v3 grants, canonical bytes, signature domains and manual behavior are not
promoted or migrated. The fresh registry also initializes exact saved worklists.

Paired endpoint review and apply require `--background-updates
--allow-scheduled-msi`. Apply retains all existing delivery, reusable jobs,
coordinated mutations, LocalSystem, observer relay/process query and background
WUA acknowledgements, plus separately unchecked `--acknowledge-scheduled-msi`.
The read-only plan rejects acknowledgements. Optional WUA scheduling remains its
separate `--allow-scheduled-updates` / `--acknowledge-scheduled-updates` choice.
The paired plan uses v5 for scheduled MSI plus manual background WUA, or v6 when
both domains independently opt into scheduling. The existing background fence
roster binds the complete new MSI grant and exact reciprocal participant,
configuration and registration digests; it cannot adopt an old participant.
Both services remain disabled after staging. Original manager finalization and
separately approved service activation are unchanged.

## Exact approval and immutable window

In an imported device's Software/worklist session, first review the exact
package and receive the existing signed readiness. A named operator with both
`windows_managed_msi_install` and `windows_managed_msi_schedule` can then expand
Schedule installation and approve one explicit UTC start/end. A fresh unchecked
confirmation covers package, terms, LocalSystem/custom-action risk, reviewed
synchronous actions and future dispatch after the browser closes.

Start must be later than approval, within 24 hours, and at or after the baseline
readiness permit expires. Duration is 1–10 minutes. End cannot outlive either
the original grant or the exact approving certificate. The immutable intent
pins artifact identity plus retired count, original binding, transfer, grant-wide
job sequence, complete package/hash/publisher/native/terms review, named actor,
full grant digest, leaf/expiry and original signed baseline evidence. Changed
occurrences, renewed leaves and different readiness cannot substitute for it.
Approval requires the current authenticated session, CSRF and final session fence.
Later dispatch is separately approved prospective authority, so the browser need
not remain open. The saved fleet stage below only submits these exact per-device approvals.

The intent lives on the existing per-device record in the same enrollment
transaction, not another execution ledger. A saved request digest and actor let
GET reconcile a lost approval response. The browser never retries an unconfirmed
POST. Cancel uses the exact schedule digest and serializes with issuance.

## Saved fleet scheduling for one selected package

Select one retained catalogue occurrence and save the intended device list. After
explicit delivery and package review, choose Schedule and review one shared UTC
window. The preview enumerates exact eligible devices and shows separate exclusions
for unavailable/changed assignment, local scheduling capability, original actor,
fresh readiness and window bounds. Another retained package, identical content in
a new custody occurrence, later-ready devices or a renewed leaf cannot substitute.

A fresh unchecked acknowledgement explicitly covers the selected package and terms,
LocalSystem/custom-action risk, synchronous actions and prospective dispatch after
the browser closes. Both named-operator install and schedule capabilities and each
device's original fresh scheduled grant are required. Confirming the bounded list
creates no intent or permit. While its original session and baseline readiness
remain valid, the browser submits each original per-device schedule request in
order through the existing endpoint, with its exact batch reference. The batch
lasts at most 60 seconds; it does not wait for the UTC window. There is no deferred
manual approval, timer queue, automatic next stage or all-or-nothing execution
across devices.

Each successful request atomically saves the existing per-device prospective intent
and a `scheduled` journal item with the distinct approval digest. Scheduled means
intended, not permit issued or installed. The existing authenticated endpoint relay
and original bounded local authority must still satisfy every v4 dispatch guard.
One device can be scheduled while another remains unsent or fails. An uncertain
response stops further sends and reconciles only with GET; it never retries or
resumes a POST. Reopening preserves those separate outcomes. Explicit Stop closes
only remaining unsent batch requests; it does not cancel saved intents. Cancel each
saved schedule through its existing exact digest control; issued permits cannot be
recalled. Installation results and explicit result-bound cleanup remain unchanged.

Original worklist limits (nine lists, 25 targets, nine batches and 256 KiB per
record), catalogue limits (four entries, shared 128 MiB reserved-byte budget),
monotonic custody occurrences and retirement floors remain unchanged. Schedule-only
fields are omitted from all earlier stage bytes. Pending, blocked, expired or
canceled intents do not qualify unresolved assignments for history compaction.

The private worklist API adds POST `/worklists/{id}/schedule-preview` with the
revision and exact start/end. POST `/batches` accepts `kind: "schedule"` with those
same window bounds on every item and fresh schedule-specific acknowledgements.
The existing per-device `/schedule` accepts the strict optional batch reference;
its original standalone body and v4 request/approval/permit contract are unchanged.

## One readiness, one permit, one native attempt

The existing authenticated observer poll is the only dispatcher. Inside the
window it issues one new signed readiness challenge, advancing the existing
readiness sequence once. It is durably claimed before delivery/inspection. Fresh
physical and package facts must match the baseline. The schedule-specific
comparison excludes only capture time and the separately fixed maintenance end;
the existing manual comparator remains unchanged.

Before one installation permit can be saved, signed readiness and the signed
shared-owner status must both have been captured inside the window and be less
than 60 seconds old. Shared status must be active, idle and unblocked. Missing or
busy shared evidence does not consume an installation permit: a later ordinary
relay pass may reconcile only the same still-valid readiness. There is no
readiness refresh, deadline extension, automatic rearm, reschedule or native
retry. Every signed v4 permit fits the unchanged 8 KiB IPC accept boundary.

Actor install+scheduling permission, exact original assignment/grant, current
leaf, original expiry and window are checked before dispatch and again after
storage/configuration waits. Removing a capability durably blocks pending intent,
including startup reconciliation after a restart; restoring the capability cannot
revive it. Canceled, expired and blocked intents remain terminal. Manual review
or immediate approval cannot repurpose the same scheduled assignment.

Cancellation stops unsent installation only. Once an installation permit is
issued, cancellation reports too late. Issued work cannot be retroactively
recalled. The deployment service deliberately reads local public authority and
has no independent manager HTTP client: it cannot instantly learn a later central
actor revocation after an authenticated relay already delivered the permit.
Manager issuance, claim and final relay release retain live actor checks. At the
actual native call, the short original signed deadline, fixed window, current
local grant/leaf and exact one-use shared owner are checked after all waits.
No online revocation channel or weaker local guard is introduced.

Existing consume-before-delivery, durable Attempted-before-native, one-use native
admission and settled-result release remain unchanged. Installation may continue
past the window. A stop, timeout, lost response or crash does not prove native
cancellation or rollback. Known 0 requires verified registration; 3010 remains
restart-required with separate registration truth; 1618 stays consumed busy;
1641, unknown return or cleanup uncertainty stays attention/fenced. There is no
automatic reboot, repair, uninstall, package cleanup or shared-owner unlock.

The compact EN/DE row shows waiting, readiness issued, permit issued or terminal
schedule state alongside the original result. Evidence and original bounds are
available on demand. Configuration and saved captures do not prove the service
is available now.

## Essential checks and remaining gates

Focused source fixtures cover old-byte/fresh-consent separation, exact occurrence,
restart, one readiness/permit/result flow, cancel-versus-issuance, actor removal,
final expiry/leaf changes, shared-fence busy/stale evidence and lost-response
read-only recovery. UI checks cover unchecked UTC review, bounds, cancellation
and GET-only reconciliation. Existing hosted source fixtures are extended without
starting a local server or browser; source fixture checks are not pixel evidence.

Exact-source hosted captures and full CI remain pending until publication.
Separately approved disposable Windows x64 acceptance must verify fresh setup and
activation, the unchanged service identities/rights, one exact reviewed package,
WUA contention, final-edge local revocation/expiry, interruption and no replay.
No native acceptance is established by compilation or these inert tests.

## Optional fresh manual-download coexistence

The separate [download coexistence profile](windows-selected-update-downloads.md#fresh-manual-download-and-scheduled-install-coexistence)
adds explicitly acknowledged manual WUA download to a fresh paired setup with
one or both independently selected installation schedulers. Existing profiles
retain their bytes and authority. Download never becomes scheduled, supplies
installation approval, moves a fixed window or unlocks a busy/uncertain owner.
Exact successful download retirement precedes a separate fresh WUA installation
review and approval. Native Windows acceptance remains separately gated.
