# Linux log sources: current chooser and expansion design

Status: the source chooser is implemented; the amendment lifecycle and broader
collectors below are a design, not installed or enabled functionality. No fixture
or browser test changes a Linux host or proves real journal visibility.

## What works now

The Logs page offers bounded search of the device's existing service inventory,
recognizable labels for known exact units, and search shortcuts for SSH, Docker,
containerd, networking, DNS, cron, APT and Tracebolt. A shortcut shows its literal
search term; it is not an installed-service catalog and may not match every Linux
distribution. The full searchable inventory and manual exact-unit fallback remain.

Only rows actually returned by the existing service-inventory API are selectable.
The original unit is retained; labels never resolve aliases, combine services or
change an allowlist. The inventory is already age-, identity-, generation- and
paging-bound. Selection does not capture logs or acknowledge content risks.

Three independent facts must stay separate:

1. **Observed:** a service name appeared in retained inventory. This is not proof
   that it is still installed, running, emitting logs or readable.
2. **Supported:** its exact name fits the existing service-only collector.
3. **Authorized:** the endpoint's current root-protected policy permits this
   query. The manager does not receive that allowlist in v1. The chooser therefore
   says permission is unverified, never guesses from inventory or past success.
   A displayed denial is explicitly the last request for the selected service;
   it is not attributed to another selected service.

An endpoint whose current approved list is `ssh.service`, `docker.service` and
`tracebolt-agent.service` continues to allow only those three. No preset adds a
unit, and `systemd-journald.service` is the journal daemon's own diagnostics,
not the whole journal. Existing source and policy bytes are unchanged.

## Locally grantable service expansion: next implementation

The create-only [helper setup](linux-journal-helper.md) cannot edit an existing
installation. Do not rerun it, hand-edit policy copies, remove setup evidence, or
reinitialize consent to make an amendment pass. Add a separate reviewed
`deploy/journal/amend.py` workflow; the following is its proposed contract, not a
command currently shipped. First implementation supports adding exact service
units only. Explicit removals/revocation remain a separately reviewed operation;
a caller cannot accidentally replace the original list with a shorter list.

### Read-only plan

- Fixed installed paths, identities, binary, unit templates and installer lock;
  reuse the source-version-specific ownership checks from `setup.py`. Verify
  both deployment copies and both policy copies are identical; exact numeric
  owners/groups, modes, non-symlink ancestors and one-link regular files apply.
  Check the helper account's absence of supplementary group memberships and
  unit-scoped journal GID. Reject aliases, drop-ins, unknown runtime states and
  unresolved installer/amendment transactions. Never read private agent state as
  root or invoke the journal source.
- Accept repeated exact `--add-unit` values in the existing canonical grammar.
  Compute sorted union with the existing list; reject duplicates, no-op changes,
  unsupported syntax and more than 32 units. Preserve all existing units and
  every other policy limit, scope, identity, transport and acknowledgement.
- Display old/new/additional unit lists, exact manager origin, transport risks,
  numeric identities, old policy hash, proposed next revision, binary/unit/
  deployment hashes, fixed write/backup targets, stop/restart effects and
  planSHA256. Read-only planning takes no lock that creates state and makes no
  file, account, group, unit, socket, journal, enrollment or network change.
- A plan is not approval. Apply requires its exact digest, content-risk
  acknowledgement and a separate HTTP plaintext acknowledgement where needed.
  The parent/user must approve the named host, added units and persistent access
  amendment. A manager request or UI click cannot authorize it.

### Revision and pre-existing requests

A replacement with the same policy bytes must never revive a former revision.
Use `tracebolt.journal-content-policy.v2` for amended policies, retaining the
exact v1 service scope plus a positive monotonic `revision` and a fresh random
256-bit `grantGeneration`. First amendment starts at revision 1; later amendments
increment it, with overflow rejected. The generation is public binding metadata,
not a credential. No v1 grant implies v2. Restoring old bytes is not a rollback.

Pending v1 requests currently acquire their policy digest only when claimed.
Changing an allowlist alone therefore cannot reject all requests queued before
an amendment. A local timestamp compared with manager `CreatedAt` also cannot
prove this under clock skew. The first amendment must add explicit generation
binding across the full request path:

- The upgraded endpoint publishes a fixed metadata-only capability report over
  its existing authenticated transport: identity binding, v2 service capability,
  current revision, generation and full canonical policy digest. No log content,
  arbitrary paths or secrets enter this report. Do not publish before the local
  transaction is committed. The report is revision-ordered and replay-protected;
  stale/foreign reports cannot replace a newer policy view. The local amendment
  disclosure explicitly includes this metadata transmission to its bound manager.
- The upgraded manager creates a new `tracebolt.journal-request.v2` Description
  only from a fresh current report, putting the exact generation and policy
  digest in the request's canonical query digest. Operator create includes the
  expected generation; a concurrent report change rejects the creation instead
  of silently adopting a newly expanded scope. Existing v1 endpoints keep v1.
- Agent and helper reject every v1 request against amended v2 policy, and reject
  mismatched v2 generation/policy digests before claiming or collecting. A typed
  `TBJ2` helper request carries these exact fields; no untyped extension map.
  The permit retains them for final delivery recheck. A fresh generation can
  never validate a request queued under its predecessor, regardless of clock
  skew. Creation after capability refresh requires a new explicit operator
  capture and the existing content/HTTP acknowledgements.
- The agent remembers an identity-bound accepted (revision, generation, full
  policy digest) tuple. Runtime requires exact equality, rejecting downgrades,
  same-revision conflicts and higher uncommitted revisions. After migration,
  a missing/corrupt tuple also denies v1 fallback. The manager similarly retains a capability floor. The report's
  freshness and monotonic floor are separate: expiry removes capture eligibility
  but cannot erase replay protection. Restart never resets either floor.
- Original manager and agent consumed-sequence floors, identity, request expiry
  and cached-content lifetime remain intact. No reset/re-enrollment or extension
  of cached content is allowed. Previously delivered manager RAM content cannot
  be recalled by a local policy update and keeps its original expiry. Claimed
  and consumed requests retain their original one-shot semantics.

This requires coordinated manager/agent/helper compatibility. Keep policy
amendment apply default-off until this entire binding path and durable floors
are implemented and independently tested. A partial pure planner is not
permission to replace live policy files.

### Apply, transaction and recovery

- Hold the existing installer lock; repeat the full read-only plan and require
  the approved digest. Stop only the owned agent, socket and helper and verify
  inactive state. Remember prior activity; never enable a previously disabled
  service. Use the existing nonroot numeric agent identity and empty supplementary
  groups to run a new metadata-only amendment preview. It validates existing
  enrollment/ledgers and installed v2 runtime capability, returns binding/leaf/
  policy/revision facts and acquires the sender lock. Missing capability stops
  before writes. Never initialize a missing marker or read its secrets as root.
- Keep byte-for-byte old policy backups (copies, never hardlinks) and staged
  transaction evidence in a root-private 0700 revision-specific directory.
  Backups and fixed write-target checks cover both policy files, both deployment
  declarations, the activation record and the separate private tuple, including
  absence before first migration. Evidence records the approved plan, old/new
  hashes, fresh generation, numeric
  identities and original activity. Create-only no-follow files and directory
  fsync are required. Reject unknown prior remnants; no automatic adoption.
- Introduce one fixed root-owned 0644 activation record
  `/etc/tracebolt/journal-activation.json`, readable by both identities. It
  contains only a strict schema, phase (`pending` or `committed`), binding,
  device/leaf identity, revision, generation and canonical policy hash. It is
  public binding metadata, not permission to read additional fields. Backups
  and detailed transaction records stay private. The helper never reads the
  agent's private state.
- Atomically publish and fsync activation phase=pending before changing either
  policy or the agent's private accepted tuple. The client and helper must
  independently require a valid committed activation record matching the exact
  current v2 policy tuple at every capture/release boundary. Pending, malformed,
  missing-after-migration, foreign, symlinked or ambiguous records/staging files
  deny. EACCES and I/O failures never mean absent. Path checks use no-follow
  operations through a pinned protected parent, with final path rechecks.
- The agent's private migration/floor record must exactly match the committed
  (revision, generation, policy digest). Root-side helper deployment metadata
  must permanently declare v2 migration too, so a missing activation record and
  substituted v1 policy cannot restore old authority. Both deployment copies
  are updated behind the same pending gate, preserving all numeric identities.
  Runtime/CLI capability for these checks is mandatory before any write.
- Construct one canonical new policy byte slice. Stage both policy replacements
  with their original root ownership, exact group and 0640 modes; verify pinned
  old inode/hash and both stages, atomically replace each fixed target, and
  fsync the directory. Two renames are not one transaction. Keep activation
  pending across both; verify byte-identical final copies and migrated deployment.
- Under the stopped agent identity, durably update the separate identity-bound
  accepted-policy tuple in a separate fixed `journal-policy-generation` child
  directory of the validated agent StateDirectory (0700, own lock and 0600
  record). Do not add files to the existing strict `journal` consumption directory.
  Preserve all existing consumed-request floor bytes. An exited preview no
  longer holds a lease: this write step reacquires the existing sender inspection
  lock and new generation-state lock, then rechecks the stopped identity before
  writing.
  Revalidate both policy/deployment copies and the private tuple. Any failure
  here leaves activation pending and journal reads blocked, including at reboot.
- Atomically replace the activation record with its exact committed form as the
  **sole activation point**, then fsync its parent. Only this record admits the
  reviewed new tuple; neither a matching pair of policy files nor archive state
  alone does. If the final rename/fsync is uncertain, report that the commit may
  have occurred and do not automatically restore prior activity or old policy.
  On subsequent inspection a coherent durable committed record is authoritative;
  a pending, absent or inconsistent one stays blocked. Do not claim that a failed
  fsync proves the policy was never activated.
- Archive root-private transaction evidence only after activation commits.
  Archive failure is reported as retained housekeeping/recovery evidence and
  does not falsely uncommit an already active policy. No runtime depends on
  reading the private archive. Never delete evidence to make a retry pass.
- After verified durable activation, restore prior owned socket/agent activity.
  The helper remains socket-activated, never force-started for a test read.
  Recheck ownership before restart. Report restart failure separately from
  policy commit success; no journal query runs during apply. The newly activated
  helper must have a fresh mount namespace: its existing individual ReadOnlyPaths
  policy bind mounts can otherwise retain replaced inodes.
- Before writes, a failure may restore activity only after unchanged ownership
  and policy bytes are confirmed. After uncertain writes retain all evidence.
  Ordinary inventory may resume only if ownership is unchanged and the journal
  gate is proven blocking; otherwise leave the agent stopped and report it.
  No automatic rollback, adoption, chmod repair or silent journal resume.
- Recovery/rollback requires a separately approved plan. It chooses the intended
  exact allowlist but issues a new revision/generation, preserves every monotonic
  floor and retains failure evidence. Never reinstall old bytes as live policy.
  First release may provide inspection-only recovery rather than guessing.

The local tuple/sequence floors do not cryptographically protect against a
privileged attacker restoring all filesystem state. Ordinary approved recovery
never lowers them; the manager retains its independent durable request and
capability floors.

### Required tests before shipment

Pure/injected tests must cover old-list preservation; bounds and exact grammar;
plan drift; old-policy/default-off compatibility; old queued, claimed and
consumed requests rejected across generation change; v1-to-v2 downgrade; clock-skew and expired
requests; stale/replayed capability reports; revision rollback; same-allowlist rollback; duplicate/unknown
wire fields; every policy write/fsync/rename failure; asymmetric policy copies;
crash stages and reboot gates; changed identities/units/inodes; retained backups;
no journal invocation; no unapproved network or host grants; unchanged existing
state and floors; old-helper capability rejection; pinned mount-namespace
policy inodes requiring helper restart; recovery and restart failures. Separately authorized Debian 13
VM acceptance must establish actual service/helper compatibility, additional
unit visibility, policy rejection, reboot behavior and revocation before calling
this host-ready.

## Broader source contracts after the amendment lifecycle

Kernel, whole-system and system-wide authentication sources stay unavailable.
They need a separately acknowledged typed v2 content contract across policy,
request digest, helper framing, parser, transport, cache and operator validators.
Do not encode them as fake `.service` names or interpret a missing/empty service
as an unrestricted query. No generic journalctl arguments, fields, shell,
paths, regexes, user journals, namespaces or container selection are accepted.

- `service`: one exact allowlisted unit with the existing trusted attribution
  rules (`_SYSTEMD_UNIT`, or PID 1/UID 0 plus `UNIT`); no `-u` expansion into
  coredump/object/slice branches.
- `kernel`: one explicit new scope, fixed `_TRANSPORT=kernel` match in the system
  journal, with the same bounded UTC window. Explicitly decide boot semantics:
  using the field match preserves the requested window across boots, whereas
  `-k` implies current boot. Validate trusted transport and project only the
  approved timestamp/priority/message fields; no boot/machine IDs or raw export.
- `system`: explicit broad system-journal content consent, no unit match, same
  bounded budgets and projected fields; kernel inclusion must be stated in the
  scope. Prefer a separately reviewed service-manager-only `_PID=1 _UID=0`
  scope before this broad option if it meets the diagnostic need.
- `authentication`: do not promise complete security/audit coverage from SSH or
  message keyword matching. A possible narrow `auth-facilities` scope selects
  fixed SYSLOG_FACILITY 4 and 10, clearly labeled as facility-filtered events.
  These fields are application-supplied, so they cannot establish trustworthy
  authentication-event classification. Availability varies by logger. Any audit
  transport or extra service union needs its own explicit typed scope and tests.

A future read-only capability report must separately identify collector support,
observed inventory, local policy permission and actual source-read outcome, with
identity, revision and freshness. Missing/old reports mean unknown, never allowed.
Do not use `journalctl -F` as a permission probe or invent successful empty results.

## Primary references

Debian 13's [journalctl manual](https://manpages.debian.org/trixie/systemd/journalctl.1.en.html)
defines field-match AND/OR behavior, `--system`, `--unit` expansion, kernel boot
semantics, facility filtering and field enumeration. The
[journal fields manual](https://manpages.debian.org/trixie/systemd/systemd.journal-fields.7.en.html)
distinguishes trusted underscore fields from application-supplied fields.
These semantics inform this design; they do not prove host availability or grant
permission. Review against the exact systemd version used in native acceptance.
