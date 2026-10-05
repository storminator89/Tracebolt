# Add exact Linux journal service permissions locally

`deploy/journal/amend.py` is the separate **add-only** plan/apply workflow for an
already-owned journal helper installation. It never reruns create-only setup,
creates an account, changes group membership, enables a unit, or queries a log
source. It preserves all previously allowed units, numeric identities, policy
limits, content acknowledgements, policy `enabled`, unit enablement, enrollment,
and consumed-request floors. Removing units, toggling policy enablement,
repairing a partial transaction, and rollback are not implemented by this tool.

This is source and inert-fixture functionality. It is not evidence of successful
Debian/systemd deployment, journal visibility, reboot behavior, or a live grant.
Host execution and the persistent permission expansion require separate explicit
authorization for the named host, added exact units, bound manager and content
risks. Read [installation.md](installation.md),
[linux-journal-helper.md](linux-journal-helper.md), and
[journal-content-mvp.md](journal-content-mvp.md).

## Prerequisites and trust boundary

- The installed, manifest-owned `lan-agent` and manager must support the complete
  v2 journal generation path. A normal separately authorized binary upgrade is
  needed first. The amendment never installs or upgrades a binary. Metadata-only
  preview checks the installed endpoint's support before any policy write.
- There is an activated v3 agent, the existing dedicated non-login helper account,
  and matching root-protected helper/client policy and deployment copies. The
  helper account has no supplementary membership; only its exact unit has the
  existing numeric journal GID. The main agent stays nonroot with no supplementary
  groups. No private key, config, journal floor, or sender ledger is read by root.
- Installer ownership, manifest, binary/bootstrap/unit hashes, state-directory
  identity, exact current templates, local account/NSS constraints and the
  existing installer lock must validate. There may be no installer transaction,
  amendment pending directory or stage, foreign alias/drop-in, ambiguous unit
  state, mismatched copy, or uncommitted/missing migrated activation.
- The helper socket enablement and fixed symlink must agree. Exact root/group
  modes, protected nonsymlink ancestors, regular single-link policy files, and
  socket metadata must validate. The tool does not adopt or chmod existing paths.
- Python 3.9+ and systemd are already present. Run the reviewed source with
  `/usr/bin/python3 -I`; never execute a root script from a user-writable checkout.
  The amendment module is inert when imported. Its executable bootstrap checks
  protected source bytes before compiling its sibling `setup.py` ownership
  adapter. No sibling module is imported before this verification.

## Stage reviewed committed source separately

The source staging below is a separately approved administrator operation, not
part of plan or apply. Use an independently verified full lowercase 40-character
commit ID, never a moving branch or unreviewed working tree. The destination is
create-only; preserve partial staging evidence on failure. These example commands
have not been executed against a host by the fixture tests.

```sh
sudo /bin/sh -eu <<'STAGE'
umask 077
REPO=/root/Tracebolt
REV=REPLACE_WITH_FULL_REVIEWED_COMMIT_SHA
DEST=/root/tracebolt-journal-amendment
for directory in / /root; do
  test -d "$directory" && test ! -L "$directory"
  test "$(/usr/bin/stat -c %u "$directory")" = 0
  mode=$(/usr/bin/stat -c %a "$directory")
  test "$((0$mode & 06022))" -eq 0
done
test "${#REV}" -eq 40
case "$REV" in *[!0-9a-f]*) exit 1 ;; esac
test "$(/usr/bin/git --no-pager -C "$REPO" -c core.fsmonitor=false rev-parse --verify "$REV^{commit}")" = "$REV"
test ! -e "$DEST" && test ! -L "$DEST"
/bin/mkdir -- "$DEST"
/bin/mkdir -- "$DEST/deploy" "$DEST/deploy/journal" "$DEST/deploy/systemd"
set -C
for relative in \
  deploy/journal/amend.py \
  deploy/journal/setup.py \
  deploy/systemd/tracebolt-agent.service.in \
  deploy/systemd/tracebolt-journal-reader.service.in \
  deploy/systemd/tracebolt-journal-reader.socket.in
do
  /usr/bin/git --no-pager -C "$REPO" -c core.fsmonitor=false \
    cat-file blob "$REV:$relative" > "$DEST/$relative"
done
/usr/bin/sha256sum "$DEST"/deploy/journal/*.py "$DEST"/deploy/systemd/*.in
STAGE
```

Compare those hashes against the reviewed artifact record before execution.
Staging only establishes selected committed bytes; it does not establish
publisher authenticity or authorize a host permission change.

## Inspect a read-only plan

Replace these illustrative unit names with the exact approved additions:

```sh
sudo /usr/bin/python3 -I /root/tracebolt-journal-amendment/deploy/journal/amend.py \
  --add-unit example-api.service --add-unit example-worker.service
```

The default operation reads bounded local public metadata and systemd status.
It does not acquire/create an installer lock, stop a unit, run the agent CLI,
change a file, collect a journal, or contact the manager. Existing allowlist
membership is never inferred from inventory, labels, presets or aliases.

The plan includes the old/additional/new exact allowlists, bound origin and
public device identity, numeric IDs, old file hashes and metadata, installation
and source/template hashes, preserved limits and enablement, next decimal-string
revision, fixed write/stage/backup paths, stop/restore effects, metadata reporting
disclosure, and `planSHA256`. Additions must be distinct, genuinely new service
names; the union must contain at most 32 units and fit the 8192-byte v2 policy
limit. An already-authorized name or a no-op request is rejected.

## Explicitly approved apply

Log content may contain passwords, tokens and personal information. Masking is
best effort and never a secret-free guarantee. Approve both the additional
persistent unit permissions and transmission of public generation metadata
(identity, revision, random generation and canonical policy digest) to the same
bound manager during the agent's normal authenticated cycle.

After reviewing that exact plan, use its returned digest:

```sh
sudo /usr/bin/python3 -I /root/tracebolt-journal-amendment/deploy/journal/amend.py \
  --add-unit example-api.service --add-unit example-worker.service \
  --apply --expected-plan-sha256 REPLACE_WITH_REVIEWED_PLAN_SHA256 \
  --ack-journal-content
```

For HTTP-test, additionally supply `--ack-journal-http-plaintext`. It acknowledges
that the content is readable on the network and the manager can be impersonated.
The HTTP flag is mandatory for HTTP and rejected for TLS. Neither local flag
substitutes for required human approval. Any plan drift fails before stopping
units. Content acknowledgement is required on every amendment.

The locked transaction is:

1. Acquire the existing installer lock, repeat ownership/plan checks, require the
   exact approved digest, and preserve prior agent/socket/helper activity and
   enablement. Stop the owned agent, socket and helper and verify all inactive.
2. Run only the installed binary under the existing numeric agent UID/GID with
   empty supplementary groups:
   `/opt/tracebolt-agent/lan-agent --config /var/lib/tracebolt-agent/enrollment/agent.json --service-identity UID:GID --journal-policy-amendment preview`.
   Preview validates the private existing state and installed runtime capability,
   returning a strict public DTO. It performs no collection/network operation and
   cannot initialize a missing legacy marker. Preview exits; it is not a lease.
3. Create `/var/lib/tracebolt-agent-installer/journal-amendment-N.pending`, root:root
   `0700`, with independent root:root `0600` copies of both old policy files, both
   old deployment files and old activation or explicit absence. Store approved
   plan, original activity, hashes and public nonroot preview. Private state is
   not copied/read by root; the public accepted tuple is recorded and the CLI
   independently preserves the original private consumed floors.
4. Generate a fresh 32-byte lowercase hex generation, advance revision exactly by
   one (first amendment is revision `"1"`), and build one canonical v2 policy byte
   slice preserving every non-allowlist policy field. Deployment v2 preserves all
   IDs and adds `policyGenerationRequired:true`.
5. Exclusively stage, fsync and atomically publish the root:root `0644`
   `/etc/tracebolt/journal-activation.json` record with phase `pending`, then fsync
   its parent **before any policy/deployment replacement**. The public record
   contains strict schema, phase, sender binding, device ID, certificate hash,
   and the exact revision/generation/`sha256:` policy digest tuple.
6. Exclusively stage and fsync each policy/deployment replacement at its fixed
   hidden path, check old metadata/bytes, atomically replace and fsync the parent.
   Both policy copies use the same bytes, as do both deployment copies. Each
   preserves root ownership, original helper/agent group and `0640` mode. The
   activation gate remains pending throughout all four replacements.
7. Run the same nonroot CLI with `accept --ack-journal-content` and the HTTP-only
   flag where applicable. It reacquires sender/private-generation locks, requires
   the staged pending authority, advances only the separate private generation
   tuple, rechecks it, and returns the public accepted DTO. Existing identities,
   sequence floors and original request/cache lifetimes are unchanged.
8. Recheck exact owned installation, accounts/units, all final copy bytes and
   metadata, staged activation, source/templates and the accepted DTO. Stage,
   fsync and atomically replace activation with phase `committed`, then fsync its
   parent and verify it. **This activation rename is the sole activation point.**
9. Archive evidence to the same revision's `.committed` directory. Restore only
   the previously active owned socket and agent. Never enable a unit or directly
   start the helper. Stopping the helper ensures its next socket activation gets
   a fresh mount namespace rather than stale bind-mounted policy inodes.

No generation report is sent by root apply. A running agent can report after
commit over its existing authenticated path. A previously inactive agent stays
inactive, so no report is promised until its normal authorized operation resumes.
A disabled policy stays disabled even though its metadata revision advances.

## Failure, commit status and recovery

Results distinguish `committed`, `commitState`, `failureStage`, `detailStage`,
`retainedEvidence`, `restartState`, `agentRestarted`, `socketRestarted` and a
separate `restartFailureStage`. A lock-release/parent-recheck failure is reported
without replacing an already established commit result with `committed=false`. `sourceVerified` and `contentRead` always remain
false. A zero exit means a verified commit, archived evidence and required
activity restoration; it does not prove a real journal read or host acceptance.

- Before authority writes, a failure may restore prior socket/agent activity only
  after unchanged ownership, original policy bytes and absence of stages validate.
  Partial private evidence is retained and blocks a later amendment.
- After any pending/staged authority write is attempted, an uncommitted failure
  leaves units stopped and evidence retained. Pending activation, malformed or
  mismatched authority, missing migrated activation, and the fixed
  `.journal-activation.tmp` fail closed. No automatic rollback, adoption,
  deletion, permission repair, re-enrollment or counter reset occurs.
- `commitState=commit-uncertain` means the final activation rename may have
  occurred. In particular, failure of the following directory fsync does not
  prove that activation stayed pending. Units stay stopped. Preserve all files
  and inspect through a separately reviewed recovery; do not rerun apply or copy
  old policy bytes back. Runtime authority follows a coherent committed record,
  not the existence or name of a private evidence archive.
- Archive failure after a verified commit remains `committed=true`; it is reported
  separately and does not reverse the grant. Validated prior socket/agent
  activity may be restored. If the pending archive remains, later amendments
  refuse it. Archive-fsync uncertainty retains a warning even if rename occurred.
- Restart failure also leaves `committed=true` and reports the restore failure.
  A socket may already be restored while the agent stays stopped. Do not describe
  the entire policy transaction as uncommitted merely because a restart failed.

Recovery is inspection-only in this release; an authorized administrator must
review evidence and choose a separately approved recovery plan. Any future
recovery grant must issue a fresh revision/generation and preserve all floors.
Restoring old bytes is not a rollback. Already delivered manager RAM content
cannot be recalled and retains its original expiry.

## Inert validation and separate native gate

```sh
python3 -m unittest discover -s deploy/journal -p 'test_*.py' -v
```

Synthetic Effects cover read-only planning, old-list/limit/identity preservation,
first and subsequent amendments, disabled policy, exact acknowledgements, drift,
foreign metadata/units, distinct copies, no private root reads, preview/accept,
every staged write/fsync/rename fault point, final-commit uncertainty, retained
evidence, archive failures, restart activity and no source/network invocation.
The real replacement adapter is also exercised through mocked syscalls for
exclusive stages, short writes, metadata changes, rename ordering and each fsync
boundary; it performs no host operations. Independent source review and a
separately authorized disposable Debian/systemd VM are still needed
for real service compatibility, additional-unit visibility, namespace refresh,
queued-request rejection, reboot fail-closed behavior and revocation acceptance.
