# macOS service test package: exact-source, unsigned native-test runbook

Status: a reproducible **source-built test candidate**, not a published or
native-accepted release. The build step below runs on a reviewed development
computer. Host preparation, enrollment, launchd installation and removal below
are instructions for a separately approved, disposable Mac test. None is part of
the build, and none has been run by source/fixture tests. Do not use this package
to claim production monitoring or a signed/notarized download.

## What the package contains

One deterministic gzip/USTAR archive per `darwin/arm64` and `darwin/amd64`
contains `enroll-agent`, `macos-agent`, `macos-agent-service`, the
`macos-package-prepare` Go helper, the exact Git source tar and this runbook.
The matching helper is also emitted next to the archive so it can inspect the
archive **before extraction**. `build-manifest.json` names the exact source
commit/tree, Go version, roles, targets, sizes and SHA-256 values. The helper
verifies the selected archive hash, bounded closed members, canonical inner
manifest, Mach-O target, Go role/build metadata and exact asset hashes using one
immutable in-memory snapshot. It does not fetch or execute an archive member.

The helper's `verify` action is read-only. `stage` and `rollback` are read-only
reviews unless `--apply` is supplied. Package preparation never enrolls or
starts a service; the later, separately approved service `install --apply`
registers and starts the launchd job. The preparation helper never accepts a
grant; the separately invoked `enroll-agent` does so only through its hidden
invitation, independent fingerprint check and explicit approval flow. No
package command signs, notarizes or publishes anything. The
package has no downloaded installer, account catalogue, updater or guessed
release URL. SHA-256 identifies selected bytes **after** a trusted reviewer
provides them; an unsigned manifest is not publisher authentication. Go may
insert an ad-hoc Mach-O code-signature load command on arm64; this is not a
Developer ID signature. Never bypass a Gatekeeper or security warning to run
an unsigned candidate. Choose a separately reviewed/source-built test route or
stop if the Mac's policy does not permit it.

## Build exact review bytes, without host changes

From a clean checkout of the full reviewed commit, with the Go version in
`go.mod` (currently 1.27.1), locked modules already cached, Python 3 and Git
on the **build computer**:

```sh
python3 -I -B deploy/macos-release/build-service-test-package.py \
  --version v0.0.0-macos-candidate.1 \
  --source-commit FULL_40_CHARACTER_REVIEWED_COMMIT \
  --output /absolute/new/output-directory/outside/checkout
```

The builder refuses a moving/different HEAD or tree, visible dirty or untracked
source, unusual index flags/links, path aliases/output reuse, a different Go
version and uncached modules. It compiles only a checked extraction of the
exact `git archive`, twice for every role/architecture, then compares bytes and
validates roles/targets. It builds each archive twice and compares exact bytes.
The result is private build output, not a release, installer execution or native
acceptance. A failed build leaves its new partial output for inspection and
never adopts/replaces it. Python is build tooling only; the Mac runtime entry
is the packaged Go helper and does not require Python, Homebrew or Xcode.

## Native test, only on a separately approved disposable Mac

Use the archive and matching standalone `macos-package-prepare` for that Mac's
actual architecture, kept in a current-user-owned, mode-0700 private directory
without access ACLs or shared write access. Obtain the
**full package and helper SHA-256 values from
an independently trusted review channel**; compare both before executing the
helper. Keep the public manager bootstrap separately supplied by the approved
operator; it contains no invitation secret. The manager must already have the
matching Mac TLS enrollment domain and profile explicitly enabled. The helper
needs its **full independently reviewed public-bootstrap SHA-256**. Never put
the secret invitation, a key, password or token in a command, file, URL, log,
chat or environment variable.

Use only a freshly selected dedicated numeric UID:GID between 502 and 60000.
The helper checks local and effective Directory Service collisions before
creating `_traceboltagent`; it will not adopt an existing user/group, account,
installation tree or source tree. It creates a disabled non-login local account
with no password, not an administrator. Native Directory Service race and group
semantics still need acceptance on each selected Mac version.

Set shell variables **only to public paths, profile and hashes**, never to a
secret. `PROFILE` is exactly `basic-readonly-v1` or, for a separately fresh
inventory identity, `macos-read-inventory-v1`:

```sh
PACKAGE=/absolute/reviewed/tracebolt-VERSION-darwin-ARCH-service-test-package.tar.gz
HELPER=/absolute/reviewed/tracebolt-VERSION-darwin-ARCH-macos-package-prepare
PACKAGE_SHA=FULL_INDEPENDENTLY_REVIEWED_PACKAGE_SHA256
HELPER_SHA=FULL_INDEPENDENTLY_REVIEWED_HELPER_SHA256
BOOTSTRAP=/absolute/reviewed/public-bootstrap.json
BOOTSTRAP_SHA=FULL_INDEPENDENTLY_REVIEWED_PUBLIC_BOOTSTRAP_SHA256
IDENTITY=REVIEWED_UID:REVIEWED_GID
PROFILE=basic-readonly-v1

# Stock macOS /usr/bin/shasum; stop before executing any package code on mismatch.
test "$(/usr/bin/shasum -a 256 "$PACKAGE" | /usr/bin/awk '{print $1}')" = "$PACKAGE_SHA" && \
test "$(/usr/bin/shasum -a 256 "$HELPER" | /usr/bin/awk '{print $1}')" = "$HELPER_SHA" || \
  { echo 'Reviewed package/helper SHA-256 mismatch' >&2; exit 1; }

# A transfer may strip execute permission or add unsafe write permissions.
# Check owner-only directory custody, then restore exact owner-only helper mode.
HELPER_PARENT=$(/usr/bin/dirname "$HELPER")
test ! -L "$HELPER_PARENT" && test -d "$HELPER_PARENT" && \
test "$(/usr/bin/stat -f '%u:%Lp' "$HELPER_PARENT")" = "$(/usr/bin/id -u):700" || \
  { echo 'Helper directory is not private and owner-controlled' >&2; exit 1; }
test ! -L "$HELPER" && test -f "$HELPER" && \
test "$(/usr/bin/stat -f '%u' "$HELPER")" = "$(/usr/bin/id -u)" || \
  { echo 'Helper is not an owner-controlled regular file' >&2; exit 1; }
/bin/chmod 0700 "$HELPER" || exit 1
test "$(/usr/bin/shasum -a 256 "$HELPER" | /usr/bin/awk '{print $1}')" = "$HELPER_SHA" || \
  { echo 'Helper changed after mode review' >&2; exit 1; }

"$HELPER" --action verify --archive "$PACKAGE" --package-sha256 "$PACKAGE_SHA"
sudo "$HELPER" --action stage --archive "$PACKAGE" --package-sha256 "$PACKAGE_SHA" \
  --service-identity "$IDENTITY" --profile "$PROFILE" \
  --bootstrap "$BOOTSTRAP" --bootstrap-sha256 "$BOOTSTRAP_SHA"
```

Review-only `stage` checks exact source/bootstrap bytes, TLS profile, root-owned
trusted ancestors, fixed launchd label/override absence and fresh account/paths.
It performs no host mutation. If that result and the target/permission plan are
approved, repeat the **same** command with `--apply`. This is the host account,
file and service-preparation authorization boundary. It creates only:

```sh
sudo "$HELPER" --action stage --archive "$PACKAGE" --package-sha256 "$PACKAGE_SHA" \
  --service-identity "$IDENTITY" --profile "$PROFILE" \
  --bootstrap "$BOOTSTRAP" --bootstrap-sha256 "$BOOTSTRAP_SHA" --apply
```

- `_traceboltagent` local UID:GID with disabled login
- root-owned `/Library/Application Support/TraceboltAgent` with exact four
  binaries, public `bootstrap.json`, `package-stage.json` owner receipt, and an
  empty dedicated UID:GID-owned mode-0700 `state` directory
- root-owned protected `/Library/Application Support/TraceboltAgentSource/source.tar`,
  outside the service installation directory

It does **not** create `state/enrollment`, an invitation, a key, a grant, a
launchd plist or service-registration custody, and never starts launchd. It
rejects any collision instead of repairing modes, ACLs, existing data or
another account. A partial result is indeterminate: preserve every record and
do not rerun `stage --apply` or delete files to force it through.

### Deliberate hidden-terminal enrollment

Use the existing `enroll-agent` only with the exact public bootstrap staged
above. A local terminal is required. The operator compares the **complete**
public fingerprint and comparison value independently against the manager,
then explicitly approves the new device. Invitation entry happens only in the
CLI's hidden terminal prompt. The inventory profile additionally requires
typing `ALLOW MACOS INVENTORY` before any key/state/network activity. Do not
relabel an existing basic identity to select inventory.

```sh
sudo -u _traceboltagent -g _traceboltagent \
  "/Library/Application Support/TraceboltAgent/enroll-agent" \
  --bootstrap "/Library/Application Support/TraceboltAgent/bootstrap.json" \
  --state-directory "/Library/Application Support/TraceboltAgent/state/enrollment"
```

For the **fresh** `macos-read-inventory-v1` profile only, append
`--macos-read-inventory`. For a separately approved renewable TLS bootstrap,
append `--automatic-certificate-renewal` after reviewing its scope. Neither
flag is implicit. An interrupted/lost enrollment response keeps the original
keys, pending operation and private directory; use the same public bootstrap and
directory to reconcile. Never erase the ledger or mint a replacement identity
automatically. The program's displayed handoff confirms the actual config
path. Run its existing `macos-agent --validate-guided` validation as the same
dedicated identity before installing a service. A foreground report may be
used only after separate native collection/network approval; it is not proof
of an installed job.

```sh
sudo -u _traceboltagent -g _traceboltagent \
  "/Library/Application Support/TraceboltAgent/macos-agent" \
  --config "/Library/Application Support/TraceboltAgent/state/enrollment/agent.json" \
  --validate-guided
```

### Service review, registration and checks

After enrollment is fully activated and the foreground sender is stopped,
copy `agentSHA256` and `sourceSHA256` from the helper's verified JSON result.
Independently compare them against the reviewed inner manifest. The source
archive path is fixed and outside the installation directory. The native
service command is root-only for lifecycle review/apply; it independently
checks the dedicated account, protected identity, source/binary, original
profile and current TLS handoff, plus exact launchd collision/override absence:

```sh
SERVICE="/Library/Application Support/TraceboltAgent/macos-agent-service"
SOURCE="/Library/Application Support/TraceboltAgentSource/source.tar"
AGENT_SHA=FULL_REVIEWED_AGENT_SHA256
SOURCE_SHA=FULL_REVIEWED_SOURCE_SHA256

sudo "$SERVICE" --action install --service-identity "$IDENTITY" \
  --profile "$PROFILE" --agent-sha256 "$AGENT_SHA" \
  --source-archive "$SOURCE" --source-sha256 "$SOURCE_SHA"
```

Only after separately approving this specific target, account, persistent
launchd job, data scope and consequences, repeat the same `--action install`
with `--apply`. The native adapter is create-only with durable ownership and
phase receipts. No installation result is a substitute for actual launchd
process state, a real manager-received fresh report, correct scope/partial
source labels, restart behavior or reboot persistence. Test each architecture
on a disposable supported Mac/APFS version and record pass/fail/skip. Check
foreground stop/SIGTERM drain, current TLS activation, exact pending retry,
same-key renewal/revocation where approved, a real reboot and actual service
restart/failure behavior. The prior synthetic collector run was partial; do
not call inventory interface metadata or log content native-accepted from it.
No TCC/Full Disk Access grant, firewall/security change or package action is
included.

```sh
sudo "$SERVICE" --action install --service-identity "$IDENTITY" \
  --profile "$PROFILE" --agent-sha256 "$AGENT_SHA" \
  --source-archive "$SOURCE" --source-sha256 "$SOURCE_SHA" --apply
```

### Removal and rollback boundaries

Before **any** enrollment or service registration, an exact, successful stage
can be deliberately reviewed for rollback. Use the same reviewed archive/hash,
identity/profile and original public bootstrap/hash with
`--action rollback`, first without `--apply`, then with `--apply` only after
approving exact owned-file removal. Rollback requires the original owner
receipt, identical bytes, an empty `state` directory, absent enrollment,
plist, service-registration custody, system job and retained override. It
removes only package-owned staged files/directories; it **retains the dedicated
account**. A changed/partial stage, any enrollment attempt, any job/custody or
uncertain inspection blocks it. Do not clean up with a broad recursive delete.

```sh
sudo "$HELPER" --action rollback --archive "$PACKAGE" --package-sha256 "$PACKAGE_SHA" \
  --service-identity "$IDENTITY" --profile "$PROFILE" \
  --bootstrap "$BOOTSTRAP" --bootstrap-sha256 "$BOOTSTRAP_SHA"
```

Stop here and separately approve the exact reviewed owned-file removal. Only
then run the effectful command:

```sh
sudo "$HELPER" --action rollback --archive "$PACKAGE" --package-sha256 "$PACKAGE_SHA" \
  --service-identity "$IDENTITY" --profile "$PROFILE" \
  --bootstrap "$BOOTSTRAP" --bootstrap-sha256 "$BOOTSTRAP_SHA" --apply
```

Once service installation was completed, `rollback` is unavailable because
service-registration custody is retained. To deliberately remove the **owned
installed job**, run the exact service command above with `--action uninstall`
instead of `--action install`, first read-only and then with `--apply` under
separate approval. It makes one owned removal attempt. It retains all
registration custody/tombstones, package owner marker, binaries, source
archive, public bootstrap, account, enrollment keys/approval, sender counters
and private state. Uncertainty after a started removal permits read-only
reconciliation only, never automatic retry. Credential revocation, account
deletion and permanent state removal are distinct, unsupported operations.

```sh
sudo "$SERVICE" --action uninstall --service-identity "$IDENTITY" \
  --profile "$PROFILE" --agent-sha256 "$AGENT_SHA" \
  --source-archive "$SOURCE" --source-sha256 "$SOURCE_SHA"
```

Stop here and separately approve removing that exact owned launchd job. Only
then run the effectful command:

```sh
sudo "$SERVICE" --action uninstall --service-identity "$IDENTITY" \
  --profile "$PROFILE" --agent-sha256 "$AGENT_SHA" \
  --source-archive "$SOURCE" --source-sha256 "$SOURCE_SHA" --apply
```

If stage creation or rollback stops partway through, keep the exact paths,
owner receipt, account mapping and command output for a qualified local
administrator to inspect against the original reviewed package. No automatic
repair/adoption command exists. The narrow recovery decision is whether the
original operation demonstrably never crossed a mutation boundary, whether
exact package-owned bytes remain with no enrollment/service evidence, or
whether uncertainty requires preserving custody. The helper intentionally
provides no reset, broad remove or `rm -rf` shortcut.

## Evidence still open

Source fixtures and Darwin cross-builds only prove the selected source's
bounded logic and compilation. Before claiming a release, independently test
actual Directory Service/effective UID isolation, APFS descriptor/ACL/full-flush
and interruption behavior, hidden terminal/cancellation, TLS enrollment and
real manager reports, current launchctl collision/override semantics, launchd
credentials and supplementary groups, stop/restart and reboot persistence,
and safe owned uninstall on Apple Silicon and Intel. Final signed/notarized
distribution, Gatekeeper behavior and publisher identity remain separate work.
