# Local Linux journal helper setup

This is the create-only setup path for the Linux on-demand service-log MVP.
Read [installation.md](installation.md) and the existing
[agent service contract](linux-agent-service.md) first. The script and tests are
source work: no real account, journal source, socket activation or reboot gate
has been exercised by these fixtures. Applying this setup is a separate,
explicitly approved persistent access change on the named Linux host.

## What the administrator approves

The unchanged `tracebolt-agent` service keeps its current UID, primary group,
empty supplementary group set, installed binary and private enrollment/state.
The setup creates a distinct non-login `tracebolt-journal-reader` account with
an automatically allocated system UID and its own primary group. The account
has **no supplementary membership**. Only the helper systemd unit receives the
host's already-existing numeric `systemd-journal` GID. That OS group can read a
broad journal; the helper's fixed parser and root-protected policy enforce the
explicit 1–32-service allowlist. Neither `adm`, `wheel`, capabilities, ACL changes,
nor a root-running main agent are alternatives.

Approve the exact listed services and destination. Log messages may contain
passwords, tokens, personal data and other sensitive information. Masking is
best effort and **does not make the messages secret-free**. The grant permits
one-hour queries in the preceding 24 hours, severity 0–7, and literal text search
within the resulting bounded snapshot. It is an on-demand log reader, not a
continuous feed or a general command runner. HTTP-test requires an additional
acknowledgement: log content is readable on the network and the manager can be
impersonated. Existing inventory/telemetry consent is insufficient for either
log-content consent or that separate plaintext-content risk.

The helper has a fixed Unix socket, no network, no caller-selected paths, and
no access to the packaged agent enrollment/private-key directories. The main
agent never joins the journal group. Existing ordinary telemetry must continue
if helper provisioning fails safely; a failed setup is never reported as a
working helper.

## One reviewed plan/apply command

Prerequisites:

- The selected, reviewed revision's `lan-agent` is already installed through
  `agent-service`, with a fully activated v3 identity. Use the existing reviewed
  upgrade workflow first if the installed binary lacks journal consent support.
- Linux, running systemd, Python 3.9 or newer, and the normal system `useradd`,
  `nologin`, and `systemctl` commands already exist. This script installs no tools.
- The existing install manifest, exact artifacts/unit, account, installation
  owner/state-directory identity, and existing installer lock validate. There
  are no unresolved installer transactions. Units have no aliases, drop-ins or
  transient overrides. NSS account/group lookup is local `files`, optionally
  followed by `systemd`; other account-provider layouts need separate review.
- The helper account/group, helper units/drop-ins, `/etc/tracebolt`,
  `/run/tracebolt-journal-reader` and the helper enablement link do not exist.
  Even apparently matching leftovers are refused. No foreign path is adopted.
- The script and its sibling `../systemd/*.in` templates are the reviewed source,
  root-owned in non-writable, non-symlink ancestor directories. Use the
  create-only committed-source staging below. Do not run a root Python script
  from another user's writable checkout or change arbitrary parent permissions
  to make preflight pass.

### Stage the exact reviewed committed bytes

A root-owned checkout can still be group-writable because of its creation umask.
Do not recursively chmod it or make the plan accept it. After independently
verifying the full reviewed commit, this separate administrator staging command
copies only four blobs from that commit into the fixed private prefix
`/root/tracebolt-journal-setup`: the setup script, the two helper templates and
`tracebolt-agent.service.in`. That fourth read-only template is required to
verify the exact existing main-agent unit; it is never installed by this setup.
No working-tree file is copied or executed. The following staging command is
provided for the approved host and has not been executed by the fixture tests.

Replace `REPO` with the checkout's absolute path and `REV` with the independently
verified full 40-character lowercase Git commit ID. Do not substitute a moving
branch name or an unverified working-tree checksum. This command needs a separate
administrator approval for these exact staging paths when performed by an
assistant:

```sh
sudo /bin/sh -eu <<'STAGE'
umask 077
REPO=/root/Tracebolt
REV=REPLACE_WITH_FULL_REVIEWED_COMMIT_SHA
DEST=/root/tracebolt-journal-setup

# Refuse unsafe root ancestors and any existing destination, including symlinks.
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
set -C  # No overwrite: failed or interrupted staging is retained for inspection.
for relative in \
  deploy/journal/setup.py \
  deploy/systemd/tracebolt-journal-reader.service.in \
  deploy/systemd/tracebolt-journal-reader.socket.in \
  deploy/systemd/tracebolt-agent.service.in
do
  /usr/bin/git --no-pager -C "$REPO" -c core.fsmonitor=false \
    cat-file blob "$REV:$relative" > "$DEST/$relative"
done
/usr/bin/sha256sum \
  "$DEST/deploy/journal/setup.py" \
  "$DEST/deploy/systemd/tracebolt-journal-reader.service.in" \
  "$DEST/deploy/systemd/tracebolt-journal-reader.socket.in" \
  "$DEST/deploy/systemd/tracebolt-agent.service.in"
STAGE
```

The scoped umask creates root-private directories (`0700`) and source files
(`0600`). The plan can read them as root; the helper never uses this staging
area. Existing files/directories are not adopted, removed or permission-repaired.
If any command fails, retain the partial destination and inspect the failure;
do not delete it just to rerun this command. Compare the printed hashes with the
selected reviewed revision's artifact record before proceeding. Git blob
selection verifies the chosen content identity, not publisher authenticity.

### Inspect the plan, then approve apply

On the approved host, select the actual units explicitly. These service names
are examples to replace, not service-discovery guesses:

```sh
sudo /usr/bin/python3 -I /root/tracebolt-journal-setup/deploy/journal/setup.py \
  --allow-unit example-api.service --allow-unit example-worker.service
```

This default plan performs bounded local metadata reads and read-only systemd
unit inspection. It creates no files, accounts, locks, sockets, service state or
consent markers, and it never invokes the journal source or reads the agent's
private config/key/ledger as root. It shows the exact origin from the already
hash-bound public bootstrap, existing agent IDs, existing journal GID, selected
services, fixed paths, template/installation hashes, permissions, risks and a
`planSHA256`. The private sender binding and public leaf identity are resolved
only by the stopped nonroot consent preview during apply. An active agent is
not stopped merely to make a plan.

After the administrator approves that exact host, origin, services, new helper
account/unit-scoped journal access, socket enablement and log-content risk,
repeat with the returned digest:

```sh
sudo /usr/bin/python3 -I /root/tracebolt-journal-setup/deploy/journal/setup.py \
  --allow-unit example-api.service --allow-unit example-worker.service \
  --apply --expected-plan-sha256 REPLACE_WITH_REVIEWED_PLAN_SHA256 \
  --ack-journal-content
```

Only for the explicitly selected HTTP-test profile, also provide
`--ack-journal-http-plaintext`. The script rejects that flag for TLS and rejects
HTTP apply without it. A changed reviewed plan fails before stopping the agent.
Passing flags is a local execution guard, not a substitute for an assistant's
required human authorization.

Apply holds the existing installer lock, rechecks ownership, stops only the
owned agent service, then invokes the existing binary with its existing UID/GID
and an explicitly empty supplementary group list:

```text
/opt/tracebolt-agent/lan-agent --config /var/lib/tracebolt-agent/enrollment/agent.json --service-identity UID:GID --journal-content-consent preview
```

That stopped nonroot command validates the enrollment handoff and existing
ledgers and returns only the fixed public DTO: sender binding, exact origin,
transport/collection profile, device ID, full public leaf hash and UID/GID. It
performs no collection, helper connection or network request. The preview must
match the public plan. Root does not open the private key. Only after this check
are the helper account and new root-owned fixed artifacts created.

The setup invokes the same stopped nonroot command with `initialize`,
`--ack-journal-content` and the HTTP-only plaintext flag as appropriate. That
command requires the valid root-protected client declarations and creates only
the separate journal state marker. It does not reset any enrollment or ledger.
The socket is enabled/started after initialization. The helper service is socket
activated; setup makes no log query. A previously active agent is restarted on
success and on safely recoverable setup failure. A previously stopped agent is
left stopped. Enablement of the original agent is never changed.

## Fixed artifacts and exact copies

The existing `/opt/tracebolt-agent/lan-agent` remains owned by `agent-service`.
The helper uses only its exclusive `--journal-reader` invocation. No new binary
or release role is introduced.

| Fixed artifact | Ownership / mode |
| --- | --- |
| `/etc/tracebolt` | newly created root directory, `0755` |
| `journal-setup-attempt.json` in that directory | root:root, `0600`; retained attempt evidence |
| `journal-helper.json`, `journal-content-policy.json` | root:helper-primary-GID, `0640` |
| `journal-client-helper.json`, `journal-client-policy.json` | root:existing-agent-GID, `0640` |
| `/etc/systemd/system/tracebolt-journal-reader.service` and `.socket` | root:root, `0644` |
| `/etc/systemd/system/sockets.target.wants/tracebolt-journal-reader.socket` | systemd's fixed enablement link |
| `/run/tracebolt-journal-reader/reader.sock` | systemd-created root:existing-agent-GID, `0660`, protected root directory |

The helper/client deployment files are generated from one canonical byte slice;
the helper/client policy files are generated from one canonical byte slice.
Each pair therefore has exactly identical bytes and SHA-256, not independently
re-encoded JSON. The client deployment pins the precise expected helper UID/GID
for kernel response-credential verification. Numeric units pin the exact local
IDs; no identity is inferred from remote requests or group-name text.

The only additional host effects are the fixed system account/primary-group
creation through `useradd`, fixed unit reload/socket enablement, and existing
agent stop/start. The agent's consent CLI alone owns its private journal marker.
The script has no arbitrary destination, alternate root, shell, credential,
network download, package installation, policy-edit, uninstall or reset option.

## Failure and revocation

A setup failure retains any new account, policy/unit files, attempt evidence and
consent state. A partial write, uncertain account creation or interrupted process
is **not automatically adopted, deleted or chmodded on retry**. Do not remove
leftovers or reset identity/counters to make the command pass. Inspect the exact
retained failure stage with the administrator and choose a separately reviewed
recovery. A process or host crash can leave the original agent stopped: normal
exception recovery is not a crash transaction guarantee.

If the original install ownership, unit, binary, state domain or installer
transaction changes unexpectedly, restarting it is blocked rather than bypassing
its ownership failure. The output reports `agent-restart-blocked-retain-state`;
resolve that through the existing installer recovery process. `configured=true`
means the declared files/consent/socket were provisioned and checked. It does not
prove a successful real log read or reboot. `sourceVerified` and `contentRead`
remain false because setup never runs a log query.

To revoke new reading promptly, after authorizing the exact service action on
that host, stop/disable the owned socket and stop the owned helper service:

```sh
sudo /usr/bin/systemctl disable --now tracebolt-journal-reader.socket
sudo /usr/bin/systemctl stop tracebolt-journal-reader.service
```

Verify the units are the owned fixed units with no unexpected aliases/drop-ins
before these commands. This does not stop the main agent. New helper calls and
final delivery checks fail closed, suppressing unsent content. Bytes already
written cannot be recalled, and a result already delivered to the manager can
remain in its short-lived RAM store until its original 15-minute expiry.
Do not delete the helper account, declarations, consent marker or durable query
floor to disable reading. An atomic `enabled=false` policy replacement and any
re-enable/edit lifecycle require separately reviewed ownership handling and are
not supplied by this create-only MVP. Stopping the exact socket/service is the
supported operational disable procedure here.

## Inert verification and remaining real gate

```sh
python3 -m unittest discover -s deploy/journal -p 'test_*.py' -v
```

These tests use in-memory metadata, account files, commands and sockets. They
cover read-only planning, exact policy/deployment copies, frozen write targets,
acknowledgements, strict allowlists, ownership/artifact/transaction failures,
foreign units/aliases/drop-ins/accounts, retained partial failure, nonroot
preview/init and safe original-agent recovery. They never run `useradd`,
`groupadd`, `systemctl`, `journalctl`, a real helper or real host source reads.

A separately authorized disposable native Linux/systemd VM must still establish
account allocation, hardening compatibility, real socket activation/credential
checks, journal visibility, bounded actual service/time/severity/text queries,
cancellation, revocation, restart and reboot behavior. Record exact source,
platform and results; do not describe these fixtures as that acceptance gate.
