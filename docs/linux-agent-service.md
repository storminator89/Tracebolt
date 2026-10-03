# Linux systemd agent installer

Status: implementation candidate with disposable filesystem/process tests. Actual
systemd installation, root-to-service credential dropping and boot persistence
are separate acceptance gates. Do not infer them from unit tests or cross-builds.
The native foreground sender and guided enrollment are separate tested features.

## Supported boundary

`agent-service` operates only on Linux with a running systemd PID 1 and cgroup v2.
It accepts local files; it never downloads or runs a shell pipeline. Build the
installer, `enroll-agent` and `lan-agent` from the same selected revision. Verify
the installer's own bytes before invoking it. Independently selected SHA-256
values for both client binaries, a source archive and the public bootstrap are
required for installation. These checks prove selected-byte integrity, not
publisher authenticity or a reproducible source-to-binary relationship.

The default is read-only preflight. `--apply` is an explicit local administration
boundary and requires root. Deployment, persistent identity creation, account and
service changes still require the administrator's concrete authorization. This
runbook grants no permission to operate a host.

Fixed paths:

- `/opt/tracebolt-agent`: root-owned verified native binaries and installation manifest
- `/etc/tracebolt-agent/bootstrap.json`: root-owned public bootstrap
- `/var/lib/tracebolt-agent`: dedicated account-owned mode-0700 identity/state
- `/var/lib/tracebolt-agent-installer`: root-owned mode-0700 ownership/journal records
- `/etc/systemd/system/tracebolt-agent.service`: generated root-owned unit

Existing foreign accounts, groups, units, aliases, transient units, drop-ins,
artifacts or unmarked installer directories are rejected. Paths are not adopted
or recursively chmod/chowned. The unit uses the recorded numeric UID/GID; the
sender rejects unexpected real/effective/saved IDs or additional supplementary
groups before reading its private state. Native Windows/macOS service installers
are not included.

## Installation

Build from the selected checkout with its pinned Go toolchain:

```sh
go build -buildvcs=false -o bin/agent-service ./cmd/agent-service
go build -buildvcs=false -o bin/enroll-agent ./cmd/enroll-agent
go build -buildvcs=false -o bin/lan-agent ./cmd/lan-agent
```

Prepare the public bootstrap through Add device. Do not put the invitation in an
argument, environment variable, file, chat or log. The enrollment child displays
the exact destination/trust and reads the invitation from a hidden controlling
terminal after dropping UID/GID and supplementary groups. Compare its full local
fingerprint and comparison value in the manager before approval.

First run the command below with real absolute paths and independently selected
hashes substituted for every placeholder. It performs preflight only. After
review and authorization, repeat the same command with `--apply`.

```sh
sudo /absolute/path/agent-service --action install \
  --agent-binary /absolute/path/lan-agent --agent-sha256 EXPECTED_AGENT_SHA256 \
  --enroll-binary /absolute/path/enroll-agent --enroll-sha256 EXPECTED_ENROLL_SHA256 \
  --source-archive /absolute/path/selected-source.tar --source-sha256 EXPECTED_SOURCE_SHA256 \
  --bootstrap /absolute/path/public-bootstrap.json --bootstrap-sha256 EXPECTED_BOOTSTRAP_SHA256
```

An explicitly selected disposable HTTP test bootstrap additionally requires
`--insecure-http-test`. Invitations and telemetry are observable in this mode;
the HTTP manager and activation responses are not authenticated. There is no
automatic TLS downgrade or global trust change.

The real adapter creates a dedicated non-login account, stages the selected bytes,
rechecks binary role/architecture on the protected staged snapshot, runs enrollment
as that account and invokes `lan-agent --validate-guided` as that account. That
validation checks the exact ready marker/config/certificate hashes and existing
bound sender ledger without DNS, network, collection, initialization or cleanup.
Only then does it publish, enable and start the service.

The parent installer saves/restores terminal settings on normal, canceled and
forced-child-exit paths. It requests graceful child cancellation, then applies a
bounded kill delay. Abrupt death of the installer itself can still require normal
terminal recovery; it is not a transactional terminal guarantee across host loss.

## Operations and retained state

- `--action upgrade`: requires selected replacement binary/source paths and hashes.
  Stops/drains the exact owned service, validates the existing identity/ledger,
  replaces only owned binaries/unit, and starts the service. Previous enablement
  is preserved. It never resets keys, pending bytes or sequence state.
- `--action restart`: stops/drains, validates and restarts the owned service.
- `--action uninstall`: stops/disables and removes only owned unit/binaries/manifest.
  The account, public bootstrap and all private identity/counter data remain.
  Repeating a completed owned uninstall invokes no service/account command.
- `--action install --resume`: explicitly reuses a fully recorded retained
  preparation or completed uninstall with the exact same selected artifact and
  bootstrap hashes and same private state-directory identity. It cannot replace
  an existing installed service or silently recreate lost state.

There is no reset or identity-purge flag. Invalid/missing/replaced state requires
inspection and a separately authorized recovery decision. A failure during an
uncertain account creation or a crash with an unresolved journal fails closed;
it is not automatically adopted, erased or declared rolled back. Ordinary failed
enrollment can retain a validated preparation for explicit same-identity resume.

Rollback reconciles the durable commit marker before undoing owned changes. A
confirmed commit is never destructively rolled back after an uncertain response.
Successful rollback restores owned files and prior enablement while deliberately
leaving the service stopped after failed validation. It retains account/identity.
`rolledBack: false` means recovery is unresolved, not permission to delete state.

The unit reports every 30 seconds, denies privilege escalation, restricts writes
to its state directory and has at most five failed starts in 300 seconds. It has
no automatic reset or patch execution. Generic remote transport failures remain
bounded retries; they are not asserted to be authenticated revocation notices.
`ConditionPathExists` is only a hint: the sender enforces the guided state.

## Evidence and remaining acceptance

Fixture tests cover orchestration, cancellation, same-identity resume, ownership,
foreign systemd resolution, account collisions, exact binary integrity, rollback
and enablement, repeated uninstall, numeric identity, local validation, and parent
terminal restoration after killing an inert child. No real account or service is
created by these default tests.

The separately gated [systemd test plan](../tests/systemd/README.md) requires a
fresh explicitly approved disposable VM. Its results must distinguish actual
install/start/restart/upgrade/uninstall from a true OS reboot, which needs a
separate disposable-guest gate. Do not run privileged test flags on a user host.

The unit's restart and sandbox settings follow the upstream
[systemd service](https://raw.githubusercontent.com/systemd/systemd/main/man/systemd.service.xml)
and [execution](https://raw.githubusercontent.com/systemd/systemd/main/man/systemd.exec.xml)
contracts. Account arguments follow the upstream
[useradd](https://raw.githubusercontent.com/shadow-maint/shadow/master/man/useradd.8.xml)
contract; runtime acceptance still depends on the selected supported host.
