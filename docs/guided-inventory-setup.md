# One-time local inventory collection setup

The inventory guide groups two existing default-off scopes into one deliberate
local setup for an **existing activated Linux managed-operations-v3 agent**:

- Full visible processes and mounted filesystems, at the existing 60-second
  capture cadence. Process names, mount paths and filesystem labels can be sensitive.
- All known newer cached APT candidate rows, at the existing six-hour cadence:
  package names, architectures, installed/candidate versions, holds, comparison
  gaps and original local index modification age.

Hostname and all visible interface IPv4/IPv6 addresses are a **separate optional
selection**, off in the generated command unless specifically selected. The guide
does not grant the older bounded APT-preview scope. Existing profile, device
identity, counters, pending bytes and original capture ages are preserved.

This is orchestration of the installed agent's existing consent commands, not a
new collection authority. It does not install or upgrade binaries, alter a
manager, create an account, change permissions or service definitions, refresh APT, install
packages, configure journals or repair pending journal state. It never queries
process, mount, APT, hostname, interface or journal sources itself. Normal
reporting resumes with the selected scopes only after the operator's approval.
The manager/UI cannot turn these scopes on.

## Operator flow

Use the single **reviewed, publication-verified command** supplied for the exact
source revision. Run it deliberately in a local root terminal on the intended
endpoint. Python 3, an already installed compatible agent, and the existing
owned systemd installation are required; no dependencies are installed.

1. The command verifies immutable public source bytes before executing them.
   Source runs in memory, with no staging directory or cleanup instructions.
2. Read-only preflight verifies the owned installation, fixed paths, protected
   v3 configuration, and actual installed binary's existing consent flags. It
   does not pause monitoring, acquire a sender lock or execute a consent preview.
3. Review the selected data, manager, device and transport. Consent state is
   honestly shown as **unknown until stopped-agent validation**. One confirmation
   explicitly covers the brief pause, existing validation/enables and restoring
   previous activity. Enter or EOF cancels before the agent is stopped.
4. After approval, the guide locks/rechecks the installation and pauses only the
   previously active owned agent. It previews every selected scope and checks
   protected sidecar/initialization shape before the first consent write.
5. Already enabled selections are skipped. Each missing selection uses its
   existing identity-bound enable CLI as the nonroot numeric UID:GID, with
   supplementary groups cleared, then gets a separate readback.
6. Read the per-scope result. The previously active agent resumes if safe; an
   originally inactive agent stays inactive. Check the dashboard for newly
   received generations, timestamps and coverage, which setup alone cannot prove.

HTTP-test disclosure is explicit: selected metadata is transmitted in plaintext
and the manager is unauthenticated. Its confirmation phrase includes `OVER HTTP`.
No invitation, private key or authentication token belongs in this command.

## Partial results and retry

The independent consent writes are **not one atomic transaction**. Existing
preview modes validate the base identity and report consent; deeper existing
spool checks still belong to each enable operation. Consequently an earlier
scope can be confirmed before a later scope fails.

- `already_enabled`: its existing grant was verified and left unchanged.
- `enabled_confirmed`: enable and its separate preview readback succeeded.
- `uncertain`: an enable was attempted but its outcome/readback was not confirmed.
- `not_attempted`: no enable was attempted for this selection.

A known prewrite failure restores the previously active agent only after
unchanged ownership and the existing local baseline validator pass. An uncertain
enable leaves it stopped. The report identifies the scope and fixed failure
stage and gives the exact service status/resume commands. **Inspect the failure
and verify the same protected installation before using the resume command.**
No script can guarantee recovery after SIGKILL, power loss or a second interrupt;
the status command also covers those interruptions.

Do not delete or edit consent files, initialization markers, spools, identity
files or counters. Malformed/foreign consent that a preview reports as disabled,
leftover temporary/init markers and half-created spools are rejected and retained.
An unrelated pending journal setup is neither repaired nor changed. After the
exact blocker is safely resolved, rerun the same reviewed guide: it previews
again and skips confirmed enabled selections. No per-feature manual commands
are needed for the ordinary successful flow.

## Coverage is still bounded by reality

“Full” describes all successfully enumerated visible rows in the agent's Linux
namespaces, not universal host visibility. Missing, denied and unavailable fields
stay explicit. Installed packages remain dpkg inventory, not Snap/Flatpak/manual
software discovery. Full cached APT candidates do not mean every package was
comparable, metadata is fresh, packages are installable, or the machine is fully
up to date. The existing native adapter's supported release/configuration checks
still apply; unsupported sources must not appear as a successful zero. This
setup does not add socket-to-process ownership or any new OS privilege.

The detailed scope contracts remain authoritative:
[process/mount scope](complete-overview-extension.md),
[full cached APT scope](complete-cached-updates-extension.md), and
[optional hostname/interfaces](endpoint-identity-extension.md).

## Publication and verification

Maintainers can prepare the default single command only after publishing reviewed
source and its manifest. This is command preparation, not host execution:

```sh
python3 -B deploy/inventory/prepare-guide-command.py --revision FULL_PUBLISHED_COMMIT
```

Add `--include-network-identity` only when the operator deliberately wants that
additional selection. The generator verifies every public byte against this
checkout before printing anything executable. `--refresh-manifest` is for source
maintenance before review/publication; it does not run the guide. A source commit
does not change the dashboard's download release or upgrade an installed agent.
The guide checks installed flags rather than assuming the installed binary
matches current main. Unsupported binaries fail before any service pause.

The fixture suite uses invented installation records, command responses and
state shapes. It covers no-change cancellation, unsupported installed flags,
all-previews-before-writes, safe ordinary-error restoration, partial/uncertain
outcomes, already-enabled retry, originally stopped agents, public-byte pinning,
optional scope selection and untouched pending-journal evidence. It executes no
actual host command or data source. Real installed-service, Debian/Ubuntu APT,
namespace and reboot acceptance remain separate operator-controlled gates.
