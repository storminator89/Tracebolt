# Offline socket-owner consent lifecycle: source candidate

This source-only interface supports one approved, stopped-agent provisioning
operation. It installs no helper, grants no OS capability, starts no service,
contacts no IPC/manager and collects no host metadata. Source fixtures do not
establish native systemd/LSM acceptance or authorize use on an installed host.
The main sender stays unprivileged. Helper executable/cgroup/peer gates remain
unchanged; offline setup must never substitute a helper `Verify` call.

## Fixed interface

`lan-agent` reserves these exclusive modes before all ordinary sender/helper
paths: `--socket-owner-setup-capabilities`, `--socket-owner-setup-identity`,
`--socket-owner-setup-preview`, `--socket-owner-setup-initialize`, and
`--socket-owner-setup-disable`. Capabilities is inert and takes no other flags.
Every other mode requires `--service-identity UID:GID`, executed as that same
nonroot, primary-group-only identity. No config, file, socket, service or path
selector is accepted. The sole config is
`/var/lib/tracebolt-agent/enrollment/agent.json`. Aliases, assignments, duplicates,
extra arguments and combinations with any other mode reject before state reads.

Identity and preview are read-only. They reuse the existing authoritative
activated-material producer, including ready marker, certificate/key agreement,
exact sender binding and all three existing sender ledgers. No second identity
registry is created. Their public projection uses
`tracebolt.socket-owner-setup-identity.v1`, with transport exactly `tls` or
`http-test`, sender binding as bare lowercase SHA-256, and incarnation digest
as `sha256:` plus lowercase SHA-256. Public projections are not grants.

Initialize and disable consume only a canonical `socketowner.Policy` JSON
object on stdin, no trailing newline, at most 4096 bytes. Initialize requires
`enabled:true`, `--ack-socket-owner-metadata`, and
`--ack-socket-owner-ptrace-risk`. HTTP-test additionally requires
`--ack-socket-owner-http-plaintext`; TLS rejects that extra acknowledgement.
Those flags record the single already-approved orchestration's acknowledgement;
there is no second prompt or implied permission to perform setup.

The explicit approval must cover socket endpoints, process ownership metadata,
and process names, the broad OS authority of CAP_SYS_PTRACE, and HTTP-test's
plaintext unauthenticated transport when applicable. A metadata-only application
protocol does not turn CAP_SYS_PTRACE into metadata-only OS authority.

## Create once, disable once

Mutations take the existing sender inspection lease and system-state lock,
reread activated material under both locks, and check it again before committing.
The system ledger is opened without crash recovery. Existing incomplete
system-state or consent temporaries reject; no setup operation cleans them.
Create-only mode-0600 `socket-owner-consent.json` lives in the existing protected
sender state directory. An exclusive private temporary, file fsync, no-replace
initial rename, directory fsync and protected readback establish success.
Existing enabled, disabled, corrupt, foreign or unsafe consent cannot be adopted.

Disable accepts `enabled:false` and otherwise the exact existing policy. It
first durably replaces the enabled consent with its same-identity tombstone.
Only then may it call the existing `State.Discard` for a structurally valid,
identity/sequence-bound owner-provenance-tagged pending frame. The entire pending
body is abandoned and the consumed sequence floor remains unchanged. Ordinary
pending bytes are preserved exactly. Corrupt ledgers, corrupt pending frames,
identity changes or certificate renewal reject without repair or rebinding.

Disabled consent is terminal in this slice. There is no unlink, re-enable, new
epoch, renewal, retry-drain, missing-state recovery or implicit migration path.
A failure after any persistence is incomplete, even if some bytes reached disk.
A verified tombstone followed by a drain failure is reported explicitly as
persisted disabled consent with pending disposal unconfirmed. Preserve the
private evidence and keep agent/helper stopped; a separately reviewed recovery
transition is required. Never infer completed disposal from an error or replay
initialize/disable against the retained state.

## Bounded result and remaining gates

Successful non-capability output is one JSON object, at most 8192 bytes, with
`schemaVersion: tracebolt.socket-owner-setup-result.v1`, `mode`, current public
`identity`, `state: absent|enabled|disabled`, exact `policy` or null, and
`taggedPendingDiscarded`. The discard flag describes only this successful
operation, not historical disposal or evidence that every pending body is absent.
Failures exit 2 with bounded redacted stderr and no success JSON. No private
paths, credential material, raw pending bodies or collected rows are returned.

Tests use invented identities/frames, in-memory state, injected CLI/syscall
failures and private temporary synthetic material. They cover canonical input,
acknowledgements, stopped-owner contention, immutable identity, exact matching,
partial writes, retained temporaries/tombstones, tagged-only disposal and floor
preservation. They do not run the native helper, create a socket, inspect procfs,
install an artifact, grant capabilities, change accounts or touch a service.
Actual installed-artifact, loaded-unit confinement, namespace/LSM behavior,
latency/resource bounds and reboot acceptance remain separately authorized
manual disposable-systemd-VM gates.
