# Selected APT privileged source candidate

These templates and `internal/packagehelper` are real source implementations,
not an installation or a native-acceptance result. They are default-off. No APT,
dpkg, systemd, native helper, service, account, privilege or package mutation was
run while developing this slice. Ordinary-user fixture tests use fake subprocess
runners and temporary files. No deployment script or startup initializer is
provided. The source-only explicit command
`/usr/libexec/tracebolt-package-helper --initialize --ack-local-root-package-scope`
calls `Initialize` only after separate administrator approval and preprovisioning.
It is never a runtime fallback.

## Separate local approval and preparation

An administrator must review the actual Debian 13 amd64 APT 3.0.3/dpkg 1.22.x
machine, exact binary build artifacts, source/key/pin configuration, policy and
native gate results. The root-local policy is the exact canonical JSON `Policy`
from `internal/packagehelper/policy.go`, at `/etc/tracebolt/package-actions.json`.
Its `enabled` starts false. The raw 32-byte public command key is at
`/etc/tracebolt/package-actions/command.pub`. Runtime takes no policy/key/state
path or command override. The public key is separate from enrollment trust.
The manager must bind its exact policy digest and transport. Plain HTTP requires
an explicitly disposable policy and acknowledgement of stolen-session risk.

`tools` must contain the exact ordered fixed paths from `requiredTools`, with
SHA-256 pins for the independently reviewed current artifacts. The native
acceptance digest is an explicit local assertion identifying acceptance evidence;
it does not run or magically establish that acceptance. Pin approved sources,
preferences, keyring and host configuration as described in
`internal/nativeapt/README.md`. Package selection is at most 32 sorted amd64
identities from the local allowlist. There are no request-supplied commands,
options, paths, sources, pins, keys or environment entries.

Before package state is initialized, the old service-action helper AND its socket
must be stopped. Upgrade the service-helper binary to the shared-mutation-fence
implementation and independently review its digest. Provision
`/etc/tracebolt/package-actions/service-fence-reviewed` as precisely:

    tracebolt-service-helper-shared-fence-v1
    sha256:<reviewed updated /opt/tracebolt-agent/lan-agent artifact>
    legacy-helper-quiescent-before-initialization

All lines end in LF. The policy binds the digest of these exact bytes. This is an
administrator review receipt, not a network grant. The explicit initializer
checks both service and socket inactive before creating state. Runtime checks the
live service-helper `/proc/PID/exe` digest, stable process start identity, and an
open descriptor to the exact protected shared-fence inode, as well as the on-disk pin, preventing a
still-running old executable from becoming trusted merely through disk upgrade.
Never run a legacy unfenced service helper alongside enabled package actions.

The existing directories `/var/lib/tracebolt/package-updates` and
`/var/lib/tracebolt/mutations` must be root-owned/private and preprovisioned. The
explicit initializer creates each state once and refuses existing state. It does
not reset, clear, repair, adopt or reopen consumed admissions. Partial setup
failure requires review, never deletion/reinitialization to retry. There is no automatic mkdir/state repair or installer. The explicit initialization
command does not install binaries, generate keys, grant permissions, start units
or enable policy.

## Durable lifecycle

The broker accepts one inherited fixed Unix socket and verifies kernel UID/GID.
Only capabilities, signed submission and status are accepted. Envelopes, job
records, previews, raw hook bytes, complete receipts, claims and outcomes are
root-owned create-only files. Every ancestor is opened nofollow. Final files must
be regular, single-link, correctly owned and not group/other-writable. Reads
recheck object identity/metadata and bound byte counts. The shared mutation fence
retains identity, per-action sequence floors, original admission and clock floor.

The shared admission is durably consumed, the protected original envelope and
admission marker are persisted BEFORE systemd receives
the internally derived fixed unit. Any uncertain return/crash/repeated ID stays
consumed. Neither socket status nor runner restart launches another operation.
A missing admission/claim/result is never reconstructed as permission or success.
A definite busy rejection before shared admission creates no job. After admission,
an inactive/failed unit with no pending systemd job/main process becomes explicit
needs-intervention, including a missing claim and preparation-only interruption.
This never authorizes a retry or releases an unknown mutation fence. Per-file
write-intent markers refuse partial/uncertain records without automatic repair.
An error/unknown applying outcome keeps the mutation fence active.

Historical status uses the protected current endpoint/manager/incarnation/public
key binding and verifies original signed envelopes, without requiring today's
unrelated tool hashes or enabled state to match. Replacing the agent binary while
an admitted APT process runs neither cancels it nor hides its saved result. New
admissions still fail until live pins are reviewed and updated. Rebinding identity
or changing the public key does not grant access to historical jobs.

The independent fixed runner has no agent/helper PartOf/BindsTo relationship,
Restart=no and no applying timeout/cancellation. Preparation and capture alone
are bounded at 20 minutes each. Capture and execution use byte-identical APT
argv, environment, APT_CONFIG and configuration. Mode is protected state only.
The guard proves a proc-verified apt-get ancestor owns the actual frontend POSIX
lock, acquires the inner lock, verifies exact old status/holds/versions, clean
pending/triggers state, live local configuration/policy and actual nofollow
archive bytes. Capture persists a full raw-hook/preview receipt and ALWAYS
aborts. APT exit 100 by itself is not successful preparation. Execution verifies
the approved immutable plan and original expiry under lock, consumes the only
hook admission durably, and only then permits dpkg.

After apt exits successfully, the runner reacquires both locks and checks the
complete bounded dpkg status and exact selected target versions. Unknown/failed
results retain needs-intervention and the shared fence. Reboot evidence preserves
the original observation time, native source and required/not_reported/unknown
state. There is no automatic reboot, package retry, rollback, repair, lock
removal, competing-manager termination or arbitrary shell execution API.
The underlying APT hook invokes its fixed guard through APT's normal mechanism;
maintainer scripts remain privileged and may restart services or alter the host.

## Remaining native gate

See `native-acceptance.md`. Compilation and invented fixtures do not establish
real lock custody, tool ABI compatibility, native v3 ordering, cancellation,
unit lifetime, filesystem TOCTOU, updates or successful deployment.

## Exact placement for later approved provisioning

Build `./cmd/package-helper`, `./cmd/package-runner`, `./cmd/package-guard` and the
separate native preparer into the four fixed `/usr/libexec/tracebolt-package-*`
paths (`tracebolt-apt-prepare` for the native binary), root-owned with no writable
nonroot components. The current fenced service binary stays at
`/opt/tracebolt-agent/lan-agent`. Review/pin every fixed artifact listed in Policy.
Copy these reviewed unit templates to matching filenames under
`/etc/systemd/system/`, replacing only the locally reviewed agent primary group
placeholder in the socket template. Unit installation, `daemon-reload`, enabling
and starting the socket all need separate explicit approval and are not performed
by the initialization command. Provision the documented protected directories
and files first; run the explicit initialization command only with both old
service helper and socket stopped, then independently verify state and grants.
Do not enable any unit until native acceptance and policy review are complete.

The initial exact allowlist additionally excludes apt/apt-utils/dpkg/libapt-pkg*,
libc6 variants/libc-bin, systemd*, linux-*/kernel*/grub*, openssh*, iproute2,
network-manager, and Tracebolt/localrmm packages. Updating these foundations needs
a separately reviewed support extension. Other packages' maintainer scripts are
still privileged; these exclusions are not proof that other packages are harmless.

The separate package IPC uses a 264 KiB request-frame bound (including base64 of
its 192 KiB signed envelope) and a 1 MiB response-frame bound. It does not widen
the service-action protocol. Protected hook streams remain 256 KiB, prepared
bundles/preview receipts remain 256 KiB, individual structured result files are
bounded at 256 KiB, and composed snapshots are bounded before durable publication.
