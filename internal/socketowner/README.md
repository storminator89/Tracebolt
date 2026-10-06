# Socket-owner helper and authenticated client source candidate

The fixed policy/framing contract, synchronous server, native Linux authority /
credential / namespace adapter, separate `cmd/socket-owner-reader` executable,
and zero-value `Client` now exist as **source only**. The native proc capture
dependency is `systeminventory.CaptureSocketOwners`; it retains its separate
fixed-source and sockfs-witness checks. Tests use injected protected objects,
syscall results, message sockets and invented rows. They never invoke `Run`,
create a socket, inspect procfs or execute the native helper.

**Activation requires an explicit new v2 deployment contract.** Old deployment
v1 records remain rejected. The approved agent artifact must implement the
reviewed activated-identity producer/client path identified by `ClientContract`.
The helper verifies the administrator grant, exact request binding, approved
binary and runtime principal. It does **not** independently prove enrollment
currentness. The `lanclient` system sender reuses the existing authoritative
activated-identity producer before and after capture, before staging, and before
every send/retry including restart. No extra public-identity mirror, private-key
access by the helper, or renewal ledger is introduced. New bindings need explicit
new consent; renewal and key transitions cannot silently migrate grants.

The source now includes a create-only read-admin-v2 phase, fixed service/socket
templates, offline private-consent lifecycle and explicit maintenance revocation.
See [source provisioning](../../docs/socket-owner-provisioning.md). Local completion
means exact configuration readback, not a successful native helper capture. Source
changes do not enable an installed endpoint or fix its missing PIDs. Release/pin
activation, actual grants and disposable-systemd-VM acceptance remain gates.

## Fixed boundary

Capture requests only one complete bounded local TCP4/TCP6/UDP4/UDP6 observation.
Inputs contain identity/grant/correlation metadata. There is no PID, FD, inode,
path, namespace, source selector, shell, URL, filter or resource-limit argument.
The fixed capture adapter derives its own socket set and returns existing
validated Socket rows. Helper-side clocks provide the real capture interval.
A zero-row successful enumeration differs from nil/failed source data; observed
owners, partial attribution and missing process names retain their existing rules.

Verify reads only current authority/context. An absent expected Reference is
readiness; a provided Reference must match exactly. Readiness must never rewrite
a staged source reference. References are public metadata, not bearer credentials
or independent attestation of host permissions.

`socket-owner-reader` accepts only no-argument activation or `--build-info`.
Argument rejection/build-info occurs without native initialization. The helper
has no shell, command, arbitrary path, environment-selected file or dialer. Client
transport dials only the fixed local `SocketPath`; no public path override exists.

## Protected setup records and current authority gate

The prospective fixed profile requires root:root mode-0755 directory walks,
no symlink adoption, exact object modes/ownership, single-link regular files and
named-object rechecks. Only these two canonical bounded JSON declarations are
read under `/etc/tracebolt` (root:helper-GID, mode 0640):

- `socket-owner-policy.json`: existing `tracebolt.socket-owner-policy.v1`, fixed
  scope, exact current SenderBinding/origin/profiles, numeric agent/helper IDs,
  epoch, enabled state and explicit metadata/broad-ptrace/HTTP acknowledgements.
- `socket-owner-deployment.json`: `tracebolt.socket-owner-deployment.v2`, profile
  `systemd-pid1-local-ptrace-activated-client-v2`, required `clientContract` equal
  to `tracebolt.socket-owner-activated-identity-client.v1`, exact policy digest
  and five SHA-256 fields for helper binary, agent binary, helper service, agent
  service and helper socket unit. There are no path or override fields. The
  contract identifies the reviewed agent path; it is not independent proof that
  arbitrary bytes implement it. Provisioning must bind the reviewed artifact to
  the existing exact agent digest. Old v1 and missing/wrong contract fields fail.

Artifact paths are fixed: `/opt/tracebolt-agent/{socket-owner-reader,lan-agent}`
(helper root:root 0755; agent root:root 0555, matching the native installer),
and `/etc/systemd/system/tracebolt-socket-owner-reader.service`,
`tracebolt-agent.service`, `tracebolt-socket-owner-reader.socket` (root:root 0644).
Artifacts are hashed once per runtime; every authority check rewalks/rechecks
metadata, and replacement fails closed rather than being silently rehashed or
adopted. Records are bounded and reread. Revision hashes include object identity,
owner/mode/link/size/mtime/ctime. Public hashes are revision checks, not tokens.

`ProtectedGrantBindingVerified` is deliberately narrower than enrollment
currentness: it establishes the protected administrator grant and versioned client
contract binding. Native Facts and the server's exact request comparison complete
the executable/cgroup/principal/grant proof. The helper cannot detect a compromised
authorized client's rollback of private enrollment state. That principal receives
only the fixed TCP/UDP-owner metadata operation, with no source selectors. No
boolean or public projection file may stand in for the authoritative client path.

Installed alternate units/drop-ins, type-wide/prefix drop-ins and fixed runtime
transient/generator locations are conservatively rejected. Native Facts also
check the actual running helper/peer executable objects, fixed cgroup-v2 unit
paths, identities, capability words, namespaces, NoNewPrivs=1 and Seccomp=2.
`OwnedDeploymentVerified` means those installed/observed-runtime checks passed.
It does **not** mean file bytes prove systemd's loaded unit properties, the content
of seccomp filters, or complete native acceptance. The separate source installer
checks fixed daemon-loaded properties; real kernel/systemd acceptance remains a
gate and unsupported layouts fail closed.

## Native credential, socket and namespace boundary

The prospective profile requires exactly one fd-3 systemd activation named
`socket-owner-reader`, exact LISTEN_PID/FDS/FDNAMES, the fixed root-owned mode-0660
socket at `/run/tracebolt-socket-owner-reader/reader.sock`, a root-owned inherited
AF_UNIX/SOCK_STREAM listening descriptor, SOCKFS_MAGIC and statx TYPE/INO/MNT_ID
matching fstat's type/device/inode. The socket pathname inode is never used as
the sockfs inode. No socket is created/chmodded/unlinked by the helper.

Unexpected inherited SO_PASSPIDFD is rejected and accepted sockets disable it;
any unexpected received SCM_PIDFD is closed and rejected. SO_PASSCRED is enabled
before receiving. Each data-bearing recv must carry
exactly one matching SCM_CREDENTIALS (TGID/UID/GID), including each frame boundary
read. Credentials absent from pre-option queued data fail closed. Truncated,
unknown, duplicate or malformed ancillary data is rejected; received rights are
closed before rejection, including complete FD words before malformed tails.
No unverified payload is exposed. EOF's zero-credential sentinel carries no data.
Every response send explicitly includes the helper's own SCM_CREDENTIALS;
listener-creator SO_PEERCRED alone is not response-writer proof.

Client enables both `SO_PASSCRED` and Linux 6.5+ `SO_PASSPIDFD` before connecting
through the root-protected fixed socket path. Every data-bearing receive requires
exactly one `SCM_CREDENTIALS` plus one exactly four-byte nonnegative `SCM_PIDFD`.
Helper UID/GID must match policy and PID must match across chunks. It holds the
first writer pin through full framing, correlation and timestamp acceptance;
liveness is checked before/after reads and acceptance. Later pidfds and all
received rights/error descriptors are closed. Unknown, duplicate, malformed or
truncated controls fail closed. There is no numeric-PID `pidfd_open` fallback.
The socket pathname is rechecked before/after connect and around acceptance.
Client half-closes one bounded request and requires response EOF under a six-second
budget; cancellation closes I/O and waits for pin cleanup.

`Client.Verify(ctx, policy, nil)` is readiness; a nonnil reference must match
exactly and never refreshes a staged observation. `Client.Capture` requires the
expected reference and generation. It validates canonical response framing,
reference, generation, helper interval shape and times within the local exchange.
It returns original capture times without renewal. The caller retains separate
identity/consent currentness and durable send-age responsibilities.

Source review of Linux v6.5 confirms the stream receive path separates writers,
zero-initializes the EOF credential sentinel and emits no pidfd for a missing
sender; `scm_pidfd_recv` returns a four-byte descriptor or negative errno. See
[`af_unix.c`](https://github.com/torvalds/linux/blob/v6.5/net/unix/af_unix.c),
[`scm.h`](https://github.com/torvalds/linux/blob/v6.5/include/net/scm.h) and
[`pidfd_prepare`](https://github.com/torvalds/linux/blob/v6.5/kernel/fork.c).
This source review and fake tests do not replace native kernel acceptance.

Linux 6.5+ SO_PEERPIDFD pins the connection peer. Unsupported features fail closed
without numeric-PID/start-time fallback. Pidfds remain held while proc/ns handles
are used; liveness is checked before/after pinning and at authority checkpoints.
The fixed proc root is checked as procfs, its numeric self directory matches the
kernel self entry, and pinned proc PID1's typed PID namespace must match helper,
peer and the systemd PID1-local view. PID1 must be the fixed root-owned systemd
executable. PID/net/user handles must be nsfs of the exact ioctl-reported type;
current views are rechecked against the held descriptors. No setns/unshare or
caller-selected namespace path is supported.

Helper serving/capture runs on a locked OS thread. Its current thread-self
identity/capability/typed namespaces, current-thread ID syscalls and capget words
are checked independently of the process leader. Real/effective/saved/fs IDs are
exact, supplementary groups empty or one entry equal to the already-bound
primary GID, and all five helper cap sets CAP_SYS_PTRACE
only; all five peer cap sets are zero. Bounded stable task snapshots reject
observed heterogeneous threads, with cancellation checks between threads. These
snapshots and TGID credentials are checkpoint evidence for the trusted exact
binaries, not atomic proof about every malicious thread or seccomp filter content.
The helper and approved agent must not intentionally change credentials/namespaces.
The group rule is identical in proc status parsing, native identity validation,
current-thread Getgroups and Facts: allow empty or one already-bound primary GID
(systemd initgroups may include it); reject foreign IDs, duplicates and multiple
entries without normalization. This supplies no additional group membership.
Native acceptance must still verify actual systemd service credentials.

A new runtime ID invalidates old references without authorizing another namespace
scope. Only this helper could receive CAP_SYS_PTRACE in a future separately
approved profile; the main agent stays nonroot and capability-free. CAP_SYS_PTRACE
is broad OS authority, not an OS-enforced read-only metadata grant. Debugger
syscall filters alone do not prevent procfs memory reads. Compromised-helper
memory confidentiality requires separately reviewed enforced confinement.

## Bounds, cancellation and revocation

- Canonical fixed JSON inside one TBS1 frame; unknown/duplicate fields, aliases,
  missing required nulls, trailing bytes and oversized frames fail.
- Clients half-close after one request; the exact EOF boundary has a deadline.
- Request body <=2 KiB; response body <=512 KiB+1 KiB. Existing socket row/owner,
  encoded-section and source-shape limits remain authoritative.
- At most two admitted connections and one synchronous capture. Verify remains
  available during a capture. Startup/pin work also shares the two-slot limit.
- Five-second cooperative capture and six-second connection budgets remain native
  validation candidates. Cancellation stops bounded userspace loops and waits for
  cleanup; it cannot promise to interrupt a blocked kernel call.
- A monotonic 30-second interval is consumed on capture admission, including
  failed/partial/canceled captures. Busy/rejected calls do not queue. Backward
  time fails closed. Restart resets this per-runtime limit.
- Capture checks authority before bounded batches and closes all source handles
  before return. The server rechecks after capture, before output and between
  16-KiB chunks. Artifact bytes are not repeatedly hashed in those guards.
- Revocation/context change suppresses remaining rows. A partial frame is invalid.
  A canceled request may receive a fixed denial with no reference/observation if
  that send wins the close race. Already-read or written bytes cannot be recalled.

fdinfo parsing still bounds userspace-returned headers, not descriptor-specific
kernel seq_file work. Native CPU/latency/syscall/LSM compatibility remains unrun.

The caller must preserve durable systemwire provenance, check the authoritative
identity/consent before stage and every send/retry/restart, and discard an entire
changed/expired tagged body while preserving consumed sequence floors. The
source read-admin phase binds compatible receiver/client/helper artifacts under
one explicit approval. Its maintenance revoke path disables the root grant,
stops/drains the participants, retains a disabled private tombstone and discards
only tagged pending bytes. No re-enable, epoch reuse or renewal transition is
supplied. Actual grants and stop/drain behavior still require separately approved
native acceptance; source fixtures do not establish those host results.

The concrete default-off sender/consent/capture/stage/retry path and remaining
rollout gates are described in [activated client source](../../docs/socket-owner-client-source.md).
