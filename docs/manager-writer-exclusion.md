# Cooperating manager writer exclusion (TB-16 source increment)

The updated Linux `lan-manager` optionally holds an exclusive, nonblocking
directory-FD `flock` for its selected private `StateDirectory`. It acquires this
**before profile/store preparation** and releases it only after admitted HTTP
handlers, run-owned workers, controllers, sessions and stores have finished.
A second cooperating updated manager using that same directory is rejected
before opening its databases. No lock file, configuration setting, credential,
schema migration or host permission is introduced.

This is **one runtime ownership increment**, not a complete stopped-writer
capture fence, backup/restore implementation or freshness proof. #143 remains
open. See the [complete integration architecture](backup-capture-architecture.md).

## Filesystem and compatibility boundary

The lease API admits local-kernel candidates ext2/3/4, XFS, Btrfs, tmpfs and
overlayfs. This is not native qualification of every filesystem/kernel/mount;
tmpfs in particular supplies no persistent-storage guarantee. Source fixtures
exercise actual directory locking on the execution environment only.

Network, FUSE and unknown filesystem types do not receive a successful lease.
Unsupported/denied lock-mechanism syscalls likewise report a fixed unavailable
result. **Ordinary manager startup retains its previous behavior** in exactly
that unavailable case, with a fixed warning that writer exclusion is absent.
It does not reject existing installations merely because their filesystem type
is unknown. Busy, invalid storage/protection and quarantine failures never use
that compatibility fallback; wrapped/joined unavailable errors do not erase
another denial. A future capture operation must require qualified, complete
exclusion and must never reuse the startup fallback.

Linux documents advisory locks and filesystem-dependent NFS/SMB behavior in
[`flock(2)`](https://man7.org/linux/man-pages/man2/flock.2.html). A successful
local lease is not permission to infer cross-host locking or durable capture.
Protected directory/ancestor identity is checked; symlinks, public state paths
and substitution detected by `Check` fail without chmod/adoption. Same-UID/root
compromise, remounts and raw whole-volume replacement remain outside this local
boundary. `O_CLOEXEC` prevents leaking ownership into an executed child.

## Old versions, external writers and upgrades

Old binaries, manual DB/filesystem tools and standalone setup commands do not
participate in this new lease. An old running manager cannot be detected or
stopped by acquiring it. Different manager roots, external package ledgers,
credential custodians and overlapping/nested roots are not coordinated by this
one-root guard. Directory `flock` does not prohibit a noncooperating file write.

Continue the existing maintenance procedure: stop **all** writers and automatic
starts before an upgrade/recovery. Do not use a lease acquisition as proof that
an old process has stopped, that another authority domain is frozen, or that a
snapshot is complete/current. No service stop/restart, mounting, ACL change or
automatic rollout follows from this source change. Never reset durable package
`active=1`, uncertainty, consumed state, consent or replay/renewal floors merely
because a crashed process's OS lock became available again.

## Shutdown liveness and retained ownership

Operator and endpoint HTTP handlers share one admission/drain gate. Shutdown
closes admission atomically; later requests receive a fixed no-store 503 without
entering authority code. Both servers retain the existing **total five-second
graceful shutdown budget**. A timeout closes their connections, but connection
closure alone is never treated as completion of a handler's local work.

If an admitted handler still runs, shutdown returns a fixed **incomplete** error
instead of success. There is no additional unbounded handler wait in `run`.
After run-owned workers join, cleanup retains all prepared stores/controllers
and the writer lease until that handler actually returns. A deferred cleanup
then closes state before releasing ownership. If the handler never returns,
those resources and the lease remain owned until process exit.

The actual CLI already treats a returned runtime error as fatal and exits;
process exit terminates remaining handlers and releases OS descriptors. Durable
crash/uncertainty guards remain intact. An in-process caller must not interpret
incomplete shutdown as a clean restart/capture grant or force-close retained
state. This deliberately favors safe retained ownership over an unsafe early
restart. Existing run-owned worker joins remain unchanged; a blocked worker can
still delay shutdown and retain the lease. No timeout/kill or host-service policy
has been changed to hide that condition.

## Verification and remaining gates

Non-GUI source fixtures cover same-/independent-process conflict, isolated child
crash, close/exec ownership, protected paths/substitution, quarantine precedence,
filesystem/mechanism classification, startup compatibility, preparation failure
cleanup and shared HTTP admission. An actual disposable loopback handler ignores
cancellation past a short fixture shutdown deadline: shutdown reports incomplete,
the lease remains busy, and cleanup/reacquisition happens only after its last
owned work finishes. No real manager state, credentials or backup is used.

Native supported-filesystem/container/upgrade/forced-exit acceptance, every
standalone writer, the complete dependency graph, external custody freeze,
atomic capture, current-authority reconciliation and recovery drills remain
separate gates. Neither this guard nor passing fixtures closes #143 or changes
the [deny-only restore quarantine](restore-quarantine.md).
