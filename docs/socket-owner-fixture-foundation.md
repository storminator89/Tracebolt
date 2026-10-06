# Socket-owner attribution fixture foundation

Status: source refactor and inert fixtures only. This does **not** resolve missing
PID/process names on an installed endpoint. It installs no helper, grants no
capability, changes no service, and enables no additional collection.

## Current production behavior

The existing nonroot provider still opens the same pinned procfs paths, resolves
only numeric PID/FD entries, reads `socket:[inode]` FD link text without following
its target, and reads `comm` only for matched processes. The extracted internal
`ownerSource` interface lets fixtures exercise that same bounded enumeration.
All production resource ownership, limits, global uncertainty, per-process
socket deduplication and owner/name outcomes remain unchanged. A denied process
can hide another owner, so its scan failure still makes all ownership results
partial while retaining any observed owners. Socket-row coverage is separate.

The seam carries only directory names, matched socket inode values, bounded
process-name readers and fixed error reasons. It accepts no external path or
command. Only the existing Linux adapter performs procfs operations.

## Unwired fdinfo parser

A possible future isolated helper could scan `/proc/<pid>/fdinfo` rather than
`/proc/<pid>/fd`. The new pure parser is deliberately unexported and has **no
production caller**. It consumes only the four exact `pos`, `flags`, `mnt_id`,
and `ino` header lines within 256 bytes. It does not read ahead into or retain
descriptor-specific metadata. Duplicate fields within that prefix, malformed
values and truncated headers fail. The exact complete three-header prefix with
EOF is unsupported, matching older sources without `ino`; no broader privilege
fallback is implemented. Suffix bytes are not inspected, even when they resemble
another header. Tests explicitly forbid reading a single suffix byte.

Only the mount ID and inode participate in a possible socket match. Equal inode
numbers on another filesystem are not a match. The expected socket mount ID is
just an input to this pure parser, **not proof of authority**. A future native
adapter must independently verify its inherited socket and the observation
context before deriving that value. Upstream Linux uses a shared sockfs mount
for socket files; native acceptance of that correlation is still required.

## Privilege design remains deferred

The checked Linux fdinfo implementation has ordinary readable DAC modes but
also enforces `PTRACE_MODE_READ_FSCREDS`. Using fdinfo may avoid the extra
`CAP_DAC_READ_SEARCH` required by the existing FD-directory walk. It does not
remove the need for a separately reviewed `CAP_SYS_PTRACE` grant for arbitrary
cross-account processes on the checked kernels.

`CAP_SYS_PTRACE` is broad OS authority, not an intrinsically read-only permission.
It can expose process memory and other sensitive data. Denying debugger syscalls
alone does not prevent memory access through procfs. A future fixed-function
helper therefore requires independent privilege/isolation review, an explicit
local identity-bound opt-in, live withdrawal/pending-data rules and a separately
authorized disposable-VM acceptance plan. Existing journal/action grants cannot
silently become socket grants. The main agent must remain nonroot and unchanged.

There is no capability, policy, helper protocol, root adapter, setup command or
runtime fdinfo collector in this patch. No host-level acceptance was performed.
Process exit/reuse, shared descriptors, ownerless sockets, permission/LSM denial,
namespace limits and work ceilings must remain explicit even after future work.
Local binding does not prove external reachability.

## Evidence and validation

Fixtures cover shared/duplicate descriptors, owner-name failures, denied/exited
processes, numeric-entry rejection, closure, cancellation and exact/excess work
limits. Existing parser, wire-shape and collection tests remain applicable.
They neither inspect this execution host nor instantiate the real collector.

Relevant upstream source/documentation:

- [Linux 6.12 fdinfo permission checks and header emission](https://raw.githubusercontent.com/torvalds/linux/v6.12/fs/proc/fd.c)
- [Linux 6.12 proc entry modes](https://raw.githubusercontent.com/torvalds/linux/v6.12/fs/proc/base.c)
- [Linux 6.12 ptrace access checks](https://raw.githubusercontent.com/torvalds/linux/v6.12/kernel/ptrace.c)
- [Linux 6.12 sockfs/socket allocation](https://raw.githubusercontent.com/torvalds/linux/v6.12/net/socket.c)
- [fdinfo fields, including Linux 5.14 `ino`](https://man7.org/linux/man-pages/man5/proc_pid_fdinfo.5.html)
