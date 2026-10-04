# Complete process and mounted-filesystem capture contract (held candidate)

`internal/completeoverview` is an inert, Linux-only capture foundation. It does
not change the running agent, existing report format, consent, retention, or UI.
There is no package initialization collection. Its fixture tests do not call the
real collector, read `/proc`, execute commands, inspect a host, or use a network.

**Activation gate:** existing managed-operations-v3 acknowledgement describes
bounded previews and does not authorize this larger scope. Runtime use requires
fresh explicit local complete-overview opt-in and a separately recognized wire
version, reviewed before any source is called. The candidate refuses UID 0. It
never reads command lines, environment, usernames, account identifiers, journal
content, process descriptors, or process working directories; it never starts a
subprocess. An ordinary mount-point label or process name can nevertheless be
sensitive and must remain operator-only, outside AI/export projections.

## Exact retained contract

The schema identifier is `tracebolt.linux-complete-overview.v1`; the scope is
`agent-visible-linux-namespaces`. `docs/complete-overview.schema.json` specifies
the JSON member/type contract. The Go `Validate`/`DecodeStrict` functions also
verify cross-field consistency, ordering, derived values and encoded byte limits.
All declared members are required. Unknown and duplicate members, noncanonical
integer encodings, invalid UTF-8, and null nonnullable members are rejected.

`Snapshot` contains exactly:

- `schemaVersion`, `generationId` (`sample_` plus 32 lowercase hex characters)
- `captureStartedAt`, `captureFinishedAt`: original UTC capture interval
- `scope`, `processes`, `volumes`

A section contains `meta` and `items`. `meta` contains exactly `generationId`,
`coverage` (`complete` or `failed`), `reason`, `observedCount`, `countExact`, and
`fieldCoverage`. The seven field-coverage counters are `observed`, `denied`,
`exited`, `invalid`, `unsupported`, `unavailable`, and `notApplicable`.

- `complete` means the visible source enumeration reached EOF and every
  enumerated identity has one row. Its reason is `none`, observedCount is the
  row count, countExact is true, and fieldCoverage sums to that count.
- Complete enumeration does **not** mean that every process was readable, every
  capacity was measured, the host was globally visible, or the capture was
  atomic. Every field-coverage counter is recomputed and validated from rows.
- A failed section contains zero rows, observedCount null, countExact false and
  zero field counters. Count/byte/resource/deadline failures never retain or
  publish an apparently complete prefix. A completed independent section can
  remain available if the other section fails. A total encoded-byte failure
  rejects both sections.
- Process creation, exit, PID reuse, namespace visibility and permissions may
  change during the interval. A returned PID is not a durable process-instance
  identifier; no start-time or cross-generation process identity is claimed.
  `hidepid`/namespace-hidden identities are outside the enumeration's scope.

Process rows contain only `pid`, nullable `parentPid`, `name`, `state`, `rssBytes`,
`cpuTimeSeconds`, `threads`, and an `observation` with `status`/`reason`.
`cpuTimeSeconds` is cumulative user + system CPU time, never utilization percent.
All seven allowed process fields are present; on a detail failure only PID remains
populated. Expected per-row outcomes retain denied, exited, invalid, unsupported
and read-failed identities instead of dropping them. Unknown kernel states are
unsupported, not silently normalized to a fabricated known state.

Volume rows contain `id` (`mount_<canonical numeric mount ID>`), `mountPoint`,
`filesystem`, `kind`, `filesystemGroup`, `capacityScope`, nullable `totalBytes`,
`availableBytes`, `usedPercent`, and `measurement` (`status`/`reason`).

- Kind is `local`, `memory`, `virtual`, `remote`, or `unknown`. Measured local
  rows sort first, root first within its class; other local, memory, remote,
  unknown and virtual rows follow. Mount point and mount ID break ties.
- Virtual/pseudo filesystems have not-applicable capacity. Remote/FUSE sources
  are skipped; unknown types are unsupported. `tmpfs`, `devtmpfs`, `hugetlbfs`
  and `ramfs` are memory-backed and may be measured, never physical disk space.
- `capacityScope` is always `agent-mount-namespace`. A zero total has null
  usedPercent; otherwise it is `(totalBytes - availableBytes) / totalBytes * 100`.
- `filesystemGroup` is `fs_<major>_<minor>` from mountinfo, a namespace-local
  grouping hint. Equal groups must never be added as independent capacity.
  Different groups still do not prove independent physical disks: layers,
  subvolumes and pools may overlap. No aggregate physical-capacity claim exists.
- Mount sources, options and filesystem roots are never retained. Existing
  `/home/<account>` and `/run/user/<account>` redaction is preserved in the
  display mount point. The unredacted point/root exist transiently only to pin
  and compare kernel-discovered targets.

## Explicit rejection ceilings, not supported-capacity claims

| Resource | Maximum |
| --- | ---: |
| Enumerated process rows | 32,768 |
| Enumerated mount rows | 16,384 |
| proc directory entries including non-PID entries | 65,536 |
| Encoded section | 16 MiB |
| Encoded snapshot | 24 MiB |
| One mountinfo source | 16 MiB |
| One mountinfo record | less than 64 KiB |
| One process stat source | 16 KiB |
| Cumulative production proc source reads | 128 MiB |
| Simultaneously pinned measurement targets | min(1,024, soft NOFILE minus 128) |
| Cooperative collection budget | 15 seconds |

These are finite rejection guards, not claims that a device population, mount
count or timeout has been validated on a deployment. A target over a ceiling
fails visibly. No limit is a successful truncation size. The current process soft
file-descriptor limit is read, never raised; an explicit reserve is left below it.
Other descriptors may still consume that budget. Exhaustion rejects all volume
measurements rather than silently accepting the first measurable subset.

The API is synchronous and package-wide single-flight. Context checks occur
between bounded operations. A kernel syscall that does not return promptly can
exceed the cooperative budget; there is no hard 15-second cancellation claim and
no detached/abandoned worker goroutine. Admission remains held through source
closure so a second capture cannot run concurrently with a stuck first capture.

## Source protections and non-atomic coherence

The provider pins `/proc` and verifies procfs type; it reads only its `self`
symlink and accepts only a canonical positive numeric PID. The numeric child is
opened without following symlinks and checked as procfs. `os.Getpid()` is never a
fallback because it can name a different PID namespace. PID directories and
`stat`/`mountinfo` files are opened relative to pinned proc descriptors, with
no-follow/type checks, nonblocking opens and byte bounds.

Mount enumeration is from that pinned self's `mountinfo`. Local/memory targets
are pinned via cache-only `openat2` (`RESOLVE_CACHED`, no symlinks/magic links,
beneath a pinned root) with no weaker fallback. Cache misses and unsupported
kernels produce explicit measurement failures. Known remote, FUSE, unknown and
automount ancestors are not traversed. `statx` uses no-automount/don't-sync flags
and verifies mount ID and device identity on each descriptor.

After all descriptors are pinned, one full bounded mountinfo reread must match
the initial identities before any `fstatfs`; another full reread checks coherence
after measurements. There are three mountinfo reads total, not a full reread per
row. Mount paths are indexed for ancestor checks, avoiding a per-target scan of
the entire mount set. A changed/missing mount invalidates the entire volume
section. A matching list still is not an atomic host snapshot; the interval and
namespace scope remain visible.

## APIs and fixture verification

- `Collect(ctx, generationID, at)` is the held, explicitly invoked Linux source
  entry point. It is not a consent check and is not wired into runtime here.
- `CollectWithProvider` is the isolated synchronous fixture seam and shares
  admission with Collect. The provider contract requires cooperative bounded work.
- `ParseProcessStat` and `ParseMountInfo` are pure parsers; `MountRecord` is
  transient source identity and must never be serialized as retained telemetry.
- `Validate`, `Encode`, `DecodeStrict`/`Decode`, `ValidateProcess`,
  `ValidateVolume`, and `ValidateSectionMeta` support a future dedicated wire and
  normalized generation/chunk store. Store the original generation and interval;
  paginate retained rows without relabeling a preview as complete collection.

Synthetic tests cover 97 processes, the exact 32,768-process ceiling, 32 virtual
mounts followed by a real root (all 33 retained), more than 32 mounts, per-row
failures, bind grouping, memory/pseudo/remote classification, unsafe path/PID
rejection, strict JSON, byte/count rejection with no prefix, and synchronous
single-flight cancellation. These tests establish source/contract behavior only;
real endpoint service, permissions, performance and consent acceptance remain
unexecuted gates.
