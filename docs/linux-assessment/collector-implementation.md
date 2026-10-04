# Isolated Linux package source collector

Implemented and fixture-checked on 2026-10-04 UTC in the source workspace.
This document describes only `internal/packagecollector`; it does not approve
native inventory reads, transport enablement, enrollment, deployment, APT or
catalog matching. Production `Collect` was not invoked for these checks. No real
release/status file was read, command run to inventory packages, or external
request made. The existing frozen operational/offline archives were untouched.

## Entry point and private seams

`Collect(context.Context, generationID string, at time.Time)
(linuxpackages.Snapshot, error)` is the sole exported function. The caller must
supply the enclosing capture's unchanged generation and UTC timestamp. An empty
unavailable DTO is validated before admission or provider construction, so nil
context, malformed generation, zero/non-UTC/out-of-range time fail before all
source work with the fixed `package_collector_invalid_input` error.

A single process-wide atomic slot spans provider construction, reads, parsing,
metadata rechecks, descriptor cleanup and export. A competing call returns both
sections explicitly unknown/`collector_busy`, with no provider construction or
source access. Cancellation is checked before admission, after admission,
around source reads/parses and before export. A canceled attempt clears both
sections to unknown/`timeout`. Sources are otherwise independent: a failure or
change clears only that source's fields or rows/counts, never reuses previous
facts and does not prevent the other source's attempt.

Private `collectWith` accepts a caller-supplied admission slot and provider
factory. The private provider returns pinned readers with `recheck` and `close`;
the Linux implementation also has instance-local root/openat seams for inert
fault injection. There is no exported root/path override and no mutable global
test hook. The production opener is fixed to `/` and expected UID 0. Tests use
explicit disposable fixture roots and the fixture owner's UID. Source selection
is an internal enum, never a caller-controlled path.

Ordinary unavailable observations have a nil Go error and fixed DTO reasons.
EACCES/EPERM map to denied/`permission_denied`; missing paths map to unknown/
`source_missing`; wrong ownership, writable protected paths, nonregular objects,
forbidden links and malformed/over-limit source data map to `invalid_source`.
Other source I/O errors map to `read_failed`. Recheck failures map to
`source_changed`. The inherited dpkg oversized-line scanner error stays
`read_failed`, consistent with the pure parser contract. Raw OS errors, source
paths, ignored content and partial parse results never enter the DTO or returned
errors. Other operating-system builds return both sections unknown/
`not_supported`; they do not claim Windows/macOS inventory support.

## Fixed descriptor traversal

Production opens `/` as a no-follow, close-on-exec directory descriptor, checks
that it is owned by UID 0 and has no group/world write bits, then walks only
fixed components with the same protection checks. Directory opens use
`O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC`; paths are resolved relative to
pinned parents, not through string concatenation or arbitrary symlink targets.

The release source is `/etc/os-release`. A regular file takes precedence even
if its content is malformed. Only exact ENOENT for that leaf, after successful
validation of its `/etc` parent, permits the fixed `/usr/lib/os-release`
fallback. A missing, denied, unsafe or symlinked parent does not enable fallback.
The only allowed leaf symlink texts are `../usr/lib/os-release` and
`/usr/lib/os-release`. Both select the fixed `/usr/lib/os-release` descriptor
walk. The target must itself be regular: no second link or link-chain resolution
is permitted. A selected fallback also retains an absence assertion for the
original `/etc/os-release` path.

A leaf is first pinned with `O_PATH | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC` and
classified before any read. For a regular source the collector then opens the
same fixed leaf with `O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC` and compares
its metadata with the pinned probe. Regular sources must be owned by UID 0 and
have no group/world write bits. FIFOs, directories, sockets and devices fail
classification without a content read. An allowed release symlink must be
owned by UID 0, have the exact allowed text and a protected parent; its intrinsic
0777 symlink mode is not treated as regular-file write permission. Its fixed
target receives the regular-file mode/ownership checks.

Inventory reads only `/var/lib/dpkg/status` through protected `/var`, `/var/lib`
and `/var/lib/dpkg` descriptors. Symlinked directories and leaves are rejected.
No dpkg command, subprocess, APT operation, network client, file-write operation,
credential/service API or ambient environment override exists in this package's
production implementation.

## Bounds, consistency and duration

The initial descriptor size must be nonnegative and at most 65,536 bytes for
release or 33,554,432 bytes for status. The pure parsers additionally enforce
their byte caps with a one-byte overflow probe, line/key/record/field/value limits
and all-or-nothing parsing. A private context reader checks cancellation both
before and after every underlying read. No read goroutine or background retry
is created. Synchronous filesystem reads or metadata calls may outlive the
caller's deadline; this is a cooperative budget, not a hard wall-clock guarantee.
The slot remains occupied until actual work and cleanup return.

Every successfully opened source is checked immediately before parsing, after
its parse, and again after the entire two-source attempt, including when the
other source fails. All descriptors remain pinned through the final checks:

- Current root and each pinned directory must still match their original device,
  inode, type/mode, UID/GID and link count. Parent names are checked relative to
  their pinned parents with no-follow metadata lookup. Directory size/mtime are
  deliberately excluded so unrelated entry activity alone is not a file mutation.
- Pinned source/probe descriptors and each current fixed leaf path must still
  match device, inode, mode, UID/GID, link count, size, mtime and ctime.
- Allowed symlink descriptor/path identities and exact link texts are rechecked.
  A selected fallback requires `/etc/os-release` to remain absent.

Ordinary same-inode mutation, replacement, permission/ownership change, parent
replacement, changed link target or a newly shadowing fallback invalidates the
affected source. These checks cannot provide an atomic two-file snapshot, detect
every adversarial transient ABA replacement, defeat an administrator controlling
the OS/mount namespace, or authenticate vendor origin. The namespace remains
agent-visible; an OS-managed mount may itself perform remote I/O, and no remote
filesystem isolation is claimed.

Complete successful parser results establish observed and installed counts.
`linuxpackages.Trim` sorts a deterministic prefix and enforces 128 rows/16 KiB
without changing original generation, collection time or exact full-source
counts. A valid residual-only source can produce healthy zero counts; empty,
malformed or changed status cannot. Duration uses monotonic elapsed time for the
attempt, including synchronous cleanup and the first trim. A final bounded trim
accounts for growth of the duration field's decimal representation; that last
export operation is outside its captured duration.

## Fixture evidence and remaining gates

All tests use injected bytes/errors or disposable descriptors; no test calls
production `Collect`. Coverage includes:

- Caller validation before provider creation; cooperative cancellation before,
  between and during reads, failed provider construction and the final recheck;
  busy admission and slot
  retention while a synthetic synchronous read remains blocked
- Exact release precedence, both allowed link spellings and ENOENT fallback;
  denied/failing `/etc` reads without fallback; missing/unsafe/symlinked parents,
  unsafe leaves, link chains, wrong-owner metadata and no-block FIFO rejection
- Initial source byte caps, oversized injected dpkg/release sources, line caps,
  malformed/read-failing sources with valid prefixes and fixed-error privacy
- File/symlink/FIFO replacement between probe and read open; parent replacement
  during directory opening; mutation/replacement after EOF; final cross-source
  changes even when the other parse failed; fallback shadowing and link changes
- Independent clearing, exact selected fields/counts, residual-only healthy zero,
  sorting, byte/item caps, no omitted-row backing-array retention and duration
- Non-Linux unsupported implementation and fixture compile checks

Verified with the existing Go 1.27.1 linux/amd64 toolchain after sourcing
`scripts/env.sh`, with `GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off`:

```sh
go test -buildvcs=false ./internal/packagecollector -count=1
go test -race -buildvcs=false ./internal/packagecollector -count=1
go vet -buildvcs=false ./internal/packagecollector
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go test -c -buildvcs=false ./internal/packagecollector -o /tmp/packagecollector-windows-amd64.test
GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go test -c -buildvcs=false ./internal/packagecollector -o /tmp/packagecollector-darwin-arm64.test
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test -c -buildvcs=false ./internal/packagecollector -o /tmp/packagecollector-linux-arm64.test
```

These commands passed. Windows, Darwin and Linux arm64 were compile-only;
platform runtime acceptance was not performed. Focused coverage was 88.1%,
with production `Collect` and its Linux system-root factory deliberately uncalled.
A full-repository run was not part of this isolated worker's checks. This
workspace has no Git metadata, so no commit/revision is claimed. Separately
authorized nonprivileged Debian 13/Ubuntu 24.04 runtime acceptance, exact
transport/profile/store review, enrollment consent and enabling/deployment gates
remain independent of these source/fixture results.

## Subsequent integrated cloud attempt

After the isolated fixture review, the opt-in package-profile three-binary test
ran actual basic/operational/package collection attempts through an ephemeral
loopback manager in both TLS and explicit HTTP-test modes. The package source
attempts returned unknown with zero selected rows and null source counts. A
separate fixed-path metadata check found this sandbox's root hierarchy is not
root-owned and its dpkg status database is absent; the trust checks were retained.
This establishes actual transport and conservative source-failure handling, not
positive supported Debian/Ubuntu package inventory. No APT, service installation,
global trust change, external inventory transfer or raw-field test output occurred.
The earlier worker coverage numbers above still describe its inert fixtures only.
