# Proposed Linux package source-reader boundary

Status: implemented reader boundary for the locally reviewed package candidate.
The separate opt-in three-binary cloud test executed the production attempt and
preserved unknown data for this sandbox’s untrusted root layout/missing database.
It does not establish positive Debian/Ubuntu package coverage or deployment.
The reader lives in `internal/packagecollector`, keeping `internal/linuxpackages`
free of file/process/network operations.

## Entry and source selection

`Collect(ctx, generationID, collectedAt) (linuxpackages.Snapshot, error)` accepts
only a valid caller-owned generation and UTC observation time. Invalid input
fails before opening any source. The enclosing collector supplies the same
identity/time as the operational snapshot. Error strings are fixed, never OS
messages or file contents. A single shared in-process slot admits the full
attempt; a competing call returns an explicit unknown `collector_busy` snapshot.
There are no per-read goroutines, background retries or configurable paths.

Read only `/etc/os-release` and `/var/lib/dpkg/status`. For release, a regular
`/etc/os-release` takes precedence. If and only if it is absent, try the fixed
`/usr/lib/os-release`. The only accepted leaf symlink spellings at `/etc/os-release`
are `../usr/lib/os-release` and `/usr/lib/os-release`, both mapped to that one
fixed target. Do not follow any other symlink or fall back after denied, malformed,
changed or otherwise invalid `/etc` data. The target must itself be regular.

Production parent directories are walked from an owned root descriptor using
no-follow directory opens. Each fixed component must be a directory with trusted
system ownership and no group/world write bits. Pin descriptors through reads;
never concatenate caller-controlled paths or resolve an arbitrary link target.
Files are opened no-follow, nonblocking and close-on-exec, then checked as regular
system-owned files with no group/world write permission. Explicit parent/leaf
trust and namespace assumptions must be documented; this is not a defense against
an administrator who can replace the running OS or mount namespace.

## Bounded read and consistency

Use the pure parser's fixed byte and line ceilings. Verify descriptor identity,
size, mode/ownership and modification metadata before/after the bounded read.
After the complete release plus dpkg attempt, also recheck both pinned descriptors
and each current fixed path/link identity. Ordinary replacement or mutation makes
the affected source unknown and clears its dependent fields/rows/counts. No
successful prefix is promoted. Release and inventory failures remain independent.
These checks do not make two OS files an atomic snapshot or establish physical
host-wide scope; the result remains agent-visible data.

Cancellation is checked before admission, around each read/parse and before
export. A synchronous filesystem read or metadata operation can outlive that
cooperative budget; do not advertise a hard deadline. Keep the slot occupied
until the actual work returns, rather than accumulating abandoned goroutines.
No subprocess, APT, package refresh, network client, credential, service, global
trust or filesystem write belongs to this package. OS-managed filesystem mounts
remain an environmental boundary, not a promise of remote filesystem isolation.

Successful parsers produce the exact smaller DTO, then its deterministic Trim
function enforces128 rows/16KiB while preserving complete-source counts and
original generation/time. Duration reflects the actual attempt. Unsupported OS
builds return explicit unknown/not-supported metadata; this does not claim native
Windows/macOS collection support.

## Fixture acceptance

Production `Collect` is never invoked by this package's tests. A private inert
source-provider/opener seam supplies all bytes, errors and identity changes.
Descriptor helpers may use disposable test-owned files under an explicit internal
fixture root/expected owner, never system paths. No exported configurable root,
path, executable or mutable global test hook is introduced.

Required cases include exact symlink/fallback precedence; denied/unsafe/changed
parents and leafs; non-regular/FIFO/symlink rejection without blocking; oversized
source and EOF/change races; final cross-attempt recheck; independent failure
clearing; no prefix or raw-error export; cancellation before/between/after reads;
single-flight busy/release without extra work; generation/time rejection before
open; sorting/truncation/count preservation; and non-Linux compile-only behavior.
Actual supported Debian/Ubuntu runtime reads are a later explicit acceptance
gate. They do not authorize package updates or host/security changes.
