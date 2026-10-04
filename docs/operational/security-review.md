# Operational collector: isolated boundary review

Date: 2026-10-03. Scope: the isolated `internal/operational` collector and typed
validation contract. This does not approve transport, enrollment, storage,
retention, UI integration or a deployed collection profile.

The finalized consent identifier is `managed-operations-v1`; the snapshot schema
remains `tracebolt.linux-operational.v1` and current implementation/acceptance is
Linux-only. Renaming this previously unintegrated identifier does not establish
support for another operating system.

The final reviewed files are identified by
[`review-source.sha256`](review-source.sha256), SHA-256
`3fdc3351cbe55a2697673bec18a83d1740e03c019d43955ce03ddc0280d50f5c`.
Full per-file manifests before and after the final checks were identical.
This final manifest covers collector files, collector documentation and the
independent tests; the separately evolving integration proposal is not included.

## Boundaries reviewed

- Collection has fixed local sources and fixed trusted command arguments. It
  accepts no arbitrary command/path/remote target, uses no shell or active
  network probe, and replaces ambient command environment settings.
- Item, source-byte and output caps bound sampling. The snapshot and standalone
  retained-section validators enforce a 48 KiB encoded ceiling, finite safe
  numbers, valid bounded strings and consistent provenance/count metadata.
- Mount discovery excludes credential-bearing sources/options and direct
  hardware identifiers. Local measurements use pinned and reverified mount
  identity/type; remote, FUSE, virtual and unknown filesystems are unmeasured.
- Process command lines, environment, account IDs, executable/CWD links and
  user-file contents are excluded. Package descriptions/maintainers/file lists,
  network address/MAC/SSID/route values and raw event messages are not exported.
- Journal queries request metadata only, discard mandatory cursor/boot/sequence
  identities and reject malformed selected values. Successful queries remain
  explicitly incomplete samples of visible system-journal records. Systemd can
  suppress some partial-access notices even after a successful preflight.
  [Upstream access-check implementation](https://github.com/systemd/systemd/blob/v257/src/shared/journal-util.c)
- Exactly one collection is in flight. Queued callers can cancel, commands have
  bounded execution/output, and direct reads cooperate between operations.
  Blocking kernel calls do not have a guaranteed hard timeout; measured duration
  can exceed the requested deadline. No abandoned worker accumulation is used.
- Unknown/denied/partial data remains distinct from a successful empty result.
  Generation and observation timestamps are preserved per retained section;
  mixed historical sections are not a new coherent fresh snapshot.

Operational names and mount labels can themselves contain personal or secret-like
text. These exclusions do not provide anonymity or guaranteed secret removal.
Mounted filesystems and other resources are those visible to the collector's OS
namespace. The service's filesystem sandbox changes that view; it must not be
weakened to manufacture an apparently complete physical-host inventory.
[Systemd namespace documentation](https://github.com/systemd/systemd/blob/v255/man/systemd.exec.xml)

## Corrections verified

Independent fixtures reproduced inconsistent complete service/event counts,
incompatible local-filesystem measurement claims and oversized mount IDs. These
are now rejected. Event counts correctly sum grouped source records rather than
equating a group with one record.

Additional reviewed fixes prevent malformed or fully omitted data from becoming
healthy-empty, preserve truncation markers, measure queued cancellation duration,
handle sysfs files whose advertised size exceeds their actual short content,
reject dot interface names and null/binary journal values, and cap independently
retained sections. Journal completeness remains explicitly unverified rather
than inferring complete access from a successful command.

## Final independent evidence

Linux amd64, Go 1.27.1:

- 22 inspected pure/provider/inert package tests: pass with the race detector;
- five independent public-contract tests: pass with the race detector;
- scoped `go vet`: pass;
- full before/after manifest comparison: identical.

The final identifier-only edit was checked by reversing the literal and matching
the previously reviewed hashes. The same 22 fixture tests, five independent
tests and vet were then rerun successfully against the new identifier with
unchanged before/after hashes.

The independent test file `tests/security/operational_boundary_test.go` has
SHA-256 `5d2a7b330de5fc52634cfe8e90447f956283414f1e96c97ab2fef2288193f222`.
The reviewer did not execute native process/package/journal inventory collection
or export actual operational records. Owner-reported smoke/cross-build evidence
is separately described in [the collector documentation](collector.md).

## Integration gates still required

1. Fresh explicit profile consent must bind server configuration, bootstrap,
   proof/intent, activated identity and a separate sender-state domain. Existing
   basic clients must not silently adopt the larger collection scope.
2. The raw network decoder must separately reject unknown/duplicate/case-aliased
   fields and malformed JSON before typed validation. Typed `Validate` alone
   cannot detect duplicate keys discarded by a prior decoder.
3. Authorization, replay, revocation, observation commit and last-good retention
   must remain atomic. Per-device/global quotas and trusted-clock expiry/pruning
   need integration tests, including mixed generations and rejected-frame age.
4. UI coverage/freshness must reflect namespace limits, bounded samples, partial
   journal visibility and expired clocks. No complete fleet/security-health or
   vulnerability/update assessment claim follows from this collector.
5. Operational fields and operational-derived case/evidence text remain outside
   external AI/provider packets, support bundles and public artifacts until a
   separate allowlist/export policy is reviewed.

This review does not establish actual nonprivileged systemd/journal behavior,
Debian database runtime coverage, service deployment or non-Linux operational
support. The independently approved installer test is a separate workstream and
does not inherit acceptance from these fixtures.
