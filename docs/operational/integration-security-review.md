# Operational enrollment and transport: targeted security review

Date: 2026-10-04 UTC. Scope: fresh `managed-operations-v1` enrollment, bounded
Linux operational transport, durable observation/retention transactions,
operator reads, consent and AI export exclusion. This is a targeted source and
fixture review, not a production security certification or a complete audit.

## Source boundary

The final runtime candidate is recorded in
[`integration-runtime.sha256`](integration-runtime.sha256): 137 Go runtime and
module files, manifest SHA-256
`b1b01f81c93c57a7ff37587c3473b3d2b8c72c981cf572a8af20f9e73fdde711`.
The manifest identifies the tested tree; it does not imply that every preexisting
line was newly audited. The separate final UI candidate and its unchanged
before/after hashes are described in
[`integration-ui-security-review.md`](integration-ui-security-review.md).

## Reviewed protections

### Consent and identity

- The selected collection policy is bound to fresh manager configuration,
  bootstrap, proof/issuance context, activated identity and a distinct guided
  sender-state domain. An existing basic identity/ledger is not silently adopted
  into the expanded profile. Changing the policy is not a wire-supplied choice.
- Managed invitation creation requires explicit acknowledgement of metadata
  collection. Basic enrollment retains its original request shape. The native
  enrollment client discloses the expanded categories before invitation entry.
- Current implementation is Linux-only. The cross-platform policy identifier
  does not establish macOS or Windows operational collection support.
- Operator routes retain exact transport/Host/Origin, session and write-CSRF
  guards. Reads do not trigger collection. TLS and explicitly selected HTTP-test
  transport remain separate; signed HTTP does not provide network confidentiality
  or server/browser authenticity.

### Wire, authority and persistence

- Basic v1 frames and operational v2 frames are accepted only for the matching
  stored policy. The strict raw decoder rejects unknown, duplicate, case-aliased,
  missing and inappropriate null fields before typed validation. Frame and
  operational snapshot limits remain 72 KiB and 48 KiB respectively.
- Certificate approval, activation/revocation, profile, replay and observation
  persistence are rechecked against the same durable store. A pre-body or earlier
  successful authorization cannot replace the final transaction's decision.
- Exact retries preserve the original receipt and collection age. Rejected,
  canceled, malformed, stale, replayed or over-quota frames do not refresh state.
- Last-good sections preserve their own generation and collection times. Unknown
  new data cannot become healthy-empty or a newly collected historical section.
  Last-good data is bounded and pruned after 24 hours; views enforce expiry.
  The latest authenticated raw frame is retained until replacement for replay
  verification. This is not a promise to erase every operational byte at 24 hours.
- Limits remain 25 retained identities including tombstones, 128 KiB logical
  operational data per device, and a 4 MiB global ceiling. At the first two
  limits, only 3.125 MiB can be reached; the workload does not claim independent
  saturation of the global ceiling. Byte measures and benchmarks are defined in
  [`store-budget.md`](store-budget.md).

### Admission and transaction-local reuse

- Global ingress work remains bounded to two requests. A per-certificate slot
  is reserved only after verified TLS possession or a complete verified HTTP
  signature. A copyable public certificate header cannot reserve that identity.
  Unverified requests can still consume the separately bounded global work slots.
- Operational reads have a separate bounded admission slot. Cancellation and
  ordinary valid retry release admission; copied ingress handles share both the
  certificate map and its mutex.
- Pure frame parsing is reused only inside one transaction, keyed by exact raw
  SHA-256 and full original receipt time. All mutable returned categories are
  detached. Authority, current validity, profile, replay, quota and commit
  decisions are not memoized across requests or skipped on cache hits.
- The existing five-second SQLite lock deadline is unchanged. Only a concrete
  SQLite BUSY/LOCKED error from the initial BEGIN is classified as `ErrBusy`.
  It produces a fixed `storage_busy` response with HTTP 429 and Retry-After.
  String lookalikes, arbitrary code-bearing errors, cancellation, corruption,
  quota errors and post-BEGIN/commit uncertainty are not treated as safe busy
  outcomes. The transaction does not retry internally.

### Export and truthfulness

- Managed-instance AI requests are rejected before case text is loaded,
  independent of missing or spoofed case/evidence labels. No operational-derived
  cases are created in this slice. Optional persisted provenance supplies an
  additional packet-builder check, not the authority for allowing export.
- Operational fields remain outside basic support bundles and public bootstrap
  files. Metadata labels can themselves contain sensitive text; this is not
  anonymization or guaranteed secret filtering.
- Namespace, loaded-service, partial journal and sampling limitations remain
  visible. Unknown updates/vulnerabilities are not represented as a clean
  assessment. Collector details are in [`security-review.md`](security-review.md).

## Findings and regression evidence

The optional evidence-provenance addition initially broke the strict basic
development-telemetry decoder. The decoder was corrected and the independent
synthetic basic compatibility test now passes. The AI fixture also used
`INSERT OR IGNORE` with existing IDs, so intended tag changes had not actually
been persisted; corrected fixtures and independent distinct-case tests now
verify the real stored labels.

Independent UI tests found stale acknowledged consent surviving failed or
malformed configuration refresh, including late secret disclosure. Final UI v2
invalidates the old context synchronously and passes all preserved regressions;
see its separate report for exact hashes and 269-test component evidence.

Before parse reuse, dense cross-handle race-instrumented work reached SQLite's
five-second lock deadline. After reuse, an instrumented signed-HTTP run still
observed one operator read fail at 5.018 seconds while ingress and revocation
succeeded. A later exact-source run passed; that does not erase the observed
contention limit or establish that the pointer-only admission fix improved
latency. These tests use three independent Store handles. The actual prepared
runtime shares one Store/sql.DB; its separately tested dense TLS and HTTP
first-attempt operations passed natively and under race instrumentation.

Typed BEGIN-busy handling was added transparently after those observations.
Independent external-lock tests held the original five-second deadline for
read, admission and revocation. Each returned exact `ErrBusy` with no authority
output, left durable rows byte-identical, and succeeded on the same operation
after the lock was released. Exact retry/cache age and revoked-duplicate
invariants remained intact. Native capacity and shared-Store first-attempt
assertions stay strict. Only the explicitly race-instrumented, cross-handle
correctness branch may accept this precise busy result; it must prove unchanged
affected state and a subsequent successful retry. Generic storage failures,
HTTP 503 and other HTTP 429 codes remain failures.

## Validation status

On the held runtime manifest above, six independent profile/API/AI groups passed
under the race detector for three repetitions. Three ordinary generated-key
admission/cancellation/copied-handle groups passed for five repetitions, with
scoped vet. These final reruns include the typed BEGIN-busy mapping rather than
relying only on the earlier pre-mapping admission result.

The final independent store file has eleven top-level tests, plus transport
subtests. The current-source native set passed in 43.400 seconds, retaining
strict first-attempt capacity assertions. Eight focused race safety/busy groups
passed in 22.321 seconds, including deterministic real-driver lock rejection,
byte-identical lifecycle/frame/cache state and exact post-release retry. Dense
real loopback TLS/HTTP and same-Store race evidence immediately before the
BEGIN-only mapping change is distinguished above. A duplicate final dense run
was deliberately stopped before a result; it is not counted as a pass.

The final offline serial aggregate completed successfully with
`go test -json -race -p1 -buildvcs=false ./... -count=1 -timeout=15m`:
**37 tested packages passed**, four package entries were skipped/no-test entries,
and no failure was recorded. The owner ran the command; the independent reviewer
inspected its event log and verified all **430 candidate files** against the
immutable candidate manifest, SHA-256
`560a7eeda38d59cdb81c9c85a9633974f3939b2299e5b641c8954092ff4170f3`.

The final dense owner workload reported three first-attempt successes, zero busy
outcomes and zero retries. The deterministic external-lock test separately
exercised the permitted race-only busy invariance/retry branch successfully.
The aggregate also passed actual basic and operational three-binary enrollment
and foreground tests over **both TLS and explicit HTTP-test transport**. The
race detector instruments the Go test harness; native subprocess executables
are ordinary builds. Actual privileged systemd installation and Docker runtime
tests were explicitly skipped, not counted as acceptance.

Cross-compilation then identified a test-only portability issue: the independent
manager API tests referenced Linux-only fixtures without a matching build
constraint. Candidate v2 adds only `//go:build linux` to
`tests/security/operational_api_boundary_test.go`; removing that prefix exactly
reproduces the fully tested original body and assertions. The independent
reviewer verified this is the sole change among the 430 source entries. Final
candidate manifest SHA-256 is
`8a24b42055e08d5d6ec659259cb1e119f637e4aadb93ea4be16aa5cd3f121276`;
the tagged test file is
`9b9bf79a01ff430164a739d048b8a55bb00f4d03234775c81435819aaa0fcb5f`.
Runtime and UI hashes are unchanged.

On v2, the owner reran the focused Linux API/profile race tests, full vet and
module verification successfully. Windows amd64/macOS arm64 security-test
compilation and Linux arm64 manager/agent cross-builds passed; those binaries
were not executed. Compatibility checks also passed thirteen HTTP-boundary,
six fake-AI and seven managed-preview groups, plus actual Linux CLI schema
validation. These follow-on results do not imply native non-Linux operational
support or a new browser gate.

The owner additionally passed five framing-reader cases and fourteen real
two-process development-transport checks, including an actual 120-second expiry
after sender exit with no manager fallback. Source hashes remained unchanged.
The sanitized proof contains pass/skip scope, counts and hashes rather than raw
runtime telemetry; its SHA-256 is
`94b648dcbc653712dce17366abbb7c9012684e0bb34fa99f00e9bf27a67b1fcd`.
The reviewer read that proof and reconciled its remaining gates with this report.

The first aggregate inherited a restrictive `umask 077` intended for its private
log. Existing negative enrollment-client fixtures created supposed unsafe
0755/0644 paths without explicitly setting their final modes; the mask instead
made them safe 0700/0600, which the runtime correctly accepted. Those mode-fixture
tests failed and the aggregate was interrupted. That run is not a pass. The
unchanged candidate passed under its established `umask 022`, with
logs explicitly created 0600. The fixture umask assumption is a test-portability
limitation, not evidence of relaxed runtime checks. The dedicated installer
restrictive-umask regression passed separately within the final aggregate.

Independent boundary tests use disposable generated credentials, synthetic
operational observations, owned loopback servers and a fake AI provider. The
owner's native three-binary tests additionally collect local Linux observations;
sanitized reports omit their raw values. Independent reviewers did not export
actual process/package/journal inventory. Benchmarks are local observations,
not p95/p99, slow-disk, peak-memory, production throughput or availability promises.
Race-instrumented durations are diagnostic rather than latency guarantees.

## Dependency and remaining gates

The changed-scope external advisory scan is **unverified and pending explicit
authorization for module/package metadata submission to the advisory service**.
No completed fresh vulnerability result is claimed. Prior installer advisory
evidence must not be relabeled as covering this operational code.

An independent local-only `GOPROXY=off GOSUMDB=off go mod verify` passed, and all
runtime/module manifest entries matched afterward. Checksums establish cached
dependency integrity, not absence of vulnerabilities. No dependency was added
for this operational slice.

Exact-source hosted browser, container runtime and real installed
service acceptance remain separate gates. Earlier browser enrollment quarantine
and the failed first systemd installer attempt are not converted into passes by
these results. No actual user-host deployment, global trust/firewall change,
production credentials, non-Linux operational acceptance or production-security
claim follows from this review.
