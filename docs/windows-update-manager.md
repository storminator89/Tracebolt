# Windows cached-update manager and operator contract

**Source integration candidate, 10 October 2026. Fixture evidence only; no native
Windows WUA acceptance, installed-service acceptance or released deployment is
established by this document.**

[Source and freshness contract](windows-update-inspection.md) ·
[Windows status](windows-status.md) ·
[Separate Windows observation scopes](windows-read-observation-setup.md)

## Wire admission

`tracebolt.agent-telemetry.windows.v7` requires the existing bounded
`windowsInventory` and the new `windowsUpdates` snapshot. Event headers, volumes,
process metrics, network endpoints and service startup remain independently
optional. Their original validation and scope boundaries still apply. Versions
v1 through v6 retain their original shape and bytes when updates are absent;
none accepts a new update member.

The new member is exactly `tracebolt.windows-update-inspection.v1` with scope
`windows-cached-update-inspection-v1`. Admission rejects missing, null, duplicate,
unknown, noncanonical or incorrectly typed snapshot fields, invalid update
identities or KB metadata, incoherent counts/quality/truncation, and excess rows
or bytes. Snapshot limits remain 64 rows and 24 KiB; the entire frame, including
all older siblings and its health observation, remains at most 72 KiB. Individual
per-scope limits cannot be added to bypass the complete-frame limit.

An update's generation and original capture must equal its base inventory's
exact generation and capture. The bundle's generation/completion time may be
later; it must not precede capture. Fresh ingress retains the existing two-minute
maximum sample age and 30-second future-clock allowance. The new grant must be
well-formed and distinct from any other visible extension grant. This validates
a wire binding, not local consent: only the endpoint can authenticate its
protected identity-bound update receipt. The manager never grants collection.

Only an authenticated, activated Windows identity whose durable collection
profile is `windows-inventory-v1` can submit this frame. TLS and explicitly
configured signed HTTP-test admissions use the same validated durable frame
path. Basic Windows identities and all Linux collection profiles cannot acquire
this scope by sending new fields or changing payload labels. HTTP-test signatures
do not encrypt the update titles and identifiers or authenticate manager
responses; production still requires HTTPS.

## Durable retry and capture floor

The existing credential row stores one latest bounded exact frame and its replay
receipt atomically. There is no new manager collection grant, schema migration,
update polling loop or parallel update ledger.

An exact lost-response retry returns the original receipt, including its original
capture and receipt times, even if a later retry would otherwise be too stale
for fresh admission. Activation, identity, revocation and certificate validity
are checked before acknowledging a duplicate. Conflicting payloads and reused
or regressed sequence/generation/capture values are rejected. A malformed frame
does not consume the next valid sequence.

Updates share their exact base capture. The durable base floor strictly advances
across update-present and update-absent frames, so temporarily omitting this
scope cannot let a later update roll back its capture. A newly accepted frame
without updates exposes no retained update sibling. Disabling the endpoint scope
does not create a manager grant or collect a replacement snapshot from the UI.

## Private operator view

The existing same-origin authenticated GET
`/api/devices/{agentId}/windows-inventory` carries an optional `updates` member
in `tracebolt.windows-inventory-view.v1`. It returns the admitted bounded snapshot
with its original `collectedAt`; the view's `receivedAt` remains the original
accepted frame receipt. There is no separate source read, online scan, refresh
command or endpoint action attached to this route.

The view uses the existing operator session, identity/platform/profile,
revocation, certificate-expiry and base privacy gates. It independently removes
update data at 24 hours from the original update capture, and removes it when
the base snapshot is unavailable. Expiring another optional sibling does not
hide younger updates. The response-time recheck can change a fresh view to stale
or unavailable; it never refreshes either time. A revoked or expired operator
session during a retained read prevents serialization of private update rows.

Private rows do not enter the basic health observation, resource history, public
health summaries, provider packets, CVE verdicts, action permissions or AI
approval. This integration does not add a provider exception or change the
existing managed-profile export exclusion.

## Meaning of displayed evidence

- `source` is always `wua-cache`; `cacheFreshness` is always `unknown`.
- `collectedAt` is an inspection/base capture time, not cache age or an online
  scan or refresh time.
- Zero successful cached rows do not mean "up to date", patched, protected,
  compliant or free of applicable vulnerabilities.
- `observedCount` is the cached fixed-search result count, not machine-wide
  update coverage. An inexact count is a lower bound, including zero.
- Snapshot truncation, row metadata truncation, partial source data, denied and
  unavailable states retain their separate meanings.
- Severity is the WUA vendor label. Downloaded means WUA says content was already
  cached; it does not mean this client downloaded, installed or approved it.

The existing shared Windows Updates tab can locally search, sort and page this
bounded retained evidence. Those controls do not collect, create local consent,
accept update terms, download, install, reboot or refresh Windows Update.
The fresh five-scope observation Setup contract remains unchanged.

## Portable verification and native gate

New manager fixtures use invented reports, update rows and disposable in-memory
identity material. Focused tests cover:

- All 32 optional older-sibling combinations in v7, and old v1-v6 byte round trips
- Missing/null/unknown/duplicate members, changed generation/capture/grant,
  malformed count/quality/title/KB values and whole-frame/snapshot limits
- Empty observed/partial/denied/unavailable cache truth without patch assessment
- Durable reopen and exact retry preserving original receipt/capture
- Rejected payloads not consuming sequence, and update omission preserving the
  monotonic durable capture floor
- Basic-profile rejection, revocation and private-data exclusion from basic views
- Independent 24-hour expiry, certificate/base expiry, response-time stale checks,
  session revocation/cancellation and the authenticated same-origin API boundary

Run the added fixtures with the repository's pinned toolchain:

```sh
go test -race -count=1 -run '^TestWindowsUpdates' \
  ./internal/lanstore ./internal/enrollmentstore ./internal/api
go vet ./internal/lanstore ./internal/enrollmentstore \
  ./internal/enrollmentservice ./internal/api
```

The sender's separate injected pipeline suite exercises signed TLS and HTTP-test
ingress, consent selection/replacement/revocation, exact pending bytes and restart.
Those are portable fixtures, not a real Windows WUA search or a real deployment.
Native acceptance still needs separate approval for the exact reviewed artifact,
identity and local update scope, controlled cached data, traffic observation,
limited-token/error cases, resource and cancellation measurements, and an actual
installed-service shutdown/lifetime check. No fixture authorizes those host reads,
new persistent grants, lifecycle operations or network/security changes.
