# Windows x64 unsigned prerelease changelog

This describes the fresh-host Windows Setup candidate and its bounded publication
contract. It does not itself announce a release or establish that a native gate
has passed. Use the exact prerelease's `release-manifest.json`, accepted workflow
run and attached native-subset evidence for its version, source and results.

## Setup wizard

- Native, resizable Windows wizard with DPI-aware layout, scrollable review text,
  embedded versioned service payload and SHA-256 package validation. It does not
  fetch an executable at installation time.
- Public manager bootstrap selection and independent display of manager ID,
  enrollment/agent origins and full trust fingerprints. The selected public
  export is validated and held unchanged; there is no invitation file or
  command-line input route.
- Exact-manager compatibility check before installation writes. A matching
  manager/frontend revision with guided Windows enrollment is required; an old
  manager cannot silently downgrade the setup path.
- Explicit local approval of five bounded observation scopes: inventory and
  machine/network identity, Application/System event headers, caller-visible
  volumes, per-process CPU/working-set and numeric TCP/UDP endpoint metadata.
  Service/startup, persistent identity and independent trust comparison have
  separate initially unchecked acknowledgements.
- Dedicated no-echo local invitation console and separate manager approval of the
  displayed device fingerprint/comparison value. Staging uses a disabled limited
  LocalService service; automatic startup and Start are requested only after
  activation and exact protected grant verification.
- HTTPS by default; a matching disposable HTTP-test bootstrap requires a separate
  acknowledgement of plaintext invitation/telemetry and forgeable responses.
  TLS errors never trigger fallback.
- Cooperative cancellation, finite public diagnostics and retained partial state.
  Existing or foreign installations are not adopted or overwritten. Separately
  confirmed service removal verifies ownership, observes Stop and actual SCM
  absence, and retains files, keys, identity, counters and grants.

## Native subset and publication provenance

The manual `windows-setup-acceptance.yml` gate defines four isolated actual-EXE
cases on fresh hosted Windows Server 2025 x64 machines: TLS install/service
removal, separately approved HTTP-test install/service removal, cancellation at
hidden invitation input, and interrupted transport/cancellation while manager
approval is pending. Synthetic invitation handling and manager approval use a
disposable loopback fixture, not a human invitation or a real Linux deployment.

Publication requires all four cases to pass in one successful first-attempt,
owner-dispatched run on `refs/heads/main`, under source-specific native approval.
The reports must use strict canonical `tracebolt.windows-setup-acceptance.v2`,
with the same source and matching Setup, service, driver and source-input hashes.
Bounded `frameProgress` records inventory/extension readiness and finite telemetry
outcomes. Both install/removal cases require complete progress and at least two
accepted v5 frames; cancellation cases retain zero/not-started progress. No raw
observations are added to the finite evidence.

The canonical `tracebolt.windows-setup-native-subset.v2` aggregate adds
`executionProvenance`. Publication independently authenticates the exact native
run, attempt, repository/owner/actors, workflow, case jobs and expected steps and
`windows-2025` labels. It requires four distinct positive case job IDs and four
distinct positive runner registration IDs, plus exact artifact IDs, archive
hashes, canonical report hashes and ZIP members. Hostnames may be shared across
jobs. Neither a hostname nor a runner registration ID attests to VM/hardware
identity. Fresh isolation relies on standard GitHub-hosted Windows job isolation,
the reviewed workflow and native fresh-state checks. Artifact REST records have
no uploader-job field, so case attribution relies on the reviewed one-case-one-
upload workflow. `vmIdentityAttested` remains false.

The publisher promotes the TLS case's exact six retained public files and the
unchanged finite accepted evidence. No executable is rebuilt, changed, renamed
or signed during promotion. The reviewed installation guide and this changelog
are attached verbatim; only the separate release binding is generated. The v2
verification plan freezes job and runner registration identities together with
all seven artifact IDs/archive hashes and all ten release-asset hashes. Live
provenance verification runs at read-only verification, write preparation,
before the first write, before publication and at final readback, followed by
compact lease/native/all-seven-artifact checks. Publication remains a separate
explicit decision: the five-input manual workflow defaults `publish` to `false`.

The retained executable names and embedded version intentionally stay
`v0.0.0-setup-candidate`; the v2 `release-manifest.json` binds the separately
selected prerelease version to those exact bytes, their source/run evidence and
`executionProvenance`. The original `SHA256SUMS`, package, source-input and build
manifests remain unchanged.
In particular, build-time `nativeExecution: false` remains truthful; the later
native-subset evidence records the separate gate outcome. A rebuild of the same
commit is not interchangeable with the retained package.

## Limitations

- Publication makes a point-in-time verification and never overwrites or adopts
  an existing release. Its no-overwrite policy is not GitHub platform immutability;
  no repository setting is changed.
- Both executables are unsigned. Checksums and workflow linkage do not provide
  an Authenticode publisher identity. Unknown-publisher or SmartScreen warnings
  and policy blocks remain possible; security protections must not be disabled.
- Fresh x64 installation only. Human UAC, real invitation entry, real Linux
  manager/shared-dashboard behavior, Windows desktop coverage, OS reboot,
  upgrade and ARM64 runtime acceptance remain separate unproven gates.
- VM disposal is required after native tests but is not verified by the evidence.
  Cancellation and removal retain state; neither proves complete cleanup.
- Service start requested does not establish a first accepted report or reboot
  persistence. A failed transition may require inspection of indeterminate state.
- No general repair, resume/reset, rollback, automatic updater, Apps & Features
  registration or full file/data removal. Service removal does not revoke manager
  trust and does not make retained state eligible for a fresh reinstall.
- No grant for configured service-startup metadata, event-message content, remote
  actions, Windows Update/CVE operations or external-AI export.

Read `windows-prerelease-install.md` before considering a test installation.
