# macOS endpoint release readiness and source-built test packages

Status: source construction for **unreleased** macOS test candidates. It
authorizes no native run, host change, signing, workflow dispatch or publication.
The foreground candidate remains deliberately foreground-only. A separate
per-architecture service test package adds native installation source and an
explicit preparation helper; neither artifact is a native-accepted release.

## What the current source actually provides

- `make macos-source` cross-builds `enroll-agent`, `macos-agent` and
  `macos-agent-service` for Darwin arm64 and amd64 without executing them.
  `.github/workflows/macos-source.yml` adds cross-compilation, synthetic UI and
  fixture checks. Those checks establish neither native execution nor installability.
- A fresh, nonroot basic TLS identity can be prepared with the macOS enrollment
  source and report in one-shot or bounded foreground mode. The separate fresh
  `macos-read-inventory-v1` profile needs its own local typed consent, protected
  state, manager enablement and foreground runtime. Existing basic, Linux and
  Windows grants do not acquire inventory authority. See
  [macOS source status](macos-status.md) and
  [inventory runtime](macos-read-inventory-runtime.md).
- Explicit same-key **certificate** renewal has source paths. It is not binary
  update, profile expansion, a new endpoint identity or a release updater. A
  foreground process must remain running for its scheduler and retention work.
- The assembled service-test source adds a native, create-only launchd
  install/uninstall adapter. `macos-agent-service --action install|uninstall`
  reviews without host mutation; `--apply` is the distinct effectful boundary.
  The separate Go package helper verifies the reviewed archive and can stage a
  fresh dedicated `_traceboltagent` account, fixed root-owned binaries and
  protected state/source paths before deliberate enrollment. Neither command
  has been accepted on a Mac. See [service test runbook](macos-test-package.md)
  and [launchd source](macos-agent-service.md).
- The foreground builder emits a source-review manifest, and the service-test
  builder prepares an exact-source private archive/manifest, but there is no
  **published or native-accepted Mac release** asset set, verified public Mac
  download command, signed `.pkg`/`.dmg`, publisher signing/notarization stage
  or Mac release publisher. Linux's attested release/bootstrap is Linux-specific;
  Windows' Setup and unsigned prerelease publisher are Windows-specific. A
  source archive or SHA-256 manifest copied from either cannot inherit its
  platform trust or acceptance claim.

## Evidence and acceptance matrix

The supported **release** OS versions have not yet been selected or accepted.
The existing hosted native evidence used `macos-15` arm64 and
`macos-15-intel` amd64 (both macOS 15.7.9 in the first recorded run). Treat
each cell independently; one profile or architecture does not qualify another.

| Gate | Apple Silicon arm64 | Intel amd64 | Effect on release claim |
| --- | --- | --- | --- |
| Go 1.27.1 target compilation and fake/temporary-file fixtures | Source CI is configured | Source CI is configured | Compilation and fixture behavior only; verify exact final commit/CI result. |
| Fixed native inventory collector | First run passed hardware, receipt IDs and process rows; both interface-family metadata parsers rejected | Same partial result | Inventory profile cannot claim accepted IPv4/IPv6 rows or complete native collection. See [first run](macos-native-evidence-20261013.md). |
| Synthetic Apple log probe | First JSON query rejected event schema; later queries never ran | Same | No production log provider or log-content release scope. |
| Native endpoint subset on disposable runner | Manual source gate prepared; no accepted result recorded | Manual source gate prepared; no accepted result recorded | The gate uses a simulated loopback peer and explicitly keeps Stage 1 blocked even if its subset passes. See [endpoint gate](../tests/macosendpointfixture/NATIVE_GATE.md). |
| Fresh enrollment with a **real** manager, independent fingerprint approval and received report | Missing | Missing | Required for a foreground basic-TLS release; repeat separately for fresh inventory scope. A loopback peer cannot substitute. |
| Exact pending retry, interrupted enrollment, lock exclusion, restart, same-key renewal, expiry and revocation against real manager | Missing | Missing | Required before claiming durable foreground operation or renewal. Preserve identity and original observations. |
| Dedicated account, ACL/descriptor behavior, launchd job binding, real reboot, stop/restart and owned removal | Native gate missing; source adapter and package helper prepared | Native gate missing; source adapter and package helper prepared | Hard blocker for any **installed-service release**. Source fixtures/cross-builds cannot prove native behavior. |
| Final distribution bytes, trust and installation/download UX | Private exact-source test candidate path; no publisher | Private exact-source test candidate path; no publisher | No public Mac download/install command or signed/notarized claim. Native acceptance is a release gate, not a prerequisite to building the test archive. |

The first [manual native inventory/log run](macos-native-evidence-20261013.md)
failed on both architectures while retaining bounded evidence. Its partial
success must not be restated as general native acceptance. The later diagnostic
source still needs a separately approved exact-commit dispatch; do not silently
rerun the failed gate or infer a parser fix from its metadata. Automated
`macos-native-fixtures.yml` runs temporary-file/synthetic fixtures, not endpoint
acceptance. `macos-endpoint-acceptance.yml` and `macos-native-acceptance.yml`
default their manual selectors off.

## Deliberately foreground-only candidate bytes

The separate `deploy/macos-release/build-foreground-candidate.py` and inert
fixtures prepare a **source-only, non-publishing** candidate from a clean,
reviewed commit. Its role set is
just
`enroll-agent` and `macos-agent` for each of `darwin/arm64` and `darwin/amd64`.
Exclude `macos-agent-service` from the **foreground** asset set so that artifact
is never mistaken for an installer. The separate service-test package has its
own four-role builder and runbook. Keep the existing `make macos-source`
target's broader compilation checks unchanged.

The precedent is `deploy/release/build-linux-release.py`: it requires a clean,
exact Git checkout, the Go version in `go.mod`, a new output directory outside
the checkout, locked modules, fixed Go target flags, `git archive` of the exact
commit and a bounded hash manifest. Reuse that **structure**, not the Linux
bootstrap, platform admission, attestation or asset names. Windows'
`deploy/windows-setup/build-setup.py` provides a useful source-input and
repeated-byte comparison precedent, but its PE/Setup/native-service checks do
not apply to Mach-O.

Implemented foreground builder contract:

1. Accept an explicitly reviewed full source commit/version and a fresh output
   path; require HEAD equality, clean visible tracked/untracked tree, reject
   unusual index flags, require exact Go 1.27.1, `GOTOOLCHAIN=local`,
   `GOWORK=off`, `GOFLAGS=-mod=readonly` and verified cached locked modules.
   Never use a moving branch or silently fetch a toolchain. Generate a bounded
   `git archive` of that exact commit and compile only from its validated,
   link-rejecting extraction. Ambient ignored files cannot enter that tree.
2. Use `CGO_ENABLED=0`, `GOOS=darwin`, explicit `GOARCH`, `GOAMD64=v1` or
   `GOARM64=v8.0`, `-trimpath` and `-buildvcs=false` because the extracted tree
   contains no `.git`. Build each of the two roles twice into private scratch, compare exact bytes, then inspect
   the final thin Mach-O architecture/role and size. Recheck the source lease
   after building. A matching pair proves only this local build's repeatability.
3. Retain that exact `git archive` source tar. Emit a closed,
   canonical JSON build manifest with source commit/tree, exact Go version,
   target/role, build flags, source archive and binary sizes/SHA-256 values,
   plus explicit `nativeAccepted: false`, `installable: false`,
   `publisherSigned: false` and `published: false`. Reject missing/extra
   artifacts, path aliases, symlinks, output reuse and size-limit failures.
   Do not include private bootstrap, endpoint state, invitations or telemetry.
4. Provide inert tests for role/architecture enumeration, exact-clean-source
   rejection, toolchain mismatch, manifest closure, hash/size mismatch,
   double-build drift, incorrect Mach-O header, archive traversal/link/duplicate
   and size rejection, output collisions, bounded tool output and a source
   change during build. On the final assembled tree, run these with existing
   Mac cross-build/source suites. Store the candidate only as a review artifact;
   do not add a release-write permission, dispatch trigger or dashboard link.

An unsigned checksum manifest identifies bytes after a trusted reviewer obtains
it; it does not authenticate the publisher. The Go Darwin/arm64 linker may embed
an ad-hoc `LC_CODE_SIGNATURE` without any Developer ID signature. Here
`publisherSigned: false` means no verified publisher identity was applied, not
that the load command is absent. The builder does not verify that signature.
It cannot certify Developer ID signing/notarization, Gatekeeper behavior, actual macOS syscalls, native
collection, real-manager interoperability or launchd. Decide the intended
publisher trust model and user-facing distribution mechanism only after the
native foreground gates pass. A future signed candidate must hash the **final**
signed/notarized deliverables and independently verify their identities.

## Release decision boundaries

**Foreground-only preview:** require final exact-source review and source CI,
native arm64 and amd64 PTY/hidden-input/cancellation evidence, protected-state
and TLS/fingerprint checks, real-manager enrollment/approval/report visibility,
original-byte retry/renewal/revocation results, and reviewed final distribution
bytes/trust and human instructions. Explicitly say the process stops when its
terminal/foreground process stops. Select basic or fresh inventory scope
deliberately; the current interface failure blocks an inventory-completeness
claim. No service persistence, installer or auto-binary-update claim follows.

**Installed-service release:** independently review and natively verify the
source-built create-only launchd adapter, collision/override inspection, protected
root-owned custody and exact job binding. Obtain separate host/account/service
permission, then verify both architectures on disposable supported Mac versions:
dedicated nonroot identity and no unexpected groups, granted profile, actual
manager reports, stop/SIGTERM drain, failure restart behavior, real reboot
persistence, safe owned uninstall and interruption/uncertainty reconciliation.
The existing fake lifecycle tests cannot fill these cells. Binary upgrade needs
its own same-identity/no-state-reset design and native gate; current certificate
renewal is not that design.

Publication is a final, separate decision after all applicable gates and final
artifact review. Keep the frozen Windows preview.3 bytes and unrelated release
pins unchanged. Never infer native approval from a source-only workflow pass.

## Follow-on unsigned service test package (source construction)

The separate [service test package runbook](macos-test-package.md) describes a
bounded source-built, per-architecture archive and a cross-compiled Go
preparation helper. This is a **native test candidate**, not a public release
or an assertion that the release gates above have passed. It retains the
foreground builder and its four binary source-review outputs unchanged.
The package adds the service CLI and an explicit Go entry to verify the closed
archive, stage a fresh dedicated account/root-owned binaries/public TLS
bootstrap and protected source/state paths, and perform a deliberately
reviewed pre-enrollment rollback only when exact owned state is still unused.
The existing `enroll-agent` hidden-terminal fingerprint/invitation flow is a
separate user-authorized step. The native service CLI's `--action install`
and `--action uninstall` likewise require explicit `--apply`; uninstallation
retains the account, source, binaries, credentials, identity and sender state.
No helper silently adopts a prior grant, changes TCC/security settings, creates
an invitation or resets an uncertain ledger.

The test archives carry a canonical exact-source SHA-256 manifest, repeatable
local archive bytes and a verifier that checks one immutable byte snapshot,
role metadata and closed members. This establishes local byte/source review
properties only; it cannot prove Apple signing/notarization, publisher origin,
Gatekeeper operation, native launchd semantics, reboot persistence or actual
manager-received reporting. The current Mac native collector evidence remains
partial. Do not expose an end-user install/download link or claim Mac release
readiness until both architectures complete their separate fresh enrollment,
collection, protected-state, launchd and owned-removal native gates and final
distribution trust review.
