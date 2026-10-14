# macOS endpoint release readiness and source-only packaging proposal

Status: planning document for an **unreleased** macOS source candidate. It
authorizes no native run, host change, signing, workflow dispatch or publication.
The first useful distribution target is a deliberately foreground-only endpoint.
An installed launchd service is a separate later target, not a packaging option
that can be enabled by changing a release label.

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
- `macos-agent-service` can render a plist and perform existing-host read-only
  preflight. Its `--action install` and `--apply` both return unavailable before
  host inspection: there is no native `InstallBackend`. There is no native
  install, restart, upgrade or uninstall adapter. Its fixed root-owned binary,
  dedicated `_traceboltagent` account and protected paths are prerequisites to
  inspect, not things the CLI provisions. See
  [launchd source](macos-agent-service.md).
- This slice prepares a source-review build manifest, but there is no
  **published or native-accepted Mac release** manifest/asset set, verified Mac
  download command, installer, `.pkg`/`.dmg`, publisher signing/notarization stage
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
| Dedicated account, ACL/descriptor behavior, launchd job binding, real reboot, stop/restart and owned removal | Missing; native adapter itself absent | Missing; native adapter itself absent | Hard blocker for any **installed-service** release. Source preflight/plist rendering and fixtures are insufficient. |
| Final distribution bytes, trust and installation/download UX | No Mac candidate or publisher | No Mac candidate or publisher | No public Mac download/install command or signed/notarized claim. |

The first [manual native inventory/log run](macos-native-evidence-20261013.md)
failed on both architectures while retaining bounded evidence. Its partial
success must not be restated as general native acceptance. The later diagnostic
source still needs a separately approved exact-commit dispatch; do not silently
rerun the failed gate or infer a parser fix from its metadata. Automated
`macos-native-fixtures.yml` runs temporary-file/synthetic fixtures, not endpoint
acceptance. `macos-endpoint-acceptance.yml` and `macos-native-acceptance.yml`
default their manual selectors off.

## Narrow next slice: prepare unsigned foreground candidate bytes

The separate `deploy/macos-release/build-foreground-candidate.py` and inert
fixtures prepare a **source-only, non-publishing** candidate after the current
macOS runtime fixes are assembled into a clean, reviewed commit. Its role set is
just
`enroll-agent` and `macos-agent` for each of `darwin/arm64` and `darwin/amd64`.
Exclude `macos-agent-service` from the foreground asset set so a binary with an
unavailable install operation cannot be mistaken for an installer. Keep the
existing `make macos-source` target's broader compilation checks unchanged.

The precedent is `deploy/release/build-linux-release.py`: it requires a clean,
exact Git checkout, the Go version in `go.mod`, a new output directory outside
the checkout, locked modules, fixed Go target flags, `git archive` of the exact
commit and a bounded hash manifest. Reuse that **structure**, not the Linux
bootstrap, platform admission, attestation or asset names. Windows'
`deploy/windows-setup/build-setup.py` provides a useful source-input and
repeated-byte comparison precedent, but its PE/Setup/native-service checks do
not apply to Mach-O.

Proposed Mac builder contract:

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

**Installed-service release:** additionally implement and independently review
the native create-only launchd adapter, collision/override inspection, protected
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
