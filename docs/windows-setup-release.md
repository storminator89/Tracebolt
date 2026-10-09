# Windows Setup packaging and release gates

The `tracebolt_setup` build of `cmd/windows-service` is a native Windows wizard
candidate. Its separate, embedded ordinary service executable uses the existing
SCM controller. **Building these files does not establish native installation,
release readiness, signing, reboot behavior, or manager/dashboard acceptance.**
The initial package is fresh-install only; an existing installation, protected
state, or foreign path must block before replacement. It is not an updater.
The preview has no Apps & Features registration: rerun the exact reviewed Setup
and choose **Uninstall service**. It retains binaries, public bootstrap and
private state; it does not promise full application-file removal.

The source builder produces a normal GUI-subsystem `…-Setup.exe` with an embedded
`requireAdministrator` UAC manifest and Windows version information. UAC approval
alone is not collection consent or manager trust approval. The ordinary service
payload has an `asInvoker` manifest and never becomes an administrator service.

## Build without running Windows software

Use the exact Go version in `go.mod`, Python 3.12 or later, and a clean exact Git
checkout. The build command works on the build host without Windows, a resource
compiler, WiX/Inno, signing credentials, or changes to Go dependencies:

```sh
python3 -I -B deploy/windows-setup/build-setup.py \
  --version v0.0.0-setup-candidate \
  --source-commit FULL_40_CHARACTER_SOURCE_COMMIT \
  --output /absolute/new/directory/outside/the/checkout
```

Use `--arch amd64` or `--arch arm64` to build one architecture; by default both
are compiled. `--go` selects the already installed, exact pinned Go executable.
The source snapshot contains no prebuilt payload: generated embed inputs and
`.syso` resource objects live only in a temporary source copy.

For a local uncommitted/no-Git source review only, explicit `--source-snapshot`
records the supplied commit as the **base**, not the commit of the changed
candidate. `source-inputs.json` identifies the exact bounded Go/module/packaging
inputs copied by path, size and SHA-256; its digest is recorded separately. Such
an output must never be relabeled an exact committed release. Native acceptance
and release publication should use an exact clean reviewed Git revision.

Every normal build compiles each service and Setup twice, compares repeated
bytes, and statically checks the actual PE machine, zero timestamp, subsystem,
unsigned certificate directory, and exact embedded UAC/version resources. It
also verifies that Setup contains the exact service bytes and package manifest.
A tiny read-only build-host verifier applies the real installer
`ParseManifest`/`Validate` functions to both payloads; it does not call provisioning
or service APIs. These checks never load or execute a Setup/service image. Byte reproducibility is verified
for repeated builds with these fixed inputs/toolchain, not promised across
arbitrary toolchain releases, signing operations, or build platforms.

Outputs for each architecture:

- `Tracebolt-VERSION-windows-ARCH-Setup.exe`: unsigned GUI installer candidate
- `tracebolt-VERSION-windows-ARCH-service.exe`: the exact separately inspectable
  payload embedded in that installer
- `setup-package-ARCH.json`: canonical schema/version/source/architecture and
  final service SHA-256, also embedded in Setup
- `source-inputs.json`, `build-manifest.json`, and `SHA256SUMS`: source-input and
  final-asset evidence; no secrets or runtime state

The `Build unsigned Windows Setup candidates` workflow has read-only repository
permissions. It runs portable fixtures and produces artifacts on a Linux runner.
It does not install a service, create an endpoint identity, grant a local scope,
dispatch native acceptance, sign, or publish a GitHub release. A successful
artifact build is not approval to run the installer.

## Installer security contract

- One explicit combined local acknowledgement covers the exact existing five
  read scopes and their disclosures. Hidden invitation entry and separate
  manager fingerprint/comparison approval remain required.
- HTTPS is the default. An exact `http-test` bootstrap may be selected only with
  its separate deliberate plaintext-risk acknowledgement and all five existing
  HTTP warnings. Transport, identity and grants must match; no TLS failure may
  trigger an HTTP fallback.
- The first wizard implementation uses the existing dedicated hidden local
  console for invitation entry. The wizard must explain that step. Invitation
  bytes never enter arguments, environment, redirected stdin, files, telemetry,
  installer logs, package metadata, or artifacts.
- Use the fixed KnownFolder layout, protected create-only placement, validated
  bootstrap, existing limited LocalService/service SID, and durable controller
  receipts. Do not install as LocalSystem, grant `SeDebugPrivilege`, weaken TLS,
  repair arbitrary ACLs, or add inbound firewall exceptions.
- Keep the fresh service disabled until the same identity is activated and all
  exact grants are verified and durably recorded. SCM Running alone is not proof
  of manager approval, first received telemetry, or visible dashboard data.
- A cancellation or partial failure must retain the original evidence, identity,
  expiry and grants. Never reset, re-enroll, adopt, silently retry a mutation, or
  remove the binary while a retained service may still reference it.
- Disable generic repair/upgrade and background update behavior. The executable
  digest is bound into protected receipts and the SCM description; overwriting
  it is not a valid upgrade. A future updater needs its own same-identity,
  same-scope transaction and interrupted-replacement recovery design.
- Uninstall requires explicit local intent and an exact owned stopped service.
  Observe stop and SCM deletion separately; deletion may remain pending while
  handles are open. Preserve private state and identity. Do not report complete
  removal, delete binaries, or schedule deletion/replacement at reboot without
  separately designed and verified ownership-safe semantics.
- Never force a reboot. Actual boot persistence, shutdown cancellation and
  delete-pending behavior are native acceptance results, not packaging features.

## Signing and publication sequence

These artifacts are explicitly unsigned. SHA-256 files and GitHub artifact
provenance do **not** create an Authenticode publisher identity. The current
builder intentionally rejects unexpectedly signed outputs instead of mixing
signing into its deterministic candidate contract.

Before a signed public release, design and approve a separate signing stage:

1. Freeze and review the exact source, build inputs, toolchain and native results.
2. Build the ordinary service, then sign and timestamp that service with the
   authorized publisher identity. Verify its Authenticode signature.
3. Compute the hash of those **final signed service bytes** and embed them with
   the matching package manifest in Setup. Signing the service after embedding
   would invalidate the package/controller's digest binding.
4. Build Setup; sign and timestamp Setup last. If the release adds another
   executable or an uninstaller, sign and verify those executables too.
5. Recompute final public-asset hashes and provenance after signing. Verify
   architecture, embedded payload, publisher and final download bytes before
   exposing a download button. Never modify signed files afterward.
6. Publish only a separately approved new release/version. The current workflow
   deliberately has no release-write or signing permissions.

Microsoft explains that even correctly signed new executables can show
SmartScreen warnings, and EV certificates no longer provide an automatic bypass.
Smart App Control or enterprise policy can also block an unsigned candidate.
Do not instruct users to disable protections or promise a warning-free install.
See [Microsoft SmartScreen guidance](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation)
and [Smart App Control code signing](https://learn.microsoft.com/en-us/windows/apps/develop/smart-app-control/code-signing-for-smart-app-control).

## Acceptance checklist before release

1. Independent review of the combined wizard, staging, bootstrap, controller,
   resources, build pipeline and final artifact metadata.
2. Real x64 Windows fresh-machine wizard: pre-consent Cancel causes no host
   mutation; wrong bootstrap/trust rejection; UAC denial; bounded hidden input,
   cancellation, restored console mode, and no invitation output/logging.
3. Correct pending approval keeps SCM disabled; explicit manager comparison
   approval leads to exact grants, limited runtime token, actual accepted report
   and expected dashboard rows. Failure must not be misreported as success.
4. Separate disposable machines for post-identity cancellation, expired/rejected
   approval, staged receipt/ACL failure and indeterminate startup transitions.
   Retained create-only state is not reset between cases.
5. Repeated/foreign install, modified executable/receipt/ACL, reparse/hard-link
   targets and denied paths all fail without adoption or overwrite.
6. Same installed identity and counters survive genuine shutdown/guest reboot.
   Verify stopped and running uninstall, Cancel, open-handle delete-pending,
   foreign SCM mismatch and retained private-state behavior.
7. Native ARM64 acceptance before claiming ARM64 runtime support. Cross-building
   proves compilation only. Record exact Windows version/architecture/NTFS/path
   constraints instead of inferring compatibility from another machine.
8. Final signed-download byte verification and native tests of that exact
   packaged artifact. Source/manual-controller tests alone do not establish
   acceptance of the wizard the user will download.

Primary references: [application manifests](https://learn.microsoft.com/en-us/windows/win32/sbscs/application-manifests),
[PE/COFF format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format),
[version resources](https://learn.microsoft.com/en-us/windows/win32/menurc/versioninfo-resource),
[LocalService](https://learn.microsoft.com/en-us/windows/win32/services/localservice-account),
and [deferred service deletion](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-deleteservice).

## Retaining the exact native-tested x64 download

The manual `windows-setup-acceptance.yml` gate builds on each assigned fresh
Windows x64 machine and drives that packaged executable. It does not assume
Windows and Linux checkouts/builds have identical bytes. After a successful TLS
lifecycle case, the runner rereads and verifies the unchanged package, then
retains exactly six public files: Setup, service, package manifest, build
manifest, source-input manifest and SHA256SUMS. No working directory, console
buffer, private state, invitation or raw observation is uploaded.

A separate Linux aggregation job downloads only artifacts from the same workflow
run into distinct directories. It requires four passed cases, the same exact
committed source/run, distinct assigned machines, and matching Setup/service/
driver/source-input hashes. It rechecks canonical manifests, PE resources, exact embedded
payload bytes and all public hashes, then copies the tested TLS package without
rebuilding or rewriting it. The accepted public artifact is
`windows-setup-native-subset-public-SOURCE`; the separately retained
`windows-setup-native-subset-evidence-SOURCE` binds its hashes to those finite
results. Both currently have seven-day workflow retention, so separately approved
delivery must preserve and verify these exact public bytes before expiration.

The original build manifest truthfully keeps `nativeExecution: false`: it records
what the builder did. The separate later native-subset evidence records the
approved gate outcome. No metadata is rewritten to imply signing or a release.
A later authorized download must use those exact accepted x64 bytes and their
source/hash evidence; rebuilding the same commit is not sufficient. If any case
fails, the gate cannot export an accepted package. ARM64 stays build-only until
its own separately approved native gate passes. Signing or changing any executable
later creates new final bytes that need their own native artifact acceptance.
