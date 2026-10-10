# Windows x64 unsigned prerelease installation guide

This guide covers the fresh-host Tracebolt Setup wizard and the evidence to
check before running it. It does not announce an available release. A published prerelease must carry
its own exact source, accepted
workflow run and file hashes in `release-manifest.json` and the accompanying
native-subset evidence.

Use an explicitly approved, disposable **x64** test machine with no existing
Tracebolt installation or protected state. The native gate is limited to fresh
GitHub-hosted **Windows Server 2025 x64** machines. It does not establish Windows
10/11 desktop, human UAC or invitation handling, real Linux manager/dashboard,
reboot, upgrade or ARM64 acceptance. Plan for retained files and keys and for
disposal of the test machine; successful test evidence does not verify that
platform disposal occurred.


## Selected native evidence

The selected packaged-GUI subset passed in [run 38069058865](https://github.com/storminator89/Tracebolt/actions/runs/38069058865),
attempt 1, on 10 October 2026, using source
`14719116bdb663d13e4bcaef434a4374a6265fe6` and tree
`d2ec1451a0fb4332a48f0ee48b17c35eca807ad4`. All four fresh hosted Windows Server
2025 x64 cases and the aggregate passed. The original accepted Setup SHA-256 is
`24b635060bbeeefae01ba48acc4510cf8b9e434f8278dab5bbfc0ddef35295c5`;
the service SHA-256 is
`05459d54ff6fa582515c2de1d897fee264b5a32b1c4a79048b06a6acb603cccf`.

This evidence establishes that bounded subset only. It does not establish human
UAC or invitation entry, a real Linux manager/shared dashboard, Windows 10/11,
reboot, upgrade, ARM64 runtime, complete file/data uninstall or VM disposal.
Both executables remain unsigned. The later initial-chooser readiness proposal
is absent from these accepted bytes. Release availability and the exact version
must be established by the published release and its own binding manifest.

## Verify the download before running it

Obtain the assets from the exact approved prerelease in
[`storminator89/Tracebolt`](https://github.com/storminator89/Tracebolt/releases),
not a similarly named repository, a moving branch build or an unsolicited link.
Keep all release evidence with the download. The six retained package files are:

- `Tracebolt-v0.0.0-setup-candidate-windows-amd64-Setup.exe`
- `tracebolt-v0.0.0-setup-candidate-windows-amd64-service.exe`
- `setup-package-amd64.json`
- `build-manifest.json`
- `source-inputs.json`
- `SHA256SUMS`

The other four attachments are `tracebolt-setup-native-subset.json`,
`windows-prerelease-install.md`, `windows-prerelease-changelog.md` and
`release-manifest.json`. The v2 release manifest records sizes and SHA-256 hashes
for the nine other assets, plus the package source commit/tree, acceptance run
and retained archive digests, the separate publisher source revision, and
`executionProvenance` for the case jobs and their retained evidence.

The executable names and embedded package version intentionally remain
`v0.0.0-setup-candidate`. Publication preserves the exact native-tested bytes;
it does not rebuild, rename, reversion or sign them. The chosen prerelease
version is bound separately in `release-manifest.json`. Do not substitute a
fresh build of the same source commit.

Before launch:

1. Check the release tag and full package source commit/tree against
   `release-manifest.json` and the reviewed repository revision. Check the
   recorded acceptance run is the successful manual
   `windows-setup-acceptance.yml` first-attempt run on `refs/heads/main` for that
   same source. Native approval is source-specific; publication approval is a
   separate decision.
2. Check `tracebolt-setup-native-subset.json` uses
   `tracebolt.windows-setup-native-subset.v2`, with four passed
   `tracebolt.windows-setup-acceptance.v2` reports and matching Setup, service,
   driver and source-input hashes. Its finite `frameProgress` must show complete
   progress and at least two accepted v5 frames for each install/removal case;
   cancellation cases retain zero/not-started progress. The aggregate and release
   manifest must agree on `executionProvenance`, including four distinct positive
   case job IDs, four distinct positive runner registration IDs and the exact
   report/package artifact IDs and hashes. The publisher independently checks
   the live run/jobs/steps and report ZIP bytes against these bindings; merely
   having correctly shaped JSON is insufficient. A build-only artifact or an
   individual case report is insufficient.
3. Compute SHA-256 hashes of the downloaded files and compare them with the
   release manifest and checksum evidence. For example, in PowerShell opened
   in the download folder:

   ```powershell
   Get-FileHash -Algorithm SHA256 -LiteralPath '.\Tracebolt-v0.0.0-setup-candidate-windows-amd64-Setup.exe'
   Get-FileHash -Algorithm SHA256 -LiteralPath '.\tracebolt-v0.0.0-setup-candidate-windows-amd64-service.exe'
   ```

   Repeat for the other seven assets listed in the release manifest, checking
   file sizes as well. The manifest does not hash itself. The retained
   `SHA256SUMS` covers the five other original package files; it does not cover
   itself or later release attachments. Check the separately added evidence and
   documentation against the release-level hashes too. Any missing evidence,
   mismatch or unexpected file is a reason to stop.
4. Check that the package and build manifests identify `amd64`, the same exact
   source commit and service hash. `source-inputs.json` records the bounded build
   inputs by path, size and hash. The unchanged build manifest correctly retains
   `nativeExecution: false` and its source-candidate distribution status: it
   describes the builder. Later native results belong to the separate evidence.

The native cases use standard hosted `windows-2025` jobs. Fresh isolation relies
on GitHub's hosted Windows job contract, the reviewed workflow and native fresh-
state checks. GitHub artifact REST records do not identify the uploading job;
case attribution depends on the reviewed one-case-one-upload workflow. Shared
hostnames are allowed. Neither hostnames nor runner registration IDs attest to
VM or hardware identity, and `vmIdentityAttested` remains false.

These checks link bytes to the selected repository and recorded run. Keep the
verified files and evidence: this is not a platform-immutability guarantee, and
checksums alone do not authenticate their own source or an Authenticode publisher.
Both executables are unsigned.
Windows may show **Unknown publisher**, SmartScreen warnings, or block execution
under Smart App Control or enterprise policy. No warning-free installation is
promised. Do not disable protections, change security policy or bypass a block
to make the test pass; consult the administrator and stop if execution is not
approved.

## Prepare the manager and public bootstrap

An authorized administrator must prepare the manager and matching frontend from
the **same reviewed source revision as Setup**, with guided Windows enrollment
enabled. The older published Linux endpoint release is not a compatible-manager
guarantee. Manager upgrade and stopped-state backup are separate administrator
work; Setup does not perform them.

In that manager, select Windows, create a fresh Windows inventory invitation,
then choose **Download bootstrap file**. Save the public JSON export to a normal
local file. It contains the manager and agent origins, public certificates and
invitation ID, never the invitation secret or a private key. Do not hand-author
the export or put the secret in it.

HTTPS is the default. Only a deliberately selected matching `http-test` export
permits the separate disposable HTTP test: invitation secrets and observation
metadata travel in plaintext, the manager is not authenticated, and responses
can be forged. The wizard requires an additional unchecked risk acknowledgement.
There is no fallback from failed HTTPS. Production must use HTTPS.

## Install deliberately

1. Launch `Tracebolt-v0.0.0-setup-candidate-windows-amd64-Setup.exe` only after the
   file and target checks above. Deliberately approve the administrator prompt
   when permitted. UAC approval alone does not grant collection or device trust.
   The separate service executable is supplied for inspection; Setup already
   embeds the exact payload and does not download another executable.
2. Choose the public bootstrap file. Independently compare the displayed manager
   ID, both origins and every full public trust fingerprint with the manager's
   trusted information. Review the four initially unchecked acknowledgements:
   complete read scope, limited service and automatic startup, persistent endpoint
   identity, and independent trust comparison. Back or a changed export clears
   the acknowledgements.
3. Read all five scope notices before choosing Install:
   - Bounded machine, process, service and software inventory, hostname,
     interface names/IP addresses and basic system metrics
   - Application/System event headers, without message text or event content
   - Caller-visible volume identifiers, types and capacity
   - Per-process CPU and working-set memory for bounded inventoried processes
   - Numeric TCP/UDP addresses, ports, TCP state and API-reported owning PIDs

   These reads can expose private names, software and network topology. They
   remain bounded and may be partial or unavailable. The choice does not grant
   configured service-startup metadata, event-message content, remote actions,
   Windows Update/CVE operations or external-AI export.
4. Choose **Install**. Before installation writes, Setup checks its package and
   the fresh-host boundary, then checks the exact selected manager's public
   `/v1/windows/setup-capabilities` route. An incompatible, mismatched or
   unreachable manager blocks installation. Do not weaken TLS or change transport
   to get past a failure.
5. Keep the dedicated local console open. It displays public trust and the fresh
   device fingerprint/comparison value. Enter the invitation only at its hidden
   prompt, never in arguments, environment variables, redirected input, a file,
   chat or logs. Separately compare and approve that exact device in the manager.
6. The service stays disabled while approval is pending. Setup verifies activation
   and all five exact identity-bound grants before changing the owned limited
   **LocalService** service to automatic startup and requesting Start. A final
   **service start requested** status is not a received report. Check the manager
   separately for the first accepted report and expected rows; it is not reboot
   proof either.

Setup creates protected application-only locations under the Windows KnownFolder
Program Files/ProgramData layout. It does not install as LocalSystem, grant debug
privileges, change global certificate trust or add inbound firewall exceptions.
It has no silent-install or secret command-line mode.

## Cancellation and partial state

Cancel or Close before Install leaves installation state untouched. After staging
begins, cancellation is cooperative: let the wizard release its console and
finish. Do not force termination. Forced shutdown cannot guarantee clean
cancellation, and one wizard session never retries an apply attempt.

A failed or interrupted install can leave files, a disabled service, protected
keys, pending enrollment or partial grants. A failure during the final startup
transition can leave startup **indeterminate**, and a Start failure can retain a
completed configuration. Preserve the state and displayed public diagnostic for
administrator review. Do not delete state, re-enroll or rerun to repair it.
The installed `tracebolt-windows-service.exe --inspect` provides a read-only SCM
snapshot; it does not repair anything. No general reset, repair, upgrade,
rollback or fresh-install resume flow is provided.

## Remove only the owned service

Run the same reviewed Setup and choose **Uninstall service**, then review its
separate confirmation. Removal requires a completed protected receipt and the
exact owned executable and SCM configuration. Setup requests Stop, observes
Stopped, requests Delete and waits for actual SCM absence. Delete-pending or a
timeout means removal is unconfirmed. Missing, incomplete, foreign or changed
state is not adopted or cleaned up.

Service removal retains executables, public bootstrap, package provenance and
all private identity, counters, grants and state. It does not revoke manager
trust, and retained state still blocks reinstallation. There is no Apps & Features
registration or full application/data uninstaller. Any later revocation or data
disposal needs its own explicit plan and approval; a disposable test VM must not
be reused as a fresh installation merely because its service was removed.
