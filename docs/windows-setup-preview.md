# Windows Setup.exe fresh-host preview

This source builds a real self-contained native Windows Setup.exe wizard. It is
an **unsigned, unreleased fresh-host preview**, not general production installation,
repair, upgrade, reboot or desktop-OS acceptance. Native acceptance must launch
and drive the exact GUI executable; coordinator fixtures are not a substitute.
See [build and provenance](windows-setup-release.md) for final artifact generation.
The existing public Linux rc.3 download pin is unchanged and is not a Windows
installer or compatible-manager guarantee.

For the dated native results and current release blockers, read
[Windows status and limitations](windows-status.md). Some x64 setup/telemetry
phases have passed; final service removal and complete acceptance remain open.

## What a human does

1. Obtain the separately reviewed Setup.exe and its exact source/hash manifest
   from the authorized distributor. No executable is downloaded at runtime. The
   embedded service image is versioned and SHA-256 checked before any installation
   writes. A hash alone does not establish the publisher; this build is not signed.
   Do not bypass a Windows security warning to make an acceptance test pass.
2. On a compatible manager, select Windows and create a fresh Windows inventory
   invitation. Choose **Download bootstrap file**. This is the existing public
   JSON export with exact manager/agent origins, public CA/issuer certificates and
   invitation ID. It contains no invitation secret or private key. Do not author
   configuration manually, build endpoint binaries, or put the secret in a file.
3. Launch Setup, accept the Windows administrator prompt deliberately, and select
   that public export. Check the displayed manager origins and complete trust
   fingerprints independently. Review all five full collection notices, the
   limited LocalService service/automatic-start changes, persistent identity, and
   trust acknowledgements. Every checkbox begins unchecked. Back or a changed
   export clears acknowledgement. No silent-install or secret command-line mode
   exists.
4. HTTPS is the default. The existing `http-test` profile is available only for a
   deliberately selected matching export with a **separate unchecked acknowledgement**
   covering every plaintext warning. Invitations and read metadata are exposed,
   manager responses can be forged, and the manager is not authenticated. There
   is no HTTPS-error fallback. Production must use HTTPS.
5. Install checks the package and fresh-host boundary, then makes one bounded,
   exact-origin request to `/v1/windows/setup-capabilities`. Old, mismatched or
   unreachable managers fail before any file/service/key/grant changes. No
   credential or invitation is sent by this public compatibility check.
6. A dedicated local console displays manager trust, the fresh device fingerprint
   and comparison value. Enter the invitation only at its hidden prompt. Keep
   the console open. Approve the matching public identity separately in the
   manager. The staged service remains disabled while approval is pending.
7. The existing hardened coordinator verifies activation and all five exact
   identity-bound grants before changing only the owned service to automatic
   startup and requesting Start. Setup reports **start requested**. Check the
   manager separately for the first accepted report. Start is not reporting or
   reboot proof.

The wizard fits the current monitor work area and can be resized. It scales its
font and controls together when DPI changes; long public review/progress text
scrolls while consent and navigation keep their own space. If the available
area cannot contain the minimum 600 × 440 logical-pixel client plus the Windows
frame, Setup refuses to begin. If a later display change makes layout unusable,
a running operation is cooperatively cancelled and retains the same partial-state
boundaries described below. Geometry and on-screen control-bound tests do not
establish visual readability, human UAC or desktop-specific acceptance.

The five scopes are bounded Windows inventory, Application/System event headers,
caller-visible volumes, per-process CPU/working-set, and numeric TCP/UDP endpoint
metadata. Configured service-startup metadata, event-message content, remote
commands/actions, Windows Update/CVE and external AI are not granted.

## Compatible manager requirement

Use the manager and frontend built from the **same reviewed source revision as
Setup**, with the existing guided Windows enrollment authority enabled. The old
published Linux rc.3 endpoint release does not supply this new compatibility
route. A source commit identifies bytes, not a reviewed or deployed manager.

For an existing Linux/Docker manager, an authorized administrator must follow
[installation runbook, update and backup](installation.md#10-stop-back-up-restore-update-uninstall):
keep a consistent stopped state backup and the exact old image, preserve protected
configuration/issuer custody and existing volume, review migration compatibility,
build the manager image from the selected Setup revision, and replace only the
known manager container using the existing Compose file and approved origins.
For example, in that reviewed source checkout and using the existing approved
configuration, `docker compose -f deploy/compose.yaml build manager` builds the
TLS template; `docker compose -f deploy/compose.yaml up --no-build -d manager`
replaces that configured service. These are administrator maintenance steps,
not authorization to execute, change network exposure or copy a different
Compose profile. The user's existing HTTP pilot must use its reviewed existing
HTTP Compose/configuration instead. Never delete volumes or create another empty
manager to bypass old state. Native-manager users replace the reviewed binary and
matching web assets while preserving protected configuration/state under the same
stopped-backup procedure. Verify Windows invitation creation and obtain a fresh
public export after the update. The wizard diagnoses compatibility; it does not
upgrade a manager remotely.

## Cancellation, retained state, and service removal

Cancel or Close before Install leaves installation state untouched. Once staging
begins, Cancel requests cooperative interruption and the wizard stays alive until
its operation releases console/handle ownership. Repeated clicks cannot start a
second operation. After any apply attempt, the same wizard session cannot retry.

Any post-staging failure can retain app files, a disabled service, protected
identity, pending enrollment or partial grants. Failure during the final startup
transition can leave automatic startup indeterminate; never infer disabled state
from a generic error. A completed setup followed by Start failure retains its
completed identity/configuration. There is **no public general repair/reset or
fresh-install resume flow**. Preserve state for administrator inspection; reruns
are deliberately blocked. The installed `tracebolt-windows-service.exe --inspect`
is a read-only SCM snapshot, not repair or permission to reset. Keep only the
finite public diagnostic code for support, never invitation or private state.
Unexpected process termination cannot guarantee a clean cancellation.

Run the same reviewed Setup and choose **Uninstall service** to separately approve
service removal. It requires the completed protected receipt and exact executable,
SCM configuration and ownership. It requests Stop once, observes Stopped, requests
Delete once, and observes actual SCM absence. Deletion pending/timeout is reported
as unconfirmed removal. Incomplete, missing, foreign or changed receipts fail
closed. No automatic adoption or destructive cleanup occurs.

Executable, public bootstrap, package provenance and **all identity/state/counters/
grants remain**; manager trust is not revoked. Reinstallation remains blocked.
This is service removal, not complete package/data deletion. No Apps & Features
registration, automatic updater, repair, rollback or generic cleanup is promised.

## Evidence required before broader distribution

Portable/injected tests and amd64/arm64 cross-builds prove source/build properties
only. Separate explicit native approval must bind exact source, final Setup and
embedded service hashes, disposable machine/run, service/filesystem/identity/read
scopes, synthetic memory-only invite, manager comparison, local fixture transport,
Stop/Delete and VM disposal. Actual GUI/hidden-console cancellation, pending-disabled
state, all-grant verification, first accepted reports, duplicate installation
rejection and service-removal outcomes must be observed on the exact executable.
Windows desktop/UAC/SmartScreen, real Linux manager/dashboard, reboot, ARM64 runtime,
recovery and released-download/signature provenance remain distinct gates.

The source-only native gate is
[Manual disposable packaged Windows Setup GUI acceptance](../.github/workflows/windows-setup-acceptance.yml),
using [the bounded actual-EXE runner](../tests/windows_native_acceptance/run_setup_gui.py).
It has no automatic event, all native permissions default false, and it binds a
reviewed source SHA, resulting Setup/payload digests, first run attempt and fresh
hosted Windows x64 machine. Its four isolated cases are TLS lifecycle/service
removal, cancellation at hidden input, cancellation at pending manager approval,
and separately approved HTTP-test lifecycle with the extra plaintext checkbox.
Do not reuse an older coordinator-only approval, execute it from ordinary CI, or
claim GUI success when the hosted desktop/UAC session is unavailable. Source
publication and artifact compilation do not authorize dispatch.

The final gate preserves only the successful TLS case's six allowlisted public
package files, including the exact Setup and service bytes actually exercised.
A separate read-only aggregation job requires all four cases to pass in that
same run on distinct assigned machines, with identical source, Setup, service, driver
and source-input digests. It revalidates the public package and copies those
bytes without rebuilding them. Only the resulting
`windows-setup-native-subset-public-SOURCE` artifact plus its separate finite
linkage evidence may support a later approved x64 preview download. Local
snapshot builds, Linux cross-build artifacts, or another build of the same
commit are not interchangeable with that tested file. The build manifest remains
unchanged build-time evidence; the separate native-subset record describes the
later four-case result. This establishes only the recorded Windows Server 2025
fixture subset, not general desktop, UAC, reboot, upgrade or ARM64 acceptance.
