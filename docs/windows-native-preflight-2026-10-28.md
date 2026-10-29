# Windows 11 read-only preflight, 28 October 2026

This is **preflight evidence only**, not native Tracebolt installation,
enrollment, provider access, reboot, recovery or release acceptance. The human
signed in to the fresh disposable VM110 and separately authorized only console
reads of the Tracebolt service, fixed app paths and the two public image hashes.
No installer/service operation, key, grant, trust, firewall or permission change
was performed by these checks. Raw device identifiers, credentials and enrollment
state are not included.

## Native observations

The Windows **System → About** page confirmed Windows 11 Pro, version 26H2,
OS build **26300.9457**, x64 operating system/processor and 6 GB RAM. Device
identifiers were collapsed before recording the Windows version. Proxmox shows
the intended VM110 console, SATA boot disk and the separately prepared CD media.

In an ordinary, non-elevated Windows Command Prompt:

```text
sc.exe query traceboltwindowsagent
[SC] EnumQueryServicesStatus:OpenService FEHLER 1060
Der angegebene Dienst ist kein installierter Dienst.
```

Two finite `if exist` checks for `C:\Program Files\Tracebolt` and
`C:\ProgramData\Tracebolt` returned `programfiles_not_visible` and
`programdata_not_visible`. These are process-visible indicators, not proof that
an elevated protected-path/ACL preflight will succeed. Setup must repeat its own
strong fresh-host checks before writes. No existing path or state was removed.

Native `certutil.exe -hashfile <exact public file> sha256` succeeded for both
files on the attached `D:` medium:

| Exact public image | Native SHA-256 |
| --- | --- |
| `Tracebolt-v0.0.0-setup-candidate-windows-amd64-Setup.exe` | `97fc385e513363e50e1a4adc56bda55f0b5e6c5270c2c794dd2a8b8ca8f87f5e` |
| `tracebolt-v0.0.0-setup-candidate-windows-amd64-service.exe` | `2ab700f2f597e541277b7fc9efe8d4d80068cd72c1c29cf4bbd14206607e48cf` |

Both match the published unsigned
[preview.3](https://github.com/storminator89/Tracebolt/releases/tag/v0.1.0-windows-preview.3),
source `992b8d8c9d9693a97bd63301a3c147e1b2681357`. The public media's ten
release attachments were also checked before transfer against live GitHub sizes/
digests and the release manifest, then checked again on Proxmox. It contains no
invitation, bootstrap, credentials, autorun or unreleased recovery controller.
No executable was run by a hash calculation.

The first `sc` input was affected by the German guest keyboard's Y/Z mapping and
returned syntax help. The corrected displayed `query` line then produced the
1060 result above. Path separators and subsequent complete commands were checked
before interpreting output. Syntax help was never treated as an absence result.

## Non-installing GUI follow-up

The human opened the original reviewed Setup and handled elevation. Its first
page displayed the expected source, embedded service digest and 21-scope profile.
The public Setup was copied to the signed-in user's Downloads folder, where a
native SHA-256 check again matched the released Setup digest above. The CD-launched
wizard was canceled before Install. The human was asked to open that local copy;
an open wizard was subsequently observed at page 1, but its full process image
path was not independently read.

After the human created a fresh Windows invitation and downloaded its **public**
bootstrap, an exact public-field/trust check and the ordinary TLS capability GET
passed on WorkstationB. The public-only CD handoff contained the bootstrap,
checksums and a note, with no invitation secret, private key or executable. It was
mounted in the existing CD drive without changing the SATA disk or boot order.

Choosing the bootstrap directly from that CD produced the generic local-file
validation error. The existing `validPublicPath` admits fixed/removable local
drive types 3/2, not CD-ROM type 5; no check was weakened. Copying the same public
file with Explorer to Downloads and choosing it there was accepted by the native
wizard. The review page displayed the expected manager/origins and three full
trust fingerprints, 21 read scopes, four unchecked acknowledgements and a disabled
Install button. This proves native public-bootstrap parsing/review only. It does
not establish VM-to-manager connectivity: that HTTP compatibility check belongs
to the later Install path, which was not invoked.

The invitation's original ten-minute deadline elapsed during preparation. It was
not used for enrollment. The creation dialog was closed and its one-time secret
was no longer present in that dialog; the operator's separate secret availability
was not assumed or inspected. No persistent endpoint key, collection grant,
service installation, activation or first observation was established. Do not
select Install with that expired bootstrap. A subsequent fresh invitation needs
its own public bootstrap selection and deliberately renewed local confirmations.

The source clarification now names CD/DVD/network exclusions and the local-copy
step. The original released Setup and running manager were not replaced; this
wording change has no new packaged native acceptance evidence.

Follow-up checks on Windows x64 WorkstationB passed: `go test -buildvcs=false
./internal/windowssetupui ./cmd/windows-service`, `npx vitest run enrollment`
(8 files / 204 tests), and `npm run build` (the existing Vite large-chunk warning
remains). These are source tests/builds, separate from the released Setup's native
public-file selection above. No native Install, enrollment or provider gate ran.

## Later changed state: preserve the partial installation

The preceding GUI observations describe the earlier checkpoint, not VM110's
current state. After a several-hour observation gap, at about 15:48 local time,
the two separate Edge windows were confirmed. The guest instead showed page 3
with `package-failed`, service phase `enrollment`, reason `enrollment_failed`.
The human explicitly reported not having selected Install since the earlier
review page. The trigger and timing of the intervening transition are unresolved;
neither an actor nor a consent bypass is established by these observations.

Within the already authorized read-only console scope, the guest hostname still
matched the intended target. Native `sc.exe query TraceboltWindowsAgent` now
confirmed an existing own-process service, `STOPPED` (1), with Win32 exit 1077.
`sc.exe qc TraceboltWindowsAgent` reported `DISABLED` (4), LocalService and the
canonical configuration:

```text
"C:\Program Files\Tracebolt\tracebolt-windows-service.exe" "--run-service"
```

Both fixed Tracebolt roots were now visible to the ordinary console process.
`certutil.exe -hashfile` against that exact public executable returned Win32 2
(`ERROR_FILE_NOT_FOUND`), so no installed-image digest was obtained. A finite
`dir` query for that same executable also reported file not found. These ordinary
process-visible results do not establish privileged file absence or valid ACLs.
The package source protects its payload for SYSTEM/Administrators and LocalService,
without ordinary Users read access; that is a reason to check the token/context,
not proof that ACLs caused this particular Win32 error.

At released source `992b8d8`, `windowspackage.Code` uses `package-failed` as its
generic fallback. `setup.go` wraps failures from its enrollment coordinator with
`enrollment_failed`; the Read-admin replacement includes claim, activation,
grant setup and readbacks. The displayed labels therefore cannot distinguish
invitation input, expiration, transport, private identity or grant outcomes.
No raw receipts, enrollment state, keys or credentials were read to fill that gap.

VM110 is no longer a fresh-install target. Its disabled service and retained
roots must be preserved. No new invitation, retry, start, reinstall, deletion or
recovery operation followed these observations.

### Elevated public-image verification

The human subsequently opened an elevated PowerShell console. Within the
approved public-image read scope, `Get-Item -LiteralPath` and `Get-FileHash
-Algorithm SHA256 -LiteralPath` against the exact installed service path above
succeeded. The file exists, is **15,418,368 bytes** and has SHA-256
`2ab700f2f597e541277b7fc9efe8d4d80068cd72c1c29cf4bbd14206607e48cf`,
matching the published preview.3 service. Its reported LastWriteTime is not
installation-time evidence. The earlier ordinary-console errors did not prove
that the executable was absent; their precise cause remains unresolved. No ACL
inspection/change, installed-image execution or protected state read was needed
for these two checks.

After the human changed the VM bridge to `vmbr1`, the console's existing network
output confirmed the newly supplied IPv4 address. A TCP connection to its RDP
port from WorkstationB succeeded; no RDP authentication was attempted. This is
neither manager/agent connectivity nor enrollment evidence. QEMU guest-agent
access remains unavailable. The checks made no guest network/firewall changes.

A separate diagnostic executable was then built locally from clean source
`4985b433f6cf77476d497fe07f9d5741614cdbe6` using Go 1.27.1, Windows/amd64,
`-buildvcs=false -trimpath`. Its SHA-256 is
`1843e673e310213cc9be8a6bcd00c032023a6b0eafbf98b50e82eff584e3ce21`
and its size is 21,593,600 bytes. This is an unreleased source build, not a
replacement for the installed preview. The intended sole invocation is
`tracebolt-diagnostic.exe --read-admin-recovery-status`; the executable also
contains general service CLI modes, which are outside the proposed test.
`go test -buildvcs=false ./cmd/windows-service -run
'^TestReadAdminRecoveryStatus' -count=1` passed on WorkstationB. At that build
checkpoint no candidate transfer, guest-media change or native diagnostic
execution had occurred.

The [bounded read-only status command](windows-read-admin-recovery-status.md)
would inspect the two protected installer metadata files and the staged service.
The human subsequently approved transfer, guest hash verification and exactly
that status invocation. All three allowlisted files (EXE, public build manifest,
instructions) were transferred to a new isolated Proxmox staging directory and
their hashes rechecked before ISO creation. The 21,968,896-byte ISO has SHA-256
`b4b2a7b14796622aeb2a4962c24068a21870665ffffb8c461f38081066eaa2bb`.
After SSH became unavailable, the live Proxmox Hardware view confirmed that the
old medium remained attached. The approved media switch was then completed
through the existing authenticated browser session: `ide2` shows
`Tracebolt-VM110-Readonly-4985b43-20261028.iso`, size 21454K, with a successful
Configure task. No disk, boot order, network or protection setting was changed.

A Windows Update dialog then blocked the existing elevated PowerShell console,
announcing a scheduled 18:15 restart. Escape did not dismiss it. The human was
asked to decide that OS dialog; no restart/update choice was made by the test.
At that checkpoint guest hash verification and diagnostic execution were not
run. The human later confirmed that the OS dialog was handled and the elevated
PowerShell was visible; no OS restart outcome is inferred from that confirmation.

### Approved native read-only diagnostic: PASS

At approximately 18:59 local time, native `Get-FileHash -Algorithm SHA256
-LiteralPath "D:\tracebolt-diagnostic.exe"` matched the diagnostic digest above.
The single approved invocation then completed:

```powershell
& "D:\tracebolt-diagnostic.exe" --read-admin-recovery-status
```

It returned the bounded schema `tracebolt.windows-read-admin-recovery-status.v1`,
phase `claim-started`, evidence `protected-file-snapshot-not-manifest-verified`,
service `process-visible-owned-stopped-disabled` and recovery
`no-resume-authority`. A subsequent `Write-Output $LASTEXITCODE` returned **0**.
This is a native Windows success for this exact source build's bounded protected
file/SCM inspection on this staged preview.3 installation, not a fixture result.

The local receipt reached the marker written before the enrollment hook; it does
not prove invitation entry, manager claim acknowledgement, activation, grants or
the cause of the earlier enrollment error. The status command does not open the
installer manifest or private enrollment ledger. It provides no rollback proof
or authority to recover, re-enroll, reset or start the service. It also does not
resolve the actor/timing of the earlier unexpected GUI transition.

The ISO remains attached. No installed executable was replaced, no additional
CLI mode was run and no service, scope, identity or security change was requested
by the diagnostic. Its native failure/rejection cases and packaged release
acceptance remain separate outstanding gates.

Even a successful status result would provide no continuation authority,
private identity/grant verification, provider acceptance or installation success.

## Manager and browser boundaries

The existing real manager uses image tag `tracebolt-manager:9327060`, running
image ID `sha256:fbf48299a4611e820bc026baef04099529b12518bba5c18adb1aba4c665110a4`.
The tag alone is not independent source/build attestation. No manager was
upgraded, downgraded or restarted. From **WorkstationB**, the actual client
`CheckWindowsSetupManager` passed the exact public v10 21-scope contract using
the already approved private CA and ordinary TLS/name verification. No invitation
was sent. That public GET does not test VM110 connectivity, agent ingress or
enrollment. Existing expired invitation material was not reused for enrollment.

The [dashboard preparation audit](windows-installation-audit.md) additionally
records actual in-app-browser EN/DE layout and local file-chooser/WebCrypto
success/rejection on compiled source `410a767`. Those empty UI fixtures create
no real device or invitation. They do not establish native Setup or provider
acceptance and are not deployed to the existing manager.

## Remaining gate

The earlier public-bootstrap review passed, but the later partial state above
blocks the planned fresh attempt on VM110. A new invitation alone is insufficient.
Retain all partial state. The elevated public-image check has now resolved file
existence and digest; the approved bounded native status now reports
`claim-started` with exit zero. No reset or continuation authority follows from
these checks. The expired public invitation must not be reused; a phase label
cannot establish the stronger continuation candidate's committed claim or
original pending deadline.

Fresh native acceptance still needs an actually fresh inspected target, unexpired
public bootstrap, independent manager/trust comparison and initially unchecked
local 21-scope/service/identity approvals. Hidden invitation entry and dashboard
device comparison remain human steps. No successful native installation, activated
identity or first authenticated observation has been established; the later
private identity/grant state remains unknown.

A later successful integration would establish only the actual reviewed client/
manager pair. It cannot be relabelled as acceptance of the release guide's exact
manager source, newer main binaries, all providers, renewal cutover or reboot.
