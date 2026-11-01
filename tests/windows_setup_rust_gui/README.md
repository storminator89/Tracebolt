# Rust Setup native GUI acceptance: inert source harness

**Current evidence: source/portable tests and cross-link only. No Windows run.**
This harness is the next bounded acceptance step for the opt-in frontend in
[`rust/windows-setup`](../../rust/windows-setup/README.md). It is not an installer,
an enrollment workaround, a release or proof of Rust-agent feature parity.
The separately authorized PR201-only CI draft below adds **one inert TLS GUI
test** to the existing Setup build workflow. It has not been run on Windows.
Other native execution still requires separate coordination on a selected
Windows machine; nothing here authorizes host grants.

## Two different gates

### A. Native view + actual Go consent flow, inert hooks

The specially tagged `TestRustNativeGUIFixture` runs the real statically linked
Rust Win32 frontend, its real Cgo ABI and the existing Go `flow`. Every install/
uninstall hook is replaced **only in this test binary** with bounded memory-only
recording. It cannot invoke SCM, provisioning, enrollment, crypto, a manager,
network, a helper or a real hidden-input console. The embedded bootstrap and
fingerprints are invented; the preview accepts only those exact invented bytes.
The displayed version explicitly says `INERT_GUI_FIXTURE_NO_HOST_ACTION`.

There is no production flag, test environment switch or alternate coordinator
in the released/setup entry. Both extra build tags and an explicit runtime
fixture acknowledgement are required; ordinary tests/imports are inert. The
manual driver still rejects CI, non-Windows, dirty/mismatched source and an unpinned
image. It requires Python isolated/no-bytecode mode and loads its fixed helper
source directly, never a cached repository `.pyc`.

The driver acts only on its own retained `Popen` child's fixed Rust window class,
PID, owner/child relationship, class and control ID. It rechecks identity before
actions. It uses timeout-bounded messages, queued modal clicks and asynchronous
own-window positioning. There is **no global keyboard/mouse input, clipboard,
desktop/DPI/resolution change, screenshot, UAC, privilege or security-setting
change**. A temporary per-thread DPI coordinate context is restored on exit.
It reads only its own fixture's text/font/rectangles; other windows' text is not
read. Raw text, exceptions, paths, child output and screenshots are not exported.
GDI objects are process-private: `WM_GETFONT`/`GetObjectW` inspection therefore
runs inside the test child, never in the Python parent. A private test-only stdin
pipe accepts at most 16 exact `FONT_CHECK` tokens and returns ordinal/Boolean
acknowledgements only. It accepts no secrets, shell commands, hook invocation or
installer input. The driver closes its retained write end before waiting; the
child's probe-reader join is bounded and mandatory. This is test instrumentation,
not a production frontend IPC route or invitation channel.

Only an existing single-linked EXE on a fixed local disk is accepted. Read-only
`OPEN_EXISTING` ancestor/image handles reject reparse objects and remain held
while the SHA256-pinned child runs. There is no create/write/delete/ACL fallback.
These defensive leases are **not adversarial executable-binding acceptance**;
use an operator-provisioned trusted private test directory in the disposable VM,
with no concurrent untrusted writers. Native handle/race behavior still needs
verification; this is not the installer path/ACL hardening work.

Each run has a 60-second UI budget; message calls, child waits, bounded 64-KiB
output drains and cleanup have separate finite limits. Fixed-local-disk image
reads have a 128-MiB byte limit, not a guarantee against a hung kernel/device.
On failure, only this inert fixture child's retained process handle may be
terminated. Uncertain cleanup is `not_accepted`, never success. If an OS operation
itself stalls, stop the disposable VM through its separately authorized operator
watchdog; do not adapt this termination logic to a real installation coordinator.

| Case | Native controls/flow observed if actually run |
| --- | --- |
| `close-input` | Visible synthetic provenance, zero hook admissions, safe Close |
| `tls` | Four unchecked boxes, Back clearing, disabled Install until exact consent, single submit |
| `http` | Separate unchecked plaintext-risk acknowledgement and exact ordinary hook |
| `renewal` | Separate unchecked same-key acknowledgement and exact renewable hook |
| `failure` | Finite failure rendering; invented private error never rendered |
| `cancel` | Close requests cancellation; window remains while fake cleanup is owned |
| `uninstall` | Independent default-No modal; No is inert; Yes admits one fake removal |
| `modal-resize` | Resize while the modal holds the native borrow; current layout before fake admission |

The driver also checks the actual 12-DIP Segoe UI font descriptor, client/control
bounds, minimize/maximize style, own-window maximize/restore and unchanged
placement after own-window settings/display messages. It does **not** change the
real desktop to synthesize DPI. Font descriptors/bounds are not proof that every
themed glyph is visible: native pixels, complete consent wrapping, real keyboard
navigation, the chooser, mixed-DPI monitors, real bootstrap validation, secret
console, UAC, services, enrollment, manager/browser, telemetry, reboot and full
parity are always explicitly **false** in this subset report.

The previously considered 40×40 `layout-cancel` native case is deliberately **not
offered**: normal `WM_WINDOWPOSCHANGING`/minimum-tracking behavior may clamp it,
so requesting that size would not prove the unavailable-layout path. That path
remains portable-source coverage only. No production constraint, display setting
or window procedure is bypassed to manufacture a native pass.

### Separately authorized PR201-only CI source draft (not executed)

The `rust-gui-tls` job in `windows-setup-build.yml` is restricted to this
repository's **pull request 201** and `pull_request` events. It does not run on
push, another PR, dispatch, `pull_request_target` or a reusable workflow. The
existing build job remains unchanged. Contents-read permissions and pinned
checkout/Go/Python actions remain; no secrets, signing, release, service or
identity permission is added. No EXE or raw window/child output is uploaded.

`build_ci.py` and `run_ci.py` require a distinct explicit inert-CI acknowledgement,
the exact repository/workflow path/job/ref, a GitHub-hosted Windows X64 runner
and matching GitHub source context. CI variables stay present in the child.
These are configuration guards, **not cryptographic authentication**; the
reviewed PR-only workflow and exact immutable checkout are the authority.
The original `run.py` and `TestRustNativeGUIFixture` retain their CI refusal.
The separate `TestRustNativeGUITLSCI` exists only with the additional
`tracebolt_setup_gui_ci_fixture` test-build tag; no production entry selects it.
TLS is hard-coded; there is no CI case or arbitrary test/command selector.

Source means the synthetic PR merge commit (`github.sha`), not the PR head.
Depth-two checkout, exact HEAD and its ordered base/head parents, clean source,
tracked compilation/driver input hashes and unchanged source after the run are
required. The job uses the runner image's existing MinGW compiler only after
checking its x64 GNU target. Official pinned Rust 1.99.1 plus its GNU target,
Cargo/Go caches and all build outputs are isolated under `RUNNER_TEMP`; no host
package installer, shell-profile/global-toolchain change or security setting is
used. Missing tools or unavailable official downloads fail; no mirror, compiler
fallback or policy bypass is provided.

The official runner's [toolset](https://raw.githubusercontent.com/actions/runner-images/main/images/windows/toolsets/toolset-2025.json)
and [MinGW installer](https://raw.githubusercontent.com/actions/runner-images/main/images/windows/scripts/build/Install-Mingw64.ps1)
select GCC15/UCRT, unlike the local GCC14/MSVCRT cross-build. The finite DLL
allowlist therefore includes only the specifically evidenced additional Windows
OS component `ucrtbase.dll` ([MinGW import definition](https://raw.githubusercontent.com/mingw-w64/mingw-w64/master/mingw-w64-crt/lib-common/ucrtbase.def.in),
[Microsoft UCRT deployment](https://learn.microsoft.com/en-us/cpp/windows/universal-crt-deployment?view=msvc-170)).
It does not accept wildcard API sets or libgcc/libwinpthread/libstdc++ runtimes.
The target triplet and local link do not prove the hosted CRT/import set or
runtime compatibility; the first native CI build/run still has to establish that.

Before one launch, the builder requires locked dependencies, exact Go 1.27.1,
repeat Rust archives and test EXEs, actual AMD64/console/zero-timestamp/unsigned
PE headers, a strict system-DLL-only import list, exact three Go test tags,
Windows/Cgo target and exact project dependency roots. A closed manifest binds
source/tree/input, tool-binary/archive/image hashes and repeat-build equality.
The driver independently rechecks source, manifest, image bytes, PE, tool hash
and actual Go build-info before the original held-file image leases and PID/
control/consent/cleanup guards admit the child.

Go `-trimpath` intentionally suppresses recorded linker flags; build-info does
**not** prove source binding. The reviewed build recipe injects the exact source
into this test-only image; the driver checks its presence, and the child then
independently checks/acknowledges that compiled value against its CI context.
The extra tag changes the EXE: no old manual-fixture digest is accepted by fiat.

This job runs exactly the existing **TLS** unchecked-consent/Back/single-attempt
memory-hook case. No TLS connection, invitation, persistent key, service, SCM,
provider read or installer operation exists in that fixture. The interactive
desktop check remains mandatory: unavailable desktop is `not_accepted` and job
failure, never a skip/pass. There is no auto-login, session/desktop switch,
global input, resolution/DPI change or UAC/protection relaxation. Only the own
inert child can be terminated, under the original bounded cleanup contract.
One successful future run would prove only that TLS inert-control subset on
that hosted image. Every original false coverage field, including real Setup,
hidden console, pixel visibility, enrollment and full Rust-agent parity, stays
false. Native CI execution and this workflow draft remain unverified here.

The first published CI attempt reached `not_built / provenance`; its GUI step
was skipped. That is **not** a native GUI pass and does not identify the failing
subcheck. A diagnostic-only follow-up keeps every guard and adds fixed `phase`
and `check` labels to failure reports, including failures during tool discovery.
Labels distinguish tool/version checks, Rust/EXE repeat equality, PE structure
and import allowlisting, Go build-info, dependencies and source rechecks. They
never include DLL names, commands, paths, exceptions, output bytes or other raw
values. Success manifests/acceptance rules are unchanged; no guard is loosened
and no failed native attempt is relabelled as accepted.

The next finite report localized the first rejected import to the PE allowlist;
the actual name remains private/unknown. Local GCC14 evidence has nine allowed
system imports, while official MinGW13's [CRT configuration](https://raw.githubusercontent.com/mingw-w64/mingw-w64/v13.0.0/mingw-w64-crt/configure.ac)
and [library recipe](https://raw.githubusercontent.com/mingw-w64/mingw-w64/v13.0.0/mingw-w64-crt/Makefile.am)
build the UCRT import library from fifteen fixed API-set contract families,
separately from the direct UCRT-base import library. The existing Cgo recipe
also explicitly names two system link libraries not in this test's allowlist.
Neither fact proves which import failed, nor that it may safely be admitted.

The follow-up reports only one of five fixed rejection categories: a public
source-defined CRT contract, an already-declared system link, a conventional
compiler-runtime name, API-set-shaped text, or other. Shape/category is not OS
availability or trusted-module proof. All unlisted imports still fail the exact
same membership guard, including every categorized CRT/API-set/runtime import.
Only the first rejection is classified; no DLL name, substring, path, hash or
multi-import fingerprint is exported. No allowlist, linker recipe or runtime
guard changes follow from this diagnostic.

The subsequent first-rejection category was `known-crt-contract`; the GUI step
still did not execute. A separate **read-only evidence producer** now runs only
after that exact original rejection on the Windows 2025 job. It never admits an
import or resumes building/running the fixture. It uses the existing GCC bin
folder's GNU `objdump.exe -p` to independently inspect the same hash-bound own
image while retaining the original reviewed read-only ancestor/file leases for
the image, tool and compiler. The private tool output has an 8 MiB bound per
stream, a 20-second execution limit, own-child-only cleanup, no shell, and no raw
output export. Source, image and tool bindings are rechecked; failed cleanup,
source/hash/lease/tool/query uncertainty, malformed output, or any import outside
the original eleven plus this fixed catalogue discards **both** vectors.

The only new import information is a fixed fifteen-Boolean `requiredCRT` vector,
in this public order: **conio, convert, environment, filesystem, heap, locale,
math, multibyte, private, process, runtime, stdio, string, time, utility**. Each
entry denotes exactly `api-ms-win-crt-<family>-l1-1-0.dll`; no other name, prefix,
version, hash of a rejected name, or arbitrary multi-import fingerprint is
exported. The independent producer recognizes these names **for evidence only**;
the original PE parser/eleven-DLL membership guard stays byte-identical and
continues to reject every one of them.

The second fifteen-Boolean `schemaPresent` vector queries those same constant
contract stems **without `.dll`**, using Microsoft's documented
[`IsApiSetImplemented`](https://learn.microsoft.com/en-us/windows/win32/api/apiquery2/nf-apiquery2-isapisetimplemented).
Bindings are exclusively fixed `kernel32.dll` (read-only file APIs) and
`api-ms-win-core-apiquery-l2-1-0.dll` (the documented system query API), with
[`LOAD_LIBRARY_SEARCH_SYSTEM32`](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryexw).
No candidate/import-derived library is loaded, no candidate/test EXE is started,
no guessed KernelBase export or fallback is used, and no host setting changes.
The query means only **availability in the running composed API-set schema**,
not a physical file, particular export, trusted-module proof or successful future
call. False results remain false; unsupported binding is unavailable, never a
positive default. `ImageOS=win25` is an additional expected job marker, not OS
attestation. Positive observations carry the already-approved source/image
hash bindings; unavailable observations contain no partial vectors.

This evidence producer has portable fake/negative coverage only. Actual hosted
fifteen-contract observations, the GUI run, installer acceptance and full Rust
agent parity remain outstanding. The outer result remains `not_built`,
`nativeExecution=false`, `installerHostActionsAttempted=false`; no `build.json`
or GUI execution follows from diagnostic success. Any eventual admission change
requires separate concrete evidence and review, not this diagnostic.

Runner/tool/context references: [official Windows 2025 image inventory](https://github.com/actions/runner-images/blob/main/images/windows/Windows2025-Readme.md),
[GitHub default-variable semantics](https://docs.github.com/en/actions/reference/workflows-and-actions/variables),
and the pinned Go source's `cmd/go/internal/load/pkg.go` build-info handling
([Go issue 52372](https://go.dev/issue/52372)).

### B. Actual packaged Setup and matching manager

After A is observed, a separate approved fresh disposable Windows 11 and Server
2025 plan must run the real packaged frontend/coordinator with matching Linux
manager/browser. It needs human scope/service/persistent-identity/trust approval,
UAC, hidden local invitation entry and independent device-fingerprint/manager
approval. Check all 21 exact scopes/receipts, disabled staging until approval,
fresh advancing accepted reports and actual provider coverage, repeated/Back/
cancel/modal/DPI/keyboard/secret visibility, and receipt-owned removal/retention.
Service/identity/trust/ACL changes require their own explicit host authorization.
Use no existing/retained endpoint, reset, migration or privilege weakening.

A fixture pass cannot promote a profile or establish B. The Go coordinator and
Go service payload remain; replacing the separate four-metric Rust Basic agent
with all Go Read admin capabilities is still separate implementation work.

## Build without running Windows

Use the exact Go/Rust versions and locked dependencies, plus the independently
verified matching Windows-GNU C toolchain already provisioned in the build
workspace. Do not install/change host tools or a workflow to run this harness.
Build the existing Rust staticlib first; then set `GOOS=windows`, `GOARCH=amd64`,
`CGO_ENABLED=1`, the matching `CC`, and build-time `CGO_LDFLAGS` containing the
archive directory and the reviewed static/timestamp flags:

```sh
go test -c -trimpath -buildvcs=false -mod=readonly \
  -ldflags='-buildid= -s -w -linkmode=external' \
  -tags=tracebolt_setup_rust,tracebolt_setup_gui_fixture \
  -o /approved-build-output/windowssetupui-inert-gui.test.exe ./internal/windowssetupui
go vet -tags=tracebolt_setup_rust,tracebolt_setup_gui_fixture ./internal/windowssetupui
```

This links a **test EXE**, not Setup or an installable package. Bind its hash to
the exact clean source/toolchain/archive inputs and independently review it.
No EXE execution follows from a successful build.

Portable checks (Linux is sufficient):

```sh
python3 -B -m unittest discover -s tests/windows_setup_rust_gui
go test -race ./internal/windowssetupui
```

## Exact Windows execution needs (not performed here)

1. Explicitly select/approve a disposable x64 Windows 11 or Server 2025 VM and
   its interactive unlocked user desktop. Use an ordinary account; no real
   endpoint installation, credentials, manager access, admin grant or private
   desktop work is needed. Use existing display/DPI settings only.
2. Provision matching clean source, Git, x64 Python 3.12+ and the reviewed test
   EXE in a trusted short private local directory (for example an independently
   provisioned `C:\fixture`). The driver does not create/protect that directory,
   change ACLs or install a tool. Independently pin the build's EXE SHA256 and
   source commit. Do not substitute a production EXE or arbitrary downloaded file.
   Stop at OS/org execution protection; do not disable it or weaken policy.
3. Keep CI environment markers absent. Run **one** reviewed case at a time:

```powershell
python -I -B .\tests\windows_setup_rust_gui\run.py `
  --execute-gui-fixture --case tls --source <reviewed-full-commit> `
  --image C:\fixture\windowssetupui-inert-gui.test.exe --sha256 <reviewed-sha256>
```

4. Require `passed_inert_gui_subset`, its exact case/hash/checkout and the strict
   single-hook test result. Preserve finite failure stages, not raw buffers or
   screenshots. Repeat each case independently. A skipped/missing test report,
   absent control, timeout, wrong PID, wrong image, raw error or cleanup uncertainty
   is not a pass. Review the false coverage fields before quoting any result.
5. Separately review actual full consent text at supported minimum dimensions,
   keyboard/focus/close behavior and existing mixed-DPI monitors if available;
   no API-set global DPI or fabricated DPI message counts as native coverage.
   Then obtain the approvals for B. Do not call this source harness a completed
   installation or close the installer/agent parity work from portable tests.

API sources: Microsoft's [CreateFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew),
[SendMessageTimeoutW](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-sendmessagetimeoutw),
[SetWindowPos](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setwindowpos)
and [SetThreadDpiAwarenessContext](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setthreaddpiawarenesscontext).
