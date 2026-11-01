# Rust Setup native GUI acceptance: inert source harness

**Current evidence: source/portable tests and cross-link only. No Windows run.**
This harness is the next bounded acceptance step for the opt-in frontend in
[`rust/windows-setup`](../../rust/windows-setup/README.md). It is not an installer,
an enrollment workaround, a release or proof of Rust-agent feature parity.
No workflow/pipeline is added or changed. Native execution requires separate
coordination on a selected Windows machine; nothing here authorizes host grants.

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
manual driver rejects CI, non-Windows, dirty/mismatched source and an unpinned
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
