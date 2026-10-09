# Native Windows setup UI candidate

`Run(Config, Hooks) error` uses fixed Win32 controls through `x/sys/windows`,
without WebView, browser navigation, downloads, third-party GUI packages, or a
second installation engine. The caller supplies the embedded service provenance,
complete five-scope disclosure and existing coordinator hooks.

The three pages choose a public bootstrap, review trust and scope, and display
operation status. The selected public file is bounded to 64 KiB; Windows permits
only regular local-drive files and rejects reparse traversal. Its validated bytes
are frozen in memory. Preview must reject private/unknown bootstrap fields. There
is no invitation control, file, command-line or environment entry route here.

All four acknowledgements begin unchecked: exact full read scope, service and
automatic-start authority, persistent device identity, and independent comparison
of manager ID, origins and every full public trust digest. Back clears them.
The separate hidden invitation console and later manager device approval remain
mandatory. No existing installation is adopted by this fresh-only wizard.

HTTPS remains the default, with no downgrade or fallback. A validated bootstrap
can explicitly select isolated HTTP-test. Both origins must then use HTTP; mixed
transport is rejected. The complete separate HTTP disclosure is mandatory and
an additional unchecked checkbox acknowledges plaintext invitation, five-scope
telemetry and forged manager-response risks. The install hook receives `true`
only after this additional approval; TLS always receives `false`. Back and new
input clear the HTTP acknowledgement too.

Only one operation can run in a UI session. Cancel before apply is inert. During
an operation, Cancel, Close and ordinary session shutdown request cancellation
but leave the wizard alive until the hook releases its console and returns.
Neither interruption nor failure permits retries, cleanup, reset or re-enrollment.
Abrupt process termination or forced OS shutdown is outside this UI guarantee;
the coordinator's durable retained-state contract remains authoritative.

Uninstall requires a separate Yes/No confirmation, with No selected by default.
It removes only the owned service and retains files, identity, grants and state;
it cannot revoke the manager identity. The hook must enforce this contract.

Progress may contain only fixed public text and finite diagnostic codes. The UI
does not display raw hook errors, bootstrap contents or invitation input. Its last
public status survives a failure. Run returns finite errors only. A successful
install says that service start was requested; first report and reboot remain
unverified.

The portable tests exercise consent, invalid/replaced inputs, Back, repeated
submit, separate uninstall confirmation, cancellation, stale completion and
retained-state outcomes without SCM, enrollment or native UI execution. Windows
cross-compilation and inert ABI layout tests do not establish native rendering,
keyboard navigation, DPI behavior, console handoff, installation or reboot
acceptance. Those require a separately approved disposable Windows gate.

Native automation contract: window class `TraceboltFreshSetupWizard`; button IDs
1 Next/Install, 2 Cancel/Close, 101 Back, 102 Choose file, 103 Uninstall, and
104/105/106/107 scope/service/identity/trust checkboxes. The HTTP-risk checkbox is
108 and exists only for explicit HTTP-test. Display IDs are
200 heading, 201 provenance, 202 note/status, 203 selected file, 204 review and
205 operation status. The standard public-file
dialog title is `Choose public bootstrap only (never the invitation)`. No hidden
test command, preapproved control, invitation argument or bypass is provided.

Win32 structure/reference sources:

- https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-wndclassexw
- https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-msg
- https://learn.microsoft.com/en-us/windows/win32/api/commdlg/ns-commdlg-openfilenamew
- https://github.com/microsoft/win32metadata/blob/main/generation/WinSDK/RecompiledIdlHeaders/um/commdlg.h

The SDK header, rather than the documentation's `_MAC`-inclusive rendering,
defines the 152-byte `OPENFILENAMEW` used on supported 64-bit Windows targets.
