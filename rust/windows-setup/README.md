# Experimental in-process Rust Windows Setup view

This is a **source-only, opt-in frontend** for the existing Go Windows Setup
coordinator. It is not the separate `rust/windows-agent` Basic agent/PowerShell
installer and does not expand that agent's four-metric collection. It does not
establish installer parity, a release, successful enrollment or native acceptance.
The default Go UI and the existing unsigned Setup builder remain unchanged.

## Implemented behavior

With the explicit `tracebolt_setup_rust` build tag **and a matched static Cgo
link**, `windowssetupui.Run` uses Rust Win32 controls in the same process. Go
still constructs its exact original Config/Hooks and owns its existing `flow`:

- Protected bounded local public-bootstrap selection and optional embedded/
  adjacent configuration; Rust never reads the bootstrap or invitation.
- Fresh 21-scope Read admin grouped/full review, public trust comparison, and
  separate initially unchecked scope, service, persistent identity and trust
  checkboxes. Explicit HTTP-test and same-key-renewal acknowledgements retain
  their original independent hooks. Back/reselection clears all consent.
- A single deliberate install attempt, using the unchanged hardened Go package,
  compatibility, provisioning, hidden console, enrollment/grant and service
  coordinator. No command, PowerShell, subprocess, IPC or dynamic-loader fallback.
- Independently confirmed, default-No service-only uninstall through the same
  original receipt-owned hook; files, identity, grants and state are retained.
- Public progress and finite outcome truth. Cancel/Close requests cooperative
  cancellation and waits for console cleanup; there is no retry/reset/recovery.
- Native keyboard controls, DPI-aware layout using the original Go geometry,
  original rounded 12-DIP/nine-point Segoe UI font, resize/minimize/maximize,
  minimum size and centered initial placement. Settings/display changes preserve
  the current rectangle and clamp it to the work area; DPI suggestions use their
  destination monitor. Unavailable layout disables new operations.

These are implemented source paths, not verified native behavior. The original
hidden-console secret input and public device-fingerprint/manager approval stay
entirely in the Go backend. Neither Windows service privileges nor the Rust Basic
service account/token model are changed or asserted equivalent.

## Ownership and ABI

`internal/windowssetupui/rust_bridge.h` defines one fixed scalar event structure
and a synchronous callback. Go locks the window OS thread and passes only an
integer `runtime/cgo.Handle`; it never passes a Go pointer to Rust. Rust owns a
512 KiB scratch buffer. The callback copies bounded JSON containing **public
control text/geometry/state only** into that buffer. Rust deserializes owned
strings before reuse. Raw bootstrap bytes, certificates, invitation input,
private keys, raw errors and endpoint telemetry are not ABI inputs or outputs.

All native state/events stay on the calling window thread. Reentrant modal/control
messages cannot acquire the already borrowed Rust `RefCell`, so they cannot
alias mutable state or submit another action. `WM_DESTROY` termination is handled
before that borrow; it must work even during synchronous `DestroyWindow`.
Display changes observed during a modal Go dialog are recorded outside that
borrow and current DPI/client/work-area geometry is reconciled before any
prepared operation can be acknowledged. Stale pre-dialog geometry cannot apply.
Native callbacks contain panics, and RAII removes window userdata before freeing
its state. No C/Rust callback runs from a Go worker.

Go owns the async hook, cancellation and latest-public-status slot. A prepared
operation cannot invoke a hook until Rust has successfully rendered the operation
page and established its polling timer. Repeated presentation/submission events
cannot repeat an attempt. On native return/failure, Go cancels and **joins** any
active hook before deleting the cgo handle. Geometry/render failure never bypasses
consent or silently hands work to another process/frontend.

## Build boundary and current evidence

The pinned Rust toolchain is 1.99.1; dependencies are locked. Portable checks:

```sh
cd rust/windows-setup
cargo fmt --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo clippy --locked --target x86_64-pc-windows-gnu --all-targets -- -D warnings
```

Go lifecycle tests are `go test -race ./internal/windowssetupui`, using the exact
Go version in `go.mod`. Tests cover unchecked/exact profile mappings, immutable
bootstrap snapshots, render-before-mutation, Back/reselection, duplicate submits,
separate uninstall confirmation, cancel/join and private-output exclusion. Rust
tests exercise the real bounded callback/copy and decoder, ABI layout and nested
mutable-borrow rejection. Portable layout regressions cover exact original font
rounding, maximize/resize style, initial centering, preservation, clamping,
negative monitor coordinates and DPI minimums. Actual consent-text wrapping and
Windows pixels remain unverified; these tests are not Win32 UI acceptance.

The source tag requires `windows`, `cgo`, a matching 64-bit Rust static archive
named `tracebolt_windows_setup`, and the matching Windows C compiler/linker. Its
archive location is an explicit build-time `CGO_LDFLAGS=-L…` input. The checked-in
builder deliberately does **not** select the tag or accept an unverified archive.
Selecting the tag with Cgo disabled fails closed; no Go/PS/IPC fallback is used.
Do not use a raw manually linked development EXE as an installation package.

In the editing Linux amd64 environment, portable Go/Rust checks, Windows-target
Rust Clippy, Go default amd64/arm64 test cross-compilation, the tagged no-Cgo
cross-compilation and Cgo export generation passed. A subsequently authorized
**workspace-only** toolchain extraction resolved the missing dlltool/compiler:
Debian Trixie's signed InRelease was verified against the existing Debian archive
keyring; the amd64 package index and all six official packages were SHA256-bound
to that metadata. `dpkg-deb -x` extracted binutils 2.44, GCC 14.2.0 POSIX and
MinGW-w64 12.0.0 into an isolated workspace, without running maintainer scripts or
changing host packages, alternatives, trust, security settings or services.

The real pinned-Rust Windows-GNU release staticlib and a Go 1.27.1 Cgo-linked
amd64 Setup development candidate then built successfully. Rust's
`--print native-static-libs` establishes kernel32/ntdll/userenv/ws2_32/dbghelp;
the Cgo declarations include those dependencies. Explicit build-time flags
`-static -static-libgcc -Wl,--no-insert-timestamp` select static GCC support and
avoid a timestamped link. The original PE checker validates Windows GUI,
requireAdministrator, unsigned resources and the exact original embedded service
payload/manifest. The inspected imports are Windows system DLLs, not additional
libgcc/libwinpthread/libstdc++/Go runtime DLLs. This proves a native link, **not
execution**. No Windows image, installer, service or UI was executed.

The existing builder still does not package this experimental frontend. Before
an installable opt-in candidate is enabled there, integrate the verified matched
Rust/Cgo link and complete source/archive/toolchain provenance into the original
package contract, retain repeat-build/resource/manifest/UAC/import checks, and
obtain independent review. Then separately authorize
fresh disposable Windows 11 / Server 2025 native UI/keyboard/DPI/modal/reentrancy,
hidden-console/fingerprint/consent/cancellation/install/removal tests with a real
matching Linux manager/browser and fresh advancing accepted reports. Provider
coverage, reboot behavior and Rust Basic collection parity remain separate gates.
No existing installation, retained VM110 state, privilege, trust, host setting,
download default or release is changed by this source slice.
