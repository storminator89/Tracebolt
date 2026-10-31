# Windows Setup: frontend-neutral in-process adapter

This source refactor is a production prerequisite for replacing the Windows
installer frontend, not a Rust installer, an enrollment fix or native acceptance.
The packaged Go Setup still calls the same `windowssetupui.Run`. No download,
release pin, installer command, IPC, privilege, host grant or stored state changes.

## Implemented boundary

`cmd/windows-service/setup_frontend.go` assembles the existing public
`windowssetupui.Config` and four installation hooks plus preview/removal. The
Windows entry supplies only the existing backend functions. Construction validates
and snapshots bounded public package/bootstrap bytes but invokes no backend,
network, console, service, key or state operation. Each installation hook snapshots
its bounded public input before progress callbacks and retains the existing
`setupWizardInstall` coordinator and finite failure reporting.

The mappings remain exact:

- Basic and Read admin hooks preserve their existing distinct five/21-scope
  choices; the fresh Read admin hook reconstructs consent v14 and receipt12.
- Ordinary hooks accept an HTTP acknowledgement only for an explicitly selected
  HTTP-test bootstrap. Renewable hooks force TLS and forward only the independent
  explicit same-key acknowledgement. No existing scope/identity is adopted.
- Actual package/host preflight, exact v10 Read admin manager compatibility under
  its original 20-second bound, the hidden no-echo local console and guarded
  provisioning remain the existing Windows functions.
- The same console writer reaches the existing enrollment/grant coordinator.
  Package pins close before the console; the child cancellation context closes
  after both. Partial and uncertain outcomes retain their original semantics.
- Removal still uses the exclusive receipt lease, exact owned service inspection,
  pending-deletion observation and finite diagnostics, with all identity/state
  retained. No direct name-only removal or restart shortcut was added.

The adapter is private to the existing process/package. Its hooks are **not** a
new authorization token, silent-install API, retry/repair interface or alternative
CLI. The existing frontend owns unchecked consent, page/busy/attempted state and
duplicate-submit control; backend identity/grant/lifecycle checks remain
independent. Tests use injected memory-only backends and ephemeral public crypto
fixtures, never a native installer or host grant.

## Next Rust step and outstanding gates

A separately reviewed Rust-native frontend can be compiled into an alternative
entry in this same process and consume this adapter instead of rebuilding the
coordinator or invoking a command. Before connecting it, define and test native
window-thread ownership, callback/progress/cancellation/reentrancy and copied
public-data lifetimes across FFI. Keep private keys, invitation input and the
hidden console entirely in the existing backend. A scalar review-model prototype
does not implement that callback/consent contract.

The matched Windows Rust/Cgo link toolchain and resulting runtime imports still
need build verification; no new toolchain installation or DLL/IPC/extraction
fallback follows from this refactor. Existing Go package construction and native
release gates must remain enforced. Actual fresh Windows 11 / Server 2025,
real Linux manager/browser, human UAC/consent/fingerprint input, fresh advancing
accepted reports, provider coverage and separately measured reboot behavior
remain outstanding. Preserve VM110's partial installation; nothing here permits
reset, reinstall, recovery or a download/default switch. Rust Basic remains a
different four-metric endpoint profile, not Read admin parity.
