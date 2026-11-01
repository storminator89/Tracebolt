# Rust agent interoperability and native acceptance

`protocol_test.go` and `enrollment_test.go` consume invented fixtures emitted by
Rust examples and validate them using the real Go ingress and crypto contracts.
`installer_bootstrap_preflight_test.go` and `manager_preflight_test.go` are
source-order contracts only, not PowerShell/SCM execution. Portable Rust
`tests/installer_preflight.rs` checks bounded public bootstrap semantics and
rejection before enrollment state/key creation using disposable local inputs;
see [the bounded preflight contract](../../docs/rust-installer-preflight.md).
Portable Rust `tests/credential_preflight.rs` similarly checks local preprovided
certificate/key semantics and exact preservation before CLI/library sender-state
creation. Its source-order regression checks credential validation placement in
the installer/CLI/library without executing PowerShell or Windows SCM. It does
not establish chain approval or native installation acceptance.

`cmd/nativefixture` is a **test-only loopback protocol peer**, not a production
manager. It uses the production Go enrollment cryptography, issuer, state engine
and telemetry validator. Production `enrollmentstore` intentionally supports
Linux only, so this native Windows fixture uses an ephemeral in-memory engine.
Its HTTP adapter is test code and does not establish Linux-manager interoperability.
It generates test-only CA/issuer/server keys in memory, writes only the public
server CA and safe acceptance metadata, and automatically approves only the
specific key fingerprint allowlisted by the local acceptance script.

On a fresh, disposable elevated Windows runner, with Go from `go.mod` and the
Rust package built from the same source:

```powershell
.\tests\rustagent\Run-NativeAcceptance.ps1 `
  -PackageArchive .\artifacts\windows-rust.zip
```

This rejects archives outside the exact five-file root allowlist, verifies all
four payload hashes, and extracts the immutable ZIP into a new temporary path.
It invokes that package's own default tokenless installer/EXE/removal script and installs
`TraceboltRustAgent` as restricted LocalService. It checks the installer's local
public key against the pending request before permitting fixture approval,
waits for activated mutual-TLS telemetry with real CPU/RAM/system-volume metrics,
requires a durable local validated receipt, stops the service within 25 seconds,
checks its settled receipt, starts it, requires a newer acknowledged sequence, then
uninstalls. It refuses any existing installation and removes only the paths it
staged after that fresh-state check. No production manager is contacted. Raw
telemetry, private keys and enrollment ledgers are never uploaded as artifacts.

The public result is `artifacts/windows-rust-native.json`. This gate covers the
hosted Windows version used by CI, service installation/account access,
tokenless onboarding, reporting, service restart and removal. It does **not**
prove OS reboot persistence, GUI/UAC interaction, every Windows version, native
MSVC/LLVM equivalence, or a real Linux manager/dashboard deployment. Actual Go
store/service/API fixture tests run separately on Linux.

`Test-PackageStaging.ps1` is a separate portable PowerShell filesystem regression:
it uses an inert synthetic EXE file, never runs an installer or SCM command, and
checks the exact package allowlist, ZIP bytes/checksums and preservation of
pre-existing directories/nested foreign files/archives. `Build-Package.ps1`
refuses an existing output directory or ZIP; select a new `-OutputDirectory` for
a repeat build rather than deleting or reusing retained files automatically.

The separate `runtime_stop_fixture` Rust example uses this same disposable Go
peer on Linux: real enrollment/issuance/activation and mutual TLS, but invented
metrics and no Windows calls. A stop predicate flips after every enrollment
phase, including activation/sender initialization. No collector or telemetry is
admitted before stop; reopening the same ledger then acknowledges sequence 1
exactly once without changing identity or enrollment payload. CI runs it with:

```sh
go build -o /tmp/tracebolt-runtime-peer ./tests/rustagent/cmd/nativefixture
cd rust/windows-agent
cargo run --locked --example runtime_stop_fixture -- /tmp/tracebolt-runtime-peer
```

This covers the enrollment-to-telemetry stop boundary, not native SCM shutdown
timing or full Go parity. A phase admitted before stop (including collection
plus send) finishes under its existing bound rather than being force-killed.
