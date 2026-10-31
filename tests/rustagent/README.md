# Rust agent interoperability and native acceptance

`protocol_test.go` and `enrollment_test.go` consume invented fixtures emitted by
Rust examples and validate them using the real Go ingress and crypto contracts.
`credential-fixture.json` is the reverse, public-only Go issuer fixture: Rust's
private fixed-leaf verifier and `credential_contract_test.go` check the same DER,
original intent and fixed clock. It contains no private key or live credential.
`installer_bootstrap_preflight_test.go` and `manager_preflight_test.go` are
source-order contracts only, not PowerShell/SCM execution. Portable Rust
`tests/installer_preflight.rs` checks bounded public bootstrap semantics and
rejection before enrollment state/key creation using disposable local inputs;
see [the bounded preflight contract](../../docs/rust-installer-preflight.md).

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
  -Executable .\artifacts\windows-rust\tracebolt-windows-agent.exe
```

This invokes the actual default tokenless installer and installs
`TraceboltRustAgent` as restricted LocalService. It checks the installer's local
public key against the pending request before permitting fixture approval,
waits for activated mutual-TLS telemetry with real CPU/RAM/system-volume metrics,
stops and starts the service, requires a newer acknowledged sequence, then
uninstalls. It refuses any existing installation and removes only the paths it
staged after that fresh-state check. No production manager is contacted. Raw
telemetry, private keys and enrollment ledgers are never uploaded as artifacts.

The public result is `artifacts/windows-rust-native.json`. This gate covers the
hosted Windows version used by CI, service installation/account access,
tokenless onboarding, reporting, service restart and removal. It does **not**
prove OS reboot persistence, GUI/UAC interaction, every Windows version, native
MSVC/LLVM equivalence, or a real Linux manager/dashboard deployment. Actual Go
store/service/API fixture tests run separately on Linux.
