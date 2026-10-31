# Tracebolt Rust Windows basic agent

Standalone x64 Rust service for CPU/RAM/system-drive usage and uptime. No Go
binary, service wrapper, .NET runtime or external database is needed on the
endpoint. SQLite and the MSVC runtime are linked into the native release EXE.
This is the first basic-telemetry version, not full Go Read admin parity.

## Integrated candidate and installation

Use the Windows ZIP and `manager-linux-amd64.tar.gz` from the same integrated
candidate release. The manager package includes its matching frontend, deployment
examples and installation runbook. `release-manifest.json` records source, hashes
and actual test classes; it does not grant privileges or attest the agent. Existing
preview packages remain separate releases.

## Install: no token by default

Extract the release ZIP. In an administrator PowerShell:

```powershell
.\Install-Tracebolt.ps1 `
  -ManagerOrigin 'https://manager.example:9443' `
  -AcknowledgeBasicMetrics
```

`ManagerOrigin` is the **operator/enrollment HTTPS origin**, not the mTLS agent
port. For a private server CA add `-ServerCAFile 'C:\Protected\manager-ca.pem'`.
Without this option the client uses its bundled public WebPKI roots. It never
turns off TLS verification or imports trust into Windows. `-AgentOrigin` can
optionally pin the expected telemetry origin; otherwise it comes from the
TLS-authenticated manager bootstrap.

For automatic/invitation enrollment the installer validates public
configuration/origins and the CA with the actual Rust parser, then makes one
bounded, credential-free HTTPS capability read before
it creates a service, directory or key. An older/incompatible manager fails with
`MANAGER_PROTOCOL_UNSUPPORTED`; TLS, network and temporary server failures report
`MANAGER_PREFLIGHT_UNAVAILABLE`. No HTTP fallback, proxy, redirect, trust import,
or invitation/endpoint identity is used for this check. `init` rechecks before
opening state, and the enrollment initializer also enforces this for library
callers. Preflight proves current protocol support, not enrollment, approval,
continued availability or accepted telemetry. See the
[compatibility contract](../../docs/rust-manager-compatibility.md).

The installer generates a fresh Ed25519 key locally, creates the restricted
`TraceboltRustAgent` Windows service, and starts automatic onboarding. There is
**no default invitation token, agent ID or client certificate to enter/copy**.
The manager shows a pending automatic Rust registration. Compare its public key
fingerprint with the installer output and approve it in the dashboard. The
service then retrieves its certificate, activates and reports automatically.
No further endpoint command is needed. Registration phases run every 30 seconds;
allow a few minutes after approval for initial reporting.

The manager must run the matching source with the Windows guided TLS/non-renewal
enrollment domain and protected issuer configured. A stock manual-v1 manager or
an older manager does not support automatic registration. The new routes are
`POST /v2/windows/enrollment/self-bootstrap` and `self-claim`; challenge, signed
status, credential delivery and activation reuse the existing protocol. See
[manager onboarding](../../docs/windows-rust-onboarding.md). Pending requests
expire after 30 minutes and remain bounded by the existing capacity limits.
The service does not silently create replacement identities after expiry,
rejection, revocation or lost state.

**Optional invitation workflow:** add `-InvitationBootstrap <approved-public-bootstrap.json>`.
Only this explicit mode asks for an invitation token in a hidden local terminal
prompt. Tokens never go in command arguments, environment variables or files.
Existing server invitation workflows remain supported. Advanced provisioning
can instead use `-CredentialDirectory`, `-AgentId` and `-FreshApprovedIdentity`
with a fresh, approved, never-used TLS identity; it is not the default and its
distinct legacy telemetry-origin semantics are outside the new compatibility
preflight. Do not treat that unchanged advanced mode as newly verified.

## Scope and delivery

CPU uses two GetSystemTimes samples (observed processor group), RAM uses physical
memory, and disk usage uses caller-quota capacity on the fixed system drive.
Unavailable measurements stay unknown. No hostname/IP, processes, services,
software, serials, sessions, logs, updates or remote actions are collected.
Device health stays unknown.

The unchanged Windows telemetry route accepts
`tracebolt.agent-telemetry.windows.v1` frames with mandatory inventory sections
marked **unavailable**, not empty complete inventories. The existing manager
identity profile remains `windows-inventory-v1`; the Rust collector implements
only its basic subset. Automatic registration does not create a new server-side
basic-only authorization domain or bypass operator approval.

HTTPS mutual TLS uses the selected trust roots. Redirects, HTTP plaintext and
proxy environment settings are disabled. Receipt identity, sequence and original
collection time must match. Exact pending bytes survive failed sends and restart
in an exclusive durable SQLite ledger. At 100 seconds a stale sample consumes
its sequence and is replaced; counters are never reset or reused. Missing,
corrupt or mismatched state fails closed. Credential activation and first sender
initialization are transactionally coordinated in the enrollment database.

The service runs as LocalService with a restricted service SID. Binaries live in
`%ProgramFiles%\Tracebolt Rust`; protected configuration and state live under
`%ProgramData%\TraceboltRust`. The service can write only its state directory;
administrators and SYSTEM retain full access. Failure leaves staging/state for
inspection rather than silently adopting or resetting it. Check both service
state and **fresh accepted reports in the authenticated dashboard**.

Stop/shutdown interrupts interval waits. In-flight enrollment can take up to
20 seconds and telemetry up to roughly 16 seconds to finish. `check --directory`
validates local configuration/state without sending. With the service stopped,
`onboard --directory` advances one enrollment phase and prints only public status;
`once --directory` sends one report once activated. No payloads, credentials or
server response bodies are logged. The optional `claim-invitation` command uses
hidden terminal input and preserves a previously staged claim.

`Uninstall-Tracebolt.ps1` stops/removes the service and retains identity/state.
Revoke the endpoint before deliberate archival/removal. Automatic certificate
renewal, upgrades and reinstalling over retained state are not implemented.
The existing issuer's certificate lifetime still applies.

## Build and verify

Use the pinned Rust toolchain and Cargo.lock. On x64 Windows with Rust and Visual
Studio C++ Build Tools:

```powershell
.\deploy\windows-rust\Build-Package.ps1
```

Output: `artifacts/windows-rust.zip`, containing EXE, installation/removal scripts,
this guide and SHA256 hashes. Packages are unsigned; normal Windows execution
policy and OS protections still apply.

```sh
cd rust/windows-agent
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo run --locked --example wire_fixture > ../../tests/rustagent/fixture.json
cargo run --locked --example enrollment_fixture > ../../tests/rustagent/enrollment-fixture.json
cd ../..
go test ./tests/rustagent
```

Tests use invented data and disposable keys. They cover real loopback mutual TLS,
redirect refusal, exact retry after invalid receipts/restart, ledger protection,
and Rust-generated enrollment proofs verified by the actual Go crypto package.
The actual Go ingress validator accepts the Rust telemetry fixture. The Windows
CI acceptance fixture is isolated from production and validates installed-service
onboarding/reporting against the Go protocol/crypto. See the exact release's CI
results for native coverage. Windows 10/11, reboot persistence and real shared
Linux-manager/dashboard interoperability are separate acceptance targets.
