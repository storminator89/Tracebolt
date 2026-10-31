Integrated unsigned Rust Windows test candidate, built with its matching Linux manager and frontend from one source commit.

- Reports CPU, physical RAM, system-drive usage and uptime over mutual TLS.
- No manual token by default: generates a local key, appears as a pending device,
  and starts reporting automatically after dashboard approval. Optional invitations
  still use a hidden local token prompt.
- Includes a restricted Windows service, installer/uninstaller, durable retry state
  and SHA256 hashes. No Go runtime or separate service wrapper is required.

Download and extract **windows-rust.zip**. Run its `Install-Tracebolt.ps1` as
administrator with `-ManagerOrigin <operator HTTPS origin> -AcknowledgeBasicMetrics`.
For a private server CA, also provide `-ServerCAFile <protected CA PEM>`.
Read the included README before installation. The standalone EXE is provided too;
the ZIP includes the installation scripts.

Download **manager-linux-amd64.tar.gz** from this same release for the matching Linux manager and frontend. Extract it, review its included `docs/installation.md`, and start the manager from the extracted directory with approved protected configuration. The manager is not configured or started automatically. Set the protected LAN configuration's `webDirectory` to the absolute path of the extracted `web` directory; use the actual CLI flags documented in the included runbook.

**Do not mix components from different releases.** `release-manifest.json` binds every package and EXE hash to the source commit and CI run; `SHA256SUMS.txt` verifies all release assets. This candidate requires
the configured Windows guided TLS/non-renewal enrollment domain and protected
issuer. An old or manual-v1 manager does not implement automatic registration.
Operator identity comparison/approval remains required; pending requests cannot
send telemetry. This release does not automatically deploy or reconfigure a manager.

For automatic/invitation enrollment the installer validates public origins/configuration and the CA and reads the bounded HTTPS Rust-basic manager capability before creating a service, directory or key. Incompatible managers fail with `MANAGER_PROTOCOL_UNSUPPORTED`; TLS, network and temporary server failures use `MANAGER_PREFLIGHT_UNAVAILABLE`. `init` rechecks before opening enrollment state. The advanced preprovided mode retains its distinct legacy destination semantics and is outside this new preflight. This establishes protocol support at the check, not enrollment, approval, continued network availability or accepted telemetry. The manifest records the separate manager/frontend/agent source commits, Rust-basic profile and required protocol contract; it does not confer Go Read admin capabilities.

Publication from main is gated by the matching Linux manager/frontend build, Rust tests, Go enrollment/protocol/API tests, and a
disposable Windows Server 2025 installation/onboarding/reporting test using
the Go protocol/crypto fixture. That fixture does not establish real shared
Linux-manager/dashboard interoperability. Windows 10/11 and reboot persistence
remain unverified. Packages are unsigned; normal Windows protections remain enabled.

This basic collector is not full Go Read admin parity. The existing server
authorization profile remains Windows inventory. Automatic certificate renewal,
upgrading existing agents and reusing/resetting old identities are not supported.
