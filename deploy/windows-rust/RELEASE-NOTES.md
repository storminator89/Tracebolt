First unsigned x64 Rust basic-agent preview with automatic registration after installation.

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

**Use the manager built from this release's exact source commit.** It requires
the configured Windows guided TLS/non-renewal enrollment domain and protected
issuer. An old or manual-v1 manager does not implement automatic registration.
Operator identity comparison/approval remains required; pending requests cannot
send telemetry. This release does not automatically deploy or reconfigure a manager.

Publication is gated by Rust tests, Go enrollment/protocol/API tests, and a
disposable Windows Server 2025 installation/onboarding/reporting test using
the Go protocol/crypto fixture. That fixture does not establish real shared
Linux-manager/dashboard interoperability. Windows 10/11 and reboot persistence
remain unverified. Packages are unsigned; normal Windows protections remain enabled.

This basic collector is not full Go Read admin parity. The existing server
authorization profile remains Windows inventory. Automatic certificate renewal,
upgrading existing agents and reusing/resetting old identities are not supported.
