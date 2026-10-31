# Integrated Rust Windows test candidate

This integration combines the existing development branches in main. Rust Basic
provides CPU, physical RAM, system-drive capacity and uptime. Go Read admin stays
a separate, broader profile. Neither is a production RMM release.

## Get matching components

Choose a published **integrated Rust test** prerelease from the
[release list](https://github.com/storminator89/Tracebolt/releases). The
**Rust Windows basic agent** workflow builds its Windows x64 ZIP/EXE and Linux
amd64 manager from the same source commit. Use that candidate's manifest and
SHA256SUMS to select and verify both components. Main publication uses a new
immutable candidate tag per commit; older preview assets are not overwritten.
Do not combine the Rust preview with an arbitrary older main manager.

Set up the Linux manager using [the installation runbook](installation.md), with
Windows guided enrollment enabled, TLS and the protected client-auth issuer.
The manager artifact does not create operator credentials, TLS trust or an issuer.
This tarball is a prebuilt binary distribution: its Compose templates require
a source checkout/Dockerfile and cannot build from the tarball alone. After
preparing the protected configurations described in the runbook, set
`webDirectory` in the LAN configuration to the absolute extracted `web` directory,
and start the supplied binary directly:

```sh
./manager --lan-config /absolute/protected/lan.json --enrollment-config /absolute/protected/enrollment.json
```

Use the included frontend and manager from the same candidate. The default
Windows self-registration requires a TLS non-renewal domain.

## Install on a Windows x64 test machine

Extract windows-rust.zip, verify SHA256SUMS, then run elevated PowerShell from its
directory (replace the example origin with your configured operator origin):

```powershell
.\Install-Tracebolt.ps1 -ManagerOrigin 'https://manager.example.test:8443' -AcknowledgeBasicMetrics
```

For private PKI, additionally pass `-ServerCAFile 'C:\approved\server-ca.pem'`.
The explicit acknowledgement approves the described basic collection. No token
is requested by default. The service registers in the background; compare its
locally displayed fingerprint and comparison value in Devices / Setup / Windows,
then approve the matching identity. Only a fresh accepted report confirms data
arrival. Optional invitation mode remains described in the package README.

In current main, automatic/invitation installation validates configuration/CA,
optional public invitation-bootstrap content and the bounded HTTPS Rust-basic
manager capability before service/directory/key creation. `init` and library
initialization recheck before opening enrollment state. See the
[compatibility contract](rust-manager-compatibility.md) and
[invitation preflight limits](rust-installer-preflight.md). Older immutable test
packages keep their original behavior: check the chosen source pin and included
README rather than assuming every candidate has the current checks. Advanced
preprovided credentials remain outside the new compatibility preflight; full
path/ACL/executable-hash and native negative-case acceptance remain open. A
successful check cannot promise later network availability or accepted reports.

## Evidence and remaining gates

The workflow runs Rust checks, Go protocol tests and native Server2025 service
installation/enrollment/telemetry/service-restart/removal against the disposable
protocol fixture. These are separate from a real Linux-manager/browser workflow.
Windows11, actual OS reboot, renewal across certificate expiry, signed packaging,
upgrade/repair and full purge remain open. Non-renewal credentials are bounded
by issuer validity and typically at most seven days from issuance; this candidate
is for controlled testing, not unattended long-term customer deployment.

Preserve retained identity/state when removing the service. Never delete used
state or counters to repair an installation. See issues #127–#158 for the full
planned gates and individual acceptance criteria.
