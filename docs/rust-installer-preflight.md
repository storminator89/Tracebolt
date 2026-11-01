# Rust Windows installer: bounded input preflight

This source candidate addresses the invitation-bootstrap and local preprovided-input portions of
[TB-07 / #134](https://github.com/storminator89/Tracebolt/issues/134). It is not a
claim that every installer or native acceptance criterion is complete.

## Order and boundaries

`Install-Tracebolt.ps1` already selects one mode, checks fresh paths/service
absence, required files and x64 execution, then invokes the actual Rust
`validate-config` parser before `New-Service` / `New-Item`. The existing
[manager compatibility check](rust-manager-compatibility.md) is unchanged:
automatic/invitation installation requires a matching manager; preprovided
identities retain their legacy offline/destination behavior.

For invitation mode the installer now passes `--bootstrap` to that read-only
command. The public file is bounded to 64 KiB and strictly deserialized (unknown
or duplicate fields fail). Shared semantic validation checks:

- Bootstrap present only for invitation mode, required in that mode.
- Exact v2 TLS/non-renewal and Windows inventory profile; exact configured
  enrollment origin, canonical HTTPS telemetry origin and any configured pin.
- Canonical, nonzero lowercase-hex manager/invitation IDs.
- One current CA root and issuer certificate, and the issuer signature under
  that root; advertised server CA syntax under the existing Rust CA parser.

Advertised server trust is never imported into Windows or substituted for the
selected `-ServerCAFile` / bundled public roots. No invitation secret is read by
preflight. No enrollment, claim, key generation, service or local state write is
part of `validate-config`.

Direct `init` and `Enrollment::open(..., true, ...)` use the same mode/bootstrap
semantics before compatibility checks and before opening `enrollment.lock`,
creating a database or generating/storing a key. Saved-ledger validation retains
the exact invitation binding. Existing identity, replay and consent state is
never reset or promoted.

## Offline validation is not offline installation

### Preprovided local material

Preprovided `validate-config` now requires `--credential-directory` with the
existing approved `client.pem` and `client.key`; other modes reject that option.
The installer forwards it before SCM/directory staging. The bounded read-only
validator rejects missing/oversized/malformed material, extra key blocks or
noncertificate data, expired/future certificates, a CA leaf, and a leaf lacking
digital-signature usage or dedicated client-auth EKU. It accepts at most eight
certificate blocks, leaf first, with current CA certificates thereafter, and
rejects duplicate extension OIDs or any extension the parser marks malformed. It
builds the sender's actual TLS client, so malformed/unsupported or mismatched
private keys fail locally without sending any request. No file bytes or private
key are printed. Direct fresh `init` and library sender initialization repeat
the material checks and TLS construction before opening sender state.

For example, a local-only material check is:

```powershell
.\tracebolt-windows-agent.exe validate-config --manager-origin 'https://telemetry.example:9444' --mode preprovided --agent-id '<approved-id>' --credential-directory 'C:\Protected\fresh-identity'
```

Use `--server-ca-file` for separately selected private server trust. Certificate
chain input is not adopted as server trust. The configured approved ID is not
derived from a certificate CN/SAN. This bounded check does not verify client
chain trust, signatures/revocation or the manager's independent exact-certificate
approval, establish that the identity has never been used, or add a manager
compatibility claim. Existing runtime opens keep their certificate-expiry
diagnostics and ledger behavior; no existing identity or state is promoted/reset.

Without `--check-manager`, `validate-config` performs local-only validation.
Preprovided mode still requires its explicit fresh approved identity and does
not gain an enrollment-compatibility claim. Automatic/invitation installation
continues to require the existing online check. A valid bootstrap does not
prove invitation liveness, manager approval, accepted telemetry or future
network availability. Input files and the target can change after a check;
post-preflight failure still retains disabled staging for inspection.

## Evidence and remaining gates

Portable Rust regressions cover repeatable offline success; wrong profile,
scope, origins, IDs, CA/issuer/signature and mode combinations; malformed,
oversized, unknown/duplicate JSON; CLI and library rejection before network or
state/key creation; exact existing-file preservation; and positive invitation
initialization/reinitialization protection using disposable loopback TLS.
Go source-order contracts verify installer/CLI/library placement only. These
tests do not execute PowerShell or Windows SCM and are not native acceptance.

Portable preprovided regressions additionally cover repeated offline validation,
valid leaf/CA-chain input, wrong mode/missing directory, invalid key/certificate
shapes, validity, role and pair mismatches, and rejection before CLI/library
initialization with exact foreign-file/directory preservation. Their additional
source-order contract checks credential validation before installer/sender
mutations without executing PowerShell or SCM. Boundary fixtures cover eight
versus nine certificates and invalid middle-CA validity/extensions. A retained
expired sender fixture reopens with the same expiry diagnostic, advanced sequence
and exact pending bytes; stricter fresh checks never reset/adopt that state. The existing
real loopback mutual-TLS retry/restart test still exercises sender construction.

TB-07 remains open. Native negative tests on an explicitly approved disposable
Windows target are still required for the complete input matrix and unchanged
service/directory/key/foreign-file evidence. Strong executable/manifest hash
binding, reparse-point/parent/ACL/target checks and complete preprovided
chain/approval semantics are outside these bounded changes. There is no new claim
that those broader requirements are complete. No real Windows installation,
credential/trust change or external device action is authorized by source tests.
