# Rust Windows installer: bounded input preflight

This source candidate addresses the package/path, invitation-bootstrap and local preprovided-input portions of
[TB-07 / #134](https://github.com/storminator89/Tracebolt/issues/134). It is not a
claim that every installer or native acceptance criterion is complete.

## Order and boundaries

`Install-Tracebolt.ps1` already selects one mode, checks fresh paths/service
absence, required files and native x64 execution. Before invoking any candidate it
also checks package checksums, PE architecture and installation parents as
described below. It then invokes the actual Rust
`validate-config` parser before directory/SCM staging. The existing
[manager compatibility check](rust-manager-compatibility.md) is unchanged:
automatic/invitation installation requires a matching manager; preprovided
identities retain their legacy offline/destination behavior.

### Package and path boundary

Use the whole independently selected/reviewed ZIP, not a standalone EXE. The
installer requires its exact sibling `tracebolt-windows-agent.exe`, the new
`Package-Preflight.ps1` helper, scripts, README and bounded ASCII `SHA256SUMS.txt`.
The directory must contain exactly these six regular files; the manifest must
contain exactly five canonical lowercase-SHA256 records. Missing, duplicate,
unknown, malformed, mismatching or oversized inputs fail before any candidate
invocation or target staging. The EXE is inspected only as data for bounded PE
headers, AMD64/PE32+ and executable/not-DLL characteristics before its first
invocation. This is not complete Windows loader validation or a safety verdict.

On Windows the helper opens package directory ancestry root-to-leaf and all
manifest/payload leaves with no-follow native handles, checks object types and
reparse attributes by handle, and retains actual read-access/read-only-sharing
handles through preflight, copy and initialization. Sharing conflicts fail
closed. This is intended to prevent leaf/ancestor replacement during use rather
than assuming a leaf handle also pins its pathname. Windows sharing/namespace
behavior requires its own native evidence. The target EXE is created without
overwrite, copied from the verified handle, checked against the original digest
and held read-only through startup.

Input/package path chains reject reparse points. Installation parents and their
ancestors must be ordinary directories owned by SYSTEM, Administrators or
TrustedInstaller, have a non-NULL DACL, and have no applicable allow ACE granting
other principals file writes, deletion/child deletion, permission changes or
ownership takeover. Inherit-only ACEs do not apply to the parent itself. This
conservative allow-ACE check is not a complete Windows effective-access
calculation and never repairs an existing parent or changes its ACL.
`CreateDirectories` alone can remain on a parent: new target directories are
created exclusively with an initial protected SYSTEM/admin DACL; competing
existing leaves are never adopted. Only after configuration preflight and those
new directories does disabled SCM staging begin. Existing LocalService and
restricted service-SID rights are unchanged.

**Unsigned checksums are consistency bindings, not publisher authentication.**
A changed EXE plus changed manifest can still agree; independently verify and
review the selected release/source before elevating its scripts. The helper is
part of that script trust, not a boundary against malicious installer code.
Package directory handles do not prohibit all child creation; use an independently
trusted package location, without other processes writing into it. The exact
entry check is a snapshot, not a DLL-search/code-integrity guarantee. No signer,
anti-malware, Authenticode or release-acceptance claim follows, and this is not
a boundary against administrators or a compromised elevated session.

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
network availability. Non-package input files can change after a check;
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

Data-only PowerShell fixtures are added to `Test-PackageStaging.ps1`: package
allowlist/manifest failures, wrong PE architecture/shape despite a matching hash,
repeatability, exact foreign-file preservation, links and lock cleanup. Windows
branches additionally check blocked writers/renames and in-memory parent ACL
descriptors without executing the fixture EXE, installer, SCM or ACL mutator.
These tests must actually run on the selected Windows revision before claiming
their results. The Go package/path test is a source-order contract only.

TB-07 remains open. Native negative installation tests on an explicitly approved disposable
Windows target are still required for the complete input matrix and unchanged
service/directory/key/foreign-file evidence. Publisher authentication, complete
loader/code-integrity/DLL-search guarantees, all filesystem/race combinations,
and complete preprovided chain/approval semantics are outside these bounded
changes. There is no new claim
that those broader requirements are complete. No real Windows installation,
credential/trust change or external device action is authorized by source tests.
