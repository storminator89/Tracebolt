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
other principals file/attribute/extended-attribute writes, deletion/child
deletion, permission changes or ownership takeover. Unmapped generic-write/all
ACE bits also reject; they are not lost in an enum cast or a zero diagnostic.
Inherit-only ACEs do not apply to the parent itself. This
conservative allow-ACE check is not a complete Windows effective-access
calculation and never repairs an existing parent or changes its ACL.
`CreateDirectories` alone can remain on a parent: new target directories are
created exclusively with an initial protected SYSTEM/admin DACL; competing
existing leaves are never adopted. Only after configuration preflight and those
new directories does disabled SCM staging begin. Existing LocalService and
restricted service-SID rights are unchanged.

There is one narrowly bound **relative-creation eligibility** classification for
the observed native `ProgramData` / BUILTIN Users / concrete matched mask `274`
(`WriteData`, `WriteAttributes`, `WriteExtendedAttributes`), or its earlier
bit-`2` subset. This is not general parent/path trust. A sealed native directory
lease must already own live, ordinary no-follow read handles for the exact
canonical directory and every ancestor, denying data-write/delete sharing. The
installer acquires both complete target-parent chains before reading ACLs and
retains the parent chains and binary/data directories through startup; it
immediately extends coverage to each freshly created directory before dependent
work. The state leaf remains pinned through initialization, then requires the
specific final-protection handoff below before the first service cycle. A pre-existing incompatible
writer, wrong path, missing/disposed lease or sharing conflict fails closed.
Owner/DACL inspection reads **each actual retained handle** with `GetSecurityInfo`,
not a racy `Get-Acl(path)` result. The actual KnownFolder path and leased object
determine the role; callers cannot supply a role label. Each qualifying applicable
BUILTIN Users ACE must individually match mask `2` or `274` on that parent to
require the relative transition. Separate grants are not aggregated into the tuple. Deletion,
child deletion, ownership, DACL, generic/additional dangerous rights, standalone
attribute/EA writes, unsupported applicable allow ACEs, unknown rights, bad owners
and NULL DACLs still reject. Deny and inherit-only entries never cancel an unsafe
allow. Other ancestors/principals remain strict.

Review eligibility permits **only** mandatory protected handle-relative creation.
It does not mark an existing child as bound or satisfy a pathname-operation gate.
The public create method repeats the real-handle ancestor review, then must retain
the successfully created child and verify its object/full-path binding before it
returns. Therefore `New-TraceboltProtectedDirectory` cannot return before the
bound-child transition. The bound binary/data directories precede disabled SCM
staging; the bound `state` child follows that staging, before Copy/Init. A failure
while preparing `state` can still leave the disabled service for inspection;
this does not add rollback or a claim that every failure leaves no service. The privately retained,
nondeletable entry also keeps its parent nonempty. A pure fixture evaluator returns
classification only; it cannot create native lease state. Missing, unrelated,
forged or disposed leases and failed creation cannot grant a bound child. There is
no Boolean bypass, ACL repair, unlock-and-retry or pathname creation fallback.

These handles address installation-time namespace operations, not arbitrary
future ACL changes, every filesystem mechanism or a compromised administrator.
The permanent service/binary/state ACLs and all runtime authority remain as before.

### Bound state handoff before service startup

A retained read/share-read-only state-directory handle conflicts with a full-path
atomic health rename: resolving the rename destination requests `FILE_ADD_FILE`
on that directory. The own-TEMP causal fixture on exact head `2c20f728` observed
`MoveFileExW(REPLACE_EXISTING)` error `32` while that state lease was held,
unchanged synthetic source bytes/names, and successful rename after its release.
A separate control kept the data parent and every ancestor strictly pinned and
confirmed rename succeeds with a permissive fixture-only state handle
([native job](https://github.com/storminator89/Tracebolt/actions/runs/41331313678/job/124921834582)).
That head still failed the real local-receipt gate; this was not full acceptance.

Immediately before enabling and starting the service, after copying, protected
configuration and initialization, one no-argument transition may release **only** the exact privately
bound `state` leaf. It first rechecks binary/data/state identities and the ordinary
retained ancestors. It reads the actual retained data/state descriptors and requires
Administrators ownership, protected present non-NULL three-ACE DACLs, exact OI/CI
allow entries for SYSTEM/Administrators FullControl and the internally resolved
fixed `NT SERVICE\TraceboltRustAgent` SID. That SID must have exactly
ReadAndExecute on data and Modify on state, including the normal synchronize bit.
Unexpected paths, unbound/disposed leases, owners, SIDs, ACLs or uncertain identity
reject before releasing any handle or enabling this fresh disabled service.
No caller-supplied path/SID/role authorizes it.

The released state entry is removed from coverage/binding; the same lease cannot
re-pin its path, case alias or subtree. Binary/data/ancestor handles, the verified
EXE and package remain pinned through startup. The protected data parent prevents
ordinary users from replacing the state entry. State is deliberately writable by
its specific service SID, not immutable against that service's own code. This is
not general share-write permission, an unlock-and-retry, a health-TMP cleanup or a
state-recovery/upgrade path. No ACL/account/privilege is broadened. Negative
handoff fixtures and full installed-service receipt/stop/restart acceptance must
still pass on the exact integrated head before a native-success claim.

### Handle-relative protected creation candidate

Fresh directories now require a live native lease and a single fixed child
component. `NtCreateFile` receives the already-open parent as `RootDirectory`,
exclusive `FILE_CREATE`, `OBJ_DONT_REPARSE`, directory/no-follow/synchronous
options and the initial protected creation descriptor. There is no pathname-based
creation fallback, adoption, write-handle/privilege fallback or state relocation.
The returned read/no-delete child handle is retained without a reopen gap. The
initializer verifies successful fresh creation, ordinary parent/child objects,
the exact SYSTEM/admin creation ACL, volume/file IDs and normalized volume-GUID
paths. Before copy/init/SCM, a verification-only full-path open must identify the
same child. The first implementation supports only the local NTFS contract;
unsupported metadata, flags, collisions or uncertain identity fail closed and
retain any already-created protected staging without retry.

`OBJ_DONT_REPARSE` alone is not an immutable-root guarantee. The new native
fixture must establish original-held-parent creation or refusal, with no child
created in the redirection target, even when its own TEMP parent is changed to
a junction before/during creation. Fixture targets are exclusively new random
siblings inside one owned TEMP root. No existing ACL, service, trust, account,
network or host setting is modified. Native tests create only their own children
with the initial protected ACL, compare collision bytes/ACLs, join their bounded
worker before cleanup and restore owned junctions before recursive removal.
Attribute-only mutation that the selected platform refuses is reported as
not-tested, not as adversarial coverage. Bounded race sampling is not an
exhaustive race/OS/filesystem proof.

The public creation entry point always supplies no callback. To cover the
critical edge deterministically, the own-TEMP fixture reflects the same private
core and changes its own parent immediately after all prechecks and immediately
before `NtCreateFile`. It requires confirmed checkpoint entry/mutation and still
rejects any artifact in its redirection target even when the primitive refuses.
This is a test-only in-process checkpoint, not a manager, CLI or public callback
route, and not a proof of every interleaving or platform.

Attribute/EA access is not excluded by read sharing; the reparse specification
accepts write-attributes as well as write-data. The exact head `5aaef008` passed
the relative primitive's positive, identity/ACL, collision, lease, prechanged-parent,
deterministic native-edge and bounded data/attribute-only junction fixtures on
hosted Windows Server 2025/NTFS, with no artifact in an own redirection target
([native job](https://github.com/storminator89/Tracebolt/actions/runs/41315623739/job/124874921439)).
Those source/native primitive results motivated the relative-only integration;
they did **not** establish an installed agent (that head deliberately retained
the old `274` rejection). Subsequent head `2c20f728` passed the integrated
negative/synthetic classification, real-handle eligibility and primitive fixtures,
installed the service and reached activation/mTLS/basic metrics, but failed the
local-receipt gate described above. The handoff candidate's full unchanged-ACL
installed-service acceptance remains pending. No Windows 10/11, PowerShell 5.1,
arbitrary-filter, complete race matrix, full parity or user-host acceptance follows.

An unsafe allow ACE reports `INSTALL_PARENT_ACL_UNSAFE` with only a fixed parent
class, well-known-principal category (all unknown SIDs map to `other-principal`),
the matched forbidden-bit mask and inherited/not-inherited flag. Its value has no
parent path, account, raw SID or SDDL; normal PowerShell error rendering can still
show the script source location. This is cause evidence, not permission to weaken the
guard or repair an existing ACL. In particular, directory `WriteData` aliases
`CreateFiles`; its appearance alone does not prove it safe to admit.

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
