# Interrupted Windows Read admin: read-only status

The current source adds `tracebolt-windows-service.exe --read-admin-recovery-status`
for a staged, interrupted twenty-one-scope Read admin installation. It is not in
the previously published preview executables. Source/fixture checks do not
establish packaged native acceptance or authorize replacing an installed binary.
The separate [same-identity continuation candidate](windows-read-admin-continuation.md)
has stronger admission and its own outstanding native gate.

The command reports a provisional observation, not a recovery plan or permission
to continue. It accepts no apply, bootstrap, invitation, collection-consent,
renewal or transport options. It does not resume enrollment, extend deadlines,
activate an identity, apply grants, finalize a receipt, start/reconfigure SCM or
change security settings. There is no manager call or private enrollment-ledger
read. Human authorization for a native run remains separate from source tests.

## Evidence and output

The Windows adapter resolves the existing fixed layout. It reads only protected
`intent.json` and `receipt.json` files from the installer directory, at most
64 KiB each, using the existing administrator-only native file reader. These
reads enforce descriptor, ancestry, reparse and hardlink protections but do not
open, create or verify the installer store/manifest. They cannot establish
rollback protection or reserve a future recovery operation.

Canonical bytes, current receipt version 12, exact acknowledged twenty-one-scope
consent, original intent/receipt layout, installation ID, executable digest and
disabled configuration digest must agree. Historical profiles are rejected.
The exact-owned staged-service inspector checks the fixed service, SID,
configuration, protected executable and its hash using read-only access. The
command rereads both files and reinspects the service; changes, missing state,
inspection/release errors or cancellation prevent a usable result.

Example fixture output, not evidence of an installed endpoint:

```json
{"schemaVersion":"tracebolt.windows-read-admin-recovery-status.v1","phase":"claim-started","evidence":"protected-file-snapshot-not-manifest-verified","service":"process-visible-owned-stopped-disabled","recovery":"no-resume-authority"}
```

Output contains only these bounded labels. It includes no paths, identity IDs,
grant digests, certificates, credentials or raw error text. Exit zero means this
limited observation succeeded; `no-resume-authority` still blocks continuation.
The command does not check whether invitation entry, a remote claim, activation
or individual grants succeeded, or whether their original deadlines remain valid.
Do not infer their state from a phase name.

Only `install-started`, `claim-started`, `activation-started`, `grants-started`,
`grants-incomplete` and `grants-verified` are supported with an exact stopped,
disabled staged service. Completed records and `startup-transition-started`
require different inspection/reconciliation and are rejected. Failure emits the
existing finite CLI diagnostic and no status JSON; it never means service absence.

The SCM view remains process-visible. Security-software isolation can change that
view; this command does not detect or bypass a sandbox. Compare existing native
Windows service evidence and exact security events as described in the
[installation guide](windows-prerelease-install.md#conflicting-service-inspection-and-security-software-isolation).
Neither a successful snapshot nor a matching executable hash proves a normal host
execution context or authorizes an exclusion.

## Verification boundary

Injected tests cover bounded/canonical files, exact current consent and intent
binding, changed observations, unavailable/isolated SCM results, read and handle
release failures, cancellation, finite output and rejection of mutating CLI flags.
They use no native host operations or manager.

One separately approved native Windows 11 VM110 observation on 28 October 2026
passed with source build `4985b433f6cf77476d497fe07f9d5741614cdbe6` against the
retained preview.3 partial installation: the guest verified the diagnostic image
hash, the sole status invocation returned `claim-started` and
`no-resume-authority`, and its exit code was zero. See the
[exact build, handoff and native evidence](windows-native-preflight-2026-10-28.md#approved-native-read-only-diagnostic-pass).
This establishes the successful bounded protected-file/SCM path for that pair;
it does not establish native rejection cases, manifest rollback protection,
remote enrollment outcomes or packaged release acceptance. The separate
same-identity continuation candidate's native gate remains outstanding. Preserve
the partial installation until those gates are addressed.
