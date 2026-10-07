# Closed read-only Windows prerequisite diagnostics

The ordinary read-only job on both exact source `5bd1340` and corrected `fe6c5a6`
reported `blocked`, `ancestor-policy`, `prerequisite-blocked`. These historical
results do not identify which ancestor condition failed. They are not evidence
of LocalService denial, an unsupported OS, or permission to change a root ACL.

This amendment changes evidence only. Every descriptor admission predicate,
owner/writer allowlist, read/share mask, path rule, open/create disposition and
protected executable/state policy remains unchanged. There is no additional
host read, service/token/credential grant, ACL mutation or repair command.

## Version 2 report

`tracebolt.windows-prerequisites.v2` adds `diagnostic`, which is null unless the
first failed check is an ancestor prerequisite. A blocked ancestor result must
include these exact fields:

- `location`: only `volume-root`, `program-files`, `program-data` or `intermediate`.
  No actual path, drive letter, depth or redirected folder name is emitted.
- `failure`: one finite classification of the failed operation/policy: opening,
  object metadata, reparse/type/link rejection, final-path query/mismatch,
  case-sensitivity query/flags, security-descriptor/owner/DACL query or validity,
  unsupported/malformed ACE, or untrusted write grant.
- `rights`: empty except for a rejected untrusted ordinary allow ACE. Then it
  contains canonical fixed categories such as `add-file`, `delete-child`,
  `change-dacl` or `generic-write`. It contains no raw access mask, trustee SID,
  ACE body, descriptor, account name, handle or native error text/code.

Only the first failed predicate is described. A later check has not been proven
safe. A read deny remains subject to the existing policy; diagnostics do not
reinterpret it as an effective service-token decision. The JSON validator rejects
missing/extra/duplicate fields, unknown categories, wrong types, duplicate or
out-of-order rights, and facts inconsistent with the result. The only logged
additional line is reconstructed from those validated finite categories.

## Interpreting the result

An `open-access-denied` outcome concerns the actual ordinary read-only observer,
not the future LocalService token. `case-query-unsupported` means that particular
query returned a supported closed unsupported-query status; it never means
Windows as an OS is unsupported. An invalid query parameter is separately named
`case-query-invalid`, rather than guessed to be an OS capability limit.

`untrusted-write-grant` identifies the existing conservative static policy that
rejected an allow ACE and the relevant rights categories. It is not by itself
proof that an existing descendant can be replaced. Analyze the measured right
and path role against native Windows semantics before proposing any change.
No guard may be removed merely because a hosted image's default policy differs.

The observer still reports `readOnly=true`, `hostMutated=false`,
`nativeServiceAcceptance=false` and `effectiveServiceTokenAccessVerified=false`.
Supported/blocked/unverified are completed policy measurements, while malformed
or failed execution fails CI. The separate privileged manual workflow remains
unchanged and still requires its exact-source approval for every scope.

## Validation and remaining evidence

Portable tests cover finite classifications, canonical rights and redaction.
Windows-only tests use in-memory descriptors, invented file metadata and fixed
error values; no file, process token or SCM handle is opened by those tests.
Existing descriptor-policy fixtures remain and must keep their original decisions.
Ordinary prerequisite CI runs only the native-package/observer in-memory fixtures
before measurement, checks their required named passes without skips, and withholds
raw test output. This adds no installed service or host-permission operation.
Cross-builds are not native fixture execution.

The actual fe6c failure condition remains unknown until this exact diagnostic
source runs in ordinary read-only CI. That result must be read before another
path-policy correction or any proposal to launch privileged native acceptance.

Microsoft contracts: [file/directory access-right definitions](https://learn.microsoft.com/en-us/windows/win32/fileio/file-access-rights-constants),
[GetSecurityInfo returned descriptor components](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo),
and [FILE_CASE_SENSITIVE_INFORMATION flags](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_case_sensitive_information).

## Root acquisition categories (f3b7bb2 follow-on)

The f3b7bb2 ordinary read-only result was `volume-root` / `open-failed`.
Its source already resolves the first `QueryDosDevice` mapping and opens only
`\Device\HarddiskVolume<number>\` with `RootDirectory = NULL`. It does not
pass a DOS-drive or VolumeGUID alias to `NtCreateFile`. The old category did not
prove that native open was reached: syntax, drive type, repeated mapping query,
buffer validation and target validation failures all became `open-failed` too.

Root failures now have a closed `root-` category, valid only at `volume-root`
with empty rights. Pre-open categories identify syntax, drive type, device query,
buffer, target allowlist or name encoding. Native failures distinguish access,
sharing, reparse, invalid request, missing/invalid name/path, wrong object type,
unsupported operation, privilege, unresolved reparse, unavailable device, I/O,
and an explicit other category. They expose neither raw numeric status/error
text nor the resolved device, drive letter, path, trustee, ACL or handle.
The same native failures and policy refusals are preserved, including their
internal error identity. There is no retry, alternate alias, new read, access
mask change, flag removal, ACL repair or mutating fallback.

The exact root request retains `0x001200a1` desired access (including
SYNCHRONIZE), read/write sharing without delete, existing-only `FILE_OPEN`,
`OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE`, and directory, synchronous,
open-reparse-point and no-recall options. The short directory-compatible-option
list in Microsoft documentation does not establish which status occurred here;
this amendment does not infer an invalid parameter or weaken either protection.

In-memory root fixtures intercept all three APIs before a host call, verify the
resolved physical name and every request field, and exercise failure stages and
typed statuses. Their names are required by ordinary read-only CI. A new measured
result is still needed to establish the actual cause. An `other` outcome remains
unknown, and no root category proves future SCM-token access or native acceptance.

Primary contracts: [QueryDosDevice current mapping](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-querydosdevicew),
[NtCreateFile name, access and disposition](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile),
and [RootDirectory and OBJ_DONT_REPARSE](https://learn.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_object_attributes).
