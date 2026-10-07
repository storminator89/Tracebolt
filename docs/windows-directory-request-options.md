# Windows directory request compatibility correction

Ordinary read-only prerequisites on exact
`c0fc06a47315078e666dac1692918319f201fc79` reached the native volume-root open and
reported `root-open-invalid-request`. This category covers invalid-parameter,
invalid-parameter-mix and numbered invalid-parameter statuses. It does not
identify a particular rejected flag or prove that the correction below is the
only issue on that host. Host mutation, effective service-token proof and native
acceptance remained false.

## Contract and bounded correction

Both `windowspath.ntOpenWith` and `windowsstate.ntOpen` previously constructed
these directory CreateOptions:

`FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT | FILE_OPEN_NO_RECALL` (`0x00600021`).

[MS-FSA section 2.1.5.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/8ada5fbe-db4e-49fd-aef6-20d54b748e40)
explicitly defines the valid directory option set and an invalid-parameter
outcome when a directory request includes other bits. OPEN_REPARSE_POINT is in
that set; NO_RECALL is the sole extra bit in this request. This supports removing
only NO_RECALL from directory requests. Directory options become `0x00200021`;
non-directory options remain `0x00600062`, including NO_RECALL and write-through.

MS-FSA is an [SMB-supporting abstract object-store model](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/860b1516-c452-47b4-bdbc-625d344e2041),
not a trace of the local syscall. The [user-mode NtCreateFile table](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile)
lists a narrower directory-compatible set. The source correction therefore
remains a bounded compatibility candidate supported by the documented model and
measured error class. A fresh ordinary read-only result must establish whether
it resolves this host's rejection. There is no retry using weaker flags.

## Protections retained and precise limit

`OBJ_DONT_REPARSE` remains on every native object-name request. Directory opens
also retain `FILE_OPEN_REPARSE_POINT`, directory type enforcement and synchronous
I/O. Microsoft documents both [no-reparse name parsing](https://learn.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_object_attributes)
and [opening reparse objects without normal target processing](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntcreatefile).
The change removes neither protection and introduces no target-following fallback.

All access/share masks, sharing-relevant directory pins, physical-root resolution,
component-relative names, create-only dispositions, protected creation descriptors,
identity/hash checks, trusted-owner/destructive-writer rules and private service-SID
DACL requirements remain unchanged. Existing post-open reparse/type/other handle
validation still applies. File requests and their no-recall option are unchanged.

Directory acquisition no longer requests NO_RECALL. Post-open admission checks
cannot establish an acquisition-time no-recall guarantee or exclude all provider
side effects. The driver reference describes NO_RECALL as an instruction against
content recall, not a universal no-callback/no-network guarantee. This candidate
does not claim either guarantee for directory acquisition.

## Validation and remaining gates

The root/path request fixtures assert the new exact directory mask and unchanged
file mask, no-reparse object attributes, parent/name binding, share/access masks
and no retries. A new protected-state request fixture intercepts NtCreateFile,
checks both open/create and file/directory variants, and returns invented reparse,
access and sharing failures to require unchanged failure propagation. All Windows
calls in these request fixtures are intercepted; they create no native object.
Ordinary read-only CI now requires these inert state fixtures as well as the
existing path/native/observer fixtures. Missing or skipped checks do not pass.

Cross-building is not native execution. The next ordinary prerequisite observation
and the separately approved real SCM/token/private-state/cleanup gates remain
outstanding. No ACL repair, token grant, key creation, service action, privileged
workflow dispatch, production manager/browser acceptance or OS reboot follows.
