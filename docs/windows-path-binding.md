# Windows path binding correction (source candidate)

The read-only 45af prerequisite observation identified a ProgramData allow ACE
with `add-file`, `write-ea`, and `write-attributes`. This is evidence about the
first rejected ACE, not a complete ACL, effective LocalService access, or a native
service pass. Existing OS ACLs are never widened or repaired.

## Admission and binding

Only the resolved ProgramData **leaf** permits those three specific untrusted
rights. Volume roots, intermediate directories, Program Files, app-owned
parents and the final executable retain their stricter policy. Trusted owner,
ordinary supported ACE layouts, non-null DACL, and rejection of generic write,
generic all, delete, delete-child, change-owner and change-DACL remain required.
Final executable read/execute checks and private service-SID state are unchanged.
The ordinary read-only result still fixes `hostMutated`,
`effectiveServiceTokenAccessVerified` and `nativeServiceAcceptance` to false.

Add-file on a directory does not authorize replacing a protected existing child.
However, `FILE_WRITE_DATA` (the same bit as directory add-file) or
`FILE_WRITE_ATTRIBUTES` can satisfy the access check for setting a reparse point.
A metadata-only no-delete-sharing handle is not a rename/delete pin. These facts
are why simply ignoring the three ACE bits would be insufficient.

`internal/windowspath` opens the local physical volume once and traverses each
single component relative to the held parent. Every directory handle includes
`FILE_LIST_DIRECTORY`, `FILE_TRAVERSE`, read-control, read-attributes and sync;
none shares delete. Opens use `OBJ_DONT_REPARSE`, `FILE_OPEN_REPARSE_POINT` and
explicit directory/file kinds. Reparse points, case-sensitive directories and
mismatched final paths are refused. These are real current-token opens, not an
invented token or a descriptor-based effective-access calculation.

Manual provisioning uses `NtCreateFile(FILE_CREATE)` with the protected descriptor
at creation and the exact parent handle. There is no absolute create-then-reopen,
`OPEN_IF`, adoption, or retry at another destination. It checks the held parent
before and after creation and retains the returned app-directory handle, its
identity and exact protected ACL. A squatted name causes a collision/refusal.

The protected child keeps ProgramData nonempty: untrusted users cannot delete
the child or use parent delete-child rights, which admission rejects. Microsoft
specifies that setting a reparse point on a nonempty directory fails. Creation
racing an empty ancestor's conversion must fail on the no-reparse relative open
or leave the child bound to the original checked parent. Post-create checks
never authorize continuing after an unexpected parent or child. Failures retain
created resources for owned/manual cleanup; they do not delete unknown objects.
Attribute/EA writes are not claimed to be frozen by sharing flags.

Artifacts are created relative to the retained protected app parent, hashed and
flushed, then their writer handles are replaced with read-only no-write/no-delete
pins. That transition preserves the parent binding and checks the file identity
and ACL again. Only trusted administrators/SYSTEM can change the protected child.
Cleanup first validates its receipt, complete tree, identities, hashes and ACLs.
It releases its own normal-lifetime pins before acquiring DELETE handles. Each
child is opened through its already-frozen direct parent handle, avoiding a
second ancestor open that would conflict with that parent's DELETE access. It
rechecks identities and deletes only exact opened objects bottom-up. Unknown
children and incomplete receipts still stop cleanup. It never deletes OS roots.

## Evidence and remaining native gate

Portable fixtures check canonical components, the exact scoped rights mask and
injected parent/create/retain/child ordering, including failures. Cleanup fixtures
model two-way delete sharing, require reuse of frozen parent handles, and check
reverse-order release on a failed acquisition with no absolute-path fallback. In-memory Windows
fixtures intercept native requests before the syscall and require single-component
RootDirectory binding, no-reparse flags, `FILE_CREATE`, descriptors and no retry
on collision, reparse or access denial. These fixtures create no host object.
Cross-builds establish compilation only.

Separately approved disposable-Windows tests must still exercise:

- metadata-only versus sharing-relevant pin rename/delete attempts;
- a reparse conversion raced before create under an initially empty shared parent;
- refusal of existing/squatted names, without mutation outside the owned target;
- a retained protected child preventing its ancestor becoming empty/reparsed;
- attribute/EA changes, forbidden destructive grants and final-file read denials;
- artifact image use while pinned, then receipt-bound cleanup without sharing leaks;
- actual SCM LocalService token, private-state access and unrelated-service denial.

No such native action is established by this source correction or an ordinary
read-only policy pass. Production manager, hidden-console input and actual OS
shutdown/reboot remain their existing separate acceptance gates.

## Primary Microsoft semantics

- [File access rights](https://learn.microsoft.com/en-us/windows/win32/fileio/file-access-rights-constants)
- [Delete-sharing algorithm](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/82b364ce-6d7b-422f-8d88-4db32eea809a)
- [RootDirectory and OBJ_DONT_REPARSE](https://learn.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_object_attributes)
- [Set-reparse access and nonempty-directory checks](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/4aeefef8-92c3-4abc-af7a-a610caf8a165)
- [Attribute/EA access and sharing](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
