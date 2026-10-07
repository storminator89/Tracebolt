# Separately consented Windows visible volumes

Source candidate only. No native Windows read or service acceptance is established
by portable fixtures or Windows cross-compilation.

`Collect` requires a live sender-bound `windows-visible-volumes-v1` consent and a
sample generation before it reaches the native boundary. Missing, disabled,
malformed or foreign consent cannot trigger a read. The parent owns persistence,
stopped-service authorization, grant revocation and exact pending retry checks.

FindFirstVolumeW/FindNextVolumeW enumerate caller-visible volume GUID roots,
including volumes without drive letters. The collector never enumerates mount
paths, files, labels, serials, network shares or remote connections. GetDriveTypeW
classifies GUID roots; unsupported/remote types are reported unknown/unavailable
without a capacity query. No elevation, privilege changes, subprocess or write
API is used.

GetDiskFreeSpaceExW supplies three distinct uint64 decimal strings:
- totalBytes: caller/quota-aware total capacity
- availableBytes: caller/quota-aware free capacity
- freeBytes: physical volume free capacity, which may exceed caller total

Enumeration quality describes enumeration, independently of per-row capacity
quality. Failed capacity is null, never zero. A successful empty enumeration is
observed but does not claim whole-machine disk visibility. Native enumeration
stops at 128 rows without an extra call to prove exhaustion, so that limit always
has countExact=false. Exhaustion below the cap establishes only the scoped count.
Transport keeps at most 64 rows and 12 KiB, sorted by GUID and trimmed from the
end. FitBudget can reduce this further for the enclosing frame without changing
capture, grant, generation, observed count or exactness. Omission marks truncation
and incomplete coverage. Enumeration failure after valid rows is partial and its
count remains a lower bound even if all rows are omitted in transport.

A five-second cooperative budget and caller context are checked between native
calls. These synchronous Windows APIs cannot interrupt an in-flight OS call;
there is no hard wall-clock guarantee or abandoned worker/handle. Collection
closes its enumeration handle on every normal/error/cancel path.

Portable tests inject the cursor boundary; Windows-only tests inject every API
procedure and never call the system procedures. Native execution on an expressly
authorized disposable Windows environment remains a separate acceptance gate.
