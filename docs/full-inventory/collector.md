# Complete package source adapter (isolated)

`packagecollector.CollectComplete` is implemented but unused by runtime profiles,
transport and scheduling. It returns a `fullinventory.SourceInventory` from the
same fixed protected release/dpkg source capture as the existing `Collect`, before
selected-row `Trim`. Its error must be passed to `fullinventory.Build`.

The existing `Collect` still uses exactly its old finalizer and selected export.
Both paths share one source-capture core, descriptor/ancestor protections, final
identity rechecks, explicit source limits, cooperative cancellation, synchronous
cleanup and source-admission slot. No command, arbitrary path or network input is
added. Callers must additionally bound the whole collection/build/spool lifecycle;
this source slot alone is not an unlimited pending-generation queue.

A healthy full dpkg parse produces all supported installed/incomplete rows. The
full contract subsequently sorts and budgets them as one generation; neither
layer promotes a selected prefix as complete. Missing, empty, malformed, changed,
denied or oversized dpkg sources return zero full-source rows and a fixed error.
A valid residual-only source returns a nonnil empty list and can complete with
zero selected installed/incomplete rows.

Release availability is independent: unavailable/denied/invalid release metadata
remains unknown applicability beside otherwise complete dpkg scope. A detected
replacement/change of either source during capture invalidates the coherent
generation. No vendor-origin, complete-host or assessment trust is established.
Original collection time is retained; duration describes source capture, not
later hashing/spooling/network transfer. Cancellation remains cooperative and
cannot promise a hard deadline on synchronous filesystem calls.

New inert tests retain all517 invented rows versus the existing selected export,
exercise multiple chunks, zero versus missing data, independent release denial,
source replacement, malformed input after a valid prefix, error redaction,
cancellation, cleanup and shared busy admission. Focused race tests pass. No
actual host package inventory was read for this adapter's tests, and no published
checkpoint or user state was changed.
