# Windows context collection fairness

Source-only correction to the combined read profile. It changes no local grant,
provider permissions, worker mode, native installation or accepted telemetry
schema. Earlier profiles and pending v1–v11 frames remain compatible.

## Bounded opportunities

The required base capture still runs first. Fresh odd sender sequences give
the earlier event/volume/process/network/startup/adapter group first opportunity.
On even fresh sequences, enabled isolated cached-update, patch, Security and
Sessions sources run before the earlier optional providers. The first isolated
source rotates across those even sequences. The leading earlier source also
rotates on successive odd/even pairs, so that group cannot repeatedly starve its
own tail. Collection and wire assembly are separate: results are appended in the existing canonical order, preserving all
original generation bindings, row fitting and the 72 KiB telemetry bound. The
earlier-only profiles without patch, Security or Sessions retain their existing
scheduling behavior.

Each optional source has a maximum five-second parent budget and respects
the three-second remaining-deadline primary-delivery reserve. Earlier sources
keep any tighter native bounds they already had. Skipped/timed-out earlier
providers produce finite current-grant unavailable envelopes too; process and
startup fallbacks bind the exact current base PID/service rows and never reuse
old values. Maximum-row fallbacks are fitted to their existing component byte
caps before validation, preserving counts, truncation and any admitted self PID.
No outer timeout is increased. A source that normally needs its existing budget is not given a
permanently reduced equal slice. Odd cycles preserve the earlier group's first
opportunity; rotating both groups prevents an earlier consistently slow optional
provider from starving context sources on every fresh cycle. A valid pending
retry does not collect, rotate, change bytes or refresh timestamps. The durable
sequence advances under the existing acknowledge/discard rules only.

Current activated config/certificate/ready-receipt authority and the exact local
grant are checked before and after each precollection and again at the existing
append/stage/send boundaries. Revocation/replacement still suppresses retries.
All cooperative optional providers stop before the primary reserve. The earlier
native APIs remain synchronous and cooperatively bounded: a kernel
or provider call that does not return cannot be forcibly canceled by this
scheduler. This is not a hard deadline guarantee for those APIs or for the
required base capture. No abandoned goroutine or unbounded background work was
added; fully isolating these earlier APIs is outside this correction.

## Original captures beside the latest failure

The private operator inventory response optionally adds `retainedContext`.
It holds at most one previously useful complete snapshot per independent
cached-update, patch, Security or Sessions scope. Useful means observed/partial
source evidence, including a genuinely observed empty source. It does not mean
healthy, protected, compliant or current. Row-bound process/startup data is
never copied into a newer generation.

The latest attempt remains unchanged, including unavailable/budget/denied
reasons. The UI offers a collapsed **Show previous capture** alongside it,
with its original generation and conservative capture time. A fresh base report
or exact retry cannot refresh that age. Each retained capture disappears at
its own original 24-hour boundary, independently of the latest base capture;
operator session/visibility/identity loss still clears it. A partly useful new
scope snapshot replaces that scope's earlier snapshot as a whole; this is not
per-field history or a synthetic merge of different provider captures.

The manager stores this bounded cache separately from the exact replay frame.
The optional `enrollment_windows_context_retained` table has at most one row
per existing Windows credential, with an 80 KiB per-row bound. Canonical source
validation and the current frame's exact grant are required on use. Absence of
a section means disabled under the existing wire contract and clears its cached
source; replacing the grant also clears it. A missing cache loses availability
only and can never supply authority or resurrect data. Existing managers open
without a cache; the first useful accepted observation creates it, without
conferring collection permission. This remains development source for fresh clean
installations; no installed user base or migration/old-to-new upgrade plan is
assumed.

The private response cap is 154 KiB (existing 74 KiB view plus at most 80 KiB
retained context); the sender frame, native source and worker bounds do not grow.
Display expiry is enforced independently at manager response time and in the
browser. Existing bounded maintenance reclaims one cached identity row per
step using the original 24-hour source expiry; expired certificates are also
reclaimed. Termination deletes the cache in the authority transaction, and the
foreign key cascades any credential deletion. This does not claim secure deletion
of historical database pages or backups.

## Verification boundary

Synthetic source fixtures cover slow earlier-provider and slow isolated-sibling
fairness, bounded primary delivery, original capture/expiry, restart, exact lost-
response retry, absent/replaced grants and current identity authority. Private UI
fixtures cover separate current failure/previous evidence, malformed authority,
original expiry and session cleanup. Compilation is not native acceptance.

A separately approved disposable Windows gate must still establish actual
LocalService provider timing, worker termination, protected local consent and
native-to-manager-to-browser behavior with the combined profile. No host read,
installation, grant, account, ACL, credential, network or security change follows
from these source checks.
