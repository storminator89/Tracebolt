# From cached-update preview to complete rows

Historical design assessment. The implementation is documented in
[the complete cached-update extension](complete-cached-updates-extension.md); its
separate consent does not change the preview checkpoint described here.

At the preview checkpoint the cached-update candidate exported only a
bounded preview and exact full-query counts. This note does not claim that omitted
rows can already be requested, nor authorize any endpoint action or local grant.

## What is already available

- Full dpkg generations already implement immutable bounded chunks, durable exact
  retry, consumed sequence floors, atomic manager completion and generation-pinned
  operator paging/search.
- Complete process/mount observations have similar mechanics but deliberately
  distinct fixed scopes and consent. These are typed contracts, not arbitrary
  record or job stores.
- The authenticated journal request path is a narrowly allowlisted, consume-once
  journal-content operation. It is not a generic remote job channel. Operator
  inventory GETs are read-only manager queries and cannot currently request an
  endpoint collection.

Do not insert APT rows into package/process/service fields, inflate the existing
16 KiB authority JSON cap, or label a preview as a complete inventory. Do not turn
the journal action into an arbitrary command executor.

## Smallest sensible next implementation

Prefer an incremental shared bulk-inventory primitive over four copied update
subsystems. Keep every existing wire schema and endpoint unchanged. Start with
only the existing dpkg generation and the new cached-update generation as users
of the shared implementation; process/mount refactoring is unnecessary now.

1. Expose a private pre-trim result from the cached collector: ordered candidate
   rows, original collection time, release, source-age facts, checked/unknown
   counts and complete capture outcome. A failure never produces a successful
   generation; unknown comparisons remain explicit.
2. Extract common pure mechanics from the existing package-generation builder and
   validator: bounded chunk formation, ordered-row validation, domain-separated
   canonical hashes, immutable manifest binding and completion receipt. Keep row
   codecs/validators and all public schema/domain constants in explicit adapters.
   Adapter selection is a fixed compile-time enum, never a user path, arbitrary
   schema, command or executable supplied in a frame.
3. Reuse the current protected generation spool/checkpoint and manager staging/
   promotion algorithms through the smallest fixed-domain parameterization. A
   cached-update domain still needs an independent durable consumed floor and
   protected spool namespace, but it does not need four separate copied packages.
   Keep existing byte, chunk, database/WAL and admission ceilings. Old dpkg state,
   pending exact bytes and receipts must remain byte-compatible and reopenable.
4. Add narrowly scoped cached-update generation upload/read routes with existing
   authenticated device and operator guards. Keep manager staging rows separate
   from complete rows, promote only after an exact completion receipt, and pin
   every page/cursor to the same manifest. Reuse current cursor expiry, bounded
   page/search scans and original-age retention. A newer failed/pending capture
   must not erase or refresh the prior complete result.
5. Replace the preview table with existing bounded-page UI behavior. Show whether
   the full generation is available, the full count, query gaps, original cache
   age, current page and remaining rows. Opening or paging reads manager data;
   it cannot run APT or refresh metadata.

Local consent must explicitly disclose transmission of **all** candidate rows,
not the current bounded sample. Use a new exact extension scope/version; do not
reinterpret already accepted preview consent. Existing v3 device identity can
remain, following the current separately bound extension pattern. No automatic
source widening follows from deploying the manager.

## On-demand alternative

A fixed authenticated `capture_cached_apt_updates` request could reduce background
APT work, but no existing generic job transport supports it today. A proper new
capability would still require explicit local consent, fixed cache-only commands,
expiry and consume-once rules, replay/revocation binding, source budgets and
complete-result generation storage. It does not remove the immutable capture and
paging requirement: re-running APT for each UI page risks mixed source versions.
An operator GET must not be silently repurposed into that request.

For the next slice, scheduled local capture plus shared immutable bulk mechanics
is therefore less novel than adding a job system. The exact capture cadence and
observation freshness should be chosen after measuring full native Debian 13 and
Ubuntu 24.04 caches under the unprivileged service account. Metadata age remains
independent, and collection must leave delivery time for basic system reports.

## Acceptance gates before replacing the preview

- Old profiles, v1/v2 system frames, package generations, pending spools and manager
  databases remain compatible; default-off still means no APT source access.
- More than 16, 128 and 1,000 candidate rows can all be traversed without hidden
  prefixes or an unbounded DOM/response, including worst-case version lengths.
- Retry after process restart preserves bytes, manifest, consumed floor and source
  time. Interrupted/expired/changed captures never become completed empty results.
- Failed newer attempts retain the older complete generation with truthful age.
- Consent withdrawal, certificate revocation, identity expiry and operator session
  changes prevent further capture/delivery/display under the established rules.
- No package list, raw repository URL, config body or stderr escapes through logs,
  AI, query strings, public feeds or dynamic executable arguments.
- Native comparison evidence on actual Debian 13 and Ubuntu 24.04 is recorded;
  fixture tests and cross-builds remain labelled separately.

This is substantial bounded-state/protocol work and review, not a UI-only paging
change. Implement and review it as a separate focused slice after the current
preview foundation, without copying four standalone state machines.
