# Selected-event content worker

Source candidate only. This package owns one private, fixed-current-executable
child for a separately authorized selected Application/System message read.
Fixtures and Windows cross-builds do not establish native acceptance, an enabled
local grant, service deployment or host log access.

`Gather(ctx, Request)` validates all exact request, policy, claim-time, local
identity and consent fields before launching. The private canonical stdin
contract has a 32 KiB maximum. The stdout response binds the request identity,
policy digest and claim time and is capped at 512 KiB, including JSON escaping.
Requests and reports redact diagnostic formatting. No metadata or content is
persisted by this package. Stderr is the null device. The non-inherited environment
contains only OS-derived `SystemRoot` on Windows and is empty elsewhere.

`Serve(ctx, in, out, resolve, consume, read)` requires three trusted callbacks:

1. `resolve` independently verifies the fixed installed service, its restricted
   token and live owning parent, activated configuration and protected local
   consent. It returns the exact request after this check. The private-pipe
   request is only a comparison value and cannot stand in for local authority.
2. `consume` obtains the child's exclusive protected consume-once state, durably
   advances the exact monotonic request floor, closes/releases that state and
   only then returns success. Failed, ambiguous or repeated consumption prevents
   a read. The parent must hold no consumption lock while the child runs.
3. `read` gets the exact selected identities and a cooperative five-second
   context. After any result, even one accompanied by an error, `resolve` runs
   again before a report can be released. Callbacks receive defensive copies of
   selections. The original claim time and expiry never advance.

A valid partial, bounded or unavailable report is retained even if the reader
also returns an error. Its fixed validated row reasons describe missing messages;
raw source errors are never sent. Invalid/missing reports and authority failures
emit no output. Capture time must be at or after the acknowledged claim, no later
than the current UTC time, and strictly before original expiry.

The parent's owned-process deadline is the earliest of caller cancellation,
ten seconds and original expiry. It kills and synchronously waits/reaps the
worker before returning. Output overflow also cancels the worker; 100 ms
`WaitDelay` bounds inherited pipe waits. This bounds the owned process and pipe
lifetime subject to OS termination/scheduling, not arbitrary descendants or other
Windows activity. The fixed command entry point must additionally enforce its
own fifteen-second orphan watchdog. In-process synchronous native calls are not
abandoned in goroutines, and no hard in-process native timeout is claimed.

Tests use only synthetic data and inert child modes. They cover canonical IPC,
full-width record IDs, exact identity/consent changes before and after collection,
durable-consumption callback ordering and replay, partial-error survival, caller
cancellation/timeout/expiry kill and reap, output overflow, inherited pipe waits,
finite stderr handling and environment filtering. Read
`docs/windows-event-content.md` and `docs/windows-event-content-request.md` for
source privacy, original expiry and the separately authorized native gate.
