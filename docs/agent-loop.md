# Foreground read-only attempt scheduler

`internal/agentloop` is a small dependency-injected scheduling library. It
implements repeated **foreground** invocation of an approved, bounded read-only
agent operation. It does not itself collect telemetry, open network connections,
read/write files, issue or load credentials, install a service, enroll an agent,
execute shell commands, or accept remote work.

This library alone is not an installed/background agent. Command integration,
installation and service lifecycle remain separate reviewed work. Its tests use
only synthetic results and fake time; passing them is not deployment or actual
scheduled-collection evidence. Existing command flags and sender behavior are
not changed by this isolated package.

## API and ownership

```go
func Run(ctx context.Context, cfg Config, deps Dependencies) (Summary, error)

type Config struct {
    Interval time.Duration
}

type Dependencies struct {
    Attempt func(context.Context) Result // Named Attempt type in the package.
    Observe func(Event) error            // Optional, synchronous status sink.
    Clock   Clock                       // Optional, local trusted test seam.
    Random  func(maxExclusive int64) int64 // Optional, local jitter seam.
}

type Result struct {
    Outcome  Outcome
    Metadata Metadata
}
```

The mandatory `Attempt` callback represents one specific approved observation and
delivery attempt. This is not a command framework. Keep the callback fixed in
local program code; do not obtain functions, paths, commands, or code from manager
responses. The scheduler passes the caller's context unchanged and never owns or
mutates observations, pending bytes, state, receipts, or timestamps.

There is one synchronous callback at a time within a `Run` call. The scheduler
does not start goroutines for attempts or status observers. The caller must own
the single scheduler instance for an agent; this package is not a global
cross-process singleton or state lock. Retain the existing sender's protected
state and exclusive-lock safeguards.

`Observe` is optional and receives bounded status values by copy. It must return
promptly and use bounded/rotated output storage. The scheduler keeps no growing
history or retry queue. Callbacks, clock and random seams are trusted local
dependencies; they are not a sandbox for arbitrary code.

## Cadence, backoff and jitter

- `Interval == 0` selects the nominal **30-second** default. Explicit intervals
  outside **15 seconds through 1 hour**, including negatives, are rejected before
  any callback. A nil context or missing attempt callback is also rejected.
- The first attempt starts immediately. Every next wait begins **after** the
  preceding callback and status emission finish. A slow attempt delays the next
  one; missed intervals are never replayed. There is no ticker or catch-up storm.
- A success resets consecutive failure count and returns to the normal interval.
- A retryable outcome uses `min(Interval × 2^(failures−1), 5 minutes)` as its
  nominal wait. The implementation caps before a multiplication can overflow.
  With the default interval the nominal sequence is 30, 60, 120, 240, 300, 300…
  seconds. A normal interval longer than five minutes therefore has a shorter
  retry cadence, capped at five minutes; the two settings are deliberately not
  interchangeable.
- Normal and retry waits subtract a uniformly selected **0–10%** jitter, never
  going below 15 seconds. The effective normal default is **27–30 seconds after
  completion**, not an exact wall-clock 30-second cadence. At the retry cap the
  wait is **270–300 seconds**. At a 15-second nominal wait no jitter is needed.
- The loop continues only until context cancellation or a terminal outcome.
  There is no maximum lifetime/attempt count hidden in the scheduler. Memory,
  each wait and status fields are bounded; this is not a claim that an arbitrary
  callback has a hard runtime limit.

The default clock is the standard library's one-shot `time.Timer` and `time.Now`.
The production clock retains Go's monotonic time component for elapsed checks;
status contains durations rather than wall-clock timestamps. The default random
function is `math/rand/v2.Int64N` used only for scheduling, never credentials.

Tests inject both clock and random functions. Clock values may not regress;
timers must be non-nil, expose a non-nil channel, deliver no earlier than their
requested delay, and never close their channel. A regression, early timer fire,
closed/nil timer channel, out-of-range random result, or dependency panic stops
with `ErrDependency`. This catches broken seams instead of permitting a tight
retry loop. A dishonest clock that fabricates elapsed time, or a dependency that
blocks forever, cannot be policed by this synchronous in-process library.

## Outcomes and existing sender integration

The five accepted outcomes are `Success`, `Retryable`, `Configuration`, `State`
and `Revoked`. Only `Success` and `Retryable` schedule another attempt.
Configuration/state/revocation stop immediately and visibly through the final
event plus returned `Summary` and fixed sentinel error. The scheduler never
repairs state, deletes pending data, changes identity, or reenrolls automatically.

An integrator can call `lanclient.Run(attemptContext, preloadedMaterial)` once per
callback and classify its result locally:

| Sender result | Scheduler outcome |
| --- | --- |
| Successful acknowledged run | `Success` |
| `lanclient.ErrConfiguration` | `Configuration` (terminal) |
| `lanclient.ErrState` | `State` (terminal) |
| `lanclient.ErrObservation`, `ErrTransport`, or `ErrReceipt` | `Retryable` |
| Explicit, trusted revocation result from an integration that supports it | `Revoked` (terminal) |
| Unclassified/unexpected adapter failure | Stop conservatively; do not assume retry or enrollment is safe |

**Do not infer revocation from a network, TLS, HTTP-status or generic transport
error.** The existing `lanclient.Run` surfaces non-success HTTP status as
`ErrTransport`; it currently has no distinct trusted revocation outcome. This
package does not add or invent one. If the parent context was cancelled, the
scheduler reports cancellation even when the sender returned a generic error.

`Metadata` permits only an unsigned sequence number, three booleans (`Duplicate`,
`RetriedPending`, `DiscardedStale`), and two availability counts. Each count and
their sum must be at most three. Check the sender's signed integer counts **before
converting to `uint8`**; do not permit wrapping conversions. Other report fields,
including profile/identity strings, do not belong in the scheduler result.

The adapter must leave retry/pending decisions to `lanclient.Run`. In particular:

1. Retry exact retained bytes through the existing sender/state path.
2. Do not refresh observation timestamps, reencode pending payloads, forge a new
   sequence, or clear pending data to make a retry look current.
3. Preserve the sender's existing stale-frame discard and fresh-collection policy.
   A backoff longer than the freshness window may cause that sender policy to
   discard a stale frame; the scheduler does not extend its life or override it.
4. Keep invalid state and credential/trust configuration terminal. A subsequent
   restart requires the operator/integrator to address that condition explicitly.

## Cancellation is cooperative

Cancel the parent context on the process's supported stop signal. A pending timer
is stopped; cancellation wins when a timer and the context are both ready. No
new attempt is started once cancellation has been observed. An already-running
callback receives the cancelled context, and the loop waits for that callback to
return. Cancellation just before a callback call can still race with that call;
the callback must check/use its context. The scheduler never overlaps a new
attempt with a previous one to simulate an enforced timeout.

The integrator owns any per-attempt `context.WithTimeout` (the existing one-shot
command uses 20 seconds; the sender has its own bounded HTTP request timeout).
An attempt-specific timeout is still **cooperative**. `context.WithTimeout`
does not kill a blocked collector, status sink or goroutine. A callback/sink that
ignores context or blocks forever prevents `Run` from returning. Runtime process
exit and `runtime.Goexit` are also outside recoverable callback failures.

A required **hard process deadline** belongs to an approved external supervisor
or service lifecycle that can terminate the process after its stop grace period.
This package neither installs nor configures that supervisor. Do not claim that
this library alone provides hard shutdown, boot persistence, unattended service
operation or production installation readiness.

## Status and failures

Each cycle emits at most `starting`, `finished`, and `waiting`, then `stopped`
when the loop terminates. `starting` names the upcoming attempt; the summary
counts only callbacks actually invoked, so cancellation or a broken clock after
that event can leave its number larger than the final count. Terminal outcomes
emit `finished` then `stopped`, with no `waiting` event or timer. Invalid initial
configuration returns a safe summary/error without calling any dependency.

Events and summaries have only allowlisted enums, fixed-width unsigned counters,
booleans and bounded durations. Elapsed duration is capped at one hour; delay is
at most one hour (at most five minutes on retry). Consecutive failures saturate
at 255 and attempt count at `math.MaxUint64` rather than wrapping. Invalid result
enums or counts are rejected before they enter events or summaries. Durations in
JSON are integer nanoseconds with explicitly named fields.

There are no raw error, hostname, path, credential, reading, payload or arbitrary
message fields. No panic/error value is formatted or returned. An attempt panic
produces `ErrAttempt`; an invalid result produces `ErrResult`. Observer errors or
panics produce `ErrObserver`, and that failed observer is never called again.
The returned summary remains available even when no final status event can be
delivered. Context errors are the standard `context.Canceled` or
`context.DeadlineExceeded`; custom cancellation causes are not exposed.

Status-sink failure is terminal, including if the final event itself fails.
Callers must treat a terminal summary as visible operational failure and avoid a
blind reenrollment/restart loop. The library cannot ensure status was persisted
when a caller supplies no observer or a broken sink.

## Deterministic verification

From the repository root with the pinned Go version on PATH:

```sh
go test -race -count=1 ./internal/agentloop
go vet ./internal/agentloop
```

Tests cover repeated success; exponential backoff, cap and reset; jitter endpoints;
cancellation before an attempt, at event boundaries, during a pending wait and
in flight; simultaneously ready cancellation/timer; slow attempts with no overlap
or catch-up; terminal outcomes; invalid configuration/results; saturating
counters; bounded metadata; safe error/panic redaction; failed observers; and
broken timer, clock and random seams. Tests neither sleep nor call the sender,
collector, filesystem, network, service manager or credential tooling.

## Native sender integration

The Linux `lan-agent` now accepts `--foreground --interval 30s`. The default is
still one bounded attempt. Foreground mode retains the existing sender ledger's
exclusive OS lock throughout attempts **and waits**, so another process cannot
interleave collection during backoff. Each attempt uses the original durable
pending request: an uncertain delivery is retried byte-for-byte, original source
timestamps are preserved, and an aged pending request is discarded before a
new observation gets the next sequence. The queue remains one bounded request.

Each attempt has a cooperative 20-second context. A generic transport/receipt
failure is retryable; it is not classified as revocation. Invalid configuration
or local state stops scheduling. SIGINT/SIGTERM cancels the loop and releases the
ledger lock. JSON status lines contain phase, counts, sequence and availability
counts, never raw readings or credentials. The synchronous stdout observer can
block on a stopped consumer; a future OS supervisor must enforce hard shutdown
or output bounds. This command does not install or enable a system service.

Integration tests combine fake scheduling time with real ephemeral loopback
TLS/HTTP fixture delivery. They cover a retained exclusive lock during waits,
response loss after a manager commit, exact duplicate retry, continued sequence
progression and lock release after cancellation. Native service installation,
reboot and long-duration offline acceptance remain separate gates.
