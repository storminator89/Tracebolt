# Native complete-inventory delivery candidate

This is isolated source for the explicitly acknowledged fresh
`managed-operations-v3` / `tracebolt.lan-agent.v5` identity. It does not deploy,
provision credentials, install services, or establish actual host acceptance.
Older v1–v4 sender behavior is unchanged. Tests use invented rows, generated
temporary test certificates, private temporary ledgers, and loopback servers.
They do not read the host package database, run apt, or contact external hosts.
Keep operational use behind the source-review and disposable acceptance gates.

## Integration contract

`openInventorySender(material)` requires valid, opaque preloaded v5 material and
opens only the existing `stateDirectory/inventory` ledger. Initialization belongs
to the one-time enrollment handoff before its ready publication. An absent,
incompatible, corrupt, or locked ledger is a fixed state error, never a reason to
create, adopt, reset, or overwrite state. The sender holds that ledger's OS lock
until `Close`, including foreground sleep between bursts.

The private `Burst(ctx)` method is synchronous. Its caller must supply a deadline;
it additionally applies a maximum cooperative 20-second budget. Each burst makes
at most 64 purpose operations, counting begin, append, finalize, failure, status,
and abort. There is no background retry or sleep. Synchronous filesystem and
source operations still need an external process supervisor for a hard deadline.
Call `Close` on every exit. Foreground integration should reuse one sender for its
whole lifetime and run the independent periodic metrics first.

The returned report contains only a fixed status, sequence, operation count, and
whether collection or pending replay occurred. `ErrInventoryPending` means the
operation budget ended with retained work; normal healthy progress should keep
the configured cadence, rather than accumulating transport-error backoff.
Transport, receipt, unresolved conflict, and state errors remain distinct fixed
errors without raw data, response bodies, OS errors, or credential material.

## Capture and durable retry

- Existing exact pending work always takes priority. Finishing it ends the burst;
  a second capture never follows in the same burst.
- A new collection is due at least six hours after the prior durable attempted-at,
  including attempts that reported failure or were explicitly aborted. Restart
  and backwards wall-clock movement cannot bypass this interval.
- Allocation durably reserves the independent monotonic sequence, generation ID,
  and original UTC attempted-at before the synchronous source is called.
- `packagecollector.CollectComplete` returns the complete successful parse before
  any selected-row trimming. Its error is always passed through to
  `fullinventory.Build`; a prefix returned alongside failure cannot become a
  successful generation. Original generation and collection time must match the
  allocation. Successful nonnil empty rows form a valid zero-chunk generation.
- Failures become only the fixed wire reason categories `source_missing`,
  `source_invalid`, `source_changed`, `resource_limit`, or `collection_failed`.
  Cancellation or interruption after allocation leaves the original deterministic
  failure work available on restart rather than recapturing.
- The durable pack retains exact begin/chunk/finalize bytes. Retries do not
  reserialize data, refresh source time, skip the cursor from status counts,
  truncate rows, or discard old pending generations automatically.

## Transport and conflict recovery

Requests use `inventorywire` purpose-bound POST paths. TLS uses the existing
explicit server CA and mutual-TLS material. HTTP-test uses the independent
inventory signing transcript, never the telemetry signature. Both reuse the
existing vetted-address transport with proxies, redirects, and automatic
compression disabled, bounded response headers, and bounded request timeouts.

Only HTTP 200 with the expected uncompressed JSON content type and at most
4 KiB of strictly decoded, purpose/request-digest-bound receipt bytes can advance
local state. The ledger additionally enforces original collection time and
retained receipt chronology. Event times over 30 seconds ahead of the caller's
clock are rejected. A future expiry is not itself an event timestamp.

A delivered 409 is actionable only when its bounded, strict error envelope has
the dedicated `inventory_state_conflict` code and fixed protocol message.
Resource-limit 409s, generic 409s, transport failures, 403s, 5xx responses, invalid
receipts, and redirect responses never initiate abort or identity replacement.
On the dedicated conflict, one new matching status request must pass the ledger's
strict retained-manifest, count, original-begin, expiry, and completion checks.
Only `expired` or `failed` unfinished state with no completion timestamp permits
an atomic request for abort. Expired status must also have reached its expiry.
The pack remains retained until the exact abort receipt is acknowledged.

A status containing a valid prior completion never authorizes local retirement
or abort. If the retained next work is already finalize, the sender can retry
those exact finalize bytes once in this burst, recovering a lost acknowledgment.
Another conflict ends the burst instead of looping. Any earlier cursor remains
retained for operator investigation; status never synthesizes skipped receipts.

**HTTP-test warning:** signatures prove client request possession only. The
traffic is plaintext and its server responses are unauthenticated. Receipt
consistency checks do not provide confidentiality, authenticated server identity,
or proof that an endpoint has been revoked. Generic TLS/HTTP transport errors also
do not establish revocation and never trigger automatic enrollment or key change.

## Synthetic verification

Focused tests cover ordinary generated loopback TLS and signed HTTP-test transport,
513 retained rows over all chunks, exact interrupted append/restart recovery,
zero-row success, the 64-operation cap and resumed remainder, six-hour durable
cadence and clock rollback, allocation-before-capture, source-prefix failure,
cancelled capture/transport, strict conflict/abort checks, lost finalize recovery,
untrusted response rejection, missing-state refusal, restart binding, and lifetime
locking. These are source fixtures, not real package-source, installed-service,
reboot, firewall, or production server acceptance.

From the repository with its provisioned offline Go toolchain:

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off go test -buildvcs=false ./internal/lanclient -run '^TestInventoryNative' -count=1
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off go test -race -buildvcs=false ./internal/lanclient -run '^TestInventoryNative' -count=1
```
