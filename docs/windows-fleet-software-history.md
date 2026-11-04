# Private fleet software-change review

The fleet's **Find machine software** panel now has an **Observed changes** view.
It searches already retained, separately consented Windows machine-software
history without opening each device first. This is a private operator read,
not a software monitor, alert, health assessment or compliance verdict.

Choose Observed changes and deliberately select **Read software changes**. An
empty search reads the existing bounded history; text search is the same literal
Unicode case-insensitive search over before/after metadata, exact registration
identity, view and change kind as the individual history view. It is not a regular
expression or version-order comparison. No query is sent merely by opening the
view or editing its search. No background refresh or browser request fanout runs.

Each fleet page contains at most five currently authorized Windows identities,
with up to three recent matching changes per identity. Large escaped metadata can
shorten a page further. The next page advances by the actual returned identities;
no omitted device is represented as an empty success. Device pages are ordered by
identity, not by the newest change across the fleet. **View matching changes**
opens an identity-bound detail page of at most twenty changes. Its original query,
history digest, source authority and review deadline remain pinned. Pages replace
one another instead of accumulating an unbounded history in the browser.

Unconfigured history, disabled history, an awaiting baseline, comparison gaps,
quota omissions, expired changes and zero retained matches remain distinct. Counts
apply to each complete bounded history, not a fabricated fleet-wide total. Every
change preserves its original before/after observations and expiry. A removed
HKLM registration is not proof of uninstall, and a textual version difference is
not proof of upgrade or downgrade. Selected-user, Store/MSIX, portable and
unregistered applications remain outside the source.

## Consent and unchanged storage

The exact existing `windows-machine-software-history-v1` local grant remains
mandatory. Ordinary software inventory does not grant history. Existing history
consent permits authenticated operator-only private search and paging; it grants
no health inference, AI, export or actions. This view adds none of those purposes.
No monitor policy, acknowledgement, derived incident, record, key, database schema,
retention extension or local scope is created. Expired history is removed only
from the current in-memory projection; the new fleet read does not persist pruning.
The existing software ledger's monotonic read-clock fence is still advanced.

The original limits remain seven days from the earlier original capture, at most
1,024 changes and 1 MiB of history per device, within the existing inventory
budgets. Grants and old software/transport/receipt bytes remain unchanged.
Changing or disabling a history grant cannot transfer its data into another
identity or preserve an earlier grant's history in this view.

## Private query and paging

The existing POST `/api/fleet/windows-software/query` accepts one explicit added
read mode: `{"view":"history","name":"","version":"","cursor":""}`.
In this mode `name` holds the existing history search text and `version` must be
empty. Omitting `view` preserves the original current-inventory request and
response. Unknown modes/fields fail closed. Existing shared/named read visibility,
Origin, CSRF and live operator-session controls are unchanged; no named-read route
allowlist or administrative permission is expanded. Searches and cursors stay in
protected bodies, never URLs, logs or browser storage.

The response schema is `tracebolt.windows-fleet-software-history-page.v1` with
nested `tracebolt.windows-fleet-software-history-device.v1` projections. Nested
ordinary device-history continuation tokens are never emitted. Only separately
signed fleet-history cursors can continue these pages. Their exact unchanged
five-minute maximum deadline is further bounded by session/current-credential
expiry and the earliest original retained change/comparison expiry. They bind the
query, session, mode/position, original identities, current leaves, exact grants
and history digests of the bounded roster. A changed roster or source requires a
new search; an old cursor cannot continue into replacement data.

One admission and enrollment transaction validates the at-most-25-device roster.
History validation is bounded by 25 existing 1 MiB histories, without reading
complete software generations or adding an index or cache. Only the selected
page's bounded projections are returned. Responses stay below 256 KiB. One
10-second context covers store admission, query, JSON preparation and final
recheck. Source/session time is sampled again after roster validation and before
release so expensive validation cannot extend authority or original expiry.

The UI retains only its current page and opaque navigation cursors in memory.
Close, view changes, navigation, blur/hidden state, session loss, unreliable clocks
and original expiry clear private content. Late or obsolete reads cannot restore
it. Detail-page order comparisons preserve source timestamp nanoseconds.

## Verification boundary

Portable tests cover unchanged legacy query bytes, separate history consent,
shared/named request guards, normal and escaped-byte-short pages, exact detail,
cursor-domain/session/query/source isolation, virtual pruning without saved
history writes, revocation, final expiry and source timestamps. A Go-generated
projection fixture is consumed by the TypeScript parser. EN/DE jsdom interaction
checks cover explicit reads, unknown/empty/gap states, no fanout, sensitive-content
clearing, interrupted reads and sub-millisecond paging.

These are source and synthetic-fixture checks. They establish no rendered browser,
native Windows source, installed endpoint, deployment or release acceptance.
No browser automation or publication belongs to this implementation slice.
