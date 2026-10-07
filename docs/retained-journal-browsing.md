# Scoped retained service-log browsing

Source candidate, not native acceptance or a permission grant. The new fresh
full-admin installation must disclose this scope in its one combined approval.
It must call the create-only adapter below and bind the exact resulting policy
digest and activation tuple. The standalone flags are an advanced entry point;
they are not another required approval screen after the combined installation.

## Explicit new scope

`tracebolt.journal-content-policy.v4` with scope
`on-demand-retained-system-service-log-content` and
`browsingContract: tracebolt.journal-browse.v1` authorizes browsing currently
accessible retained entries for every current and future supported exact system
service. The fresh profile uses `serviceAuthorization: all-system-services`
and an explicit empty `allowedUnits` array. It never uses shell patterns,
resolves alias targets, or admits arbitrary paths, kernel or whole-system queries.

The local approval explicitly includes credential/personal-data risk, the exact
manager destination, and HTTP plaintext risk when applicable. The main agent
stays nonroot, with unchanged groups. The separate fixed-purpose helper remains
the only journal source boundary. No additional approval modal is required for
each local read inside this scope. An existing v1, v2 or v3 grant is never promoted
by new binaries, metadata reads, a manager update or a changed UI.

V4's zero `maxWindowSeconds` and `maxLookbackSeconds` have a version-specific
meaning: date ranges may span the accessible retained journal. Older schemas
still reject zero and keep their original one-hour/24-hour limits. The explicit
mode is `retained-v1`; legacy requests without it retain their old semantics.

## Bounded protocol and truthful continuation

Generation report/view v3 advertises the exact browsing contract. Requests use
`tracebolt.journal-request.v3`; helper frames use `TBJ3`; source snapshots and
operator pages use v2. Old endpoints/helpers cannot interpret these as legacy
requests. Public manager support is a separate bounded metadata endpoint:
`GET /v4/journal/capabilities`. It is support metadata, not local permission.

Each request binds exact service, inclusive UTC dates, severity, literal search,
source cursor, fixed budgets and current policy-generation tuple. It is claimed
and durably consumed before reading, with original 15-minute page expiry and
exact retry bytes. Every page is a new consume-once request; querying or retrying
an existing page never refreshes its lifetime. At most one source page per device
is retained, within the existing 25-device memory cache. Display paging is at
most 100 rows/64 KiB. Replacing a source page clears the prior content.

Per source page: 500 retained rows, 512 KiB encoded content, 4 KiB/message,
4,096 scanned entries, 8 MiB raw output, 64 KiB/source line, and four seconds of
cooperative work. Manager durable admission and helper runtime admission enforce
a two-second minimum between browsing requests. These limits never become an
implicit one-hour/last-day cutoff or a claim that 500 rows are all journal rows.

The native adapter reads newest first with a fixed exact-unit/PID1-attribution
query and a bounded `journalctl --lines` count. Search is case-insensitive literal
matching over the masked message projection, not regex or a subprocess argument.
Sparse searches return an empty nonexhausted page with a continuation locator.
The UI exposes “Continue searching older logs.” It does not keep accumulating
pages or search only the currently displayed messages.

A source locator is bounded public journal navigation metadata; it may include
boot/sequence identifiers. It is never rendered as log text, never a command or
credential, and is not proof of past retention. The next operator request must
match the current accepted in-memory page's locator and unchanged query/generation.
After manager restart or content loss, continuation is unavailable rather than
silently recollected. The source seeks inclusively to the locator and verifies
the exact first anchor before dropping it. Vacuumed/rotated/missing anchors give
`cursor_unavailable`; there is no fallback to a nearby entry or empty success.

Retained queries omit `--all` while legacy argv stays unchanged. The
[official systemd JSON contract](https://raw.githubusercontent.com/systemd/systemd/main/man/journalctl.xml)
represents fields larger than 4,096 bytes as `null` by default and binary fields
as arrays. Neither representation is accepted as a projected message or silently
converted into an empty string. These entries produce an explicit partial gap;
when their source locator is valid, the next page can continue past them. A
legal source message that grows beyond the message budget during masking follows
the same explicit gap path. Ordinary page capacity instead retains the preceding
cursor so the first row that did not fit is retried on the next page.

An unprojectable entry with a valid bounded locator produces an explicit partial
gap and may be continued past. Missing/malformed locators, source/time/byte limits,
permissions and visibility restrictions remain incomplete or failed states. An
exhausted page means only that this current traversal found no more accessible
entries for that service/date/filter. It is not an archive, a historical retention
guarantee, or a stable multi-page snapshot. Earlier partial gaps remain gaps.

## Create-only integration adapter

The combined installer calls:

```python
facts, plan = journal_setup.preflight(
    effects, [], templates, all_system_services=True, retained_browsing=True)
result = journal_setup.apply(
    effects, [], templates, reviewed_plan_sha256,
    content_ack=True, plaintext_ack=(facts["profile"] == "http-test"),
    all_system_services=True, retained_browsing=True,
    retained_browsing_ack=True)
```

The exact plan includes page limits, source locators, retained-range semantics
and explicit exclusion of external AI export. It checks installed binary v4/TBJ3
support before effects. The combined approval must cover this plan; callers may
not supply the booleans based on an older read-admin receipt.

Successful configuration requires `configured`, `activationCommitted` and
`commitState: committed`, plus exact protected policy/deployment/activation and
private-floor readback. `policySHA256` is unprefixed; it must equal the digest in
`policyGeneration.policyDigest` after its `sha256:` prefix. Setup reads no logs.
Existing/partial domains fail closed and retain evidence. There is no v4 adoption,
repair, re-enrollment, policy amendment or recovery-by-deletion path here.

For the separately approved advanced standalone path, the read-only plan uses
`--all-system-services --retained-browsing`; apply additionally requires the exact
plan digest, `--ack-journal-content`, `--ack-journal-retained-browsing` and the
HTTP-only acknowledgement when applicable.

## External AI and remaining acceptance

Local browsing never authorizes AI export. The separately approved service-log
AI bridge accepts a fresh generation-view v2, or v3 with this exact browsing
contract, only for its own fixed 5/15-minute capture. V4 already authorizes the
original bounded request-v2/TBJ2 path; the bridge uses that path with the exact
new policy generation and unchanged source budgets. It never changes a retained
query into an AI query, adopts operator content, searches retained history or
follows a source cursor. `AnalyzeJournal` rejects retained queries/pages and
continuation metadata even if a caller spoofs a legacy search scope.

The old provider/device/service/window receipt remains bound to its old local
generation. A local scope change makes settings unready and blocks capture,
export and result readback; restart never rebinds it. Review the current exact
service/generation and approve future bounded captures plus provider export
again in Service-log AI. The provider can remain configured once, but local
installation approval and provider configuration alone never enable log AI.
See [the bounded AI contract](proactive-service-log-ai.md). Source support is
not an actual AI scope grant, provider call or native acceptance.

Synthetic source/protocol/policy, replay/rate, setup, UI and hosted DTO fixtures
do not establish native journal access. Before release, run the registered hosted
LAN browser case on the exact candidate and inspect its desktop/mobile pixels.
The local Chromium attempt here could not start because Unix sockets were denied.
The case is registered additively in the existing LAN runner, without changing
earlier names, session lifetimes or assertion deadlines.

A separately authorized disposable systemd VM must establish real helper
credentials/hardening, more than 500 retained rows across dates/boots, sparse
search, identical-time duplicate rows, actual cursor loss after rotation/vacuum,
restart/replay, cancellation/revocation while paging, per-page resource budgets,
and original expiry. Record source/artifact hashes and transport/platform. Fresh
combined installation, same-scope update, existing-host migration and actual OS
reboot are separate release gates. No user-host installation follows from these
source checks.
