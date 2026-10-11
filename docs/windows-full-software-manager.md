# Complete Windows machine software: manager source candidate

This separate default-off extension retains complete caller-visible machine
Uninstall registrations from both HKLM registry views. It is not a list of all
installed applications. Per-user registrations, MSIX/Store applications,
portable/unregistered programs, paths, commands, license keys and configuration
are outside the contract. No manager upgrade grants collection or changes an
existing Windows observation or complete-service grant. Native LocalService
registry visibility and installed-service acceptance remain separately approved
Windows gates; the checks below use invented rows.

## Independent authority and transfer

`windowsfullsoftware` defines the typed consent, canonical messages, manifests,
receipts and pages. `windowsfullsoftwareledger` uses separate `wfw_*` tables and
transaction-scoped SQL operations. The existing mandatory credential record gets
an irreversible `windowsFullSoftwareInitialized` marker only when the first valid
scope message commits. Missing used tables, authority/floors or the marker fail
closed. Initialization cannot adopt an earlier grant or reconstruct used state.
The old service schema, consent, sequence, data and cursor domains stay separate.

Scope, chunk and failure requests enter through
`/v1/windows/agent/full-software/{scope,chunk,failure}`. Both TLS client identity and
the purpose-specific signed HTTP-test path verify activated Windows identity,
certificate lifetime/revocation, exact configured agent-listener origin, sender
binding and current local consent revision. Enrollment/UI and agent origins may
differ. Scope changes replace or disable old authority without resetting floors.
HTTP-test remains an explicitly acknowledged plaintext test path.

The first chunk reserves its whole declared generation and advances the durable
sequence floor in the same transaction. Exact retries return original receipts;
changed retry bytes, ordering, digest or offset fail. No prefix is exposed. Final
promotion validates every canonical row and the original digest, bytes, count and
registration ordering. Failed attempts retain the previous complete capture and
its original receipt/expiry. Staging expires after 15 minutes without renewal.

Bounds are 32,768 rows, 8 MiB canonical rows, 12 MiB endpoint frozen pack, 512
chunks, and 128 rows / 64 KiB per request. The manager reserves 48 MiB per software
device and permits three current/staging/garbage generations. Software and
complete-service reservations share the same 128 MiB global logical ceiling,
including credential/authority, telemetry, event metadata and resource history.
Both domains account for the other's reservations at admission and during
transaction validation, without mutually recursive budget calls. Separate software
row/chunk/generation ceilings are 200,000 / 4,096 / 75 across the manager. These
bounds do not guarantee that two maximum-size captures fit concurrently for
replacement, or that every maximum-size device can be retained simultaneously. Existing
physical database/WAL caps still apply. Each manager maintenance tick reclaims at
most 256 rows and 16 chunks from one garbage software generation; reservations
remain until its final physical records are removed. Independent floors remain.

## Protected operator query

POST `/api/devices/{agent_id}/windows-full-software/query` requires a current
operator session, permitted read capability, trusted Origin and CSRF protection.
Names and cursors are accepted only in the JSON body, never query URLs.

Request: `{"search":"","sort":"name-asc","limit":100,"cursor":""}`.
Sorts are name, version, publisher and view, each `-asc` or `-desc`. Optional
missing fields sort last in either direction. Ties use exact `registrationId`.
Duplicate names remain distinct registrations. Search is literal Unicode
case-insensitive over name, version, publisher and registry view, with a 256-byte
query ceiling. Search/count checks the complete bounded capture, including the
integrity of rows outside the result page.

The page schema is `tracebolt.windows-full-software-page.v1`. Rows contain only:
64-hex `registrationId`; `registryView` (`32`/`64`); nullable `name`, `version` and
`publisher`; and their `observed`/`unavailable` quality fields. Optional text has
512 UTF-16-unit / 2,048 UTF-8-byte limits. Registration identity derives from the
exact native key bytes and view, never a casefolded label or guessed application
identity. Canonical source order is increasing registration ID.

Pages hold at most 100 rows / 256 KiB. Missing authority yields `not_configured`;
other states are `disabled`, `awaiting`, `unavailable` and `ready`. Only `ready`
has a complete manifest. Latest attempt is independent of retained complete data.
An empty complete capture is explicit; an unavailable source is never treated as
an empty inventory.

A cursor binds device, grant/revision, generation/manifest, exact query/sort/limit,
matching offset, operator session and original deadline. Deadline is the earliest
of first request plus 15 minutes, original source expiry, certificate expiry and
session expiry. Continuation preserves it. A newer generation, changed grant or
expired cursor requires restarting; pages never splice captures. Store and
response guards recheck current identity, session, grant, generation and original
lifetimes after waits and response preparation. Errors disclose no rows.

Errors include 400 `windows_full_software_invalid`, 403 `agent_unauthorized`,
404 `not_found`, 409 `windows_full_software_restart_required`, 429
`inventory_busy`, and 503 `storage_unavailable`. Receipt admission additionally
reports finite source/resource errors. These operator-only rows have no AI,
provider, alarm, package-action or remote-control integration.

## Source checks and remaining gates

Focused store tests cover 32,768 compact rows, duplicate display names and missing
fields, all eight sorts, whole-generation Unicode search, byte-short pages,
immutable retry receipts, restart, pending invisibility, bad final digests and
failed COMMIT rollback. Authority regressions cover current revocation/expiry,
post-commit and connection-wait checks, session/cursor isolation, configured
listener origin, lost used state, service-grant nonpromotion and cleanup floors.
Cross-domain tests fill real separate software/service reservations and prove
both admission paths and both transaction validators refuse their combined
128 MiB overage without consuming a rejected sequence.

Transport fixtures use real loopback TLS and separately signed HTTP-test requests,
including blocked bodies and last-response authority changes. Operator fixtures
exercise protected full paging, Origin/CSRF checks and late logout/revocation.
Source and fixture success establishes neither native registry behavior nor a
host grant, release, deployment or browser acceptance.
