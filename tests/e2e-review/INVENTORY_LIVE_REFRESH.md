# Visible first-page inventory refresh

The mounted Processes, Mounts, Packages, complete Updates, Services or Connections
inventory panel checks its existing status ledger every 15 seconds. Only the first
page of the current submitted search/filter is eligible. The compact status label
shows when paging, an unsubmitted edit or a required manual restart has paused it.
The agent's independent collection/reporting interval still determines when a new
capture becomes available. A UI check never starts collection.

An unchanged selected generation updates status only: no row query, cursor renewal
or replacement of the displayed page. A newer pending/failed transfer does not
replace the retained complete generation. A changed, newer complete generation is
staged with one bounded first-page query and published to the UI only after its
identity, manifest, original times, counts and rows validate together. The existing
search/filter, panel, disclosures and scroll container are retained. Metadata and
rows from different generations are never combined.

Later pages and unsubmitted search/filter edits pause polling rather than jumping
back to the first page or submitting draft text. The existing explicit refresh or
search controls resume the first-page workflow. Original capture/retention and
cursor deadlines keep aging; repeated or slowly advancing server timestamps cannot
make a retained observation younger. Cursor expiry and HTTP 409 still require an
explicit restart.

Automatic transient errors retain the last valid snapshot and its original age,
with an error and retry status. Retries back off to 30, 60 and at most 120 seconds;
a successful check restores 15 seconds. Existing ten-second request deadlines,
response/page/scan bounds, protected-request admission, abort and session epochs
remain enforced. Invalid data, clock discontinuity, access/resource loss and
authoritative revocation/expiry clear affected rows. Initial/manual errors retain
the existing explicit-retry contract.

Only the selected mounted inventory reader participates. Hidden/unfocused pages,
navigation, unmount, logout and device/session replacement cancel pending work.
Metadata-only summaries, legacy previews, journal/health service pickers, log
captures, consent, service actions and collection grants do not acquire polling.
The system-inventory hook requires an explicit opt-in from its inventory panel.

## Evidence and limits

The focused `inventory-live-refresh.test.tsx` tests use validated synthetic DTOs
and the actual resource hooks. Existing inventory/API, retained-transfer, cursor,
metadata, journal-picker and health-picker tests retain their boundary checks.
Source/DOM checks do not establish real endpoint delivery, native collection or
hosted browser acceptance. Exact-source browser evidence is still required before
claiming those results.
