# Read saved update jobs across a frozen device selection

In **Windows update worklist**, freeze the devices, open **Saved fleet update
jobs**, then explicitly read the saved jobs. Expand a device to browse ten jobs
per page in the server's original order. Job details retain the exact job ID,
update GUID/revision, purpose, recorded times and any approved UTC window.
The cached-update filter does not narrow this all-jobs overview.
Installation and download outcomes remain distinct from readiness, claimed and
scheduled states. Failure/uncertainty counts count saved results only.

This is a read-only overview of each endpoint's existing bounded history: up to
33 legacy summaries or nine reusable summaries. Empty history is distinct from
unavailable, pending and unread devices. Neither counts nor old successful
results establish current installation, patch coverage or live job status.
The history's original server read time and recorded job times stay separate.

## Authority and bounds

- Read only the already frozen device IDs that remain admitted in the current
  fleet view. Group changes never add targets. Losing a device clears the batch.
- Revalidate the exact named HTTPS operator session and installation capability
  before the batch. Every device's existing history endpoint authorizes its own
  GET. No new endpoint, collector, grant or host permission is introduced.
- At most 50 devices, four outstanding overview requests page-wide (including
  the session check), 64 KiB per history, ten
  seconds per read and one minute per batch. No polling or automatic retry.
  Unauthorized sessions clear/lock the overview; one unavailable device does
  not become an empty history or prevent another authorized read.
- The original batch starts a five-minute memory-only retention limit. No
  disclosure, pagination or result arrival renews it. Session/identity changes,
  access loss, visibility/navigation interruption, clock loss and closing the
  overview clear private results. Late responses cannot restore them. Confirmed
  server time and monotonic request-start time bound session expiry even when
  the browser wall clock was already wrong; later responses can only shorten
  that deadline. Integer history timestamps are compared at their actual
  second precision, without rejecting a valid same-second fractional auth time.
- A canceled transport that ignores abort retains its outstanding slot. Another
  explicit batch waits until those reads settle instead of adding concurrency,
  including after closing/reopening or remounting the worklist. Admission stores
  only opaque leases, never identities, credentials or results. It cannot transfer
  authority: the next explicit batch validates its own exact session again.
  Settlement releases capacity even after unmount; it never restarts a batch.
  If a broken transport never settles, the visible recovery hint is to reload
  the page, with a warning that unsaved selections will be lost. Capacity is
  never silently recycled and the page is never automatically reloaded.

The overview never opens a device, requests readiness, creates/cancels a schedule,
approves/downloads/installs an update, retires a job, exports data or writes browser
storage. It never replaces worklist receipts, exact uncertain-write references
or retirement anchors. Actual per-device review and approval remain separate.

Source/DOM checks do not establish browser rendering, screen-reader behavior,
native Windows/WUA execution, installation acceptance or release readiness.
