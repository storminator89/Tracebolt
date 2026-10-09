# Browser JSON response bounds

The shared browser request helper streams and counts response bytes before JSON
parsing by default. The ordinary ceiling is 256 KiB; caller-supplied smaller
ceilings remain effective. UTF-8 decoding is fatal on bounded paths. A numeric
Content-Length above the ceiling rejects early, but a missing or understated
header never replaces counting the actual streamed bytes. Header/body equality
is not required, including when the browser exposes decoded content.

The existing higher route budgets remain unchanged:

- Package-update workflow paths: 512 KiB (`web/src/package-update-types.ts`).
  The server's `internal/packageupdate/view.go` projects one validated job and
  preview, with the existing 32-package / 128-KiB plan contract.
- Canonical resource-history paths: 1.5 MiB, enforced by
  `internal/api/resource_history.go:writeResourceHistoryResponse`.
- Canonical investigation queries: 2 MiB, enforced by
  `internal/api/investigations.go`.

Error bodies always use bounded parsing. Unreadable, oversized or malformed
errors retain their HTTP status and generic status message, without trusting
body error codes or text. A protected 401 still invalidates the current access
scope without consuming its body. Login 401 bodies are bounded normally.

## Legacy compatibility exceptions remain unbounded

Only successful responses without an explicit caller limit are exempt for:

- GET `/overview`, `/devices`, `/cases`
- GET `/devices/{id}`, `/cases/{id}`
- POST `/cases/{id}/notes`, `/cases/{id}/status`

IDs use the server's exact `[a-z0-9_-]{1,96}` grammar. No query string, extra path
segment or other method receives an exception. Explicit caller caps always win;
for example, the existing individual-device metadata reader still uses 256 KiB.
These exceptions are compatibility behavior, not byte-safety guarantees.

`internal/api/api.go` returns complete stored case/device objects and lists.
`internal/store/store.go` returns at most 1,000 rows, but has no per-object or
aggregate response-byte contract. Case mutations permit 100 notes and 500
timeline entries; each note accepts 2,000 UTF-8 bytes. Go JSON escaping can make
100 legal notes alone exceed 1.2 MB. Overview includes complete case histories.
Store seeding also has no byte bound for general case/device fields. Assigning
an arbitrary larger limit would not establish a sound compatibility contract.

Remaining work needs a separately reviewed API design: bounded summary
projections for overview/fleet/case lists, and bounded pages for complete
histories/details, preserving original data and mutation/recovery semantics.
This scoped correction does not make every response universally bounded.
