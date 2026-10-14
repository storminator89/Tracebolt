# Route-local detail code loading

The existing `details.tsx` module is loaded only when a device route admitted by
`AuthBoundary`, or a development-mode case route, renders its existing detail component.
The two stable React lazy wrappers use the same unmodified import URL. A direct
detail URL still needs that code. The login, overview, list and settings entry
routes do not statically import it. This does not change which data or actions
an operator is allowed to access.

The loading/error boundary stays inside the existing auth and route gates. The
device key retains its device/tab/unit/navigation revision; the case key remains
the case ID so unrelated renders do not reset an existing draft. There is no
transition retaining another device's previous detail tree.

An eager, data-free lifecycle provider above `AuthBoundary` remembers blur,
hidden visibility and pagehide even while the detail module is pending. That
state survives route, actor and private-view replacement. A first detail mount
waits for visible restoration and completion of the existing auth revalidation.
Already mounted details keep their identity and their existing cancellation,
private-data clearing, retention and resume behavior. The only auth context
addition exposes the already existing `checkingAccess` flag; it changes no auth
decision or session lifetime.

A failed import has a generic, localized error with Back and explicit Reload
page controls. It does not display the raw exception or automatically retry.
Reload starts a fresh page and the existing authentication checks; it never
replays a mutation or saved approval. Ordinary navigation never recreates the
lazy wrappers, cache-busts their URL, or resets a loaded resource module.
`service-action-resource.ts` remains unchanged, including its module-scoped
unresolved-action map and auth cleanup listener. Shared auth/API modules have
one identity in the production output.

## Styles and measured build tradeoff

Detail CSS remains eager in its prior traversal order, before `styles.css`, via
`route-detail-styles.ts`. The final CSS bytes and cascade are identical to the
baseline build; no async CSS is added. Keep that ordering when adding styles.

Measured against `fb9c01ead79f75f337c77cc262645a161677e4cf` with the same Node
24.19.0, Vite 7.3.6 and Rollup 4.64.0 production settings and Node zlib defaults:

| JavaScript | Baseline raw / gzip bytes | Candidate raw / gzip bytes |
| --- | ---: | ---: |
| Initial static graph | 2,323,389 / 650,607 | 1,320,615 / 377,116 |
| Deferred detail module | 0 / 0 | 1,007,560 / 276,368 |
| All JavaScript assets | 2,323,389 / 650,607 | 2,328,175 / 653,484 |

The initial gzip reduction is 273,491 bytes, about 42.0%. Downloading both chunks
adds 2,877 gzip bytes overall, about 0.44%. Direct detail entry therefore does
not claim reduced total transfer and adds a deferred request. CSS remains
289,251 raw / 44,664 gzip bytes, SHA-256
`66dbdd3563a4f9883bf0d9889637a05556a6e5ac6bdb47d3250f078758d49421`.
These are actual emitted-byte measurements, not latency, CPU, first-paint,
user-device performance or server-compression measurements.

## Verification and remaining browser gate

`route-details.test.tsx` uses real `AuthBoundary` integration with deliberately
pending or rejected React lazy modules. It covers blocked authentication,
logout/auth invalidation, fresh actor/session replacement, delayed resolution,
blur plus route replacement/away/return, hidden/pagehide plus held revalidation,
loaded-component identity/drafts, failure localization and modal-owned Escape.
Existing device/resource tests retain all abort, private-clear, late-response
and one-read assertions. Resource-lifecycle tests wait explicitly for bootstrap
and module settlement before exercising an already mounted detail.

The pagehide/event-first same-task fixture has a bounded CI diagnostic. Its
failure hook records only a fixed phase: bootstrap, suspend-import, blocked-mount,
blocked-dom, resume-dom or resumed-mount. The sanitized reporter accepts that
enum only for this exact source-known case at its current numeric position;
unknown or extra metadata is withheld. Assertions, deadlines and execution order
are unchanged. Raw errors, DOM and runtime values remain private, and a failed
run stays failed. This diagnostic does not establish the cause of an earlier
failure or change production lifecycle behavior.

The existing hosted browser runners include four focused synthetic LAN cases
and one direct development-case entry. They use the existing disposable
fixture and real auth handlers, delay/fail only the detail script or explicit
fault responses, count requests without retaining headers/bodies, and release
held routes in `finally`. Completion awaits transfer and evaluation of the exact
same module URL. Closed diagnostic labels exclude exception and private data.
The browser cases check initial deferral, blurred route replacement, held auth
revalidation, pending logout/401, explicit reload without mutation replay and
English/German desktop/mobile loading/error captures. Existing artifact
allowlists admit the `synthetic-route-*.png` captures and manifests.

Local Chromium execution was blocked by a denied process-singleton socket.
No browser acceptance or screenshots are claimed from DOM/build checks; the
existing hosted Playwright run and independent original-pixel review remain
required. This change grants no provider call, native collection, enrollment,
service action, installation, deployment or release acceptance.
