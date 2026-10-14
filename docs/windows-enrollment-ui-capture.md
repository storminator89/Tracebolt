# Windows Setup instructions: synthetic browser evidence

This source-only gate exercises the real compiled `EnrollmentSection`, its
existing protected request code and the created-invitation Windows instruction
panel. It is not the full App, a deployed manager, real authentication,
Windows enrollment, an installer run, native provider coverage or release
acceptance. Published Windows scope and limits remain in [Windows status](windows-status.md).

## Capture matrix and boundary

The existing `Focused source checks` workflow runs this recipe in its
`Focused browser flows` job after the selected browser flows. The explicit step
runs the inert checks and then the hosted capture runner after successful UI/browser
setup, including when a separate browser flow has failed. Cancellation or a failed,
skipped or missing setup prevents this step. Its nonzero result fails that job and
the existing `PR build and affected-flow checks` aggregate. An earlier failure
remains a failure; no `continue-on-error` is added. Screenshot upload still requires
whole-job success, so this independence supplies bounded diagnostics, not partial
public screenshot artifacts.
No workflow, trigger or permission is added. Existing hosted Ubuntu, Node,
Playwright, action pins and read-only repository permissions are reused.

Each of four capture contexts uses English or German at 1440×1100 or 390×844.
Each context produces two images:

- `windows-enrollment-instructions-{en,de}-{1440,390}.png`: the actual Setup heading
  and start of the matching-manager/profile instructions.
- `windows-enrollment-release-{en,de}-{1440,390}.png`: the full publication and
  unverified-download caveat, brought into view by scrolling the real dialog.

These are **eight dialog-cropped images**, not eight full-viewport screenshots.
The manifest records the browser viewport separately from each PNG's actual
cropped dimensions and explicitly names `production-dialog` as the capture
scope. The surrounding page and automatically expanded history are outside the
crop. Fixed invented history IDs are fixture data, not real private identities.
No CSS, DOM replacement, content hiding or image mask changes the captured dialog.

## Exact synthetic creation

All requests to the reserved `windows-enrollment.invalid` origin are fulfilled
from in-memory assets and invented DTOs; every other request is blocked. The
runner never continues or forwards a browser request. It starts no listener,
logs in nowhere and opens no endpoint connection.

The initial Linux picker read and selected Windows read remain separate. The
Windows dialog must show its existing bounded `windows-inventory-v1` disclosure,
with its exact consent checkbox unchecked and creation disabled. A deliberate
fixture-only click acknowledges it. The protected mutation path must then perform
exactly one synthetic CSRF read and one matching intercepted POST. The POST must
have the production key order and bytes for request ID, Windows platform,
`collectionAcknowledged: true` and `insecureHTTPAcknowledged: false`, plus the
exact synthetic CSRF, content type and origin. Additional fields, duplicate
keys, altered byte ordering, missing consent or second creation are rejected.
No read-admin scope is added to dashboard consent.

The returned invitation is a fixed inert string. The input must initially be
masked. Existing `pagehide`/`pageshow` behavior clears that value and refreshes
status before any screenshot. The capture then asserts that the secret input is
absent and no secret or rendered raw fixture identity is inside the dialog.
The target/profile disclosure stays in its ordinary closed state. A matching
positive Range beneath it still fails, whatever native box visibility returns. No bootstrap
file is downloaded or published, and no approval or termination is performed.

## Isolated native-browser visibility controls

Before creating the four capture contexts, the hosted recipe creates and closes
one separate control context: **five total contexts = four capture + one control**.
The success report names both counts and six control cases explicitly. The
manifest requires the bounded control result; the eight production crops, four
synthetic creations and existing browser-suite contracts are unchanged.

Only that context's new empty page navigates to the same reserved origin's fixed
`/visibility-control` path. Its own interceptor serves one source-bound static
HTML document and blocks every other request, including all production/API paths.
It never forwards traffic, shares a page/context with the application, modifies
production markup/styles, downloads data or takes a screenshot. The fixed contents
are known inert fixture strings, not user values. Its CSP allows no scripts or
external resources. The synthetic control document is not uploaded.

The six controls cover safe text, visible synthetic secret text, wrapped body text
inside closed details, a closed summary, an open details body, and matched text
**directly under `display:contents`**. The latter must remain rejected even though
its parent has no box. Positive controls require positive Range geometry and
privacy rejection; the safe control must pass. Closed-body geometry is recorded
only as `positive` or `empty`, since a newly constructed fixture need not reproduce
the application's layout. Native closed-body visibility must be false. A positive
closed-body Range must still fail the unchanged privacy predicate.

`Element.prototype.checkVisibility.call(parent)` is read only after an existing
closed-body Range/text failure. All four native outcomes still reject. The default
API checks the box/flat-tree state, not painted pixels, occlusion, clipping or
opacity. It is deliberately diagnostic, not a new visibility policy. See
[CSSOM View](https://drafts.csswg.org/cssom-view/#dom-element-checkvisibility),
[HTML details rendering](https://html.spec.whatwg.org/multipage/rendering.html#the-details-and-summary-elements),
and [pinned Playwright visibility](https://github.com/microsoft/playwright/blob/v1.58.2/packages/injected/src/domUtils.ts#L78-L131).
These controls must actually pass in the authorized hosted browser before their
behavior can be claimed. Inert adapter tests do not establish browser behavior.

A control failure now names its specific fixed subphase: measurement, observation
shape, boolean Range type, native expectation, positive Range expectation,
Playwright hidden/visible assertion, privacy pass/rejection, or exact privacy-stage
sequence. After valid measurement, native outcomes are only `true`, `false`, or
`invalid` and Range outcomes only `positive` or `empty`. Privacy checkpoints add
only the accepted/rejected result and the last source-enumerated checkpoint
(or `none`/`invalid`), never text, errors, geometry or inspected values. Setup,
runtime-error count and route-boundary assertions also have separate stages.
These diagnostics retain the original control measurement order and assertions.
They do not weaken a failed control or establish production privacy or pixels.

## Checks and artifacts

Local checks are inert only:

```sh
node web/scripts/capture-windows-enrollment.mjs --check
node --test web/scripts/windows-enrollment-capture.node.mjs
```

These compile in memory and test routes, strict request shape, negative controls,
source/evidence metadata and screenshot contracts. They do not launch a browser
or establish pixel acceptance. Browser execution is gated to the existing CI job through its hosted-only
runner; there is no local-browser option or alternate executable setting.

The capture imports the same Inter Latin 400/500/600/700 faces as production
`main.tsx`. It waits for those faces to load and checks the rendered instruction
uses Inter. The four stylesheets, eight font binaries and font package metadata
are hashed separately from tracked source, with the installed version checked
against the pinned package and lockfile. This is not a fallback-font capture.

The bounded `web/tsconfig.json` is included in source provenance and passed to
esbuild explicitly as `tsconfigRaw`; inherited configuration is refused. Source,
style and font inputs pass through bounded regular-file reads before compilation.
Node/esbuild's own installed package resolution remains part of the trusted,
locked toolchain; these checks are not a general filesystem sandbox.

On hosted success, the runner verifies all eight images, exact source-input
hashes against the checked-out Git source SHA, PNG hashes/dimensions, one
synthetic creation per context and zero real API/mutation/native activity.
PNG validation accepts only bounded 8-bit non-interlaced RGB/RGBA: full chunk
ordering/CRCs, nonempty IDAT, exact zlib consumption and scanline length/filters,
IEND and decoded RGBA pixels. It caps compressed files at 8 MiB and inflated/pixel
buffers at 6 MiB; signature or IHDR metadata alone is never evidence. The existing
locked Playwright PNG decoder is reused without launching a browser.

Reports, manifests, source inputs and PNGs are read through one held regular-file
descriptor with canonical/no-symlink checks, actual byte limits, exact size and
pre/post identity/metadata checks. On Linux, the opened descriptor's canonical
path is also checked before reading. JSON evidence must match the canonical
producer encoding, so duplicate or hidden extra fields are rejected.
Diagnostics use a closed stage vocabulary and never export request bodies,
bootstrap data, invitation values, cookies, page text, raw errors or traces.
The public-safety checkpoint distinguishes protected-element presence, inspection
errors, matching Range text (including ancestry below a closed disclosure and a
fixed native parent-box true/false/unavailable/error subcategory), input
values, URL and storage. These are fixed category names only. Closed-disclosure
ancestry does not prove either visibility or invisibility; the same matching text
still fails the unchanged privacy predicate. The category must be investigated
before any capture-policy change. No screenshot is taken before all checks pass.
Only the two verified manifests and eight named images are uploaded, for three
days. Independent pixel review is still required before describing the UX as
visually accepted.

This gate is separate from existing Windows capability, Linux enrollment and
macOS capture suites. Their paths, scenarios and count contracts are unchanged.


## Independent diagnostic scheduling

The existing setup step has the stable `browser_runtime` ID. The Windows step uses
`!cancelled() && steps.browser_runtime.outcome == 'success'`. The status function
avoids GitHub's implicit prior-step-success guard while preserving cancellation;
`outcome` is the unmasked setup result. No workflow event, runner, action pin,
permission, credential, host target or capture scope changes. The existing final
aggregate still requires every prerequisite to succeed.

The accompanying inert contracts bind the exact condition and source SHA, model
all cancellation/setup combinations, and execute the unchanged aggregate script
against successful, failed, cancelled, skipped and missing prerequisite fixtures.
These contracts do not replace hosted workflow execution.

References: [GitHub status-check functions](https://docs.github.com/en/actions/reference/workflows-and-actions/expressions#status-check-functions)
and [step outcome semantics](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts#steps-context).
