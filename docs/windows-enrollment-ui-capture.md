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
The target/profile disclosure stays in its ordinary closed state. Secret-text
matches always reject. An identifier-only positive Range inside a closed body may
pass only with the independent own-parent-box and native-hidden evidence described
below; closed ancestry alone is insufficient. No bootstrap file is downloaded or
published, and no approval or termination is performed.

## Isolated native-browser visibility controls

Before creating the four capture contexts, the hosted recipe creates and closes
one separate control context: **five total contexts = four capture + one control**.
The success report names both counts and fifteen control cases explicitly. The
manifest requires the bounded control result; the eight production crops, four
synthetic creations and existing browser-suite contracts are unchanged.

Only that context's new empty page navigates to the same reserved origin's fixed
`/visibility-control` path. Its own interceptor serves one source-bound static
HTML document and blocks every other request, including all production/API paths.
It never forwards traffic, shares a page/context with the application, modifies
production markup/styles, downloads data or takes a screenshot. The fixed contents
are known inert fixture strings, not user values. Its CSP allows no scripts or
external resources. The synthetic control document is not uploaded.

The fifteen controls cover safe text; visible and closed-body synthetic secrets;
closed and open disclosure bodies; first and later summaries; nested disclosures;
matching text directly under `display:contents`; hidden text followed by another
visible match; and three `::details-content` visibility/display overrides.
The closed-secret negative requires an empty text Range and must still reach
unconditional secret rejection. Every other control requires a positive text
Range, including all identifier-exception cases. Closed-body controls also require
positive own-parent box geometry, except the deliberate unboxed
`display:contents` negative. Each source-enumerated geometry expectation is exact;
empty identifier geometry cannot pass as unexercised exception coverage.
Native visibility, Playwright visibility and the exact privacy-stage sequence are
checked independently. Secrets, visible matches, first-summary matches, unboxed
matches and overridden-visible bodies must reject; only the enumerated safe or
proven native-hidden identifier cases pass.

The narrow identifier exception applies only below a closed disclosure body,
excluding its first summary. `Element.prototype.checkVisibility.call(parent)`
must return exactly false and the parent must have a finite positive own rectangle
from `Element.prototype.getClientRects`. A missing/throwing native API, an
unboxed parent, true or invalid native result rejects. A successful exception does
not stop the scan: later matches and the existing input, URL, storage and protected
element checks still run. Secret-text matches reject regardless of geometry.
This is an explicit change from the earlier Range-only rejection rule, not a
claim that all closed content is safe. Default native visibility reports
box/flat-tree state, not painted pixels, occlusion, clipping or opacity. See
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

## Failure-only geometry observations

A Range prerequisite assertion may now trigger a separate diagnostic pass, only
when the original control context has successfully closed, the browser remains
connected and the runner has not cancelled or timed out. Setup, measurement,
native, privacy and cleanup failures do not activate this pass. The original
fifteen controls, their exact geometry expectations and assertion order are
unchanged. The failed assertion is rethrown with its original fixed stage.
Diagnostics cannot create capture evidence or make the job pass.

Each of the fifteen source-named probes gets its own new context and page, with
one fresh copy of the same static synthetic control document and its unchanged
single-document interceptor. No probe shares a document or context with another
probe, the failed control, or the production capture. It takes no screenshot and
never changes DOM, CSS or native browser APIs.

Within each probe, the read order is initial element-contents Range, finite own
box, its single direct text-node Range, repeated element-contents Range, and native
visibility. Geometry is exported only as `positive`, `empty` or `error`; native
visibility only as `true`, `false` or `error`. Rectangle data, text, attributes,
identifiers and raw errors are never exported. The unchanged privacy checker then
runs and yields only `accepted`, `rejected` or `error` plus its fixed last stage.
Those sequential reads may themselves force layout. A later privacy acceptance
does not prove its identifier exception ran, and the output explicitly records
`exceptionPath: not-observed` rather than inferring branch coverage.

Complete diagnostic output requires exactly all fifteen known names in order,
closed contexts, one document per context and no runtime/route violation. The
closed schema rejects extra keys, unknown enums, incomplete/duplicate rows and
claims of screenshots or exception proof. Setup, budget, runtime, route,
measurement or cleanup uncertainty discards all partial rows and reports only a
fixed unavailable reason; cancellation or disconnection emits no diagnostic.

The pass has a 15-second hard timer, bounded page waits, checks after every async
operation and the unchanged outer 120-second runner deadline. A timer or abort
stops all further probes and requests closure of the current context. A context
that resolves after stopping is closed before any routing or page creation. A
stuck cleanup never permits another probe or a complete report; the runner still
closes the browser. The extra validated metadata is printed separately after the
unchanged FAIL message. Success manifests, five-context/eight-image counts,
production capture, privacy/persistence gates and success-only artifact upload
are unchanged. These observations diagnose this synthetic harness only.

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
errors, rejected matching text, the fixed native-parent-box failure categories,
input values, URL and storage. It exports fixed category names only. The narrow
closed-body identifier exception above does not exempt secret matches or bypass
any later check.

For each image, a whole-document mutation observer, sticky lifecycle/animation
listeners, stylesheet/font snapshots and bounded frame checks guard the complete
precheck, screenshot and postcheck interval. Active, paused or pending animations,
observed mutations or stylesheet changes reject. Screenshot bytes stay in memory
until both privacy checks, guard checks and guard cleanup succeed. The runner then
checks runtime errors, route boundaries and PNG structure before an exclusive
write. Screenshot preparation uses `animations: 'allow'` and `caret: 'initial'`
to avoid hiding a caret or disabling animations as a capture-side mutation.

This is a bounded persistence guard for the reviewed static synthetic bundle,
not an atomic screenshot API or protection against arbitrary dynamic scripts.
A transient CSSOM/WAAPI change reverted between every observation can escape it;
source review must establish the absence of such writers in the bundled application
inputs. The inert source tripwire is not a sandbox. The guarantee is per image:
a later context or run failure can leave an earlier validated synthetic PNG locally,
but the existing whole-job-success artifact gate prevents a partial public upload.
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

### Current production states and fixed synthetic time

The instruction scene captures the real four-step installation checklist after
one invented invitation and lifecycle-driven secret clearing. The release scene
closes that dialog and reopens the real preparation view, without a second POST.
Both EN/DE desktop/mobile scenes retain the production UI and explicit local
scope/trust approval; Running or activation is never presented as fresh data.

For these eight static invented screenshots only, Playwright installs the clock
at the fixture time and pauses it at +100 ms before navigation. This avoids React
clock-driven controlled-input attribute rewrites during the mutation-protected
PNG interval. It does not change production code or disable the privacy,
mutation, animation, font or pre/post guards. These captures exercise the optional
invitation-token path, not the Rust automatic-registration installer. They prove
neither runtime expiry/timer behavior nor native installation. Advancing-clock
expiry and recovery tests elsewhere remain separate gates.
