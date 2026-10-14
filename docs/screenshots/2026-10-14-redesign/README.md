# Redesigned dashboard screenshots

These four images are genuine Chromium viewport captures from the successful
[14 October 2026 Focused source checks run, attempt 1](https://github.com/storminator89/Tracebolt/actions/runs/38628439200),
using exact [source `ccb807c7`](https://github.com/storminator89/Tracebolt/tree/ccb807c7a02ed4475e543f2bda4128102ee27a1b).
This includes the merged operations overview and Inventory / Setup / Fleet tools
redesign. The images were copied unchanged from its public-safe browser artifact
and visually inspected. No image was generated, retouched, cropped or assembled.

- **[Operations overview](overview-desktop.png):** open cases, observed device
  states and the inventory entry point. English controls retain the original
  German demo case titles; the navigation has its real keyboard focus outline.
- **[Device inventory](devices-desktop.png):** workspace navigation, search,
  filters, saved-view control and fixture device rows.
- **[Device overview](device-overview.png):** an invented Linux resource-history
  fixture with report age, explicitly unknown warning/update assessments and
  CPU, memory and root-filesystem graphs. The isolated HTTP-test warning and
  chart focus outline remain visible. This is not a production configuration.
- **[Mobile overview](overview-mobile.png):** the same operations page at a
  narrow viewport, with stacked case cards and responsive navigation.

All names, addresses, measurements and observations are invented fixtures.
The shell gallery excludes the real local collector. Resource history uses a
loopback HTTP-test fixture and intercepted invented samples. No user-host
telemetry, invitation, credential or external-provider response is displayed.
Demo macOS CPU/RAM values are invented UI examples, not evidence that the released
Mac profiles collect those percentages. These images establish rendering only,
not native collection, enrollment, installation, provider completeness or mobile
hardware acceptance. They show this source revision, not a promise that every
pinned endpoint release includes the same frontend.

Desktop captures are 1440 × 1000; mobile is 390 × 844. These are viewport images,
not full-page stitching: content can continue below the visible edge.
[Provenance and SHA-256 hashes](provenance.json) record the original filenames,
manifest disclosures, exact source, workflow and artifact identity.

## Reproduce

The repository's [Focused source checks workflow](../../../.github/workflows/pr-checks.yml)
builds the production frontend and runs its existing browser fixture harness.
At the pinned source, the shell gallery is invoked by
`node tests/e2e-review/run.mjs`; resource history is captured by
`node tests/e2e-review/lan-browser.mjs`. Follow the workflow's build, dependency
and fixture setup rather than pointing the harness at a real fleet.
The original manifests are `screenshot-manifest.json` and
`lan-browser-manifest.json`. CI artifacts expire; the selected unchanged images
and their provenance are retained here in Git.
